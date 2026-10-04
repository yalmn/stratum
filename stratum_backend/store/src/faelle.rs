//! Fälle und ihre Evidence lesen.
//!
//! Lesen braucht `case.view` (Evidence zusätzlich `evidence.view`) und steht
//! als `CASE_LIST` bzw. `CASE_OPEN` im Audit.

use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use stratum_model::{
    ActorId, AuditAction, AuditResult, Case, CaseClassification, CaseId, CaseStatus, Evidence,
    EvidenceId, EvidenceKind, Permission,
};

use sqlx::types::Json;

use crate::audit::AuditEintrag;
use crate::{Datenbank, StoreError};

/// Ein Fall mit der Zahl seiner Evidence, für Listen.
#[derive(Debug, Clone, serde::Serialize)]
pub struct FallZeile {
    /// Fall.
    #[serde(flatten)]
    pub fall: Case,
    /// Anzahl der Evidence.
    pub evidence: i64,
}

/// Vollständige bearbeitbare Fallangaben. Identität und Evidence bleiben erhalten.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FallAenderung {
    /// Titel des Falls.
    pub titel: String,
    /// Beschreibung, leer zum Entfernen.
    pub beschreibung: Option<String>,
    /// Fallordner für zukünftige Importe.
    pub ordner: Option<String>,
    /// Einstufung des Falls.
    pub einstufung: CaseClassification,
    /// Bearbeitungs- oder Aufbewahrungsstatus.
    pub status: CaseStatus,
}

fn aus_text<T: serde::de::DeserializeOwned>(t: String) -> Result<T, StoreError> {
    Ok(serde_json::from_value(Value::String(t))?)
}

const FALL_SPALTEN: &str = "id, case_number, title, description, status, classification, \
     case_folder, timezone, created_at, created_by, opened_at, closed_at";

type Fallzeile = (
    uuid::Uuid,
    String,
    String,
    Option<String>,
    String,
    String,
    Option<String>,
    Option<String>,
    DateTime<Utc>,
    Option<uuid::Uuid>,
    Option<DateTime<Utc>>,
    Option<DateTime<Utc>>,
);

fn fall_aus(z: Fallzeile) -> Result<Case, StoreError> {
    Ok(Case {
        id: CaseId(z.0),
        case_number: z.1,
        title: z.2,
        description: z.3,
        status: aus_text(z.4)?,
        classification: aus_text(z.5)?,
        case_folder: z.6,
        timezone: z.7,
        created_at: z.8,
        // Fälle aus der Zeit vor den Konten haben keinen Akteur.
        created_by: z.9.map(ActorId).unwrap_or_else(ActorId::unbekannt),
        opened_at: z.10,
        closed_at: z.11,
        tags: Vec::new(),
    })
}

impl Datenbank {
    /// Ändert Fallangaben und protokolliert vorher/nachher atomar.
    pub async fn fall_bearbeiten(
        &self,
        akteur: ActorId,
        fall: CaseId,
        a: &FallAenderung,
    ) -> Result<Case, StoreError> {
        let mut e = AuditEintrag {
            akteur,
            case_id: Some(fall),
            aktion: AuditAction::CaseEdit,
            objekt_typ: "case",
            objekt_id: Some(fall.to_string()),
            ergebnis: AuditResult::Success,
            details: json!({}),
        };
        self.verlangen(akteur, Permission::CaseEdit, e.clone())
            .await?;
        self.verlangen(akteur, Permission::CaseView, e.clone())
            .await?;
        if a.status == CaseStatus::Closed {
            self.verlangen(akteur, Permission::CaseClose, e.clone())
                .await?;
        }
        if a.titel.trim().is_empty() {
            return Err(StoreError::Eingabe("Falltitel darf nicht leer sein".into()));
        }
        if a.ordner
            .as_ref()
            .is_some_and(|p| !std::path::Path::new(p).is_absolute())
        {
            return Err(StoreError::Eingabe(
                "Fallordner muss ein absoluter Serverpfad sein".into(),
            ));
        }
        let mut tx = self.pool.begin().await?;
        let sql = format!("SELECT {FALL_SPALTEN} FROM case_file WHERE id = $1 FOR UPDATE");
        let z: Fallzeile = sqlx::query_as(sqlx::AssertSqlSafe(sql))
            .bind(fall.0)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or_else(|| StoreError::NichtGefunden(format!("kein Fall {fall}")))?;
        let vorher = fall_aus(z)?;
        let mut nachher = vorher.clone();
        nachher.title = a.titel.trim().to_string();
        nachher.description = a.beschreibung.clone();
        nachher.case_folder = a.ordner.clone();
        nachher.classification = a.einstufung;
        nachher.status = a.status;
        if a.status == CaseStatus::Closed && vorher.status != CaseStatus::Closed {
            nachher.closed_at = Some(Utc::now());
        } else if !matches!(
            a.status,
            CaseStatus::Closed | CaseStatus::Archived | CaseStatus::Retained
        ) {
            nachher.closed_at = None;
        }
        sqlx::query("UPDATE case_file SET title = $2, description = $3, case_folder = $4, classification = $5, status = $6, closed_at = $7 WHERE id = $1")
            .bind(fall.0)
            .bind(&nachher.title)
            .bind(&nachher.description)
            .bind(&nachher.case_folder)
            .bind(serde_json::to_value(nachher.classification)?.as_str().ok_or(StoreError::Wert("Einstufung ohne Text"))?)
            .bind(serde_json::to_value(nachher.status)?.as_str().ok_or(StoreError::Wert("Status ohne Text"))?)
            .bind(nachher.closed_at)
            .execute(&mut *tx).await?;
        e.details = json!({"vorher": vorher, "nachher": nachher});
        crate::audit::schreiben(&mut tx, &e).await?;
        tx.commit().await?;
        Ok(nachher)
    }

    /// Fall-ID zu einer Fallnummer (ohne Audit; für die Auswahl vor einer
    /// Aktion, die ihre Berechtigung selbst prüft).
    pub async fn fall_id(&self, nummer: &str) -> Result<Option<CaseId>, StoreError> {
        let id: Option<uuid::Uuid> =
            sqlx::query_scalar("SELECT id FROM case_file WHERE case_number = $1")
                .bind(nummer)
                .fetch_optional(&self.pool)
                .await?;
        Ok(id.map(CaseId))
    }

    /// Alle Fälle, neueste zuerst.
    pub async fn faelle(&self, akteur: ActorId) -> Result<Vec<FallZeile>, StoreError> {
        let e = AuditEintrag {
            akteur,
            case_id: None,
            aktion: AuditAction::CaseList,
            objekt_typ: "case",
            objekt_id: None,
            ergebnis: AuditResult::Success,
            details: json!({}),
        };
        self.verlangen(akteur, Permission::CaseView, e.clone())
            .await?;
        let sql = format!("SELECT {FALL_SPALTEN} FROM case_file ORDER BY created_at DESC");
        let zeilen: Vec<Fallzeile> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
            .fetch_all(&self.pool)
            .await?;
        let anzahl: std::collections::HashMap<uuid::Uuid, i64> =
            sqlx::query_as::<_, (uuid::Uuid, i64)>(
                "SELECT case_id, count(*) FROM evidence GROUP BY case_id",
            )
            .fetch_all(&self.pool)
            .await?
            .into_iter()
            .collect();
        let mut out = Vec::with_capacity(zeilen.len());
        for z in zeilen {
            out.push(FallZeile {
                evidence: anzahl.get(&z.0).copied().unwrap_or(0),
                fall: fall_aus(z)?,
            });
        }
        self.audit(&AuditEintrag {
            details: json!({"anzahl": out.len()}),
            ..e
        })
        .await?;
        Ok(out)
    }

    /// Öffnet einen Fall: Angaben und alle Evidence, nach Registrierung.
    pub async fn fall_oeffnen(
        &self,
        akteur: ActorId,
        fall: CaseId,
    ) -> Result<(Case, Vec<Evidence>), StoreError> {
        let e = AuditEintrag {
            akteur,
            case_id: Some(fall),
            aktion: AuditAction::CaseOpen,
            objekt_typ: "case",
            objekt_id: Some(fall.to_string()),
            ergebnis: AuditResult::Success,
            details: json!({}),
        };
        self.verlangen(akteur, Permission::CaseView, e.clone())
            .await?;
        self.verlangen(akteur, Permission::EvidenceView, e.clone())
            .await?;
        let sql = format!("SELECT {FALL_SPALTEN} FROM case_file WHERE id = $1");
        let z: Option<Fallzeile> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
            .bind(fall.0)
            .fetch_optional(&self.pool)
            .await?;
        let Some(z) = z else {
            return Err(StoreError::NichtGefunden(format!("kein Fall {fall}")));
        };
        let c = fall_aus(z)?;
        let roh: Vec<Json<Value>> = sqlx::query_scalar(
            "SELECT to_jsonb(v) FROM evidence v WHERE case_id = $1 ORDER BY imported_at, id",
        )
        .bind(fall.0)
        .fetch_all(&self.pool)
        .await?;
        let mut evidence = Vec::with_capacity(roh.len());
        for Json(mut v) in roh {
            // Übernommene Platzhalter haben weder Größe noch BLAKE3 noch
            // Akteur; für das Modell mit leeren Werten auffüllen.
            if let Value::Object(o) = &mut v {
                for (k, leer) in [
                    ("size", json!(0)),
                    ("blake3", json!("")),
                    ("imported_by", json!(ActorId::unbekannt())),
                ] {
                    if o.get(k).is_none_or(Value::is_null) {
                        o.insert(k.into(), leer);
                    }
                }
            }
            evidence.push(serde_json::from_value::<Evidence>(v)?);
        }
        self.audit(&AuditEintrag {
            details: json!({"evidence": evidence.len()}),
            ..e
        })
        .await?;
        Ok((c, evidence))
    }

    /// Evidence eines Falls mit diesem SHA-256, mit ihrer Art (ohne Audit;
    /// damit eine Analyse die schon registrierte Evidence wiederfindet).
    pub async fn evidence_nach_hash(
        &self,
        fall: CaseId,
        sha256: &str,
    ) -> Result<Vec<(EvidenceId, EvidenceKind)>, StoreError> {
        let zeilen: Vec<(uuid::Uuid, String)> = sqlx::query_as(
            "SELECT id, kind FROM evidence WHERE case_id = $1 AND sha256 = $2 \
             ORDER BY imported_at, id",
        )
        .bind(fall.0)
        .bind(sha256)
        .fetch_all(&self.pool)
        .await?;
        zeilen
            .into_iter()
            .map(|(id, k)| Ok((EvidenceId(id), aus_text(k)?)))
            .collect()
    }

    /// Evidence eines Falls nach Name oder ID (ohne Audit; Auswahl vor
    /// einer Aktion).
    pub async fn evidence_id(
        &self,
        fall: CaseId,
        name_oder_id: &str,
    ) -> Result<Option<EvidenceId>, StoreError> {
        let id: Option<uuid::Uuid> = sqlx::query_scalar(
            "SELECT id FROM evidence WHERE case_id = $1 AND (id::text = $2 OR name = $2) \
             ORDER BY imported_at LIMIT 1",
        )
        .bind(fall.0)
        .bind(name_oder_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(id.map(EvidenceId))
    }
}
