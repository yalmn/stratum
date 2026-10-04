//! Gemeinsame Fallmerkliste mit geprüften Objektverweisen und Audit.
use crate::{AuditEintrag, Datenbank, StoreError};
use serde_json::{json, Value};
use sqlx::types::Json;
use stratum_model::bookmark::BookmarkKind;
use stratum_model::{ActorId, AuditAction, AuditResult, CaseId, Permission};

/// Änderung einer Auswahl. Fehlende Notiz/Prüfangabe lässt bestehende Werte stehen.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Auswahl {
    /// Objektart.
    pub kind: BookmarkKind,
    /// Stabile Objekt-ID oder Dateireferenz.
    pub target: String,
    /// Arbeitsnotiz, höchstens 8000 UTF-8-Bytes.
    pub note: Option<String>,
    /// Analyst hat das Objekt geprüft; kein bestätigtes Finding.
    pub reviewed: Option<bool>,
    /// Stand des geöffneten Editors; schützt bestehende Notizen vor Überschreiben.
    pub expected_updated_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Nur aus der Auswahl entfernen, serverseitig aufbewahren.
    #[serde(default)]
    pub removed: bool,
}
impl Datenbank {
    async fn bookmark_rechte(
        &self,
        actor: ActorId,
        case: CaseId,
        edit: bool,
    ) -> Result<AuditEintrag, StoreError> {
        let e = AuditEintrag {
            akteur: actor,
            case_id: Some(case),
            aktion: if edit {
                AuditAction::BookmarkEdit
            } else {
                AuditAction::DataView
            },
            objekt_typ: "bookmark",
            objekt_id: None,
            ergebnis: AuditResult::Success,
            details: json!({"art":"bookmarks"}),
        };
        self.verlangen(actor, Permission::CaseView, e.clone())
            .await?;
        self.verlangen(actor, Permission::FileView, e.clone())
            .await?;
        if edit {
            self.verlangen(actor, Permission::BookmarkEdit, e.clone())
                .await?;
        }
        Ok(e)
    }

    async fn bookmark_quelle(
        &self,
        case: CaseId,
        kind: BookmarkKind,
        target: &str,
    ) -> Result<(String, String), StoreError> {
        if target.len() > 250 {
            return Err(StoreError::Eingabe("Objektverweis zu lang".into()));
        }
        let invalid = || StoreError::Eingabe("Objektverweis ungültig".into());
        let (target, title) = if kind == BookmarkKind::File {
            let parts: Vec<_> = target.split('|').collect();
            if parts.len() != 3 {
                return Err(invalid());
            }
            let evidence: uuid::Uuid = parts[0].parse().map_err(|_| invalid())?;
            let volume: i64 = parts[1].parse().map_err(|_| invalid())?;
            let record: i64 = parts[2].parse().map_err(|_| invalid())?;
            if volume < 0 || record < 0 {
                return Err(invalid());
            }
            let title:Option<String>=sqlx::query_scalar("SELECT path FROM file WHERE case_id=$1 AND evidence_id=$2 AND volume_offset=$3 AND mft_record=$4 ORDER BY parent_record,name LIMIT 1").bind(case.0).bind(evidence).bind(volume).bind(record).fetch_optional(&self.pool).await?;
            (format!("{evidence}|{volume}|{record}"), title)
        } else {
            let id: uuid::Uuid = target.parse().map_err(|_| invalid())?;
            let sql = match kind {
                BookmarkKind::Entity => {
                    "SELECT display_name FROM entity WHERE case_id=$1 AND id=$2"
                }
                BookmarkKind::Event => "SELECT kind FROM event WHERE case_id=$1 AND id=$2",
                BookmarkKind::Relationship => {
                    "SELECT kind FROM relationship WHERE case_id=$1 AND id=$2"
                }
                BookmarkKind::Artifact => "SELECT kind FROM artifact WHERE case_id=$1 AND id=$2",
                BookmarkKind::File => return Err(invalid()),
            };
            let title: Option<String> = sqlx::query_scalar(sql)
                .bind(case.0)
                .bind(id)
                .fetch_optional(&self.pool)
                .await?;
            (id.to_string(), title)
        };
        Ok((
            target,
            title
                .ok_or_else(|| StoreError::NichtGefunden("Objekt gehört nicht zum Fall".into()))?,
        ))
    }

    /// Auswahl aufnehmen, bearbeiten oder reversibel aus der Liste entfernen.
    /// Quelle bleibt unverändert, Änderung und Audit sind atomar.
    pub async fn bookmark_schreiben(
        &self,
        actor: ActorId,
        case: CaseId,
        selection: &Auswahl,
    ) -> Result<Value, StoreError> {
        let mut audit = self.bookmark_rechte(actor, case, true).await?;
        if selection
            .note
            .as_ref()
            .is_some_and(|s| s.len() > 8000 || s.contains('\0'))
        {
            return Err(StoreError::Eingabe(
                "Notiz höchstens 8000 Bytes, ohne NUL".into(),
            ));
        }
        let (target, title) = self
            .bookmark_quelle(case, selection.kind, &selection.target)
            .await?;
        let mut tx = self.pool.begin().await?;
        // Serialisiert Änderungen an derselben Auswahl auch vor ihrem ersten Insert.
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(format!("{}|{}|{}", case, selection.kind.name(), target))
            .execute(&mut *tx)
            .await?;
        let before:Option<Json<Value>>=sqlx::query_scalar("SELECT to_jsonb(b) FROM case_bookmark b WHERE case_id=$1 AND kind=$2 AND target=$3 FOR UPDATE").bind(case.0).bind(selection.kind.name()).bind(&target).fetch_optional(&mut *tx).await?;
        if let Some(expected) = selection.expected_updated_at {
            let current = before
                .as_ref()
                .and_then(|b| b.0["updated_at"].as_str())
                .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok());
            if current.map(|d| d.with_timezone(&chrono::Utc)) != Some(expected) {
                return Err(StoreError::Eingabe(
                    "Auswahl wurde inzwischen geändert. Neu laden und Notiz abgleichen.".into(),
                ));
            }
        }
        let after:Json<Value>=sqlx::query_scalar("INSERT INTO case_bookmark AS b (id,case_id,kind,target,title,note,reviewed,removed,updated_by) VALUES ($1,$2,$3,$4,$5,COALESCE($6,''),COALESCE($7,false),$8,$9) ON CONFLICT(case_id,kind,target) DO UPDATE SET note=COALESCE($6,b.note),reviewed=COALESCE($7,b.reviewed),removed=$8,updated_at=clock_timestamp(),updated_by=$9 RETURNING to_jsonb(b)")
            .bind(uuid::Uuid::now_v7()).bind(case.0).bind(selection.kind.name()).bind(&target).bind(title).bind(&selection.note).bind(selection.reviewed).bind(selection.removed).bind(actor.0).fetch_one(&mut *tx).await?;
        audit.objekt_id = after.0["id"].as_str().map(String::from);
        audit.details = json!({"vorher":before.map(|v|v.0),"nachher":after.0});
        crate::audit::schreiben(&mut tx, &audit).await?;
        tx.commit().await?;
        Ok(after.0)
    }

    /// Aktuelle Markierung eines geprüften Quellobjekts, unabhängig von Listenseiten.
    pub async fn bookmark_status(
        &self,
        actor: ActorId,
        case: CaseId,
        kind: BookmarkKind,
        target: &str,
    ) -> Result<Value, StoreError> {
        let mut audit = self.bookmark_rechte(actor, case, false).await?;
        let (target, _) = self.bookmark_quelle(case, kind, target).await?;
        let row:Option<Json<Value>>=sqlx::query_scalar("SELECT to_jsonb(b) FROM case_bookmark b WHERE case_id=$1 AND kind=$2 AND target=$3 AND NOT removed").bind(case.0).bind(kind.name()).bind(&target).fetch_optional(&self.pool).await?;
        audit.details = json!({"art":"bookmark_status","kind":kind,"target":target});
        self.audit(&audit).await?;
        Ok(json!({"bookmark":row.map(|r|r.0)}))
    }

    /// Aktive Auswahl eines Falls, UUIDv7-Keyset, höchstens 100 Objekte je Seite.
    pub async fn bookmarks(
        &self,
        actor: ActorId,
        case: CaseId,
        vor: Option<uuid::Uuid>,
        anzahl: i64,
    ) -> Result<Value, StoreError> {
        let mut audit = self.bookmark_rechte(actor, case, false).await?;
        let count = anzahl.clamp(1, 100);
        let mut rows:Vec<Json<Value>>=sqlx::query_scalar("SELECT to_jsonb(b) FROM case_bookmark b WHERE case_id=$1 AND NOT removed AND ($2::uuid IS NULL OR id<$2) ORDER BY id DESC LIMIT $3").bind(case.0).bind(vor).bind(count+1).fetch_all(&self.pool).await?;
        let more = rows.len() > count as usize;
        rows.truncate(count as usize);
        let next = if more {
            rows.last()
                .and_then(|r| r.0["id"].as_str())
                .map(String::from)
        } else {
            None
        };
        audit.details = json!({"art":"bookmarks","anzahl":rows.len(),"vor":vor});
        self.audit(&audit).await?;
        Ok(json!({"eintraege":rows.into_iter().map(|r|r.0).collect::<Vec<_>>(),"naechste":next}))
    }
}
