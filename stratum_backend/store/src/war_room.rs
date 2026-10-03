//! War Room: lesen, Einträge von Analysten anhängen, Systemeinträge zu
//! Jobs. Einträge werden nie geändert (die Rolle stratum_app darf es nicht).

use serde_json::{json, Value};
use sqlx::types::Json;
use sqlx::PgConnection;
use stratum_model::{
    ActorId, AuditAction, AuditEventId, AuditResult, CaseId, ObjectRef, Permission, WarRoomEntry,
    WarRoomEntryId, WarRoomEntryKind,
};

use crate::audit::{self, AuditEintrag};
use crate::{Datenbank, StoreError};

/// Höchstlänge einer Notiz in Zeichen.
pub const TEXT_MAX: usize = 20_000;

type Zeile = (
    uuid::Uuid,
    uuid::Uuid,
    chrono::DateTime<chrono::Utc>,
    uuid::Uuid,
    String,
    Json<Vec<ObjectRef>>,
    Json<Value>,
    Option<uuid::Uuid>,
    Option<uuid::Uuid>,
);

/// Eintrag mit Anzeigename des Handelnden.
type ZeileMitName = (
    uuid::Uuid,
    uuid::Uuid,
    chrono::DateTime<chrono::Utc>,
    uuid::Uuid,
    String,
    Json<Vec<ObjectRef>>,
    Json<Value>,
    Option<uuid::Uuid>,
    Option<uuid::Uuid>,
    Option<String>,
);

/// Spalten eines Eintrags.
const SPALTEN: &str = "w.id, w.case_id, w.created_at, w.actor_id, w.kind, w.object_refs, \
    w.payload, w.parent_entry_id, w.audit_event_id";

fn eintrag(z: Zeile) -> Result<WarRoomEntry, StoreError> {
    Ok(WarRoomEntry {
        id: WarRoomEntryId(z.0),
        case_id: CaseId(z.1),
        timestamp: z.2,
        actor: ActorId(z.3),
        kind: serde_json::from_value(Value::String(z.4))?,
        object_refs: z.5 .0,
        payload: z.6 .0,
        parent_entry_id: z.7.map(WarRoomEntryId),
        audit_event_id: z.8.map(AuditEventId),
    })
}

fn art_text(k: WarRoomEntryKind) -> Result<String, StoreError> {
    match serde_json::to_value(k)? {
        Value::String(s) => Ok(s),
        _ => Err(StoreError::Eingabe("Art nicht darstellbar".into())),
    }
}

/// Neuer Eintrag, bevor er geschrieben ist.
pub(crate) struct Neu<'a> {
    pub fall: CaseId,
    pub akteur: ActorId,
    pub art: WarRoomEntryKind,
    pub refs: &'a [ObjectRef],
    pub payload: Value,
    pub parent: Option<WarRoomEntryId>,
    pub audit: Option<AuditEventId>,
}

/// Hängt einen Eintrag an (innerhalb einer laufenden Transaktion).
pub(crate) async fn anhaengen(
    conn: &mut PgConnection,
    n: Neu<'_>,
) -> Result<WarRoomEntryId, StoreError> {
    let id = WarRoomEntryId::new();
    sqlx::query(
        "INSERT INTO war_room_entry (id, case_id, actor_id, kind, object_refs, payload, \
         parent_entry_id, audit_event_id) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(id.0)
    .bind(n.fall.0)
    .bind(n.akteur.0)
    .bind(art_text(n.art)?)
    .bind(Json(n.refs))
    .bind(Json(&n.payload))
    .bind(n.parent.map(|p| p.0))
    .bind(n.audit.map(|a| a.0))
    .execute(&mut *conn)
    .await?;
    Ok(id)
}

impl Datenbank {
    /// Einträge eines Falls, neueste zuerst, seitenweise (Marke ist die ID
    /// des letzten Eintrags; UUIDv7 ist zeitlich sortiert). Braucht
    /// `case.view`.
    pub async fn war_room(
        &self,
        akteur: ActorId,
        fall: CaseId,
        vor: Option<WarRoomEntryId>,
        anzahl: i64,
    ) -> Result<(Vec<(WarRoomEntry, Option<String>)>, Option<WarRoomEntryId>), StoreError> {
        self.verlangen(
            akteur,
            Permission::CaseView,
            AuditEintrag {
                akteur,
                case_id: Some(fall),
                aktion: AuditAction::DataView,
                objekt_typ: "war_room",
                objekt_id: None,
                ergebnis: AuditResult::Denied,
                details: json!({"art": "war_room"}),
            },
        )
        .await?;
        let anzahl = anzahl.clamp(1, 500);
        let sql = format!(
            "SELECT {SPALTEN}, u.display_name FROM war_room_entry w \
             LEFT JOIN app_user u ON u.id = w.actor_id \
             WHERE w.case_id = $1 AND ($2::uuid IS NULL OR w.id < $2) \
             ORDER BY w.id DESC LIMIT $3"
        );
        let zeilen: Vec<ZeileMitName> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
            .bind(fall.0)
            .bind(vor.map(|v| v.0))
            .bind(anzahl + 1)
            .fetch_all(&self.pool)
            .await?;
        let mehr = zeilen.len() as i64 > anzahl;
        let mut out = Vec::with_capacity(zeilen.len());
        for z in zeilen.into_iter().take(anzahl as usize) {
            out.push((eintrag((z.0, z.1, z.2, z.3, z.4, z.5, z.6, z.7, z.8))?, z.9));
        }
        let naechste = if mehr {
            out.last().map(|e| e.0.id)
        } else {
            None
        };
        Ok((out, naechste))
    }

    /// Notiz oder Nachricht eines Analysten. Braucht `case.view`; steht als
    /// `WAR_ROOM_POST` im Audit, der Eintrag verweist darauf.
    pub async fn war_room_schreiben(
        &self,
        akteur: ActorId,
        fall: CaseId,
        art: WarRoomEntryKind,
        text: &str,
        refs: &[ObjectRef],
        parent: Option<WarRoomEntryId>,
    ) -> Result<WarRoomEntry, StoreError> {
        if !matches!(
            art,
            WarRoomEntryKind::AnalystNote | WarRoomEntryKind::AnalystMessage
        ) {
            return Err(StoreError::Eingabe(
                "nur Notizen und Nachrichten von Analysten".into(),
            ));
        }
        let text = text.trim();
        if text.is_empty() || text.chars().count() > TEXT_MAX {
            return Err(StoreError::Eingabe(format!(
                "Text leer oder länger als {TEXT_MAX} Zeichen"
            )));
        }
        let e = AuditEintrag {
            akteur,
            case_id: Some(fall),
            aktion: AuditAction::WarRoomPost,
            objekt_typ: "war_room",
            objekt_id: None,
            ergebnis: AuditResult::Success,
            details: json!({"art": art, "zeichen": text.chars().count(), "refs": refs}),
        };
        self.verlangen(akteur, Permission::CaseView, e.clone())
            .await?;
        if let Some(p) = parent {
            let im_fall: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM war_room_entry WHERE id = $1 AND case_id = $2)",
            )
            .bind(p.0)
            .bind(fall.0)
            .fetch_one(&self.pool)
            .await?;
            if !im_fall {
                return Err(StoreError::Eingabe(
                    "Bezugseintrag gehört nicht zum Fall".into(),
                ));
            }
        }
        let mut tx = self.pool.begin().await?;
        let audit_id = audit::schreiben(&mut tx, &e).await?;
        let id = anhaengen(
            &mut tx,
            Neu {
                fall,
                akteur,
                art,
                refs,
                payload: json!({"text": text}),
                parent,
                audit: Some(audit_id),
            },
        )
        .await?;
        let sql = format!("SELECT {SPALTEN} FROM war_room_entry w WHERE w.id = $1");
        let z: Zeile = sqlx::query_as(sqlx::AssertSqlSafe(sql))
            .bind(id.0)
            .fetch_one(&mut *tx)
            .await?;
        tx.commit().await?;
        eintrag(z)
    }
}
