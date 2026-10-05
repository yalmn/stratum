//! Analystenbewertungen mit unveränderten Quellenverweisen und Änderungsverlauf.
use crate::{audit, daten::Seite, war_room, Datenbank, StoreError};
use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use sqlx::types::Json;
use stratum_model::{
    ActorId, ArtifactId, AuditAction, CaseId, DerivationKind, EntityId, EventId, Finding,
    FindingCategory, FindingDisposition, FindingId, FindingPriority, FindingStatus, ObjectRef,
    Permission, WarRoomEntryKind,
};

/// Vom Analysten verfasste Bewertung. IDs, Autor und Zeiten bestimmt der Server.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NeuesFinding {
    /// Kurzer Titel, höchstens 500 UTF-8-Bytes.
    pub title: String,
    /// Erläuterung, höchstens 16000 UTF-8-Bytes.
    pub description: Option<String>,
    /// Fachliche Einordnung.
    pub category: FindingCategory,
    /// Priorität.
    pub priority: FindingPriority,
    /// Bewertung des Sachverhalts.
    pub disposition: FindingDisposition,
    /// Beteiligte Entitäten.
    #[serde(default)]
    pub entity_refs: Vec<EntityId>,
    /// Belegende Ereignisse.
    #[serde(default)]
    pub event_refs: Vec<EventId>,
    /// Belegende Artefakte.
    #[serde(default)]
    pub artifact_refs: Vec<ArtifactId>,
}
/// Änderung einer Bewertung. Die ursprünglichen Quellenverweise bleiben erhalten.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FindingAenderung {
    /// Titel.
    pub title: String,
    /// Erläuterung.
    pub description: Option<String>,
    /// Einordnung.
    pub category: FindingCategory,
    /// Priorität.
    pub priority: FindingPriority,
    /// Bewertung.
    pub disposition: FindingDisposition,
    /// Bearbeitungsstand.
    pub status: FindingStatus,
    /// Gelesener Stand, damit parallele Änderungen nicht überschrieben werden.
    pub expected_updated_at: DateTime<Utc>,
}
fn text_pruefen(title: &str, description: Option<&str>) -> Result<(), StoreError> {
    if title.trim().is_empty() || title.len() > 500 || description.is_some_and(|d| d.len() > 16000)
    {
        return Err(StoreError::Eingabe(
            "Titel fehlt oder Text ist zu lang".into(),
        ));
    }
    Ok(())
}
const FINDING: &str = "SELECT to_jsonb(f) || jsonb_build_object('analyst',u.username, \
 'entity_refs',COALESCE((SELECT jsonb_agg(object_id ORDER BY object_id) FROM finding_ref WHERE finding_id=f.id AND object_type='entity'),'[]'), \
 'event_refs',COALESCE((SELECT jsonb_agg(object_id ORDER BY object_id) FROM finding_ref WHERE finding_id=f.id AND object_type='event'),'[]'), \
 'artifact_refs',COALESCE((SELECT jsonb_agg(object_id ORDER BY object_id) FROM finding_ref WHERE finding_id=f.id AND object_type='artifact'),'[]')) \
 FROM finding f LEFT JOIN app_user u ON u.id=f.created_by";
impl Datenbank {
    /// Liest Bewertungen mit stabiler UUID-Seitenmarke und geprüften Leserechten.
    pub async fn findings(
        &self,
        actor: ActorId,
        case: CaseId,
        after: Option<uuid::Uuid>,
        limit: i64,
    ) -> Result<Seite, StoreError> {
        let e = self
            .lesen_erlaubt(actor, Some(case), json!({"art":"findings"}))
            .await?;
        let n = limit.clamp(1, 100);
        // Ausschließlich feste SQL-Fragmente; Eingaben werden separat gebunden.
        let sql = sqlx::AssertSqlSafe(format!(
            "{FINDING} WHERE f.case_id=$1 AND ($2::uuid IS NULL OR f.id>$2) ORDER BY f.id LIMIT $3"
        ));
        let mut rows: Vec<Json<Value>> = sqlx::query_scalar(sql)
            .bind(case.0)
            .bind(after)
            .bind(n + 1)
            .fetch_all(&self.pool)
            .await?;
        let more = rows.len() as i64 > n;
        rows.truncate(n as usize);
        let next = if more {
            rows.last()
                .and_then(|r| r.0["id"].as_str())
                .map(String::from)
        } else {
            None
        };
        self.audit(&e).await?;
        Ok(Seite {
            eintraege: rows.into_iter().map(|r| r.0).collect(),
            naechste: next,
        })
    }
    /// Liest genau eine Bewertung innerhalb des Falls.
    pub async fn finding(
        &self,
        actor: ActorId,
        case: CaseId,
        id: FindingId,
    ) -> Result<Value, StoreError> {
        let e = self
            .lesen_erlaubt(actor, Some(case), json!({"art":"finding","id":id}))
            .await?;
        // Ausschließlich feste SQL-Fragmente; alle Eingaben stehen in Bind-Parametern.
        let sql = sqlx::AssertSqlSafe(format!("{FINDING} WHERE f.case_id=$1 AND f.id=$2"));
        let row: Option<Json<Value>> = sqlx::query_scalar(sql)
            .bind(case.0)
            .bind(id.0)
            .fetch_optional(&self.pool)
            .await?;
        let row = row.ok_or_else(|| StoreError::NichtGefunden("Finding nicht im Fall".into()))?;
        self.audit(&e).await?;
        Ok(row.0)
    }
    /// Erstellt eine ausdrücklich vom Analysten verfasste Bewertung im Stand New.
    pub async fn finding_anlegen(
        &self,
        actor: ActorId,
        case: CaseId,
        input: NeuesFinding,
    ) -> Result<Value, StoreError> {
        self.lesen_erlaubt(actor, Some(case), json!({"art":"finding_anlegen"}))
            .await?;
        text_pruefen(&input.title, input.description.as_deref())?;
        let count = input.entity_refs.len() + input.event_refs.len() + input.artifact_refs.len();
        if !(1..=100).contains(&count) {
            return Err(StoreError::Eingabe(
                "Ein Finding braucht 1 bis 100 Belege".into(),
            ));
        }
        let now = Utc::now();
        let f = Finding {
            id: FindingId(uuid::Uuid::now_v7()),
            case_id: case,
            title: input.title.trim().into(),
            description: input.description,
            category: input.category,
            status: FindingStatus::New,
            priority: input.priority,
            disposition: input.disposition,
            derivation: DerivationKind::AnalystAsserted,
            entity_refs: input.entity_refs,
            event_refs: input.event_refs,
            artifact_refs: input.artifact_refs,
            created_at: now,
            created_by: actor,
            updated_at: now,
        };
        self.finding_speichern(actor, &f).await?;
        self.finding(actor, case, f.id).await
    }
    /// Ändert die Bewertung unter Zeilensperre; Audit und War Room entstehen atomar.
    pub async fn finding_aendern(
        &self,
        actor: ActorId,
        case: CaseId,
        id: FindingId,
        input: FindingAenderung,
    ) -> Result<Value, StoreError> {
        let mut e = self
            .lesen_erlaubt(actor, Some(case), json!({"art":"finding_aendern"}))
            .await?;
        e.aktion = AuditAction::FindingModify;
        e.objekt_typ = "finding";
        e.objekt_id = Some(id.to_string());
        self.verlangen(actor, Permission::FindingEdit, e.clone())
            .await?;
        text_pruefen(&input.title, input.description.as_deref())?;
        let mut tx = self.pool.begin().await?;
        let before: Option<Json<Value>> = sqlx::query_scalar(
            "SELECT to_jsonb(f) FROM finding f WHERE case_id=$1 AND id=$2 FOR UPDATE",
        )
        .bind(case.0)
        .bind(id.0)
        .fetch_optional(&mut *tx)
        .await?;
        let before =
            before.ok_or_else(|| StoreError::NichtGefunden("Finding nicht im Fall".into()))?;
        let current = before.0["updated_at"]
            .as_str()
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|d| d.with_timezone(&Utc));
        if current != Some(input.expected_updated_at) {
            return Err(StoreError::Eingabe(
                "Finding wurde inzwischen geändert. Neu laden und Entwurf abgleichen.".into(),
            ));
        }
        let data = json!({"title":input.title.trim(),"description":input.description,"category":input.category,"priority":input.priority,"disposition":input.disposition,"status":input.status});
        let after:Json<Value>=sqlx::query_scalar("UPDATE finding f SET title=x.title,description=x.description,category=x.category,priority=x.priority,disposition=x.disposition,status=x.status,updated_at=greatest(clock_timestamp(),f.updated_at+interval '1 microsecond') FROM jsonb_populate_record(NULL::finding,$3) x WHERE f.case_id=$1 AND f.id=$2 RETURNING to_jsonb(f)")
            .bind(case.0).bind(id.0).bind(Json(data)).fetch_one(&mut *tx).await?;
        e.details = json!({"vorher":before.0,"nachher":after.0});
        let audit = audit::schreiben(&mut tx, &e).await?;
        war_room::anhaengen(&mut tx,war_room::Neu{fall:case,akteur:actor,art:WarRoomEntryKind::FindingUpdated,refs:&[ObjectRef::Finding(id)],payload:json!({"id":id,"title":after.0["title"],"vorher":before.0["status"],"status":after.0["status"]}),parent:None,audit:Some(audit)}).await?;
        tx.commit().await?;
        self.finding(actor, case, id).await
    }
}
