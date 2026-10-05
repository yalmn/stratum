//! Fallartefakte und wörtliche Suche über maskierte, gespeicherte Quelldaten.
use crate::{audit, daten::Seite, war_room, Datenbank, StoreError};
use serde_json::{json, Value};
use sqlx::types::Json;
use stratum_model::{
    ActorId, ArtifactId, AuditAction, CaseId, EvidenceId, Permission, WarRoomEntryKind,
};

/// Filter und Seitenmarke für gespeicherte Artefakte.
#[derive(Default, serde::Deserialize)]
pub struct ArtefaktFilter {
    /// Exakte Artefaktart.
    pub art: Option<String>,
    /// Evidence innerhalb des Falls.
    pub evidence: Option<EvidenceId>,
    /// Wörtlicher Suchtext, höchstens 512 Bytes.
    pub suche: Option<String>,
    /// UUID der letzten Zeile.
    pub nach: Option<uuid::Uuid>,
    /// Seitengröße, begrenzt auf 100.
    pub anzahl: Option<i64>,
}
impl Datenbank {
    /// Liest eine stabile Seite; Suchanfragen werden in Audit und War Room protokolliert.
    pub async fn artefakte(
        &self,
        akteur: ActorId,
        fall: CaseId,
        f: &ArtefaktFilter,
    ) -> Result<Seite, StoreError> {
        let suche = f.suche.as_deref().filter(|s| !s.is_empty());
        if suche.is_some_and(|s| s.len() > 512) {
            return Err(StoreError::Eingabe(
                "Suchtext darf höchstens 512 Bytes enthalten".into(),
            ));
        }
        let mut e = self
            .lesen_erlaubt(akteur, Some(fall), json!({"art":"artefakte"}))
            .await?;
        if suche.is_some() {
            e.aktion = AuditAction::SearchRun;
            self.verlangen(akteur, Permission::SearchRun, e.clone())
                .await?;
        }
        let muster = suche.map(|s| {
            format!(
                "%{}%",
                s.replace('\\', "\\\\")
                    .replace('%', "\\%")
                    .replace('_', "\\_")
            )
        });
        let n = f.anzahl.unwrap_or(100).clamp(1, 100);
        let mut tx = self.pool.begin().await?;
        sqlx::query("SET LOCAL statement_timeout = '8s'")
            .execute(&mut *tx)
            .await?;
        let mut q = sqlx::QueryBuilder::<sqlx::Postgres>::new(
            "SELECT a.id, jsonb_build_object('id',a.id,'kind',a.kind,'evidence_id',a.evidence_id, \
             'evidence_name',v.name,'source_locator',a.source_locator,'parser',a.parser, \
             'observations',(SELECT count(*) FROM observation o WHERE o.artifact_id=a.id), 'preview', ");
        if let Some(text) = suche {
            q.push("substr(s.document,greatest(1,strpos(lower(s.document),lower(")
                .push_bind(text)
                .push("))-60),240)");
        } else {
            q.push("left(s.document,240)");
        }
        q.push(
            ") FROM artifact_search s JOIN artifact a ON a.id=s.artifact_id \
                LEFT JOIN evidence v ON v.id=a.evidence_id WHERE s.case_id=",
        )
        .push_bind(fall.0)
        .push(" AND a.case_id=")
        .push_bind(fall.0);
        // Nur gesetzte Filter einfügen, damit auch wiederverwendete Abfragen
        // den Textindex und die Fallindizes nutzen können.
        if let Some(art) = f.art.as_deref() {
            q.push(" AND a.kind=").push_bind(art);
        }
        if let Some(evidence) = f.evidence {
            q.push(" AND a.evidence_id=").push_bind(evidence.0);
        }
        if let Some(muster) = muster {
            q.push(" AND s.document ILIKE ").push_bind(muster);
        }
        if let Some(nach) = f.nach {
            q.push(" AND a.id>").push_bind(nach);
        }
        q.push(" ORDER BY a.id LIMIT ").push_bind(n + 1);
        let zeilen: Vec<(uuid::Uuid, Json<Value>)> = q.build_query_as().fetch_all(&mut *tx).await?;
        let mehr = zeilen.len() as i64 > n;
        let zeilen: Vec<_> = zeilen.into_iter().take(n as usize).collect();
        let naechste = if mehr {
            zeilen.last().map(|v| v.0.to_string())
        } else {
            None
        };
        e.details = json!({"art":"artefakte","suche":suche,"evidence":f.evidence,"typ":f.art,"nach":f.nach,"anzahl":zeilen.len(),"umfang":"gespeicherte_artefaktfelder"});
        let audit_id = audit::schreiben(&mut tx, &e).await?;
        if suche.is_some() && f.nach.is_none() {
            war_room::anhaengen(
                &mut tx,
                war_room::Neu {
                    fall,
                    akteur,
                    art: WarRoomEntryKind::Search,
                    refs: &[],
                    payload: e.details.clone(),
                    parent: None,
                    audit: Some(audit_id),
                },
            )
            .await?;
        }
        tx.commit().await?;
        Ok(Seite {
            eintraege: zeilen.into_iter().map(|v| v.1 .0).collect(),
            naechste,
        })
    }

    /// Artefaktquelle und höchstens 100 maskierte Observationen mit Herkunftsverweisen.
    pub async fn artefakt(
        &self,
        akteur: ActorId,
        fall: CaseId,
        id: ArtifactId,
    ) -> Result<Value, StoreError> {
        let e = self
            .lesen_erlaubt(akteur, Some(fall), json!({"art":"artefakt","id":id}))
            .await?;
        let v: Option<Json<Value>> = sqlx::query_scalar(
            "SELECT jsonb_build_object('id',a.id,'kind',a.kind,'evidence_id',a.evidence_id, \
             'evidence_name',v.name,'source_locator',a.source_locator,'parser',a.parser, \
             'observations',(SELECT count(*) FROM observation o WHERE o.artifact_id=a.id), \
             'felder',COALESCE((SELECT jsonb_agg(x.v ORDER BY x.id) FROM \
               (SELECT o.id,jsonb_build_object('id',o.id,'kind',o.kind,'fields',stratum_suchdatensatz(o.fields, \
                 COALESCE(a.raw_metadata->>'domain' IN ('lsa','dpapi'),false) OR a.kind='browser_login_row' \
                 OR COALESCE(a.parser->>'name' IN ('stratum.lsa','stratum.dpapi'),false) \
                 OR COALESCE(o.fields->>'art'='passwort_klartext',false))) v \
               FROM observation o WHERE o.artifact_id=a.id ORDER BY o.id LIMIT 100) x),'[]'), \
             'herkunft',COALESCE((SELECT jsonb_agg(x.v) FROM \
               (SELECT jsonb_build_object('object_type',p.object_type,'object_id',p.object_id, \
                 'role',p.role,'analysis_run_id',p.analysis_run_id,'observation_id',p.observation_id, \
                 'source_locator',p.source_locator,'parser',p.parser) v \
                FROM provenance_full p WHERE p.artifact_id=a.id ORDER BY p.object_type,p.object_id,p.role,p.analysis_run_id LIMIT 100) x),'[]')) \
             FROM artifact a LEFT JOIN evidence v ON v.id=a.evidence_id WHERE a.id=$1 AND a.case_id=$2")
            .bind(id.0).bind(fall.0).fetch_optional(&self.pool).await?;
        let v = v.ok_or_else(|| {
            StoreError::NichtGefunden("Artefakt gehört nicht zu diesem Fall".into())
        })?;
        self.audit(&e).await?;
        Ok(v.0)
    }
}
