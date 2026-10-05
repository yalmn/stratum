//! Quellengeprüfte Kontextregeln über gespeicherte Ergebnisse, ohne Imagezugriff.
use crate::{audit, daten::Seite, war_room, Datenbank, StoreError};
use serde_json::{json, Value};
use sqlx::types::Json;
use stratum_model::{ActorId, AuditAction, AuditResult, CaseId, Permission, WarRoomEntryKind};
use uuid::Uuid;

impl Datenbank {
    /// Startet eine begrenzte Auswertung im konsistenten Datenbankschnappschuss.
    /// Benötigt Leserechte und analysis.start. Es entstehen keine Findings.
    pub async fn korrelation_starten(
        &self,
        actor: ActorId,
        case: CaseId,
    ) -> Result<Value, StoreError> {
        let mut e = self
            .lesen_erlaubt(actor, Some(case), json!({"art":"correlation"}))
            .await?;
        e.aktion = AuditAction::AnalysisStart;
        e.objekt_typ = "correlation";
        self.verlangen(actor, Permission::AnalysisStart, e.clone())
            .await?;
        self.audit(&e).await?;
        let result = self.korrelation_auswerten(actor, case, e.clone()).await;
        if result.is_err() {
            e.aktion = AuditAction::AnalysisFail;
            e.ergebnis = AuditResult::Failure;
            e.details = json!({"art":"correlation","grund":"Auswertung fehlgeschlagen"});
            self.audit(&e).await?;
        }
        result
    }

    async fn korrelation_auswerten(
        &self,
        actor: ActorId,
        case: CaseId,
        mut e: crate::AuditEintrag,
    ) -> Result<Value, StoreError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SET LOCAL statement_timeout='8s'")
            .execute(&mut *tx)
            .await?;
        let rows: Vec<Json<Value>> = sqlx::query_scalar(
            "SELECT jsonb_build_object('event_id',e.id,'kind',e.kind,'entity_id',n.id, \
             'entity_kind',n.kind,'role',ep.role,'host_id',hp.entity_id,'time',e.occurred_at, \
             'snapshot',CASE WHEN jsonb_typeof(o.fields)='object' THEN COALESCE(o.fields->>'herkunft','live') ELSE NULL END, \
             'derivation',e.derivation,'source',jsonb_build_object('evidence_id',p.evidence_id, \
             'artifact_id',p.artifact_id,'observation_id',p.observation_id,'source_locator',p.source_locator, \
             'parser',p.parser,'analysis_run_id',p.analysis_run_id)) \
             FROM event e JOIN event_participant ep ON ep.event_id=e.id \
             JOIN entity n ON n.id=ep.entity_id AND n.case_id=e.case_id \
             JOIN event_participant hp ON hp.event_id=e.id AND hp.role='host' \
             JOIN entity h ON h.id=hp.entity_id AND h.case_id=e.case_id AND h.kind='host' \
             JOIN provenance_full p ON p.object_type='event' AND p.object_id=e.id \
             JOIN artifact a ON a.id=p.artifact_id AND a.case_id=e.case_id AND a.evidence_id=p.evidence_id \
             JOIN evidence v ON v.id=p.evidence_id AND v.case_id=e.case_id \
             LEFT JOIN observation o ON o.id=p.observation_id AND o.artifact_id=a.id AND o.case_id=e.case_id \
             WHERE e.case_id=$1 AND e.occurred_at IS NOT NULL \
             AND e.derivation IN ('observed','parsed','derived') \
             AND e.kind IN ('process_start','network_connection','dns_query','http_request', \
             'service_installed','service_started','scheduled_task_created','scheduled_task_executed') \
             AND n.kind IN ('file','application','process','service','scheduled_task') \
             ORDER BY e.occurred_utc,e.id,n.id,hp.entity_id,p.evidence_id,p.artifact_id,p.observation_id,p.role LIMIT 10001"
        ).bind(case.0).fetch_all(&mut *tx).await?;
        tx.commit().await?;
        let input_limited = rows.len() > 10000;
        let traces = rows
            .into_iter()
            .take(10000)
            .map(|r| serde_json::from_value::<stratum_correlation::Trace>(r.0))
            .collect::<Result<Vec<_>, _>>()?;
        let evaluated = stratum_correlation::evaluate(case, traces);
        let id = Uuid::now_v7();
        let summary = json!({"input_count":evaluated.input_count,"excluded_count":evaluated.excluded_count,
            "comparisons":evaluated.comparisons,"matches":evaluated.matches.len(),"limited":input_limited||evaluated.limited,
            "input_limit":10000,"comparison_limit":200000,"match_limit":500,
            "scope":"same case, normalized entity, host, evidence and source snapshot",
            "stratum_version":env!("CARGO_PKG_VERSION")});
        let rules = serde_json::to_value(stratum_correlation::RULES)?;
        let mut tx = self.pool.begin().await?;
        sqlx::query("SET LOCAL statement_timeout='8s'")
            .execute(&mut *tx)
            .await?;
        sqlx::query("INSERT INTO correlation_run(id,case_id,created_by,rules,summary) VALUES($1,$2,$3,$4,$5)")
            .bind(id).bind(case.0).bind(actor.0).bind(Json(&rules)).bind(Json(&summary)).execute(&mut *tx).await?;
        let results = serde_json::to_value(&evaluated.matches)?;
        sqlx::query("INSERT INTO correlation_result(run_id,case_id,id,payload) SELECT $1,$2,(x->>'id')::uuid,x FROM jsonb_array_elements($3) x")
            .bind(id).bind(case.0).bind(Json(results)).execute(&mut *tx).await?;
        e.aktion = AuditAction::AnalysisComplete;
        e.objekt_id = Some(id.to_string());
        e.details = json!({"summary":summary,"rules":rules});
        let audit = audit::schreiben(&mut tx, &e).await?;
        war_room::anhaengen(
            &mut tx,
            war_room::Neu {
                fall: case,
                akteur: actor,
                art: WarRoomEntryKind::QueryResult,
                refs: &[],
                payload: json!({"event":"correlation_completed","run_id":id,"summary":summary}),
                parent: None,
                audit: Some(audit),
            },
        )
        .await?;
        tx.commit().await?;
        Ok(json!({"id":id,"summary":summary,"rules":rules}))
    }
    /// Die letzten 20 Auswertungen, mit Regelversion und Aussagegrenzen.
    pub async fn korrelation_läufe(
        &self,
        actor: ActorId,
        case: CaseId,
    ) -> Result<Value, StoreError> {
        let e = self
            .lesen_erlaubt(actor, Some(case), json!({"art":"correlation_runs"}))
            .await?;
        let rows: Vec<Json<Value>> = sqlx::query_scalar(
            "SELECT to_jsonb(r) FROM correlation_run r WHERE case_id=$1 ORDER BY id DESC LIMIT 20",
        )
        .bind(case.0)
        .fetch_all(&self.pool)
        .await?;
        self.audit(&e).await?;
        Ok(
            json!({"runs":rows.into_iter().map(|r|r.0).collect::<Vec<_>>(),"rules":stratum_correlation::RULES}),
        )
    }
    /// Metadaten und damalige Regeln einer einzelnen, fallgebundenen Auswertung.
    pub async fn korrelation_lauf(
        &self,
        actor: ActorId,
        case: CaseId,
        run: Uuid,
    ) -> Result<Value, StoreError> {
        let e = self
            .lesen_erlaubt(
                actor,
                Some(case),
                json!({"art":"correlation_run","run":run}),
            )
            .await?;
        let row: Option<Json<Value>> = sqlx::query_scalar(
            "SELECT to_jsonb(r) FROM correlation_run r WHERE case_id=$1 AND id=$2",
        )
        .bind(case.0)
        .bind(run)
        .fetch_optional(&self.pool)
        .await?;
        let row = row
            .ok_or_else(|| StoreError::NichtGefunden("Auswertung gehört nicht zum Fall".into()))?;
        self.audit(&e).await?;
        Ok(row.0)
    }
    /// Quellen einer gespeicherten Auswertung, stabile UUID-Seitenmarke.
    pub async fn korrelation_ergebnisse(
        &self,
        actor: ActorId,
        case: CaseId,
        run: Uuid,
        after: Option<Uuid>,
    ) -> Result<Seite, StoreError> {
        let e = self
            .lesen_erlaubt(
                actor,
                Some(case),
                json!({"art":"correlation_results","run":run,"after":after}),
            )
            .await?;
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM correlation_run WHERE case_id=$1 AND id=$2)",
        )
        .bind(case.0)
        .bind(run)
        .fetch_one(&self.pool)
        .await?;
        if !exists {
            return Err(StoreError::NichtGefunden(
                "Auswertung gehört nicht zum Fall".into(),
            ));
        }
        let mut rows:Vec<Json<Value>>=sqlx::query_scalar("SELECT payload || jsonb_build_object('entity_name',n.display_name,'host_name',h.display_name) FROM correlation_result r JOIN entity n ON n.id=(payload->'traces'->0->>'entity_id')::uuid AND n.case_id=r.case_id JOIN entity h ON h.id=(payload->'traces'->0->>'host_id')::uuid AND h.case_id=r.case_id WHERE r.case_id=$1 AND run_id=$2 AND ($3::uuid IS NULL OR r.id>$3) ORDER BY r.id LIMIT 101")
            .bind(case.0).bind(run).bind(after).fetch_all(&self.pool).await?;
        let more = rows.len() > 100;
        rows.truncate(100);
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
}
