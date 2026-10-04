//! Jobs: Warteschlange in PostgreSQL.
//!
//! Anlegen braucht `analysis.start`, Abbrechen ist dem Ersteller oder mit
//! `analysis.cancel` erlaubt, Lesen braucht `case.view`. Holen, Fortschritt
//! und Beenden sind Sache des Workers und laufen ohne Rechteprüfung; im
//! Audit erscheint der Lauf selbst (ANALYSIS_START usw.) im Namen des
//! Erstellers.

use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use sqlx::types::Json;
use stratum_model::{
    ActorId, AnalysisRunId, AuditAction, AuditResult, CaseId, Evidence, EvidenceId, Job, JobId,
    JobKind, JobStatus, ObjectRef, Permission, WarRoomEntryKind,
};

use crate::audit::{self, AuditEintrag};
use crate::{Datenbank, StoreError};

/// Ohne Lebenszeichen so lange gilt ein laufender Job als verwaist.
pub const VERWAIST_NACH_SEKUNDEN: i64 = 300;

/// Höchstens so viele Analysen gleichzeitig über alle Worker.
pub const GLEICHZEITIG: i64 = 1;

const SPALTEN: &str = "id, case_id, kind, status, parameters, progress, created_by, \
     created_at, started_at, finished_at, worker, cancel_requested, error, analysis_run_id, result";

type Zeile = (
    uuid::Uuid,
    uuid::Uuid,
    String,
    String,
    Json<Value>,
    Json<Value>,
    uuid::Uuid,
    DateTime<Utc>,
    Option<DateTime<Utc>>,
    Option<DateTime<Utc>>,
    Option<String>,
    bool,
    Option<String>,
    Option<uuid::Uuid>,
    Option<Json<Value>>,
);

fn aus_text<T: serde::de::DeserializeOwned>(t: String) -> Result<T, StoreError> {
    Ok(serde_json::from_value(Value::String(t))?)
}

fn job_aus(z: Zeile) -> Result<Job, StoreError> {
    Ok(Job {
        id: JobId(z.0),
        case_id: CaseId(z.1),
        kind: aus_text(z.2)?,
        status: aus_text(z.3)?,
        parameters: z.4 .0,
        progress: z.5 .0,
        created_by: ActorId(z.6),
        created_at: z.7,
        started_at: z.8,
        finished_at: z.9,
        worker: z.10,
        cancel_requested: z.11,
        error: z.12,
        analysis_run_id: z.13.map(AnalysisRunId),
        result: z.14.map(|j| j.0),
    })
}

fn status_text(s: JobStatus) -> &'static str {
    match s {
        JobStatus::Queued => "queued",
        JobStatus::Running => "running",
        JobStatus::Completed => "completed",
        JobStatus::Failed => "failed",
        JobStatus::Cancelled => "cancelled",
    }
}

impl Datenbank {
    /// Stellt eine Analyse der Evidence `evidence` (im Fall `fall`) in die
    /// Warteschlange. `optionen` sind die Laufoptionen ohne Geheimnisse.
    pub async fn analyse_einreihen(
        &self,
        akteur: ActorId,
        fall: CaseId,
        evidence: EvidenceId,
        optionen: Value,
    ) -> Result<JobId, StoreError> {
        let id = JobId::new();
        let e = AuditEintrag {
            akteur,
            case_id: Some(fall),
            aktion: AuditAction::JobCreate,
            objekt_typ: "job",
            objekt_id: Some(id.to_string()),
            ergebnis: AuditResult::Success,
            details: json!({"art": "analysis", "evidence_id": evidence, "optionen": optionen}),
        };
        self.verlangen(akteur, Permission::AnalysisStart, e.clone())
            .await?;
        let im_fall: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM evidence WHERE id = $1 AND case_id = $2)",
        )
        .bind(evidence.0)
        .bind(fall.0)
        .fetch_one(&self.pool)
        .await?;
        if !im_fall {
            return Err(StoreError::Eingabe(format!(
                "Evidence {evidence} gehört nicht zum Fall {fall}"
            )));
        }
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "INSERT INTO job (id, case_id, kind, status, parameters, created_by, created_at) \
             VALUES ($1, $2, 'analysis', 'queued', $3, $4, now())",
        )
        .bind(id.0)
        .bind(fall.0)
        .bind(Json(json!({"evidence_id": evidence, "optionen": optionen})))
        .bind(akteur.0)
        .execute(&mut *tx)
        .await?;
        let audit_id = audit::schreiben(&mut tx, &e).await?;
        crate::war_room::anhaengen(
            &mut tx,
            crate::war_room::Neu {
                fall,
                akteur,
                art: WarRoomEntryKind::SystemEvent,
                refs: &[ObjectRef::Evidence(evidence)],
                payload: json!({"event": "job_queued", "job_id": id, "job_kind": "analysis", "optionen": optionen}),
                parent: None,
                audit: Some(audit_id),
            },
        )
        .await?;
        tx.commit().await?;
        Ok(id)
    }

    /// YARA-Auftrag nach geprüftem Katalogzugriff einreihen. Regeltext wird
    /// unverändert im Auftrag aufbewahrt; das Audit enthält nur seinen Hash.
    pub async fn yara_job(
        &self,
        akteur: ActorId,
        quelle: &crate::dateien::DateiQuelle,
        volume: i64,
        mft: i64,
        regeln: &str,
        regel_hash: &str,
    ) -> Result<JobId, StoreError> {
        let id = JobId::new();
        let e = AuditEintrag {
            akteur,
            case_id: Some(quelle.fall),
            aktion: AuditAction::JobCreate,
            objekt_typ: "job",
            objekt_id: Some(id.to_string()),
            ergebnis: AuditResult::Success,
            details: json!({"art":"yara_scan", "regel_sha256":regel_hash, "evidence":quelle.evidence, "volume":volume, "mft":mft}),
        };
        self.verlangen(akteur, Permission::AnalysisStart, e.clone())
            .await?;
        let mut tx = self.pool.begin().await?;
        sqlx::query("INSERT INTO job(id,case_id,kind,status,parameters,created_by,created_at) VALUES($1,$2,'yara_scan','queued',$3,$4,now())")
            .bind(id.0).bind(quelle.fall.0).bind(Json(json!({"evidence_id":quelle.evidence,"volume":volume,"mft":mft,"regeln":regeln,"regel_sha256":regel_hash}))).bind(akteur.0).execute(&mut *tx).await?;
        let audit_id = audit::schreiben(&mut tx, &e).await?;
        crate::war_room::anhaengen(&mut tx, crate::war_room::Neu { fall:quelle.fall, akteur, art:WarRoomEntryKind::SystemEvent, refs:&[ObjectRef::Evidence(quelle.evidence)], payload:json!({"event":"job_queued", "job_id":id, "job_kind":"yara_scan", "regel_sha256":regel_hash}), parent:None, audit:Some(audit_id) }).await?;
        tx.commit().await?;
        Ok(id)
    }

    /// Ausdrücklich gewählte externe Abfragen als Job festhalten.
    pub async fn netzwerk_job(
        &self,
        akteur: ActorId,
        fall: CaseId,
        host: &str,
        dns: bool,
        whois: bool,
    ) -> Result<JobId, StoreError> {
        let id = JobId::new();
        let parameters = json!({"host":host, "dns":dns, "whois":whois});
        let e = AuditEintrag {
            akteur,
            case_id: Some(fall),
            aktion: AuditAction::JobCreate,
            objekt_typ: "job",
            objekt_id: Some(id.to_string()),
            ergebnis: AuditResult::Success,
            details: json!({"art":"network_enrichment", "host":host, "dns":dns, "whois":whois}),
        };
        self.verlangen(akteur, Permission::CaseView, e.clone())
            .await?;
        self.verlangen(akteur, Permission::ConnectorUse, e.clone())
            .await?;
        let mut tx = self.pool.begin().await?;
        sqlx::query("INSERT INTO job(id,case_id,kind,status,parameters,created_by,created_at) VALUES($1,$2,'network_enrichment','queued',$3,$4,now())")
          .bind(id.0).bind(fall.0).bind(Json(parameters)).bind(akteur.0).execute(&mut *tx).await?;
        let audit_id = audit::schreiben(&mut tx, &e).await?;
        crate::war_room::anhaengen(&mut tx, crate::war_room::Neu { fall, akteur, art:WarRoomEntryKind::SystemEvent, refs:&[], payload:json!({"event":"job_queued", "job_id":id,"job_kind":"network_enrichment","host":host}), parent:None, audit:Some(audit_id) }).await?;
        tx.commit().await?;
        Ok(id)
    }

    /// Einzelnen Offline-HTTP-Versuch mit überprüftem Quellenverweis einreihen.
    pub async fn http_replay_job(
        &self,
        akteur: ActorId,
        fall: CaseId,
        request: &stratum_model::http_lab::HttpReplayRequest,
    ) -> Result<JobId, StoreError> {
        request.pruefen().map_err(StoreError::Eingabe)?;
        let id = JobId::new();
        let e = AuditEintrag {
            akteur,
            case_id: Some(fall),
            aktion: AuditAction::ReplayRequest,
            objekt_typ: "job",
            objekt_id: Some(id.to_string()),
            ergebnis: AuditResult::Success,
            details: json!({"art":"http_replay","direction":request.direction,"method":request.method,"source":request.source,"network_policy":"none"}),
        };
        for permission in [
            Permission::CaseView,
            Permission::FileView,
            Permission::AnalysisStart,
            Permission::ConnectorUse,
        ] {
            self.verlangen(akteur, permission, e.clone()).await?;
        }
        let mut tx = self.pool.begin().await?;
        if let Some(source) = &request.source {
            let sql = if source.kind == "entity" {
                "SELECT EXISTS(SELECT 1 FROM entity WHERE case_id=$1 AND id=$2)"
            } else {
                "SELECT EXISTS(SELECT 1 FROM artifact WHERE case_id=$1 AND id=$2)"
            };
            let exists: bool = sqlx::query_scalar(sql)
                .bind(fall.0)
                .bind(source.id)
                .fetch_one(&mut *tx)
                .await?;
            if !exists {
                return Err(StoreError::NichtGefunden(
                    "HTTP-Quelle gehört nicht zum Fall".into(),
                ));
            }
        }
        sqlx::query("INSERT INTO job(id,case_id,kind,status,parameters,created_by,created_at) VALUES($1,$2,'http_replay','queued',$3,$4,now())").bind(id.0).bind(fall.0).bind(Json(json!(request))).bind(akteur.0).execute(&mut *tx).await?;
        let audit_id = audit::schreiben(&mut tx, &e).await?;
        let refs: Vec<ObjectRef> = request
            .source
            .as_ref()
            .map(|s| {
                if s.kind == "entity" {
                    ObjectRef::Entity(stratum_model::EntityId(s.id))
                } else {
                    ObjectRef::Artifact(stratum_model::ArtifactId(s.id))
                }
            })
            .into_iter()
            .collect();
        crate::war_room::anhaengen(&mut tx,crate::war_room::Neu {fall,akteur,art:WarRoomEntryKind::ReconstructionStarted,refs:&refs,payload:json!({"event":"http_replay_queued","job_id":id,"network_policy":"none","direction":request.direction}),parent:None,audit:Some(audit_id)}).await?;
        tx.commit().await?;
        Ok(id)
    }

    /// Fallordner eines Falls, falls einer festgelegt ist.
    pub async fn fall_ordner(&self, fall: CaseId) -> Result<Option<String>, StoreError> {
        Ok(sqlx::query_scalar::<_, Option<String>>(
            "SELECT case_folder FROM case_file WHERE id = $1",
        )
        .bind(fall.0)
        .fetch_optional(&self.pool)
        .await?
        .flatten())
    }

    /// Fallordner zum Durchsuchen vor einem Import (braucht
    /// `evidence.import`) samt den Pfaden schon registrierter Evidence. Das
    /// Ansehen steht als `FILE_VIEW` auf dem Fallordner im Audit.
    pub async fn fallordner_ansehen(
        &self,
        akteur: ActorId,
        fall: CaseId,
        pfad: &str,
    ) -> Result<(String, Vec<String>), StoreError> {
        let e = AuditEintrag {
            akteur,
            case_id: Some(fall),
            aktion: AuditAction::FileView,
            objekt_typ: "case_folder",
            objekt_id: None,
            ergebnis: AuditResult::Success,
            details: json!({"pfad": pfad}),
        };
        self.verlangen(akteur, Permission::EvidenceImport, e.clone())
            .await?;
        let ordner = self.fall_ordner(fall).await?.ok_or_else(|| {
            StoreError::Eingabe("Fall ohne Fallordner; Import nur aus dem Fallordner".into())
        })?;
        let quellen: Vec<String> =
            sqlx::query_scalar("SELECT source_uri FROM evidence WHERE case_id = $1")
                .bind(fall.0)
                .fetch_all(&self.pool)
                .await?;
        self.audit(&e).await?;
        Ok((ordner, quellen))
    }

    /// Reiht einen Evidence-Import ein (braucht `evidence.import`). Erst
    /// nach der Rechteprüfung wird `pruefen` mit dem Fallordner aufgerufen;
    /// es löst die Datei auf, prüft, dass sie im Ordner liegt, und liefert
    /// die Parameter des Jobs. Der Worker prüft vor dem Lesen noch einmal.
    pub async fn import_einreihen(
        &self,
        akteur: ActorId,
        fall: CaseId,
        pruefen: impl FnOnce(&std::path::Path) -> Result<Value, String>,
    ) -> Result<JobId, StoreError> {
        let id = JobId::new();
        let e = AuditEintrag {
            akteur,
            case_id: Some(fall),
            aktion: AuditAction::JobCreate,
            objekt_typ: "job",
            objekt_id: Some(id.to_string()),
            ergebnis: AuditResult::Success,
            details: json!({"art": "evidence_import"}),
        };
        self.verlangen(akteur, Permission::EvidenceImport, e.clone())
            .await?;
        let ordner = self.fall_ordner(fall).await?.ok_or_else(|| {
            StoreError::Eingabe("Fall ohne Fallordner; Import nur aus dem Fallordner".into())
        })?;
        let parameter = pruefen(std::path::Path::new(&ordner)).map_err(StoreError::Eingabe)?;
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "INSERT INTO job (id, case_id, kind, status, parameters, created_by, created_at) \
             VALUES ($1, $2, 'evidence_import', 'queued', $3, $4, now())",
        )
        .bind(id.0)
        .bind(fall.0)
        .bind(Json(&parameter))
        .bind(akteur.0)
        .execute(&mut *tx)
        .await?;
        let audit_id = audit::schreiben(
            &mut tx,
            &AuditEintrag {
                details: json!({"art": "evidence_import", "parameter": parameter}),
                ..e
            },
        )
        .await?;
        crate::war_room::anhaengen(
            &mut tx,
            crate::war_room::Neu {
                fall,
                akteur,
                art: WarRoomEntryKind::SystemEvent,
                refs: &[],
                payload: json!({"event": "job_queued", "job_id": id, "job_kind": "evidence_import",
                    "datei": parameter.get("datei")}),
                parent: None,
                audit: Some(audit_id),
            },
        )
        .await?;
        tx.commit().await?;
        Ok(id)
    }

    /// Holt den ältesten wartenden Job und setzt ihn auf `running`, solange
    /// nicht schon [`GLEICHZEITIG`] Jobs laufen. Vorher werden verwaiste
    /// Jobs (ohne Lebenszeichen seit [`VERWAIST_NACH_SEKUNDEN`]) als
    /// fehlgeschlagen beendet, ihr Analyselauf ebenso.
    pub async fn job_holen(&self, worker: &str) -> Result<Option<Job>, StoreError> {
        let mut tx = self.pool.begin().await?;
        // Eine Sperre für die Dauer der Transaktion reiht gleichzeitige
        // Worker auf, damit die Höchstzahl gilt.
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext('stratum.job_holen'))")
            .execute(&mut *tx)
            .await?;
        let verwaist: Vec<(uuid::Uuid, Option<uuid::Uuid>)> = sqlx::query_as(
            "UPDATE job SET status = 'failed', finished_at = now(), \
             error = 'Worker ohne Lebenszeichen' \
             WHERE status = 'running' AND heartbeat_at < now() - make_interval(secs => $1) \
             RETURNING id, analysis_run_id",
        )
        .bind(VERWAIST_NACH_SEKUNDEN as f64)
        .fetch_all(&mut *tx)
        .await?;
        for (_, lauf) in &verwaist {
            if let Some(l) = lauf {
                sqlx::query(
                    "UPDATE analysis_run SET status = 'failed', finished_at = now() \
                     WHERE id = $1 AND status = 'running'",
                )
                .bind(l)
                .execute(&mut *tx)
                .await?;
            }
        }
        let laufend: i64 = sqlx::query_scalar("SELECT count(*) FROM job WHERE status = 'running'")
            .fetch_one(&mut *tx)
            .await?;
        if laufend >= GLEICHZEITIG {
            tx.commit().await?;
            return Ok(None);
        }
        let sql = format!(
            "UPDATE job SET status = 'running', started_at = now(), heartbeat_at = now(), \
             worker = $1 \
             WHERE id = (SELECT id FROM job WHERE status = 'queued' \
               ORDER BY created_at LIMIT 1 FOR UPDATE SKIP LOCKED) \
             RETURNING {SPALTEN}"
        );
        let z: Option<Zeile> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
            .bind(worker)
            .fetch_optional(&mut *tx)
            .await?;
        tx.commit().await?;
        z.map(job_aus).transpose()
    }

    /// Schreibt Fortschritt und Lebenszeichen; liefert, ob ein Abbruch
    /// angefordert ist.
    pub async fn job_fortschritt(
        &self,
        id: JobId,
        fortschritt: &Value,
    ) -> Result<bool, StoreError> {
        let abbruch: Option<bool> = sqlx::query_scalar(
            "UPDATE job SET progress = $2, heartbeat_at = now() \
             WHERE id = $1 AND status = 'running' RETURNING cancel_requested",
        )
        .bind(id.0)
        .bind(Json(fortschritt))
        .fetch_optional(&self.pool)
        .await?;
        // Nicht mehr laufend (etwa als verwaist beendet): abbrechen.
        Ok(abbruch.unwrap_or(true))
    }

    /// Vermerkt den Analyselauf eines laufenden Jobs.
    pub async fn job_lauf(&self, id: JobId, lauf: AnalysisRunId) -> Result<(), StoreError> {
        sqlx::query("UPDATE job SET analysis_run_id = $2 WHERE id = $1")
            .bind(id.0)
            .bind(lauf.0)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Beendet einen laufenden Job.
    pub async fn job_beenden(
        &self,
        id: JobId,
        status: JobStatus,
        fehler: Option<&str>,
        ergebnis: Option<&Value>,
    ) -> Result<(), StoreError> {
        let mut tx = self.pool.begin().await?;
        let job: Option<(uuid::Uuid, uuid::Uuid, String, Json<Value>)> = sqlx::query_as(
            "UPDATE job SET status = $2, finished_at = now(), error = $3, result = $4 \
             WHERE id = $1 AND status = 'running' RETURNING case_id, created_by, kind, parameters",
        )
        .bind(id.0)
        .bind(status_text(status))
        .bind(fehler)
        .bind(ergebnis.map(Json))
        .fetch_optional(&mut *tx)
        .await?;
        // Im War Room: Ende des Jobs mit den wichtigsten Zahlen.
        if let Some((fall, von, art, parameter)) = job {
            let r = ergebnis.cloned().unwrap_or(Value::Null);
            let evidence = parameter
                .0
                .get("evidence_id")
                .or_else(|| r.get("evidence_id"))
                .and_then(Value::as_str)
                .and_then(|s| s.parse().ok())
                .map(|u| ObjectRef::Evidence(stratum_model::EvidenceId(u)));
            let kurz: serde_json::Map<String, Value> = [
                "funde",
                "zeitstrahl",
                "warnungen",
                "name",
                "neu",
                "sha256",
                "report_sha256",
            ]
            .iter()
            .filter_map(|k| r.get(*k).map(|v| ((*k).to_string(), v.clone())))
            .collect();
            crate::war_room::anhaengen(
                &mut tx,
                crate::war_room::Neu {
                    fall: CaseId(fall),
                    akteur: ActorId(von),
                    art: WarRoomEntryKind::SystemEvent,
                    refs: evidence.as_slice(),
                    payload: json!({"event": "job_finished", "job_id": id, "job_kind": art,
                        "status": status, "error": fehler, "result": kurz}),
                    parent: None,
                    audit: None,
                },
            )
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// Bricht einen Job ab: wartend sofort, laufend auf Anforderung (der
    /// Worker hält vor dem nächsten Analyzer an). Erlaubt dem Ersteller und
    /// mit `analysis.cancel`.
    pub async fn job_abbrechen(&self, akteur: ActorId, id: JobId) -> Result<JobStatus, StoreError> {
        let job = self.job_lesen(id).await?;
        let e = AuditEintrag {
            akteur,
            case_id: Some(job.case_id),
            aktion: AuditAction::AnalysisCancel,
            objekt_typ: "job",
            objekt_id: Some(id.to_string()),
            ergebnis: AuditResult::Success,
            details: json!({"stand_vorher": job.status}),
        };
        if job.created_by != akteur {
            self.verlangen(akteur, Permission::AnalysisCancel, e.clone())
                .await?;
        }
        let mut tx = self.pool.begin().await?;
        let neu: Option<String> = sqlx::query_scalar(
            "UPDATE job SET \
               status = CASE WHEN status = 'queued' THEN 'cancelled' ELSE status END, \
               finished_at = CASE WHEN status = 'queued' THEN now() ELSE finished_at END, \
               cancel_requested = true \
             WHERE id = $1 AND status IN ('queued', 'running') RETURNING status",
        )
        .bind(id.0)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(neu) = neu else {
            return Err(StoreError::Eingabe(format!(
                "Job {id} ist schon beendet ({})",
                status_text(job.status)
            )));
        };
        audit::schreiben(&mut tx, &e).await?;
        tx.commit().await?;
        aus_text(neu)
    }

    /// Fordert für alle laufenden Jobs dieses Workers den Abbruch an (der
    /// Worker wird beendet). Im Audit als Abbruch durch das Systemkonto.
    pub async fn worker_jobs_abbrechen(&self, worker: &str) -> Result<u64, StoreError> {
        let ids: Vec<(uuid::Uuid, uuid::Uuid)> = sqlx::query_as(
            "UPDATE job SET cancel_requested = true \
             WHERE worker = $1 AND status = 'running' AND NOT cancel_requested \
             RETURNING id, case_id",
        )
        .bind(worker)
        .fetch_all(&self.pool)
        .await?;
        for (id, fall) in &ids {
            self.audit(&AuditEintrag {
                akteur: ActorId::cli(),
                case_id: Some(CaseId(*fall)),
                aktion: AuditAction::AnalysisCancel,
                objekt_typ: "job",
                objekt_id: Some(id.to_string()),
                ergebnis: AuditResult::Success,
                details: json!({"grund": "Worker wird beendet", "worker": worker}),
            })
            .await?;
        }
        Ok(ids.len() as u64)
    }

    /// Ein Job, mit `case.view` im Fall des Jobs; das Lesen steht im Audit.
    pub async fn job_ansehen(&self, akteur: ActorId, id: JobId) -> Result<Job, StoreError> {
        let job = self.job_lesen(id).await?;
        let e = AuditEintrag {
            akteur,
            case_id: Some(job.case_id),
            aktion: AuditAction::JobList,
            objekt_typ: "job",
            objekt_id: Some(id.to_string()),
            ergebnis: AuditResult::Success,
            details: json!({}),
        };
        self.verlangen(akteur, Permission::CaseView, e.clone())
            .await?;
        if job.kind == JobKind::HttpReplay {
            self.verlangen(akteur, Permission::FileView, e.clone())
                .await?;
        }
        self.audit(&e).await?;
        Ok(job)
    }

    /// Ein Job (ohne Audit; für den Worker und interne Prüfungen).
    pub async fn job_lesen(&self, id: JobId) -> Result<Job, StoreError> {
        let sql = format!("SELECT {SPALTEN} FROM job WHERE id = $1");
        let z: Option<Zeile> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
            .bind(id.0)
            .fetch_optional(&self.pool)
            .await?;
        job_aus(z.ok_or_else(|| StoreError::NichtGefunden(format!("kein Job {id}")))?)
    }

    /// Jobs, neueste zuerst, wahlweise nur eines Falls. Braucht
    /// `case.view`; das Lesen steht im Audit.
    pub async fn jobs(
        &self,
        akteur: ActorId,
        fall: Option<CaseId>,
        anzahl: i64,
    ) -> Result<Vec<Job>, StoreError> {
        let e = AuditEintrag {
            akteur,
            case_id: fall,
            aktion: AuditAction::JobList,
            objekt_typ: "job",
            objekt_id: None,
            ergebnis: AuditResult::Success,
            details: json!({}),
        };
        self.verlangen(akteur, Permission::CaseView, e.clone())
            .await?;
        let file_view = self.rechte(akteur).await?.contains(&Permission::FileView);
        let sql = format!(
            "SELECT {SPALTEN} FROM job WHERE ($1::uuid IS NULL OR case_id = $1) AND ($3 OR kind <> 'http_replay') \
             ORDER BY created_at DESC LIMIT $2"
        );
        let zeilen: Vec<Zeile> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
            .bind(fall.map(|c| c.0))
            .bind(anzahl.clamp(0, 10_000))
            .bind(file_view)
            .fetch_all(&self.pool)
            .await?;
        self.audit(&AuditEintrag {
            details: json!({"anzahl": zeilen.len()}),
            ..e
        })
        .await?;
        zeilen.into_iter().map(job_aus).collect()
    }

    /// Eine Evidence (ohne Audit; der Worker liest Pfad und Art).
    pub async fn evidence_lesen(&self, id: EvidenceId) -> Result<Evidence, StoreError> {
        let v: Option<Json<Value>> =
            sqlx::query_scalar("SELECT to_jsonb(v) FROM evidence v WHERE id = $1")
                .bind(id.0)
                .fetch_optional(&self.pool)
                .await?;
        let Some(Json(mut v)) = v else {
            return Err(StoreError::NichtGefunden(format!("keine Evidence {id}")));
        };
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
        Ok(serde_json::from_value(v)?)
    }
}

/// Art eines Jobs als Text (für Anzeigen).
pub fn art_text(k: JobKind) -> &'static str {
    match k {
        JobKind::Analysis => "analysis",
        JobKind::EvidenceImport => "evidence_import",
        JobKind::YaraScan => "yara_scan",
        JobKind::NetworkEnrichment => "network_enrichment",
        JobKind::HttpReplay => "http_replay",
    }
}
