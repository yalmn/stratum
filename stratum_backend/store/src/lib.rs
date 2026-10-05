//! Speichert das Datenmodell (`stratum_model`) in PostgreSQL.
//!
//! Das Schema liegt als versionierte Migrationen im Crate und wird beim
//! Verbinden eingespielt; jede Datenbank weiß so, auf welchem Stand sie ist.
//! Ein Modell wird in einer Transaktion geschrieben, je Tabelle mit einem
//! einzigen Befehl: die Zeilen gehen als JSON-Array an `jsonb_to_recordset`.
//! Vorhandene IDs werden nicht überschrieben; Entitäten ergänzen nur
//! erstmals und zuletzt gesehen und fehlende Attribute. Attribute ohne Wert
//! (`null` im Modell) werden als leeres Objekt gespeichert.
//!
//! Reihenfolge für einen Lauf: Fall anlegen, Evidence registrieren, Lauf
//! beginnen (Stand `running`), Dateikatalog und Modell speichern, nach dem
//! Report den Lauf abschließen. Fall und Evidence bleiben registriert, auch
//! wenn die Analyse danach scheitert.
//!
//! Jede fachliche Aktion nennt den handelnden Akteur und schreibt ihr
//! Audit-Ereignis in derselben Transaktion ([`audit`]). Nach den Migrationen
//! arbeitet die Verbindung als Rolle `stratum_app`, die nichts löschen und
//! das Audit nicht ändern darf.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod artefakte;
pub mod audit;
pub mod benutzer;
pub mod bookmarks;
pub mod dateien;
pub mod daten;
pub mod faelle;
pub mod jobs;
pub mod sitzung;
pub mod war_room;

use serde_json::{json, Value};
use sqlx::postgres::{PgConnectOptions, PgConnection, PgPool, PgPoolOptions};
use sqlx::types::Json;
use sqlx::{Connection as _, Executor as _};
use stratum_model::{
    ActorId, AnalysisRunId, AuditAction, AuditResult, Case, DerivationKind, Evidence, EvidenceId,
    EvidenceRelation, EvidenceRelationId, EvidenceRelationKind, Finding, Permission,
};
use stratum_normalize::{Kontext, Modell};

pub use audit::{AuditEintrag, AuditPruefung};
pub use faelle::FallZeile;

/// Ein Audit-Ereignis mit dem Anmeldenamen des Akteurs, zum Anzeigen.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AuditZeile {
    /// Ereignis.
    #[serde(flatten)]
    pub event: stratum_model::AuditEvent,
    /// Anmeldename des Akteurs.
    pub akteur: String,
}
pub use benutzer::{anmeldename_pruefen, PASSWORT_MINDESTLAENGE};

/// Fehler beim Speichern.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// Verbindung oder Abfrage fehlgeschlagen.
    #[error("Datenbank: {0}")]
    Datenbank(#[from] sqlx::Error),
    /// Schema konnte nicht eingespielt werden.
    #[error("Migration: {0}")]
    Migration(#[from] sqlx::migrate::MigrateError),
    /// Modell ließ sich nicht in JSON umwandeln.
    #[error("Modell nicht serialisierbar: {0}")]
    Json(#[from] serde_json::Error),
    /// Unter der ID ist eine Evidence mit anderem Inhalt registriert.
    #[error("Evidence {id} ist mit SHA-256 {vorhanden} registriert, nicht {neu}")]
    EvidenceAbweichung {
        /// Evidence-ID.
        id: uuid::Uuid,
        /// Gespeicherter Hash.
        vorhanden: String,
        /// Hash der neuen Angabe.
        neu: String,
    },
    /// Ein Finding verweist auf Objekte, die es im Fall nicht gibt.
    #[error("Finding verweist auf {0} Objekt(e), die es im Fall nicht gibt")]
    FindingBeleg(i64),
    /// Lauf ist unbekannt oder nicht mehr im Stand `running`.
    #[error("Analyselauf {0} läuft nicht")]
    LaufNichtAktiv(AnalysisRunId),
    /// Zeit im Dateikatalog nicht im erwarteten Format.
    #[error("Dateikatalog: Zeit nicht lesbar: {0}")]
    KatalogZeit(String),
    /// Aktion nicht erlaubt (fehlende Rolle, Anmeldung abgelehnt).
    #[error("verweigert: {0}")]
    Verweigert(String),
    /// Gesuchtes Objekt gibt es nicht.
    #[error("{0}")]
    NichtGefunden(String),
    /// Eingabe ungültig (z. B. Anmeldename).
    #[error("{0}")]
    Eingabe(String),
    /// Passwort ungültig oder nicht verarbeitbar.
    #[error("Passwort: {0}")]
    Passwort(String),
    /// Wert passt nicht in die Datenbank (z. B. Größe über `i64::MAX`).
    #[error("Wert nicht speicherbar: {0}")]
    Wert(&'static str),
}

/// Angaben zum Analyselauf, die nicht aus dem Modell stammen.
#[derive(Debug, Clone)]
pub struct LaufAngaben<'a> {
    /// Beginn der Analyse (Untersuchungszeit).
    pub started_at: chrono::DateTime<chrono::Utc>,
    /// Konfiguration des Laufs (Optionen, Analyzer, Begriffslisten).
    pub configuration: &'a Value,
    /// SHA-256 der Konfiguration in ihrer serialisierten Form.
    pub configuration_hash: Option<&'a str>,
    /// Weitere Angaben für das Audit (z. B. der Benutzer des
    /// Betriebssystems, solange die Kommandozeile ohne Anmeldung arbeitet).
    pub audit_details: Value,
}

/// Abschlussstand eines Laufs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaufStand {
    /// Abgeschlossen.
    Completed,
    /// Fehlgeschlagen.
    Failed,
    /// Abgebrochen.
    Cancelled,
}

impl LaufStand {
    fn als_text(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }

    fn aktion(self) -> AuditAction {
        match self {
            Self::Completed => AuditAction::AnalysisComplete,
            Self::Failed => AuditAction::AnalysisFail,
            Self::Cancelled => AuditAction::AnalysisCancel,
        }
    }
}

/// Neu geschriebene Zeilen je Tabelle (ohne bereits vorhandene).
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct Geschrieben {
    /// Analyselauf.
    pub lauf_id: AnalysisRunId,
    /// Fall neu angelegt (vom Aufrufer gesetzt).
    pub fall_neu: bool,
    /// Evidence neu registriert (vom Aufrufer gesetzt).
    pub evidence_neu: bool,
    /// Neue Zeilen im Dateikatalog (vom Aufrufer gesetzt).
    pub dateien: u64,
    /// Artefakte.
    pub artefakte: u64,
    /// Observationen.
    pub observationen: u64,
    /// Entitäten (neu angelegt; vorhandene werden ergänzt).
    pub entitaeten: u64,
    /// Ereignisse.
    pub ereignisse: u64,
    /// Beteiligungen.
    pub beteiligungen: u64,
    /// Beziehungen.
    pub beziehungen: u64,
    /// Herkunftsangaben.
    pub herkunftsangaben: u64,
}

/// Verbindung zur Datenbank. Klonen teilt den Verbindungspool.
#[derive(Clone)]
pub struct Datenbank {
    pool: PgPool,
}

impl Datenbank {
    /// Verbindet sich und spielt fehlende Migrationen ein.
    pub async fn verbinden(url: &str) -> Result<Self, StoreError> {
        Self::verbinden_mit(url, None).await
    }

    /// Wie [`Self::verbinden`], das Passwort getrennt von der URL (etwa aus
    /// einer Datei), damit es nicht in URL oder Umgebung stehen muss.
    pub async fn verbinden_mit(url: &str, passwort: Option<&str>) -> Result<Self, StoreError> {
        let mut optionen: PgConnectOptions = url.parse()?;
        if let Some(p) = passwort {
            optionen = optionen.password(p);
        }
        // Erst eine einzelne Verbindung als Eigentümer: Migrationen, und die
        // eigentliche Ursache eines Fehlers (Passwort falsch, Verbindung
        // verweigert) kommt an, nicht nur ein Zeitablauf des Pools.
        let mut eigentuemer = PgConnection::connect_with(&optionen).await?;
        sqlx::migrate!("./migrations").run(&mut eigentuemer).await?;
        eigentuemer.close().await?;
        let pool = PgPoolOptions::new()
            .max_connections(2)
            .acquire_timeout(std::time::Duration::from_secs(10))
            .after_connect(|conn, _| {
                Box::pin(async move {
                    conn.execute("SET ROLE stratum_app").await?;
                    Ok(())
                })
            })
            .connect_with(optionen)
            .await?;
        Ok(Self { pool })
    }

    /// Schreibt ein Audit-Ereignis in eigener Transaktion (für Aktionen ohne
    /// eigene Schreibvorgänge, etwa Lesezugriffe oder Ablehnungen).
    pub async fn audit(&self, e: &AuditEintrag) -> Result<stratum_model::AuditEventId, StoreError> {
        let mut conn = self.pool.acquire().await?;
        audit::schreiben(&mut conn, e).await
    }

    /// Die letzten `anzahl` Audit-Ereignisse (neueste zuerst), wahlweise nur
    /// eines Falls. Braucht `audit.view`; das Lesen steht selbst im Audit.
    pub async fn audit_liste(
        &self,
        akteur: ActorId,
        case_id: Option<stratum_model::CaseId>,
        anzahl: i64,
    ) -> Result<Vec<AuditZeile>, StoreError> {
        self.audit_seite(akteur, case_id, anzahl, None).await
    }

    /// Audit-Ereignisse vor einer globalen Sequenznummer, neueste zuerst.
    /// Fallbezogenes Lesen verlangt zusätzlich `case.view`.
    pub async fn audit_seite(
        &self,
        akteur: ActorId,
        case_id: Option<stratum_model::CaseId>,
        anzahl: i64,
        vor: Option<i64>,
    ) -> Result<Vec<AuditZeile>, StoreError> {
        if vor.is_some_and(|v| v <= 0) {
            return Err(StoreError::Eingabe("Audit-Seitenmarke ungültig".into()));
        }
        let e = AuditEintrag {
            akteur,
            case_id,
            aktion: AuditAction::AuditView,
            objekt_typ: "audit",
            objekt_id: None,
            ergebnis: AuditResult::Success,
            details: json!({"anzahl": anzahl, "vor": vor}),
        };
        self.verlangen(akteur, Permission::AuditView, e.clone())
            .await?;
        if case_id.is_some() {
            self.verlangen(akteur, Permission::CaseView, e.clone())
                .await?;
        }
        let liste = audit::liste(&self.pool, case_id, anzahl, vor).await?;
        let mut ids: Vec<uuid::Uuid> = liste.iter().map(|e| e.actor_id.0).collect();
        ids.sort_unstable();
        ids.dedup();
        let namen: std::collections::HashMap<uuid::Uuid, String> =
            sqlx::query_as::<_, (uuid::Uuid, String)>(
                "SELECT id, username FROM app_user WHERE id = ANY($1)",
            )
            .bind(&ids)
            .fetch_all(&self.pool)
            .await?
            .into_iter()
            .collect();
        self.audit(&e).await?;
        Ok(liste
            .into_iter()
            .map(|event| AuditZeile {
                akteur: namen.get(&event.actor_id.0).cloned().unwrap_or_default(),
                event,
            })
            .collect())
    }

    /// Rechnet die Audit-Kette nach und protokolliert das als
    /// `AUDIT_VERIFY` mit dem Ergebnis.
    pub async fn audit_pruefen(&self, akteur: ActorId) -> Result<AuditPruefung, StoreError> {
        self.verlangen(
            akteur,
            Permission::AuditVerify,
            AuditEintrag {
                akteur,
                case_id: None,
                aktion: AuditAction::AuditVerify,
                objekt_typ: "audit",
                objekt_id: None,
                ergebnis: AuditResult::Denied,
                details: json!({}),
            },
        )
        .await?;
        let p = audit::pruefen(&self.pool).await?;
        self.audit(&AuditEintrag {
            akteur,
            case_id: None,
            aktion: AuditAction::AuditVerify,
            objekt_typ: "audit",
            objekt_id: None,
            ergebnis: if p.intakt() {
                AuditResult::Success
            } else {
                AuditResult::Failure
            },
            details: json!({
                "ereignisse": p.ereignisse,
                "letzter_hash": p.letzter_hash,
                "fehler": p.fehler_gesamt,
            }),
        })
        .await?;
        Ok(p)
    }

    /// Legt einen Fall an. Ein vorhandener Fall bleibt unverändert (Titel
    /// und Stand gehören dem Analysten). Liefert `true`, wenn er neu ist.
    pub async fn fall_anlegen(&self, akteur: ActorId, c: &Case) -> Result<bool, StoreError> {
        self.verlangen(
            akteur,
            Permission::CaseCreate,
            AuditEintrag {
                akteur,
                case_id: Some(c.id),
                aktion: AuditAction::CaseCreate,
                objekt_typ: "case",
                objekt_id: Some(c.id.to_string()),
                ergebnis: AuditResult::Denied,
                details: json!({"case_number": c.case_number}),
            },
        )
        .await?;
        let j = serde_json::to_value(c)?;
        let mut tx = self.pool.begin().await?;
        let neu = sqlx::query(
            "INSERT INTO case_file (id, case_number, title, description, status, classification, \
             case_folder, timezone, created_at, created_by, opened_at, closed_at) \
             SELECT id, case_number, title, description, status, classification, case_folder, \
             timezone, created_at, created_by, opened_at, closed_at \
             FROM jsonb_populate_record(NULL::case_file, $1) \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(Json(j))
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if neu == 1 {
            audit::schreiben(
                &mut tx,
                &AuditEintrag {
                    akteur,
                    case_id: Some(c.id),
                    aktion: AuditAction::CaseCreate,
                    objekt_typ: "case",
                    objekt_id: Some(c.id.to_string()),
                    ergebnis: AuditResult::Success,
                    details: json!({"case_number": c.case_number, "case_folder": c.case_folder}),
                },
            )
            .await?;
        }
        tx.commit().await?;
        Ok(neu == 1)
    }

    /// Registriert eine Evidence. Ist die ID schon vergeben, muss der
    /// SHA-256 gleich sein; sonst bleibt alles, wie es ist (Evidence wird
    /// nie verändert). Eine neue Evidence mit denselben Mediendaten wie eine
    /// vorhandene im Fall (etwa E01 und Rohimage) wird mit ihr als
    /// `SAME_SOURCE` verknüpft. Liefert `true`, wenn sie neu ist.
    ///
    /// Ausnahme: Evidence, die Migration 0002 aus früheren Läufen übernommen
    /// hat, ist nur ein Platzhalter (ohne Größe, BLAKE3, Pfad). Sie wird bei
    /// gleichem SHA-256 einmal mit den echten Angaben vervollständigt.
    ///
    /// Im Audit: `EVIDENCE_IMPORT` für neue (und vervollständigte),
    /// `EVIDENCE_VERIFY` für vorhandene Evidence, bei abweichendem Hash mit
    /// Ergebnis `failure`.
    pub async fn evidence_registrieren(
        &self,
        akteur: ActorId,
        e: &Evidence,
    ) -> Result<bool, StoreError> {
        if i64::try_from(e.size).is_err() {
            return Err(StoreError::Wert("Evidence-Größe über i64::MAX"));
        }
        let eintrag = |aktion, ergebnis, details| AuditEintrag {
            akteur,
            case_id: Some(e.case_id),
            aktion,
            objekt_typ: "evidence",
            objekt_id: Some(e.id.to_string()),
            ergebnis,
            details,
        };
        // Registrieren braucht evidence.import; eine schon registrierte
        // Evidence nur gegen ihren Hash zu prüfen, ist Teil der Analyse.
        let vorhanden: bool =
            sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM evidence WHERE id = $1)")
                .bind(e.id.0)
                .fetch_one(&self.pool)
                .await?;
        if !vorhanden {
            self.verlangen(
                akteur,
                Permission::EvidenceImport,
                eintrag(
                    AuditAction::EvidenceImport,
                    AuditResult::Denied,
                    json!({"sha256": e.sha256}),
                ),
            )
            .await?;
        }
        let mut tx = self.pool.begin().await?;
        let neu: Option<bool> = sqlx::query_scalar(
            "INSERT INTO evidence (id, case_id, kind, name, role, original_name, source_uri, size, \
             sha256, blake3, acquired_at, imported_at, imported_by, acquisition_method, read_only, \
             support, parent_evidence_id, metadata) \
             SELECT id, case_id, kind, name, role, original_name, source_uri, size, sha256, \
             blake3, acquired_at, imported_at, imported_by, acquisition_method, read_only, \
             support, parent_evidence_id, COALESCE(metadata, '{}') \
             FROM jsonb_populate_record(NULL::evidence, $1) \
             ON CONFLICT (id) DO UPDATE SET kind = EXCLUDED.kind, name = EXCLUDED.name, \
             role = EXCLUDED.role, original_name = EXCLUDED.original_name, \
             source_uri = EXCLUDED.source_uri, size = EXCLUDED.size, blake3 = EXCLUDED.blake3, \
             acquired_at = EXCLUDED.acquired_at, imported_by = EXCLUDED.imported_by, \
             acquisition_method = EXCLUDED.acquisition_method, metadata = EXCLUDED.metadata \
             WHERE evidence.metadata ? 'uebernommen' AND evidence.sha256 = EXCLUDED.sha256 \
             RETURNING (xmax = 0)",
        )
        .bind(Json(serde_json::to_value(e)?))
        .fetch_optional(&mut *tx)
        .await?;
        if let Some(ganz_neu) = neu {
            audit::schreiben(
                &mut tx,
                &eintrag(
                    AuditAction::EvidenceImport,
                    AuditResult::Success,
                    json!({
                        "sha256": e.sha256,
                        "blake3": e.blake3,
                        "size": e.size,
                        "kind": e.kind,
                        "source_uri": e.source_uri,
                        "vervollstaendigt": !ganz_neu,
                    }),
                ),
            )
            .await?;
        }
        if neu == Some(true) {
            let gleiche: Vec<uuid::Uuid> = sqlx::query_scalar(
                "SELECT id FROM evidence WHERE case_id = $1 AND sha256 = $2 AND id <> $3",
            )
            .bind(e.case_id.0)
            .bind(&e.sha256)
            .bind(e.id.0)
            .fetch_all(&mut *tx)
            .await?;
            for ziel in gleiche {
                beziehung_schreiben(
                    &mut tx,
                    akteur,
                    &EvidenceRelation {
                        id: EvidenceRelationId::new(),
                        case_id: e.case_id,
                        source_evidence_id: e.id,
                        target_evidence_id: EvidenceId(ziel),
                        kind: EvidenceRelationKind::SameSource,
                        derivation: DerivationKind::Derived,
                        note: Some("gleicher SHA-256 der Mediendaten".into()),
                        created_at: e.imported_at,
                        created_by: Some(e.imported_by),
                    },
                )
                .await?;
            }
        } else if neu.is_none() {
            let vorhanden: String = sqlx::query_scalar("SELECT sha256 FROM evidence WHERE id = $1")
                .bind(e.id.0)
                .fetch_one(&mut *tx)
                .await?;
            let gleich = vorhanden == e.sha256;
            let pruefung = eintrag(
                AuditAction::EvidenceVerify,
                if gleich {
                    AuditResult::Success
                } else {
                    AuditResult::Failure
                },
                json!({"registriert": vorhanden, "gelesen": e.sha256}),
            );
            if !gleich {
                // Die Abweichung muss im Audit bleiben, obwohl die Aktion
                // scheitert: eigene Transaktion.
                tx.rollback().await?;
                self.audit(&pruefung).await?;
                return Err(StoreError::EvidenceAbweichung {
                    id: e.id.0,
                    vorhanden,
                    neu: e.sha256.clone(),
                });
            }
            audit::schreiben(&mut tx, &pruefung).await?;
        }
        tx.commit().await?;
        Ok(neu == Some(true))
    }

    /// Hält eine Beziehung zwischen zwei Evidence desselben Falls fest.
    /// Liefert `true`, wenn sie neu ist.
    pub async fn evidence_beziehung(
        &self,
        akteur: ActorId,
        r: &EvidenceRelation,
    ) -> Result<bool, StoreError> {
        self.verlangen(
            akteur,
            Permission::RelationEdit,
            AuditEintrag {
                akteur,
                case_id: Some(r.case_id),
                aktion: AuditAction::RelationCreate,
                objekt_typ: "evidence_relation",
                objekt_id: Some(r.id.to_string()),
                ergebnis: AuditResult::Denied,
                details: json!({}),
            },
        )
        .await?;
        let mut tx = self.pool.begin().await?;
        let neu = beziehung_schreiben(&mut tx, akteur, r).await?;
        tx.commit().await?;
        Ok(neu)
    }

    /// Speichert ein Finding samt Belegen in einer Transaktion. Jeder Beleg
    /// muss im selben Fall existieren, sonst wird nichts geschrieben.
    pub async fn finding_speichern(&self, akteur: ActorId, f: &Finding) -> Result<(), StoreError> {
        self.verlangen(
            akteur,
            Permission::FindingCreate,
            AuditEintrag {
                akteur,
                case_id: Some(f.case_id),
                aktion: AuditAction::FindingCreate,
                objekt_typ: "finding",
                objekt_id: Some(f.id.to_string()),
                ergebnis: AuditResult::Denied,
                details: json!({"title": f.title}),
            },
        )
        .await?;
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "INSERT INTO finding (id, case_id, title, description, category, status, priority, \
             disposition, derivation, created_at, created_by, updated_at) \
             SELECT id, case_id, title, description, category, status, priority, disposition, \
             derivation, created_at, created_by, updated_at \
             FROM jsonb_populate_record(NULL::finding, $1)",
        )
        .bind(Json(serde_json::to_value(f)?))
        .execute(&mut *tx)
        .await?;
        let belege: Vec<(&str, uuid::Uuid)> = f
            .entity_refs
            .iter()
            .map(|i| ("entity", i.0))
            .chain(f.event_refs.iter().map(|i| ("event", i.0)))
            .chain(f.artifact_refs.iter().map(|i| ("artifact", i.0)))
            .collect();
        if !belege.is_empty() {
            let (arten, ids): (Vec<&str>, Vec<uuid::Uuid>) = belege.into_iter().unzip();
            sqlx::query(
                "INSERT INTO finding_ref (finding_id, object_type, object_id) \
                 SELECT $1, t, i FROM unnest($2::text[], $3::uuid[]) AS x(t, i) \
                 ON CONFLICT DO NOTHING",
            )
            .bind(f.id.0)
            .bind(&arten)
            .bind(&ids)
            .execute(&mut *tx)
            .await?;
            let fehlend: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM finding_ref r WHERE r.finding_id = $1 AND NOT CASE \
                 r.object_type \
                 WHEN 'entity' THEN EXISTS (SELECT 1 FROM entity o WHERE o.id = r.object_id \
                   AND o.case_id = $2) \
                 WHEN 'event' THEN EXISTS (SELECT 1 FROM event o WHERE o.id = r.object_id \
                   AND o.case_id = $2) \
                 ELSE EXISTS (SELECT 1 FROM artifact o WHERE o.id = r.object_id \
                   AND o.case_id = $2) END",
            )
            .bind(f.id.0)
            .bind(f.case_id.0)
            .fetch_one(&mut *tx)
            .await?;
            if fehlend > 0 {
                return Err(StoreError::FindingBeleg(fehlend));
            }
        }
        audit::schreiben(
            &mut tx,
            &AuditEintrag {
                akteur,
                case_id: Some(f.case_id),
                aktion: AuditAction::FindingCreate,
                objekt_typ: "finding",
                objekt_id: Some(f.id.to_string()),
                ergebnis: AuditResult::Success,
                details: json!({
                    "title": f.title,
                    "derivation": f.derivation,
                    "belege": f.entity_refs.len() + f.event_refs.len() + f.artifact_refs.len(),
                }),
            },
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Beginnt einen Analyselauf mit Stand `running`. Fall und Evidence
    /// müssen registriert sein. Den Lauf danach mit
    /// [`Self::lauf_abschliessen`] beenden.
    pub async fn lauf_beginnen(
        &self,
        akteur: ActorId,
        k: &Kontext,
        angaben: &LaufAngaben<'_>,
    ) -> Result<AnalysisRunId, StoreError> {
        let lauf = AnalysisRunId::new();
        self.verlangen(
            akteur,
            Permission::AnalysisStart,
            AuditEintrag {
                akteur,
                case_id: Some(k.case_id),
                aktion: AuditAction::AnalysisStart,
                objekt_typ: "analysis_run",
                objekt_id: Some(lauf.to_string()),
                ergebnis: AuditResult::Denied,
                details: json!({"evidence_id": k.evidence_id}),
            },
        )
        .await?;
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "INSERT INTO analysis_run (id, case_id, evidence_id, evidence_sha256, host, \
             stratum_version, started_at, statistics, notes, status, configuration, \
             configuration_hash, started_by) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, '{}', '[]', 'running', $8, $9, $10)",
        )
        .bind(lauf.0)
        .bind(k.case_id.0)
        .bind(k.evidence_id.0)
        .bind(&k.evidence_sha256)
        .bind(k.host.as_deref())
        .bind(&k.stratum_version)
        .bind(angaben.started_at)
        .bind(Json(angaben.configuration))
        .bind(angaben.configuration_hash)
        .bind(akteur.0)
        .execute(&mut *tx)
        .await?;
        let mut details = json!({
            "evidence_id": k.evidence_id,
            "stratum_version": k.stratum_version,
            "configuration_hash": angaben.configuration_hash,
        });
        if let (Value::Object(d), Value::Object(mehr)) = (&mut details, &angaben.audit_details) {
            d.extend(mehr.clone());
        }
        audit::schreiben(
            &mut tx,
            &AuditEintrag {
                akteur,
                case_id: Some(k.case_id),
                aktion: AuditAction::AnalysisStart,
                objekt_typ: "analysis_run",
                objekt_id: Some(lauf.to_string()),
                ergebnis: AuditResult::Success,
                details,
            },
        )
        .await?;
        tx.commit().await?;
        Ok(lauf)
    }

    /// Schreibt einen Block des Dateikatalogs. `zeilen` ist ein JSON-Array
    /// aus Katalogzeilen, wie sie `stratum_analysis::write_catalog_with` als
    /// JSON Lines erzeugt; Fall und Evidence kommen vom Lauf. Vorhandene
    /// Zeilen bleiben, erhalten aber einmal die Inhaltsangaben (SHA-256,
    /// Typ), falls sie ihnen fehlen. Liefert die Zahl neuer Zeilen.
    pub async fn katalog_speichern(
        &self,
        lauf: AnalysisRunId,
        zeilen: &str,
    ) -> Result<u64, StoreError> {
        let aktiv: Option<i32> =
            sqlx::query_scalar("SELECT 1 FROM analysis_run WHERE id = $1 AND status = 'running'")
                .bind(lauf.0)
                .fetch_optional(&self.pool)
                .await?;
        if aktiv.is_none() {
            return Err(StoreError::LaufNichtAktiv(lauf));
        }
        let zeilen = katalog_zeiten(zeilen)?;
        let neu: Vec<bool> = sqlx::query_scalar(FILE)
            .bind(zeilen)
            .bind(lauf.0)
            .fetch_all(&self.pool)
            .await?;
        Ok(neu.into_iter().filter(|n| *n).count() as u64)
    }

    /// Schreibt ein Modell in einen laufenden Analyselauf, in einer
    /// Transaktion.
    pub async fn modell_speichern(
        &self,
        lauf: AnalysisRunId,
        m: &Modell,
        model_sha256: Option<&str>,
    ) -> Result<Geschrieben, StoreError> {
        let mut tx = self.pool.begin().await?;
        let aktiv = sqlx::query(
            "UPDATE analysis_run SET model_sha256 = $2, statistics = $3, notes = $4 \
             WHERE id = $1 AND status = 'running'",
        )
        .bind(lauf.0)
        .bind(model_sha256)
        .bind(Json(&m.statistik))
        .bind(Json(&m.hinweise))
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if aktiv != 1 {
            return Err(StoreError::LaufNichtAktiv(lauf));
        }

        let mut g = Geschrieben {
            lauf_id: lauf,
            ..Default::default()
        };
        g.artefakte = einfuegen(&mut tx, ARTIFACT, &m.artifacts).await?;
        g.observationen = einfuegen(&mut tx, OBSERVATION, &m.observations).await?;
        // Bei Entitäten zählt PostgreSQL ergänzte Zeilen mit; neu angelegt
        // sind nur die, bei denen kein Update stattfand (xmax = 0).
        g.entitaeten = if m.entities.is_empty() {
            0
        } else {
            let neu: Vec<bool> = sqlx::query_scalar(ENTITY)
                .bind(Json(serde_json::to_value(&m.entities)?))
                .fetch_all(&mut *tx)
                .await?;
            neu.into_iter().filter(|n| *n).count() as u64
        };
        g.ereignisse = einfuegen(&mut tx, EVENT, &m.events).await?;
        g.beteiligungen = einfuegen(&mut tx, PARTICIPANT, &m.participants).await?;
        g.beziehungen = einfuegen(&mut tx, RELATIONSHIP, &m.relationships).await?;
        g.herkunftsangaben = sqlx::query(PROVENANCE)
            .bind(Json(serde_json::to_value(&m.provenance)?))
            .bind(lauf.0)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        tx.commit().await?;
        Ok(g)
    }

    /// Beendet einen Lauf mit Endzeit, Stand, dem SHA-256 des Reports und,
    /// wenn er in eine Datei ging, deren absolutem Pfad. Ein abgeschlossener
    /// Lauf macht seine Evidence zu `analyzed`.
    pub async fn lauf_abschliessen(
        &self,
        akteur: ActorId,
        lauf: AnalysisRunId,
        stand: LaufStand,
        finished_at: chrono::DateTime<chrono::Utc>,
        report_sha256: Option<&str>,
        report_pfad: Option<&str>,
    ) -> Result<(), StoreError> {
        // Abbrechen ist ein eigenes Recht; abschließen darf, wer starten darf.
        self.verlangen(
            akteur,
            if stand == LaufStand::Cancelled {
                Permission::AnalysisCancel
            } else {
                Permission::AnalysisStart
            },
            AuditEintrag {
                akteur,
                case_id: None,
                aktion: stand.aktion(),
                objekt_typ: "analysis_run",
                objekt_id: Some(lauf.to_string()),
                ergebnis: AuditResult::Denied,
                details: json!({}),
            },
        )
        .await?;
        let mut tx = self.pool.begin().await?;
        let (evidence, fall): (uuid::Uuid, uuid::Uuid) = sqlx::query_as(
            "UPDATE analysis_run SET status = $2, finished_at = $3, report_sha256 = $4, \
             report_path = $5 WHERE id = $1 AND status = 'running' RETURNING evidence_id, case_id",
        )
        .bind(lauf.0)
        .bind(stand.als_text())
        .bind(finished_at)
        .bind(report_sha256)
        .bind(report_pfad)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(StoreError::LaufNichtAktiv(lauf))?;
        if stand == LaufStand::Completed {
            sqlx::query(
                "UPDATE evidence SET support = 'analyzed' WHERE id = $1 AND support = 'recognized'",
            )
            .bind(evidence)
            .execute(&mut *tx)
            .await?;
        }
        let case_id = Some(stratum_model::CaseId(fall));
        audit::schreiben(
            &mut tx,
            &AuditEintrag {
                akteur,
                case_id,
                aktion: stand.aktion(),
                objekt_typ: "analysis_run",
                objekt_id: Some(lauf.to_string()),
                ergebnis: if stand == LaufStand::Completed {
                    AuditResult::Success
                } else {
                    AuditResult::Failure
                },
                details: json!({"report_sha256": report_sha256}),
            },
        )
        .await?;
        if let Some(r) = report_sha256 {
            audit::schreiben(
                &mut tx,
                &AuditEintrag {
                    akteur,
                    case_id,
                    aktion: AuditAction::ReportCreate,
                    objekt_typ: "report",
                    objekt_id: Some(r.to_string()),
                    ergebnis: AuditResult::Success,
                    details: json!({"analysis_run_id": lauf, "pfad": report_pfad}),
                },
            )
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// Zählt die Zeilen je Tabelle für einen Fall (für Prüfungen).
    pub async fn zaehlen(&self, case_id: uuid::Uuid) -> Result<Vec<(String, i64)>, StoreError> {
        let mut out = Vec::new();
        for (t, sql) in [
            (
                "artifact",
                "SELECT count(*) FROM artifact WHERE case_id = $1",
            ),
            (
                "observation",
                "SELECT count(*) FROM observation WHERE case_id = $1",
            ),
            ("entity", "SELECT count(*) FROM entity WHERE case_id = $1"),
            ("event", "SELECT count(*) FROM event WHERE case_id = $1"),
            (
                "relationship",
                "SELECT count(*) FROM relationship WHERE case_id = $1",
            ),
            (
                "evidence",
                "SELECT count(*) FROM evidence WHERE case_id = $1",
            ),
            ("finding", "SELECT count(*) FROM finding WHERE case_id = $1"),
            ("file", "SELECT count(*) FROM file WHERE case_id = $1"),
        ] {
            let n: i64 = sqlx::query_scalar(sql)
                .bind(case_id)
                .fetch_one(&self.pool)
                .await?;
            out.push((t.to_string(), n));
        }
        Ok(out)
    }

    /// Verbindungspool, etwa für eigene Abfragen in Tests.
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}

/// Beziehung zwischen zwei Evidence samt Audit, in einer laufenden
/// Transaktion.
async fn beziehung_schreiben(
    conn: &mut PgConnection,
    akteur: ActorId,
    r: &EvidenceRelation,
) -> Result<bool, StoreError> {
    let neu = sqlx::query(
        "INSERT INTO evidence_relation (id, case_id, source_evidence_id, target_evidence_id, \
         kind, derivation, note, created_at, created_by) \
         SELECT id, case_id, source_evidence_id, target_evidence_id, kind, derivation, note, \
         created_at, created_by \
         FROM jsonb_populate_record(NULL::evidence_relation, $1) \
         ON CONFLICT DO NOTHING",
    )
    .bind(Json(serde_json::to_value(r)?))
    .execute(&mut *conn)
    .await?
    .rows_affected();
    if neu == 1 {
        audit::schreiben(
            conn,
            &AuditEintrag {
                akteur,
                case_id: Some(r.case_id),
                aktion: AuditAction::RelationCreate,
                objekt_typ: "evidence_relation",
                objekt_id: Some(r.id.to_string()),
                ergebnis: AuditResult::Success,
                details: json!({
                    "source": r.source_evidence_id,
                    "target": r.target_evidence_id,
                    "kind": r.kind,
                    "derivation": r.derivation,
                }),
            },
        )
        .await?;
    }
    Ok(neu == 1)
}

async fn einfuegen<T: serde::Serialize>(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    sql: &'static str,
    zeilen: &[T],
) -> Result<u64, StoreError> {
    if zeilen.is_empty() {
        return Ok(0);
    }
    let json: Value = serde_json::to_value(zeilen)?;
    Ok(sqlx::query(sql)
        .bind(Json(json))
        .execute(&mut **tx)
        .await?
        .rows_affected())
}

const ARTIFACT: &str = "INSERT INTO artifact \
    SELECT id, case_id, evidence_id, kind, source_locator, parser, raw_metadata, created_at \
    FROM jsonb_to_recordset($1) AS x(id uuid, case_id uuid, evidence_id uuid, kind text, \
    source_locator jsonb, parser jsonb, raw_metadata jsonb, created_at timestamptz) \
    ON CONFLICT (id) DO NOTHING";

const OBSERVATION: &str = "INSERT INTO observation \
    SELECT id, case_id, artifact_id, kind, fields, parser, observed_at \
    FROM jsonb_to_recordset($1) AS x(id uuid, case_id uuid, artifact_id uuid, kind text, \
    fields jsonb, parser jsonb, observed_at timestamptz) \
    ON CONFLICT (id) DO NOTHING";

const ENTITY: &str = "INSERT INTO entity AS e \
    SELECT id, case_id, kind, canonical_key, display_name, COALESCE(attributes, '{}'), first_seen, \
    last_seen, created_at \
    FROM jsonb_to_recordset($1) AS x(id uuid, case_id uuid, kind text, canonical_key text, \
    display_name text, attributes jsonb, first_seen timestamptz, last_seen timestamptz, \
    created_at timestamptz) \
    ON CONFLICT (id) DO UPDATE SET \
      first_seen = LEAST(e.first_seen, EXCLUDED.first_seen), \
      last_seen = GREATEST(e.last_seen, EXCLUDED.last_seen), \
      attributes = EXCLUDED.attributes || e.attributes \
    RETURNING (xmax = 0)";

const EVENT: &str = "INSERT INTO event \
    SELECT id, case_id, kind, (occurred_at->>'utc')::timestamptz, occurred_at, ended_at, \
    COALESCE(attributes, '{}'), derivation, created_at \
    FROM jsonb_to_recordset($1) AS x(id uuid, case_id uuid, kind text, occurred_at jsonb, \
    ended_at jsonb, attributes jsonb, derivation text, created_at timestamptz) \
    ON CONFLICT (id) DO NOTHING";

const PARTICIPANT: &str = "INSERT INTO event_participant \
    SELECT event_id, entity_id, role \
    FROM jsonb_to_recordset($1) AS x(event_id uuid, entity_id uuid, role text) \
    ON CONFLICT DO NOTHING";

const RELATIONSHIP: &str = "INSERT INTO relationship \
    SELECT id, case_id, source_entity_id, target_entity_id, kind, derivation, valid_from, \
    valid_until, COALESCE(attributes, '{}') \
    FROM jsonb_to_recordset($1) AS x(id uuid, case_id uuid, source_entity_id uuid, \
    target_entity_id uuid, kind text, derivation text, valid_from timestamptz, \
    valid_until timestamptz, attributes jsonb) \
    ON CONFLICT (id) DO NOTHING";

/// Herkunft: `object` ist `{type, id}`, `provenance` die Angabe selbst.
/// Fundstelle und Parser entfallen, wenn sie denen des Artefakts gleichen.
const PROVENANCE: &str = "INSERT INTO provenance \
    SELECT x.object->>'type', (x.object->>'id')::uuid, x.role, \
      (x.provenance->>'evidence_id')::uuid, \
      (x.provenance->>'artifact_id')::uuid, \
      (x.provenance->>'observation_id')::uuid, \
      NULLIF(x.provenance->'source_locator', a.source_locator), \
      NULLIF(x.provenance->'parser', a.parser), \
      COALESCE((x.provenance->>'analysis_run_id')::uuid, $2) \
    FROM jsonb_to_recordset($1) AS x(object jsonb, provenance jsonb, role text) \
    LEFT JOIN artifact a ON a.id = (x.provenance->>'artifact_id')::uuid \
    ON CONFLICT DO NOTHING";

/// Ersetzt im Katalogblock die Zeiten (`si`, `fn`: ISO-Text) durch
/// FILETIME. Werte ab 2^63 werden bitgleich als negative Zahl abgelegt.
fn katalog_zeiten(zeilen: &str) -> Result<String, StoreError> {
    let mut v: Vec<Value> = serde_json::from_str(zeilen)?;
    for zeile in &mut v {
        for art in ["si", "fn"] {
            let Some(Value::Object(zeiten)) = zeile.get_mut(art) else {
                continue;
            };
            for wert in zeiten.values_mut() {
                if let Value::String(t) = wert {
                    let ft = stratum_core::time::iso_to_filetime(t)
                        .ok_or_else(|| StoreError::KatalogZeit(t.clone()))?;
                    *wert = Value::from(ft as i64);
                }
            }
        }
    }
    Ok(serde_json::to_string(&v)?)
}

/// Dateikatalog. Größen über `i64::MAX` kann es in NTFS nicht geben; ein
/// solcher Wert aus einem beschädigten Datensatz wird NULL statt den ganzen
/// Block abzulehnen (die JSON-Lines-Datei behält ihn).
const FILE: &str = "INSERT INTO file AS f \
    SELECT r.case_id, r.evidence_id, x.volume_offset, x.mft_record, x.pfad, x.name, \
      x.parent_record, x.typ = 'verzeichnis', x.sequenz, \
      CASE WHEN x.groesse <= 9223372036854775807 THEN x.groesse::bigint END, \
      CASE WHEN x.gueltige_laenge <= 9223372036854775807 THEN x.gueltige_laenge::bigint END, \
      (x.si->>'erstellt')::bigint, (x.si->>'geaendert')::bigint, \
      (x.si->>'mft_geaendert')::bigint, (x.si->>'zugriff')::bigint, \
      (x.fn->>'erstellt')::bigint, (x.fn->>'geaendert')::bigint, \
      (x.fn->>'mft_geaendert')::bigint, (x.fn->>'zugriff')::bigint, \
      ARRAY(SELECT jsonb_array_elements_text(COALESCE(x.attribute, '[]'))), \
      x.streams, x.hardlinks, x.reparse_tag, x.wof, x.mft_record_offset, x.sha256, \
      x.dateityp, x.mime, x.signatur, x.hash_fehler, x.fehler, x.inhalt_fehler, r.id \
    FROM jsonb_to_recordset($1::jsonb) AS x(volume_offset bigint, mft_record bigint, \
      sequenz integer, parent_record bigint, typ text, pfad text, name text, groesse numeric, \
      gueltige_laenge numeric, si jsonb, fn jsonb, attribute jsonb, streams jsonb, \
      hardlinks integer, reparse_tag text, wof text, mft_record_offset bigint, sha256 text, \
      dateityp text, mime text, signatur jsonb, hash_fehler text, fehler text, \
      inhalt_fehler text) \
    JOIN analysis_run r ON r.id = $2 \
    ON CONFLICT (evidence_id, volume_offset, mft_record, parent_record, name) DO UPDATE SET \
      sha256 = EXCLUDED.sha256, file_type = EXCLUDED.file_type, mime = EXCLUDED.mime, \
      signature = EXCLUDED.signature, valid_length = EXCLUDED.valid_length, \
      hash_error = EXCLUDED.hash_error \
    WHERE f.sha256 IS NULL AND f.hash_error IS NULL \
      AND (EXCLUDED.sha256 IS NOT NULL OR EXCLUDED.hash_error IS NOT NULL) \
    RETURNING (xmax = 0)";
