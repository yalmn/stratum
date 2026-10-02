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
//! Reihenfolge für einen Lauf: Fall anlegen, Evidence registrieren, Modell
//! speichern (Lauf mit Stand `running`), nach dem Report den Lauf
//! abschließen. Fall und Evidence bleiben registriert, auch wenn die Analyse
//! danach scheitert.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde_json::Value;
use sqlx::postgres::{PgConnectOptions, PgConnection, PgPool, PgPoolOptions};
use sqlx::types::Json;
use sqlx::Connection as _;
use stratum_model::{
    AnalysisRunId, Case, DerivationKind, Evidence, EvidenceId, EvidenceRelation,
    EvidenceRelationId, EvidenceRelationKind, Finding,
};
use stratum_normalize::{Kontext, Modell};

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
    /// SHA-256 der Modelldatei, falls eine geschrieben wurde.
    pub model_sha256: Option<&'a str>,
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

/// Verbindung zur Datenbank.
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
        // Erst eine einzelne Verbindung: so kommt die eigentliche Ursache
        // (Passwort falsch, Verbindung verweigert) an, nicht nur ein
        // Zeitablauf des Pools.
        sqlx::Connection::close(PgConnection::connect_with(&optionen).await?).await?;
        let pool = PgPoolOptions::new()
            .max_connections(2)
            .acquire_timeout(std::time::Duration::from_secs(10))
            .connect_with(optionen)
            .await?;
        sqlx::migrate!("./migrations").run(&pool).await?;
        Ok(Self { pool })
    }

    /// Legt einen Fall an. Ein vorhandener Fall bleibt unverändert (Titel
    /// und Stand gehören dem Analysten). Liefert `true`, wenn er neu ist.
    pub async fn fall_anlegen(&self, c: &Case) -> Result<bool, StoreError> {
        let j = serde_json::to_value(c)?;
        let neu = sqlx::query(
            "INSERT INTO case_file (id, case_number, title, description, status, classification, \
             case_folder, timezone, created_at, created_by, opened_at, closed_at) \
             SELECT id, case_number, title, description, status, classification, case_folder, \
             timezone, created_at, created_by, opened_at, closed_at \
             FROM jsonb_populate_record(NULL::case_file, $1) \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(Json(j))
        .execute(&self.pool)
        .await?
        .rows_affected();
        Ok(neu == 1)
    }

    /// Registriert eine Evidence. Ist die ID schon vergeben, muss der
    /// SHA-256 gleich sein; sonst bleibt alles, wie es ist (Evidence wird
    /// nie verändert). Eine neue Evidence mit denselben Mediendaten wie eine
    /// vorhandene im Fall (etwa E01 und Rohimage) wird mit ihr als
    /// `SAME_SOURCE` verknüpft. Liefert `true`, wenn sie neu ist.
    pub async fn evidence_registrieren(&self, e: &Evidence) -> Result<bool, StoreError> {
        if i64::try_from(e.size).is_err() {
            return Err(StoreError::Wert("Evidence-Größe über i64::MAX"));
        }
        let neu = sqlx::query(
            "INSERT INTO evidence (id, case_id, kind, name, role, original_name, source_uri, size, \
             sha256, blake3, acquired_at, imported_at, imported_by, acquisition_method, read_only, \
             support, parent_evidence_id, metadata) \
             SELECT id, case_id, kind, name, role, original_name, source_uri, size, sha256, \
             blake3, acquired_at, imported_at, imported_by, acquisition_method, read_only, \
             support, parent_evidence_id, COALESCE(metadata, '{}') \
             FROM jsonb_populate_record(NULL::evidence, $1) \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(Json(serde_json::to_value(e)?))
        .execute(&self.pool)
        .await?
        .rows_affected();
        if neu == 1 {
            let gleiche: Vec<uuid::Uuid> = sqlx::query_scalar(
                "SELECT id FROM evidence WHERE case_id = $1 AND sha256 = $2 AND id <> $3",
            )
            .bind(e.case_id.0)
            .bind(&e.sha256)
            .bind(e.id.0)
            .fetch_all(&self.pool)
            .await?;
            for ziel in gleiche {
                self.evidence_beziehung(&EvidenceRelation {
                    id: EvidenceRelationId::new(),
                    case_id: e.case_id,
                    source_evidence_id: e.id,
                    target_evidence_id: EvidenceId(ziel),
                    kind: EvidenceRelationKind::SameSource,
                    derivation: DerivationKind::Derived,
                    note: Some("gleicher SHA-256 der Mediendaten".into()),
                    created_at: e.imported_at,
                    created_by: Some(e.imported_by),
                })
                .await?;
            }
        } else {
            let vorhanden: String = sqlx::query_scalar("SELECT sha256 FROM evidence WHERE id = $1")
                .bind(e.id.0)
                .fetch_one(&self.pool)
                .await?;
            if vorhanden != e.sha256 {
                return Err(StoreError::EvidenceAbweichung {
                    id: e.id.0,
                    vorhanden,
                    neu: e.sha256.clone(),
                });
            }
        }
        Ok(neu == 1)
    }

    /// Hält eine Beziehung zwischen zwei Evidence desselben Falls fest.
    /// Liefert `true`, wenn sie neu ist.
    pub async fn evidence_beziehung(&self, r: &EvidenceRelation) -> Result<bool, StoreError> {
        let neu = sqlx::query(
            "INSERT INTO evidence_relation (id, case_id, source_evidence_id, target_evidence_id, \
             kind, derivation, note, created_at, created_by) \
             SELECT id, case_id, source_evidence_id, target_evidence_id, kind, derivation, note, \
             created_at, created_by \
             FROM jsonb_populate_record(NULL::evidence_relation, $1) \
             ON CONFLICT DO NOTHING",
        )
        .bind(Json(serde_json::to_value(r)?))
        .execute(&self.pool)
        .await?
        .rows_affected();
        Ok(neu == 1)
    }

    /// Speichert ein Finding samt Belegen in einer Transaktion. Jeder Beleg
    /// muss im selben Fall existieren, sonst wird nichts geschrieben.
    pub async fn finding_speichern(&self, f: &Finding) -> Result<(), StoreError> {
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
        tx.commit().await?;
        Ok(())
    }

    /// Schreibt ein Modell als neuen Analyselauf mit Stand `running`. Fall
    /// und Evidence müssen registriert sein. Den Lauf danach mit
    /// [`Self::lauf_abschliessen`] beenden.
    pub async fn modell_speichern(
        &self,
        k: &Kontext,
        m: &Modell,
        angaben: &LaufAngaben<'_>,
    ) -> Result<Geschrieben, StoreError> {
        let lauf = AnalysisRunId::new();
        let mut tx = self.pool.begin().await?;

        sqlx::query(
            "INSERT INTO analysis_run (id, case_id, evidence_id, evidence_sha256, host, \
             stratum_version, started_at, model_sha256, statistics, notes, status, \
             configuration, configuration_hash) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'running', $11, $12)",
        )
        .bind(lauf.0)
        .bind(k.case_id.0)
        .bind(k.evidence_id.0)
        .bind(&k.evidence_sha256)
        .bind(k.host.as_deref())
        .bind(&k.stratum_version)
        .bind(angaben.started_at)
        .bind(angaben.model_sha256)
        .bind(Json(&m.statistik))
        .bind(Json(&m.hinweise))
        .bind(Json(angaben.configuration))
        .bind(angaben.configuration_hash)
        .execute(&mut *tx)
        .await?;

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

    /// Beendet einen Lauf mit Endzeit, Stand und dem SHA-256 des Reports.
    /// Ein abgeschlossener Lauf macht seine Evidence zu `analyzed`.
    pub async fn lauf_abschliessen(
        &self,
        lauf: AnalysisRunId,
        stand: LaufStand,
        finished_at: chrono::DateTime<chrono::Utc>,
        report_sha256: Option<&str>,
    ) -> Result<(), StoreError> {
        let mut tx = self.pool.begin().await?;
        let evidence: uuid::Uuid = sqlx::query_scalar(
            "UPDATE analysis_run SET status = $2, finished_at = $3, report_sha256 = $4 \
             WHERE id = $1 AND status = 'running' RETURNING evidence_id",
        )
        .bind(lauf.0)
        .bind(stand.als_text())
        .bind(finished_at)
        .bind(report_sha256)
        .fetch_one(&mut *tx)
        .await?;
        if stand == LaufStand::Completed {
            sqlx::query(
                "UPDATE evidence SET support = 'analyzed' WHERE id = $1 AND support = 'recognized'",
            )
            .bind(evidence)
            .execute(&mut *tx)
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
