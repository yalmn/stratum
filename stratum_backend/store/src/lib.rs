//! Speichert das Datenmodell (`stratum_model`) in PostgreSQL.
//!
//! Das Schema liegt als versionierte Migrationen im Crate und wird beim
//! Verbinden eingespielt; jede Datenbank weiß so, auf welchem Stand sie ist.
//! Ein Modell wird in einer Transaktion geschrieben, je Tabelle mit einem
//! einzigen Befehl: die Zeilen gehen als JSON-Array an `jsonb_to_recordset`.
//! Vorhandene IDs werden nicht überschrieben; Entitäten ergänzen nur
//! erstmals und zuletzt gesehen und fehlende Attribute. Attribute ohne Wert
//! (`null` im Modell) werden als leeres Objekt gespeichert.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde_json::Value;
use sqlx::postgres::{PgConnectOptions, PgPool, PgPoolOptions};
use sqlx::types::Json;
use stratum_model::AnalysisRunId;
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
}

/// Neu geschriebene Zeilen je Tabelle (ohne bereits vorhandene).
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct Geschrieben {
    /// Analyselauf.
    pub lauf_id: String,
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
        let pool = PgPoolOptions::new()
            .max_connections(2)
            .connect_with(optionen)
            .await?;
        sqlx::migrate!("./migrations").run(&pool).await?;
        Ok(Self { pool })
    }

    /// Schreibt ein Modell mit Angaben zum Lauf. `modell_sha256` ist der Hash
    /// der Modelldatei, falls eine geschrieben wurde.
    pub async fn modell_speichern(
        &self,
        k: &Kontext,
        m: &Modell,
        modell_sha256: Option<&str>,
    ) -> Result<Geschrieben, StoreError> {
        let lauf = AnalysisRunId::new();
        let mut tx = self.pool.begin().await?;

        sqlx::query(
            "INSERT INTO analysis_run (id, case_id, evidence_id, evidence_sha256, host, \
             stratum_version, started_at, model_sha256, statistics, notes) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
        )
        .bind(lauf.0)
        .bind(k.case_id.0)
        .bind(k.evidence_id.0)
        .bind(&k.evidence_sha256)
        .bind(k.host.as_deref())
        .bind(&k.stratum_version)
        .bind(k.zeitpunkt)
        .bind(modell_sha256)
        .bind(Json(&m.statistik))
        .bind(Json(&m.hinweise))
        .execute(&mut *tx)
        .await?;

        let mut g = Geschrieben {
            lauf_id: lauf.to_string(),
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
