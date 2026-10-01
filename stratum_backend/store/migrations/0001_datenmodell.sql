-- Datenmodell von stratum (stratum_model), erste Fassung.
--
-- IDs sind die IDs des Modells: deterministisch (UUIDv5) für alles aus der
-- Evidence Abgeleitete, UUIDv7 für Analyseläufe. Ein zweiter Lauf über
-- dieselbe Evidence im selben Fall trifft dieselben Zeilen.
--
-- Herkunftsangaben speichern Fundstelle und Parser nur, wenn sie vom
-- Artefakt abweichen; die View provenance_full setzt sie wieder zusammen.

CREATE TABLE analysis_run (
    id               uuid PRIMARY KEY,
    case_id          uuid        NOT NULL,
    evidence_id      uuid        NOT NULL,
    evidence_sha256  text        NOT NULL,
    host             text,
    stratum_version  text        NOT NULL,
    started_at       timestamptz NOT NULL,
    model_sha256     text,
    statistics       jsonb       NOT NULL,
    notes            jsonb       NOT NULL,
    stored_at        timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE artifact (
    id             uuid PRIMARY KEY,
    case_id        uuid        NOT NULL,
    evidence_id    uuid        NOT NULL,
    kind           text        NOT NULL,
    source_locator jsonb       NOT NULL,
    parser         jsonb       NOT NULL,
    raw_metadata   jsonb       NOT NULL,
    created_at     timestamptz NOT NULL
);
CREATE INDEX artifact_case ON artifact (case_id, kind);

CREATE TABLE observation (
    id          uuid PRIMARY KEY,
    case_id     uuid        NOT NULL,
    artifact_id uuid        NOT NULL REFERENCES artifact (id),
    kind        text        NOT NULL,
    fields      jsonb       NOT NULL,
    parser      jsonb       NOT NULL,
    observed_at timestamptz NOT NULL
);
CREATE INDEX observation_artifact ON observation (artifact_id);

CREATE TABLE entity (
    id            uuid PRIMARY KEY,
    case_id       uuid        NOT NULL,
    kind          text        NOT NULL,
    canonical_key text        NOT NULL,
    display_name  text        NOT NULL,
    attributes    jsonb       NOT NULL,
    first_seen    timestamptz,
    last_seen     timestamptz,
    created_at    timestamptz NOT NULL,
    UNIQUE (case_id, kind, canonical_key)
);

CREATE TABLE event (
    id           uuid PRIMARY KEY,
    case_id      uuid        NOT NULL,
    kind         text        NOT NULL,
    -- UTC-Zeitpunkt für Sortierung und Zeitfenster, auf die Mikrosekunde
    -- gerundet (Grenze von timestamptz). Die verlustfreie Zeitangabe
    -- (Original, Genauigkeit, Bedeutung) steht in occurred_at.
    occurred_utc timestamptz,
    occurred_at  jsonb,
    ended_at     jsonb,
    attributes   jsonb       NOT NULL,
    derivation   text        NOT NULL,
    created_at   timestamptz NOT NULL
);
CREATE INDEX event_zeit ON event (case_id, occurred_utc);

CREATE TABLE event_participant (
    event_id  uuid NOT NULL REFERENCES event (id),
    entity_id uuid NOT NULL REFERENCES entity (id),
    role      text NOT NULL,
    PRIMARY KEY (event_id, entity_id, role)
);
CREATE INDEX event_participant_entity ON event_participant (entity_id);

CREATE TABLE relationship (
    id               uuid PRIMARY KEY,
    case_id          uuid  NOT NULL,
    source_entity_id uuid  NOT NULL REFERENCES entity (id),
    target_entity_id uuid  NOT NULL REFERENCES entity (id),
    kind             text  NOT NULL,
    derivation       text  NOT NULL,
    valid_from       timestamptz,
    valid_until      timestamptz,
    attributes       jsonb NOT NULL
);
CREATE INDEX relationship_source ON relationship (source_entity_id);
CREATE INDEX relationship_target ON relationship (target_entity_id);

CREATE TABLE provenance (
    object_type     text  NOT NULL,
    object_id       uuid  NOT NULL,
    role            text  NOT NULL,
    evidence_id     uuid  NOT NULL,
    artifact_id     uuid  REFERENCES artifact (id),
    observation_id  uuid  REFERENCES observation (id),
    -- NULL, wenn gleich der Fundstelle bzw. dem Parser des Artefakts.
    source_locator  jsonb,
    parser          jsonb,
    analysis_run_id uuid,
    UNIQUE NULLS NOT DISTINCT
        (object_type, object_id, role, artifact_id, observation_id, source_locator)
);
CREATE INDEX provenance_object ON provenance (object_type, object_id);

CREATE VIEW provenance_full AS
SELECT p.object_type,
       p.object_id,
       p.role,
       p.evidence_id,
       p.artifact_id,
       p.observation_id,
       COALESCE(p.source_locator, a.source_locator) AS source_locator,
       COALESCE(p.parser, a.parser)                 AS parser,
       p.analysis_run_id
FROM provenance p
LEFT JOIN artifact a ON a.id = p.artifact_id;
