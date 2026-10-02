-- Fälle, Evidence mit Beziehungen untereinander, Findings und der
-- erweiterte Analyselauf.
--
-- Ein Fall hat beliebig viele Evidence-Objekte verschiedener Art (Images,
-- Speicherabbilder, Mitschnitte, Logs). Die Evidence selbst bleibt im
-- Dateisystem; hier stehen nur Metadaten und Hashes.
--
-- Ergebnisse späterer Korrelationsregeln brauchen keine eigenen Tabellen:
-- sie landen als Beziehung oder Ereignis mit derivation = 'correlated', die
-- Regel steht mit Kennung und Version in provenance.parser.

CREATE DOMAIN derivation_kind AS text CHECK (VALUE IN (
    'observed', 'parsed', 'derived', 'correlated', 'reconstructed', 'simulated',
    'analyst_asserted', 'external_intel', 'ai_suggested'));

-- Objektarten wie stratum_model::ObjectRef; Grundlage für generische
-- Verweise (Herkunft, Finding-Belege, später Tags und Whiteboard).
CREATE DOMAIN object_type AS text CHECK (VALUE IN (
    'case', 'evidence', 'analysis_run', 'artifact', 'observation', 'entity',
    'event', 'relationship', 'finding'));

-- "case" ist in SQL ein Schlüsselwort.
CREATE TABLE case_file (
    id             uuid PRIMARY KEY,
    case_number    text        NOT NULL UNIQUE,
    title          text        NOT NULL,
    description    text,
    status         text        NOT NULL CHECK (status IN (
                       'new', 'active', 'review', 'suspended', 'closed', 'archived')),
    classification text        NOT NULL CHECK (classification IN (
                       'open', 'internal', 'confidential', 'strictly_confidential')),
    case_folder    text,
    timezone       text,
    created_at     timestamptz NOT NULL,
    -- Akteure kommen mit Benutzern und Audit; bis dahin ohne Fremdschlüssel.
    created_by     uuid,
    opened_at      timestamptz,
    closed_at      timestamptz
);

CREATE TABLE evidence (
    id                 uuid PRIMARY KEY,
    case_id            uuid        NOT NULL REFERENCES case_file (id),
    kind               text        NOT NULL CHECK (kind IN (
                           'raw_disk_image', 'e01_image', 'vhd_image', 'directory',
                           'file_collection', 'pcap', 'network_flow', 'log_bundle',
                           'mobile_backup', 'android_image', 'ios_backup', 'memory_dump',
                           'registry_hive', 'database', 'cloud_export', 'other')),
    name               text        NOT NULL,
    role               text,
    original_name      text,
    source_uri         text        NOT NULL,
    -- NULL nur bei Evidence, die aus Läufen vor dieser Migration übernommen
    -- wurde (Größe und BLAKE3 standen damals nicht in der Datenbank).
    size               bigint      CHECK (size >= 0),
    sha256             text        NOT NULL,
    blake3             text,
    acquired_at        timestamptz,
    imported_at        timestamptz NOT NULL,
    imported_by        uuid,
    acquisition_method text,
    read_only          boolean     NOT NULL DEFAULT true CHECK (read_only),
    support            text        NOT NULL CHECK (support IN (
                           'recognized', 'analyzed', 'unsupported_format', 'key_missing')),
    parent_evidence_id uuid        REFERENCES evidence (id),
    metadata           jsonb       NOT NULL DEFAULT '{}',
    -- Ziel der zusammengesetzten Fremdschlüssel unten: Verweise auf eine
    -- Evidence bleiben im selben Fall.
    UNIQUE (case_id, id)
);
CREATE INDEX evidence_sha256 ON evidence (sha256);

CREATE TABLE evidence_relation (
    id                 uuid PRIMARY KEY,
    case_id            uuid            NOT NULL,
    source_evidence_id uuid            NOT NULL,
    target_evidence_id uuid            NOT NULL,
    kind               text            NOT NULL CHECK (kind IN (
                           'DERIVED_FROM', 'SAME_SOURCE', 'BELONGS_TO', 'PART_OF')),
    derivation         derivation_kind NOT NULL,
    note               text,
    created_at         timestamptz     NOT NULL,
    created_by         uuid,
    FOREIGN KEY (case_id, source_evidence_id) REFERENCES evidence (case_id, id),
    FOREIGN KEY (case_id, target_evidence_id) REFERENCES evidence (case_id, id),
    CHECK (source_evidence_id <> target_evidence_id),
    UNIQUE (source_evidence_id, target_evidence_id, kind)
);
CREATE INDEX evidence_relation_target ON evidence_relation (target_evidence_id);

CREATE TABLE finding (
    id          uuid PRIMARY KEY,
    case_id     uuid            NOT NULL REFERENCES case_file (id),
    title       text            NOT NULL,
    description text,
    category    text            NOT NULL CHECK (category IN (
                    'execution', 'persistence', 'credential_access', 'exfiltration',
                    'lateral_movement', 'defense_evasion', 'user_activity',
                    'removable_media', 'network', 'other')),
    status      text            NOT NULL CHECK (status IN (
                    'new', 'in_review', 'confirmed', 'rejected', 'resolved')),
    priority    text            NOT NULL CHECK (priority IN ('low', 'medium', 'high', 'critical')),
    disposition text            NOT NULL CHECK (disposition IN (
                    'unknown', 'benign', 'expected', 'suspicious', 'malicious', 'relevant',
                    'not_relevant')),
    -- Ein Vorschlag eines Sprachmodells wird nie von selbst ein Finding;
    -- übernimmt ein Analyst ihn, ist es dessen Aussage.
    derivation  derivation_kind NOT NULL CHECK (derivation <> 'ai_suggested'),
    created_at  timestamptz     NOT NULL,
    created_by  uuid,
    updated_at  timestamptz     NOT NULL
);
CREATE INDEX finding_case ON finding (case_id, status);

-- Belege eines Findings. Ob das Objekt im selben Fall existiert, prüft der
-- Store beim Schreiben (ein Fremdschlüssel kann nicht auf mehrere Tabellen
-- zeigen).
CREATE TABLE finding_ref (
    finding_id  uuid        NOT NULL REFERENCES finding (id),
    object_type object_type NOT NULL CHECK (object_type IN ('entity', 'event', 'artifact')),
    object_id   uuid        NOT NULL,
    PRIMARY KEY (finding_id, object_type, object_id)
);
CREATE INDEX finding_ref_object ON finding_ref (object_type, object_id);

ALTER TABLE analysis_run
    ADD COLUMN finished_at        timestamptz,
    ADD COLUMN status             text  NOT NULL DEFAULT 'completed' CHECK (status IN (
                                      'queued', 'running', 'completed', 'failed', 'cancelled')),
    ADD COLUMN configuration      jsonb NOT NULL DEFAULT '{}',
    ADD COLUMN configuration_hash text,
    ADD COLUMN playbook_id        uuid,
    ADD COLUMN report_sha256      text;
-- Frühere Läufe wurden erst nach getaner Arbeit geschrieben, also
-- abgeschlossen; neue Läufe nennen ihren Stand selbst.
ALTER TABLE analysis_run ALTER COLUMN status DROP DEFAULT;

-- Fälle und Evidence früherer Läufe übernehmen, damit die Fremdschlüssel
-- greifen können.
INSERT INTO case_file (id, case_number, title, status, classification, created_at)
SELECT case_id, 'ALT-' || case_id::text, 'aus früherem Analyselauf übernommen',
       'active', 'internal', min(started_at)
FROM analysis_run
GROUP BY case_id;

INSERT INTO evidence (id, case_id, kind, name, source_uri, sha256, imported_at, support,
                      metadata)
SELECT DISTINCT ON (evidence_id) evidence_id, case_id, 'other',
       'aus früherem Analyselauf übernommen', 'unbekannt', evidence_sha256, started_at,
       'analyzed', '{"uebernommen": "analysis_run"}'
FROM analysis_run
ORDER BY evidence_id, started_at;

ALTER TABLE analysis_run
    ADD FOREIGN KEY (case_id, evidence_id) REFERENCES evidence (case_id, id);
ALTER TABLE artifact
    ADD FOREIGN KEY (case_id, evidence_id) REFERENCES evidence (case_id, id);
ALTER TABLE observation ADD FOREIGN KEY (case_id) REFERENCES case_file (id);
ALTER TABLE entity ADD FOREIGN KEY (case_id) REFERENCES case_file (id);
ALTER TABLE event ADD FOREIGN KEY (case_id) REFERENCES case_file (id);
ALTER TABLE relationship ADD FOREIGN KEY (case_id) REFERENCES case_file (id);
ALTER TABLE provenance
    ADD FOREIGN KEY (evidence_id) REFERENCES evidence (id),
    ADD FOREIGN KEY (analysis_run_id) REFERENCES analysis_run (id);

ALTER TABLE event ALTER COLUMN derivation TYPE derivation_kind;
ALTER TABLE relationship ALTER COLUMN derivation TYPE derivation_kind;

-- Die View hängt an provenance.object_type und muss für die Typänderung
-- kurz weichen.
DROP VIEW provenance_full;
ALTER TABLE provenance ALTER COLUMN object_type TYPE object_type;
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
