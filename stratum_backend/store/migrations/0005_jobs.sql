-- Jobs: Aufträge für Worker, Warteschlange in PostgreSQL.
--
-- Ein Worker holt den ältesten wartenden Job mit FOR UPDATE SKIP LOCKED,
-- meldet regelmäßig Fortschritt (zugleich Lebenszeichen) und fragt dabei
-- nach einem Abbruch. Läuft ein Job ohne Lebenszeichen weiter, gilt sein
-- Worker als verloren und der Job als fehlgeschlagen.

CREATE TABLE job (
    id               uuid PRIMARY KEY,
    case_id          uuid        NOT NULL REFERENCES case_file (id),
    kind             text        NOT NULL CHECK (kind IN ('analysis')),
    status           text        NOT NULL CHECK (status IN (
                         'queued', 'running', 'completed', 'failed', 'cancelled')),
    -- Nie Geheimnisse (Passwörter, Schlüssel).
    parameters       jsonb       NOT NULL,
    progress         jsonb       NOT NULL DEFAULT '{}',
    created_by       uuid        NOT NULL REFERENCES app_user (id),
    created_at       timestamptz NOT NULL,
    started_at       timestamptz,
    finished_at      timestamptz,
    worker           text,
    heartbeat_at     timestamptz,
    cancel_requested boolean     NOT NULL DEFAULT false,
    error            text,
    analysis_run_id  uuid REFERENCES analysis_run (id),
    result           jsonb
);
CREATE INDEX job_wartend ON job (created_at) WHERE status = 'queued';
CREATE INDEX job_fall ON job (case_id, created_at);
