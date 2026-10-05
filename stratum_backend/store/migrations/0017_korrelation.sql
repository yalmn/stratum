-- Regelresultate sind unveränderliche Auswertungsschnappschüsse, keine Findings.
CREATE TABLE correlation_run (
    id uuid PRIMARY KEY,
    case_id uuid NOT NULL REFERENCES case_file(id),
    created_by uuid NOT NULL REFERENCES app_user(id),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    rules jsonb NOT NULL,
    summary jsonb NOT NULL,
    UNIQUE(case_id,id)
);
CREATE INDEX correlation_run_case ON correlation_run(case_id,id DESC);
CREATE TABLE correlation_result (
    run_id uuid NOT NULL,
    case_id uuid NOT NULL,
    id uuid NOT NULL,
    payload jsonb NOT NULL,
    PRIMARY KEY(run_id,id),
    FOREIGN KEY(case_id,run_id) REFERENCES correlation_run(case_id,id)
);
REVOKE UPDATE ON correlation_run,correlation_result FROM stratum_app;
