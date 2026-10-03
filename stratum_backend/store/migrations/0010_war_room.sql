-- War Room: operativer Verlauf je Fall (Abschnitt 33 der Zielarchitektur).
-- Nur anhängen: stratum_app darf Einträge weder ändern noch löschen.
CREATE TABLE war_room_entry (
    id              uuid PRIMARY KEY,
    case_id         uuid        NOT NULL REFERENCES case_file (id),
    created_at      timestamptz NOT NULL DEFAULT now(),
    actor_id        uuid        NOT NULL,
    kind            text        NOT NULL,
    object_refs     jsonb       NOT NULL DEFAULT '[]',
    payload         jsonb       NOT NULL DEFAULT '{}',
    parent_entry_id uuid REFERENCES war_room_entry (id),
    audit_event_id  uuid
);
CREATE INDEX war_room_case ON war_room_entry (case_id, created_at, id);
REVOKE UPDATE, DELETE ON war_room_entry FROM stratum_app;

-- Ereignisse je Evidence filtern (Zeitachse einer Evidence).
CREATE INDEX provenance_evidence_object ON provenance (evidence_id, object_type, object_id);
