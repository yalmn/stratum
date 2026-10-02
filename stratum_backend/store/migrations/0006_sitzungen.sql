-- Sitzungen der Weboberfläche bzw. API. Gespeichert wird nur der SHA-256
-- des Tokens; das Token selbst kennt nur der Client. Eine Sitzung endet
-- mit der Abmeldung, nach Ablauf (absolut) oder nach Untätigkeit.

CREATE TABLE app_session (
    token_sha256 text        PRIMARY KEY,
    user_id      uuid        NOT NULL REFERENCES app_user (id),
    created_at   timestamptz NOT NULL,
    expires_at   timestamptz NOT NULL,
    last_seen_at timestamptz NOT NULL,
    ended_at     timestamptz,
    client       text
);
CREATE INDEX app_session_user ON app_session (user_id);
