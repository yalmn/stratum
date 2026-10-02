-- Benutzer, Rollen und das Audit-Protokoll.
--
-- Das Audit ist eine Hash-Kette: ein Trigger vergibt jedem neuen Ereignis
-- die nächste Nummer und berechnet
--   hash = SHA-256(vorheriger_hash || '\n' || nummer || '\n' || payload)
-- über den gespeicherten Text `payload`. Nachrechnen kann jeder, auch ohne
-- PostgreSQL. Ändern, Löschen und Leeren lehnt die Tabelle ab.
--
-- stratum arbeitet nach den Migrationen als Rolle stratum_app: lesen,
-- anlegen, ändern, aber nirgends löschen; im Audit nur lesen und anlegen.
-- Ein Superuser der Datenbank kann Trigger abschalten; dagegen hilft nur das
-- Nachrechnen der Kette (und später externe Prüfpunkte).

CREATE TABLE app_user (
    id            uuid PRIMARY KEY,
    username      text        NOT NULL UNIQUE CHECK (username ~ '^[a-z0-9._-]{1,64}$'),
    display_name  text        NOT NULL,
    kind          text        NOT NULL CHECK (kind IN ('human', 'service')),
    -- Argon2id im PHC-Format, nur bei Menschen.
    password_hash text,
    active        boolean     NOT NULL DEFAULT true,
    created_at    timestamptz NOT NULL,
    created_by    uuid REFERENCES app_user (id),
    CHECK (kind = 'human' OR password_hash IS NULL)
);

CREATE TABLE user_role (
    user_id    uuid        NOT NULL REFERENCES app_user (id),
    role       text        NOT NULL CHECK (role IN (
                   'administrator', 'case_manager', 'forensic_examiner', 'analyst',
                   'threat_intel_analyst', 'reviewer', 'read_only', 'automation_service')),
    granted_at timestamptz NOT NULL,
    granted_by uuid REFERENCES app_user (id),
    PRIMARY KEY (user_id, role)
);

-- Feste Konten (IDs wie ActorId::cli() und ActorId::unbekannt()).
INSERT INTO app_user (id, username, display_name, kind, active, created_at) VALUES
    ('90713752-b779-524a-be66-954f05a2e0c3', 'stratum-cli', 'stratum Kommandozeile',
     'service', true, now()),
    ('924f4def-f441-57c7-8284-92be2c4250ad', 'unbekannt', 'unbekannter Benutzer',
     'service', false, now());
INSERT INTO user_role (user_id, role, granted_at) VALUES
    ('90713752-b779-524a-be66-954f05a2e0c3', 'automation_service', now());

-- Akteure aus früheren Läufen und Tests, die es als Konto nicht gibt, als
-- deaktivierte Platzhalter übernehmen, damit die Fremdschlüssel greifen.
INSERT INTO app_user (id, username, display_name, kind, active, created_at)
SELECT DISTINCT a, 'uebernommen-' || a::text, 'aus früheren Daten übernommen', 'service',
       false, now()
FROM (SELECT created_by FROM case_file
      UNION SELECT imported_by FROM evidence
      UNION SELECT created_by FROM evidence_relation
      UNION SELECT created_by FROM finding) AS x(a)
WHERE a IS NOT NULL AND NOT EXISTS (SELECT 1 FROM app_user u WHERE u.id = a);

ALTER TABLE case_file ADD FOREIGN KEY (created_by) REFERENCES app_user (id);
ALTER TABLE evidence ADD FOREIGN KEY (imported_by) REFERENCES app_user (id);
ALTER TABLE evidence_relation ADD FOREIGN KEY (created_by) REFERENCES app_user (id);
ALTER TABLE finding ADD FOREIGN KEY (created_by) REFERENCES app_user (id);

-- Wer einen Lauf gestartet hat (frühere Läufe: unbekannt).
ALTER TABLE analysis_run ADD COLUMN started_by uuid REFERENCES app_user (id);

-- Rolle entziehen: die Anwendung darf nichts löschen, diese eine Löschung
-- läuft mit den Rechten des Eigentümers. Liefert die Zahl entzogener Rollen.
CREATE FUNCTION rolle_entziehen(nutzer uuid, rolle text) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
    n bigint;
BEGIN
    DELETE FROM user_role WHERE user_id = nutzer AND role = rolle;
    GET DIAGNOSTICS n = ROW_COUNT;
    RETURN n;
END
$$;

-- Kopf der Kette: letzte Nummer und letzter Hash, genau eine Zeile.
CREATE TABLE audit_head (
    id       boolean PRIMARY KEY DEFAULT true CHECK (id),
    sequence bigint  NOT NULL,
    hash     text    NOT NULL
);
INSERT INTO audit_head VALUES (true, 0, repeat('0', 64));

CREATE TABLE audit_event (
    sequence      bigint      PRIMARY KEY,
    id            uuid        NOT NULL UNIQUE,
    actor_id      uuid        NOT NULL REFERENCES app_user (id),
    -- Ohne Fremdschlüssel: auch ein gescheitertes Anlegen eines Falls wird
    -- protokolliert.
    case_id       uuid,
    occurred_at   timestamptz NOT NULL,
    action        text        NOT NULL,
    object_type   text        NOT NULL,
    object_id     text,
    result        text        NOT NULL CHECK (result IN ('success', 'denied', 'failure')),
    details       jsonb       NOT NULL,
    -- Die Felder oben als JSON, genau so, wie sie in den Hash eingingen.
    payload       text        NOT NULL,
    previous_hash text        NOT NULL,
    hash          text        NOT NULL UNIQUE
);
CREATE INDEX audit_event_case ON audit_event (case_id, sequence);
CREATE INDEX audit_event_actor ON audit_event (actor_id, sequence);

-- Läuft mit den Rechten des Eigentümers, damit stratum_app den Kopf nicht
-- selbst ändern darf. Die Zeilensperre reiht gleichzeitige Schreiber auf.
CREATE FUNCTION audit_verketten() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
    kopf audit_head%ROWTYPE;
BEGIN
    SELECT * INTO kopf FROM audit_head FOR UPDATE;
    NEW.sequence := kopf.sequence + 1;
    NEW.previous_hash := kopf.hash;
    NEW.hash := encode(sha256(convert_to(
        kopf.hash || E'\n' || NEW.sequence::text || E'\n' || NEW.payload, 'UTF8')), 'hex');
    UPDATE audit_head SET sequence = NEW.sequence, hash = NEW.hash;
    RETURN NEW;
END
$$;
CREATE TRIGGER audit_verketten BEFORE INSERT ON audit_event
    FOR EACH ROW EXECUTE FUNCTION audit_verketten();

CREATE FUNCTION audit_unveraenderlich() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit_event ist unveränderlich: % abgelehnt', TG_OP;
END
$$;
CREATE TRIGGER audit_kein_aendern BEFORE UPDATE OR DELETE ON audit_event
    FOR EACH ROW EXECUTE FUNCTION audit_unveraenderlich();
CREATE TRIGGER audit_kein_leeren BEFORE TRUNCATE ON audit_event
    FOR EACH STATEMENT EXECUTE FUNCTION audit_unveraenderlich();

-- Rolle der Anwendung.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'stratum_app') THEN
        CREATE ROLE stratum_app NOLOGIN;
    END IF;
END
$$;
GRANT stratum_app TO CURRENT_USER;
GRANT USAGE ON SCHEMA public TO stratum_app;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO stratum_app;
REVOKE INSERT, UPDATE ON audit_head, _sqlx_migrations FROM stratum_app;
REVOKE UPDATE ON audit_event FROM stratum_app;
-- Tabellen späterer Migrationen bekommen dieselben Rechte; Ausnahmen regelt
-- die jeweilige Migration.
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE ON TABLES TO stratum_app;
