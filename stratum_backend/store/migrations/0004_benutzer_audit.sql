-- Benutzer, frei definierbare Rollen und das Audit-Protokoll.
--
-- Konten registrieren sich selbst und warten auf Freigabe; Superadmins geben
-- sie frei, legen Rollen als Bündel von Berechtigungen an und vergeben sie.
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
    -- pending: selbst registriert, wartet auf Freigabe durch einen Superadmin.
    status        text        NOT NULL CHECK (status IN ('pending', 'active', 'disabled', 'rejected')),
    -- Superadmins verwalten Konten und Rollen und haben alle Rechte.
    superadmin    boolean     NOT NULL DEFAULT false,
    created_at    timestamptz NOT NULL,
    created_by    uuid REFERENCES app_user (id),
    -- Letzte Entscheidung über das Konto (Freigabe, Ablehnung, Sperre).
    decided_at    timestamptz,
    decided_by    uuid REFERENCES app_user (id),
    CHECK (kind = 'human' OR password_hash IS NULL),
    CHECK (NOT superadmin OR kind = 'human')
);

-- Rollen sind frei benannte Bündel von Berechtigungen; den Katalog der
-- Berechtigungen legt der Code fest (stratum_model::Permission).
CREATE TABLE app_role (
    id          uuid PRIMARY KEY,
    name        text        NOT NULL UNIQUE CHECK (length(name) BETWEEN 1 AND 100),
    description text,
    created_at  timestamptz NOT NULL,
    created_by  uuid REFERENCES app_user (id),
    updated_at  timestamptz
);

CREATE TABLE role_permission (
    role_id    uuid NOT NULL REFERENCES app_role (id),
    permission text NOT NULL CHECK (permission IN (
        'case.create', 'case.view', 'case.edit', 'case.close', 'evidence.import', 'evidence.view', 'analysis.start', 'analysis.cancel', 'file.view', 'file.extract', 'search.run', 'credential.view_sensitive', 'finding.create', 'finding.edit', 'relation.edit', 'report.create', 'report.export', 'audit.view', 'audit.verify', 'ti.manage', 'playbook.run', 'ai.query', 'connector.use')),
    PRIMARY KEY (role_id, permission)
);

CREATE TABLE user_role (
    user_id    uuid        NOT NULL REFERENCES app_user (id),
    role_id    uuid        NOT NULL REFERENCES app_role (id),
    granted_at timestamptz NOT NULL,
    granted_by uuid REFERENCES app_user (id),
    PRIMARY KEY (user_id, role_id)
);
CREATE INDEX user_role_role ON user_role (role_id);

-- Vorlagen: die Rollen der Zielarchitektur (IDs wie RoleId::template(name),
-- Inhalt wie stratum_model::role_templates()). Superadmins können sie
-- ändern, umbenennen oder löschen.
INSERT INTO app_role (id, name, description, created_at) VALUES
    ('87bdaf64-12b7-53d8-b1a4-f7c00eabda6b', 'Administrator', 'Alle fachlichen Rechte (Konten und Rollen verwalten nur Superadmins)', now()),
    ('04c03092-3dca-5760-bf24-237968f3bae7', 'Case Manager', 'Fälle anlegen, steuern und abschließen', now()),
    ('ab45397f-caf2-5d32-a0d7-44349b0c069c', 'Forensic Examiner', 'Forensische Analyse einschließlich sensibler Zugangsdaten', now()),
    ('28ea44af-40fc-51b3-a2ef-6d7740020a35', 'Analyst', 'Ergebnisse auswerten', now()),
    ('2c3fb948-5349-527e-9aa1-b498c308ec32', 'Threat Intel Analyst', 'Threat Intelligence bearbeiten', now()),
    ('f008d287-77fe-5072-9b1e-18ab745db395', 'Reviewer', 'Ergebnisse prüfen', now()),
    ('1fb2500b-8901-5458-abd1-a55a0eb1aac2', 'Read Only', 'Nur lesen', now()),
    ('98fd91af-5058-52ac-983d-4ad11d0697ce', 'Automation Service', 'Technische Konten für automatische Analysen (z. B. die Kommandozeile)', now());
INSERT INTO role_permission (role_id, permission) VALUES
    ('87bdaf64-12b7-53d8-b1a4-f7c00eabda6b', 'case.create'),
    ('87bdaf64-12b7-53d8-b1a4-f7c00eabda6b', 'case.view'),
    ('87bdaf64-12b7-53d8-b1a4-f7c00eabda6b', 'case.edit'),
    ('87bdaf64-12b7-53d8-b1a4-f7c00eabda6b', 'case.close'),
    ('87bdaf64-12b7-53d8-b1a4-f7c00eabda6b', 'evidence.import'),
    ('87bdaf64-12b7-53d8-b1a4-f7c00eabda6b', 'evidence.view'),
    ('87bdaf64-12b7-53d8-b1a4-f7c00eabda6b', 'analysis.start'),
    ('87bdaf64-12b7-53d8-b1a4-f7c00eabda6b', 'analysis.cancel'),
    ('87bdaf64-12b7-53d8-b1a4-f7c00eabda6b', 'file.view'),
    ('87bdaf64-12b7-53d8-b1a4-f7c00eabda6b', 'file.extract'),
    ('87bdaf64-12b7-53d8-b1a4-f7c00eabda6b', 'search.run'),
    ('87bdaf64-12b7-53d8-b1a4-f7c00eabda6b', 'credential.view_sensitive'),
    ('87bdaf64-12b7-53d8-b1a4-f7c00eabda6b', 'finding.create'),
    ('87bdaf64-12b7-53d8-b1a4-f7c00eabda6b', 'finding.edit'),
    ('87bdaf64-12b7-53d8-b1a4-f7c00eabda6b', 'relation.edit'),
    ('87bdaf64-12b7-53d8-b1a4-f7c00eabda6b', 'report.create'),
    ('87bdaf64-12b7-53d8-b1a4-f7c00eabda6b', 'report.export'),
    ('87bdaf64-12b7-53d8-b1a4-f7c00eabda6b', 'audit.view'),
    ('87bdaf64-12b7-53d8-b1a4-f7c00eabda6b', 'audit.verify'),
    ('87bdaf64-12b7-53d8-b1a4-f7c00eabda6b', 'ti.manage'),
    ('87bdaf64-12b7-53d8-b1a4-f7c00eabda6b', 'playbook.run'),
    ('87bdaf64-12b7-53d8-b1a4-f7c00eabda6b', 'ai.query'),
    ('87bdaf64-12b7-53d8-b1a4-f7c00eabda6b', 'connector.use'),
    ('04c03092-3dca-5760-bf24-237968f3bae7', 'case.create'),
    ('04c03092-3dca-5760-bf24-237968f3bae7', 'case.view'),
    ('04c03092-3dca-5760-bf24-237968f3bae7', 'case.edit'),
    ('04c03092-3dca-5760-bf24-237968f3bae7', 'case.close'),
    ('04c03092-3dca-5760-bf24-237968f3bae7', 'evidence.import'),
    ('04c03092-3dca-5760-bf24-237968f3bae7', 'evidence.view'),
    ('04c03092-3dca-5760-bf24-237968f3bae7', 'analysis.start'),
    ('04c03092-3dca-5760-bf24-237968f3bae7', 'analysis.cancel'),
    ('04c03092-3dca-5760-bf24-237968f3bae7', 'file.view'),
    ('04c03092-3dca-5760-bf24-237968f3bae7', 'search.run'),
    ('04c03092-3dca-5760-bf24-237968f3bae7', 'finding.create'),
    ('04c03092-3dca-5760-bf24-237968f3bae7', 'finding.edit'),
    ('04c03092-3dca-5760-bf24-237968f3bae7', 'relation.edit'),
    ('04c03092-3dca-5760-bf24-237968f3bae7', 'report.create'),
    ('04c03092-3dca-5760-bf24-237968f3bae7', 'report.export'),
    ('04c03092-3dca-5760-bf24-237968f3bae7', 'audit.view'),
    ('ab45397f-caf2-5d32-a0d7-44349b0c069c', 'case.view'),
    ('ab45397f-caf2-5d32-a0d7-44349b0c069c', 'evidence.import'),
    ('ab45397f-caf2-5d32-a0d7-44349b0c069c', 'evidence.view'),
    ('ab45397f-caf2-5d32-a0d7-44349b0c069c', 'analysis.start'),
    ('ab45397f-caf2-5d32-a0d7-44349b0c069c', 'analysis.cancel'),
    ('ab45397f-caf2-5d32-a0d7-44349b0c069c', 'file.view'),
    ('ab45397f-caf2-5d32-a0d7-44349b0c069c', 'file.extract'),
    ('ab45397f-caf2-5d32-a0d7-44349b0c069c', 'search.run'),
    ('ab45397f-caf2-5d32-a0d7-44349b0c069c', 'credential.view_sensitive'),
    ('ab45397f-caf2-5d32-a0d7-44349b0c069c', 'finding.create'),
    ('ab45397f-caf2-5d32-a0d7-44349b0c069c', 'finding.edit'),
    ('ab45397f-caf2-5d32-a0d7-44349b0c069c', 'relation.edit'),
    ('ab45397f-caf2-5d32-a0d7-44349b0c069c', 'report.create'),
    ('ab45397f-caf2-5d32-a0d7-44349b0c069c', 'report.export'),
    ('28ea44af-40fc-51b3-a2ef-6d7740020a35', 'case.view'),
    ('28ea44af-40fc-51b3-a2ef-6d7740020a35', 'evidence.view'),
    ('28ea44af-40fc-51b3-a2ef-6d7740020a35', 'file.view'),
    ('28ea44af-40fc-51b3-a2ef-6d7740020a35', 'search.run'),
    ('28ea44af-40fc-51b3-a2ef-6d7740020a35', 'finding.create'),
    ('28ea44af-40fc-51b3-a2ef-6d7740020a35', 'finding.edit'),
    ('28ea44af-40fc-51b3-a2ef-6d7740020a35', 'relation.edit'),
    ('28ea44af-40fc-51b3-a2ef-6d7740020a35', 'report.create'),
    ('2c3fb948-5349-527e-9aa1-b498c308ec32', 'case.view'),
    ('2c3fb948-5349-527e-9aa1-b498c308ec32', 'evidence.view'),
    ('2c3fb948-5349-527e-9aa1-b498c308ec32', 'search.run'),
    ('2c3fb948-5349-527e-9aa1-b498c308ec32', 'ti.manage'),
    ('2c3fb948-5349-527e-9aa1-b498c308ec32', 'finding.create'),
    ('2c3fb948-5349-527e-9aa1-b498c308ec32', 'report.create'),
    ('f008d287-77fe-5072-9b1e-18ab745db395', 'case.view'),
    ('f008d287-77fe-5072-9b1e-18ab745db395', 'evidence.view'),
    ('f008d287-77fe-5072-9b1e-18ab745db395', 'file.view'),
    ('f008d287-77fe-5072-9b1e-18ab745db395', 'search.run'),
    ('f008d287-77fe-5072-9b1e-18ab745db395', 'finding.edit'),
    ('f008d287-77fe-5072-9b1e-18ab745db395', 'report.create'),
    ('f008d287-77fe-5072-9b1e-18ab745db395', 'audit.view'),
    ('1fb2500b-8901-5458-abd1-a55a0eb1aac2', 'case.view'),
    ('1fb2500b-8901-5458-abd1-a55a0eb1aac2', 'evidence.view'),
    ('1fb2500b-8901-5458-abd1-a55a0eb1aac2', 'file.view'),
    ('98fd91af-5058-52ac-983d-4ad11d0697ce', 'case.create'),
    ('98fd91af-5058-52ac-983d-4ad11d0697ce', 'case.view'),
    ('98fd91af-5058-52ac-983d-4ad11d0697ce', 'evidence.import'),
    ('98fd91af-5058-52ac-983d-4ad11d0697ce', 'evidence.view'),
    ('98fd91af-5058-52ac-983d-4ad11d0697ce', 'analysis.start'),
    ('98fd91af-5058-52ac-983d-4ad11d0697ce', 'finding.create'),
    ('98fd91af-5058-52ac-983d-4ad11d0697ce', 'relation.edit'),
    ('98fd91af-5058-52ac-983d-4ad11d0697ce', 'report.create'),
    ('98fd91af-5058-52ac-983d-4ad11d0697ce', 'audit.verify');

-- Feste Konten (IDs wie ActorId::cli() und ActorId::unbekannt()).
INSERT INTO app_user (id, username, display_name, kind, status, created_at) VALUES
    ('90713752-b779-524a-be66-954f05a2e0c3', 'stratum-cli', 'stratum Kommandozeile',
     'service', 'active', now()),
    ('924f4def-f441-57c7-8284-92be2c4250ad', 'unbekannt', 'unbekannter Benutzer',
     'service', 'disabled', now());
INSERT INTO user_role (user_id, role_id, granted_at) VALUES
    ('90713752-b779-524a-be66-954f05a2e0c3', '98fd91af-5058-52ac-983d-4ad11d0697ce', now());

-- Akteure aus früheren Läufen und Tests, die es als Konto nicht gibt, als
-- gesperrte Platzhalter übernehmen, damit die Fremdschlüssel greifen.
INSERT INTO app_user (id, username, display_name, kind, status, created_at)
SELECT DISTINCT a, 'uebernommen-' || a::text, 'aus früheren Daten übernommen', 'service',
       'disabled', now()
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

-- Die Anwendung darf nichts löschen. Die drei Stellen, an denen Rechte
-- wegfallen, laufen über Funktionen mit den Rechten des Eigentümers; ob der
-- Aufrufer das darf (Superadmin), prüft stratum vorher.

-- Setzt die Berechtigungen einer Rolle auf genau die gegebene Menge.
CREATE FUNCTION rolle_rechte_setzen(rolle uuid, rechte text[]) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
    DELETE FROM role_permission WHERE role_id = rolle AND permission <> ALL (rechte);
    INSERT INTO role_permission (role_id, permission)
    SELECT rolle, r FROM unnest(rechte) AS r ON CONFLICT DO NOTHING;
END
$$;

-- Setzt die Rollen eines Kontos auf genau die gegebene Menge.
CREATE FUNCTION konto_rollen_setzen(nutzer uuid, rollen uuid[], durch uuid) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
    DELETE FROM user_role WHERE user_id = nutzer AND role_id <> ALL (rollen);
    INSERT INTO user_role (user_id, role_id, granted_at, granted_by)
    SELECT nutzer, r, now(), durch FROM unnest(rollen) AS r ON CONFLICT DO NOTHING;
END
$$;

-- Löscht eine Rolle samt Zuordnungen; liefert die Zahl betroffener Konten.
CREATE FUNCTION rolle_loeschen(rolle uuid) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
    n bigint;
BEGIN
    DELETE FROM user_role WHERE role_id = rolle;
    GET DIAGNOSTICS n = ROW_COUNT;
    DELETE FROM role_permission WHERE role_id = rolle;
    DELETE FROM app_role WHERE id = rolle;
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
