-- Konten: Startpasswort bzw. vom Superadmin zurückgesetztes Passwort muss
-- vor allem anderen durch ein eigenes ersetzt werden.
ALTER TABLE app_user ADD COLUMN password_change_required boolean NOT NULL DEFAULT false;

-- Genau ein Superadmin (Nutzerentscheidung 2026-10-03). Eine ältere
-- Datenbank mit mehreren bleibt lesbar; der Index entsteht dann nicht und
-- die Anwendung lässt keinen weiteren zu.
DO $$
BEGIN
    IF (SELECT count(*) FROM app_user WHERE superadmin) <= 1 THEN
        CREATE UNIQUE INDEX ein_superadmin ON app_user (superadmin) WHERE superadmin;
    END IF;
END $$;
