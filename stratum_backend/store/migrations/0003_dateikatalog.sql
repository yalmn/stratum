-- Dateikatalog je Evidence: alle über den Verzeichnisbaum erreichbaren
-- Dateien und Verzeichnisse der NTFS-Volumes, wie sie `--catalog` als JSON
-- Lines schreibt. Grundlage für den File Explorer.
--
-- Zeiten stehen als FILETIME (100-ns-Schritte seit 1601-01-01 UTC) in
-- bigint: verlustfrei, sortierbar und kleiner als Text; timestamptz würde
-- auf Mikrosekunden runden. Werte mit gesetztem obersten Bit (in Windows
-- ungültig, etwa nach Manipulation) bleiben bitgleich erhalten und erscheinen
-- als negative Zahl. Umgerechnet wird beim Schreiben im Store;
-- filetime_iso() liefert wieder genau den Text des Katalogs.

-- FILETIME in denselben Text, den der Katalog schreibt.
CREATE FUNCTION filetime_iso(ft bigint) RETURNS text
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE AS $$
    SELECT lpad(y, greatest(4, length(y)), '0') || to_char(d, '-MM-DD') || 'T'
           || lpad((s / 3600)::text, 2, '0') || ':' || lpad((s / 60 % 60)::text, 2, '0') || ':'
           || lpad((s % 60)::text, 2, '0') || '.' || lpad(f::text, 7, '0') || 'Z'
    FROM (SELECT d, extract(year FROM d)::text AS y, s, f
          FROM (SELECT DATE '1601-01-01' + div(u, 864000000000)::int AS d,
                       div(mod(u, 864000000000), 10000000)::bigint AS s,
                       mod(u, 10000000)::bigint AS f
                FROM (SELECT CASE WHEN ft < 0 THEN ft::numeric + 18446744073709551616
                                  ELSE ft::numeric END AS u) a) b) c
$$;

CREATE TABLE file (
    case_id           uuid    NOT NULL,
    evidence_id       uuid    NOT NULL,
    volume_offset     bigint  NOT NULL,
    mft_record        bigint  NOT NULL,
    path              text    NOT NULL,
    name              text    NOT NULL,
    parent_record     bigint  NOT NULL,
    is_directory      boolean NOT NULL,
    sequence          integer,
    size              bigint,
    -- Gültige Datenlänge, nur wenn kleiner als die Größe; dahinter Nullen.
    valid_length      bigint,
    si_created        bigint,
    si_modified       bigint,
    si_mft_modified   bigint,
    si_accessed       bigint,
    fn_created        bigint,
    fn_modified       bigint,
    fn_mft_modified   bigint,
    fn_accessed       bigint,
    attributes        text[]  NOT NULL DEFAULT '{}',
    streams           jsonb,
    hardlinks         integer,
    reparse_tag       text,
    wof               text,
    mft_record_offset bigint,
    -- Nur mit Dateiinhalten (--datei-hashes).
    sha256            text,
    file_type         text,
    mime              text,
    signature         jsonb,
    hash_error        text,
    -- Datensatz nicht lesbar bzw. Verzeichnisinhalt nicht lesbar.
    error             text,
    content_error     text,
    -- Lauf, der die Zeile angelegt hat.
    analysis_run_id   uuid    NOT NULL REFERENCES analysis_run (id),
    -- Ein Datensatz kann über Hardlinks mehrere Pfade haben; Elternverzeichnis
    -- und Name unterscheiden sie (Verzeichnisse haben in NTFS keine
    -- Hardlinks). Kleiner als ein Schlüssel über den ganzen Pfad.
    PRIMARY KEY (evidence_id, volume_offset, mft_record, parent_record, name),
    FOREIGN KEY (case_id, evidence_id) REFERENCES evidence (case_id, id)
);
-- Inhalt eines Verzeichnisses (Baumansicht).
CREATE INDEX file_parent ON file (evidence_id, volume_offset, parent_record);
-- Suche nach Dateihash, auch fallübergreifend.
CREATE INDEX file_sha256 ON file (sha256) WHERE sha256 IS NOT NULL;
