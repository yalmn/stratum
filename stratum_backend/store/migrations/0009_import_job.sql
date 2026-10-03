-- Evidence-Import als Job: Hash über große Images dauert zu lange für eine
-- Anfrage an die API.
ALTER TABLE job DROP CONSTRAINT job_kind_check;
ALTER TABLE job ADD CONSTRAINT job_kind_check CHECK (kind IN ('analysis', 'evidence_import'));
