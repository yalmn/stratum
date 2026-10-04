ALTER TABLE job DROP CONSTRAINT job_kind_check;
ALTER TABLE job ADD CONSTRAINT job_kind_check CHECK (kind IN ('analysis','evidence_import','yara_scan','network_enrichment','http_replay'));
