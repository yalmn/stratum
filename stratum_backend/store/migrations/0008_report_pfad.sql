-- Ort des Reports eines Laufs. Rohfunde stehen nur im Report; die API liest
-- sie dort nach und prüft vorher den Report gegen report_sha256.
ALTER TABLE analysis_run ADD COLUMN report_path text;
