-- Nur maskierte Quelldaten gelangen in den Suchindex.
CREATE EXTENSION IF NOT EXISTS pg_trgm;

CREATE FUNCTION stratum_suchfelder(v jsonb, geheim boolean) RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE STRICT AS $$
DECLARE aus jsonb; k text; w jsonb;
BEGIN
  geheim := geheim OR COALESCE(v->>'sensibel' = 'true', false);
  IF jsonb_typeof(v) = 'object' THEN
    aus := '{}';
    FOR k, w IN SELECT * FROM jsonb_each(v) LOOP
      IF k IN ('passwort','dcc2_hash','dpapi_machinekey','dpapi_userkey','masterkey_hex')
         OR (geheim AND k = 'wert') THEN
        aus := aus || jsonb_build_object(k, '[maskiert]');
      ELSE
        aus := aus || jsonb_build_object(k, stratum_suchfelder(w, geheim));
      END IF;
    END LOOP;
    RETURN aus;
  ELSIF jsonb_typeof(v) = 'array' THEN
    SELECT COALESCE(jsonb_agg(stratum_suchfelder(value, geheim) ORDER BY ordinality), '[]')
      INTO aus FROM jsonb_array_elements(v) WITH ORDINALITY;
    RETURN aus;
  END IF;
  RETURN v;
END $$;

-- Ungewöhnliche Wurzelwerte sensibler Datensätze vorsorglich ganz maskieren.
CREATE FUNCTION stratum_suchdatensatz(v jsonb, geheim boolean) RETURNS jsonb
LANGUAGE sql IMMUTABLE STRICT AS $$
  SELECT CASE WHEN geheim AND jsonb_typeof(v) <> 'object'
    THEN '"[maskiert]"'::jsonb ELSE stratum_suchfelder(v, geheim) END
$$;

-- JSON-Strings ohne Escapezeichen indexieren, damit auch ganze Pfade passen.
CREATE FUNCTION stratum_suchtext(v jsonb) RETURNS text
LANGUAGE plpgsql IMMUTABLE STRICT AS $$
DECLARE aus text;
BEGIN
  IF jsonb_typeof(v) = 'object' THEN
    SELECT string_agg(key || ': ' || stratum_suchtext(value), ' ' ORDER BY key)
      INTO aus FROM jsonb_each(v);
  ELSIF jsonb_typeof(v) = 'array' THEN
    SELECT string_agg(stratum_suchtext(value), ' ' ORDER BY ordinality)
      INTO aus FROM jsonb_array_elements(v) WITH ORDINALITY;
  ELSE
    aus := v #>> '{}';
  END IF;
  RETURN COALESCE(aus, '');
END $$;

CREATE TABLE artifact_search (
  artifact_id uuid PRIMARY KEY REFERENCES artifact(id),
  case_id uuid NOT NULL REFERENCES case_file(id),
  document text NOT NULL
);
CREATE INDEX provenance_artifact ON provenance(artifact_id, object_type, object_id);
CREATE INDEX artifact_case_evidence ON artifact(case_id, evidence_id, id);
CREATE INDEX artifact_search_case ON artifact_search(case_id, artifact_id);
CREATE INDEX artifact_search_text ON artifact_search USING gin(document gin_trgm_ops);

CREATE FUNCTION stratum_artefaktsuche_refresh(ziel uuid) RETURNS void
LANGUAGE plpgsql AS $$
DECLARE a artifact; geheim boolean; dokument text;
BEGIN
  SELECT * INTO a FROM artifact WHERE id = ziel FOR UPDATE;
  IF NOT FOUND THEN RETURN; END IF;
  geheim := a.raw_metadata->>'domain' IN ('lsa','dpapi')
    OR a.parser->>'name' IN ('stratum.lsa','stratum.dpapi')
    OR a.kind = 'browser_login_row';
  geheim := COALESCE(geheim, false);
  SELECT concat_ws(' ',
    string_agg(stratum_suchtext(stratum_suchdatensatz(o.fields, geheim OR COALESCE(o.fields->>'art' = 'passwort_klartext', false))),
      ' ' ORDER BY o.id), stratum_suchtext(a.source_locator), a.kind, stratum_suchtext(a.parser),
    stratum_suchtext(stratum_suchdatensatz(CASE WHEN jsonb_typeof(a.raw_metadata) = 'object'
      THEN a.raw_metadata - 'rohfund_id' ELSE a.raw_metadata END, geheim))) INTO dokument
    FROM observation o WHERE o.artifact_id = ziel;
  INSERT INTO artifact_search VALUES (ziel, a.case_id, dokument)
    ON CONFLICT (artifact_id) DO UPDATE SET case_id = EXCLUDED.case_id, document = EXCLUDED.document;
END $$;

CREATE FUNCTION stratum_artefaktsuche_trigger() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_TABLE_NAME = 'artifact' THEN
    PERFORM stratum_artefaktsuche_refresh(NEW.id);
  ELSE
    PERFORM stratum_artefaktsuche_refresh(NEW.artifact_id);
    IF TG_OP = 'UPDATE' AND OLD.artifact_id <> NEW.artifact_id THEN
      PERFORM stratum_artefaktsuche_refresh(OLD.artifact_id);
    END IF;
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER artifact_search_write AFTER INSERT OR UPDATE ON artifact
  FOR EACH ROW EXECUTE FUNCTION stratum_artefaktsuche_trigger();
CREATE TRIGGER observation_search_write AFTER INSERT OR UPDATE ON observation
  FOR EACH ROW EXECUTE FUNCTION stratum_artefaktsuche_trigger();
-- Bestehende Ergebnisse beim Upgrade nachtragen, ohne die Evidence zu lesen.
SELECT stratum_artefaktsuche_refresh(id) FROM artifact;
