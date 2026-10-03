-- Seitenweises Lesen der Timeline nach Zeit und ID (Keyset), je Fall.
CREATE INDEX event_zeit_id ON event (case_id, occurred_utc, id) WHERE occurred_utc IS NOT NULL;
-- Entitäten nach Anzeigename blättern.
CREATE INDEX entity_name ON entity (case_id, display_name, id);
