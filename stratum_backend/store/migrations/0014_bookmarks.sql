-- Auswahl und Notizen bleiben von forensischen Quellobjekten getrennt.
CREATE TABLE case_bookmark (
    id uuid PRIMARY KEY,
    case_id uuid NOT NULL REFERENCES case_file(id),
    kind text NOT NULL CHECK (kind IN ('file','event','entity','relationship','artifact')),
    target text NOT NULL CHECK (octet_length(target) BETWEEN 1 AND 250),
    title text NOT NULL,
    note text NOT NULL DEFAULT '' CHECK (octet_length(note) <= 8000),
    reviewed boolean NOT NULL DEFAULT false,
    removed boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    updated_by uuid NOT NULL REFERENCES app_user(id),
    UNIQUE(case_id,kind,target)
);
CREATE INDEX case_bookmark_page ON case_bookmark(case_id,id DESC) WHERE NOT removed;
ALTER TABLE role_permission DROP CONSTRAINT role_permission_permission_check;
ALTER TABLE role_permission ADD CONSTRAINT role_permission_permission_check CHECK (permission IN (
    'case.create','case.view','case.edit','case.close','evidence.import','evidence.view',
    'analysis.start','analysis.cancel','file.view','file.extract','search.run',
    'credential.view_sensitive','finding.create','finding.edit','relation.edit',
    'report.create','report.export','audit.view','audit.verify','ti.manage',
    'playbook.run','ai.query','connector.use','bookmark.edit'));
