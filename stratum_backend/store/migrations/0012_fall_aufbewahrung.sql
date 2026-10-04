-- Asservate bleiben mit allen Verweisen gespeichert.
ALTER TABLE case_file DROP CONSTRAINT case_file_status_check;
ALTER TABLE case_file ADD CONSTRAINT case_file_status_check
    CHECK (status IN ('new', 'active', 'review', 'suspended', 'closed', 'archived', 'retained'));
