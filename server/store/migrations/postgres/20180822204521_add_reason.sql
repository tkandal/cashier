-- +migrate Up
ALTER TABLE issued_certs ADD COLUMN message TEXT NOT NULL default '';

-- +migrate Down
ALTER TABLE issued_certs DROP COLUMN message;
