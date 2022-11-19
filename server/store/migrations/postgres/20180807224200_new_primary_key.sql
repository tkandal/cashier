-- +migrate Up
ALTER TABLE issued_certs DROP CONSTRAINT issued_certs_pkey;
ALTER TABLE issued_certs ADD COLUMN id serial primary key;
CREATE INDEX idx_key_id ON issued_certs (key_id);

-- +migrate Down
ALTER TABLE issued_certs DROP CONSTRAINT issued_certs_pkey;
ALTER TABLE issued_certs DROP COLUMN id;
ALTER TABLE issued_certs ADD PRIMARY KEY (key_id);
