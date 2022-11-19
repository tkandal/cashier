-- +migrate Up
CREATE TABLE IF NOT EXISTS issued_certs (
  key_id character(255) NOT NULL,
  principals character(255) DEFAULT '[]',
  created_at timestamp DEFAULT '1970-01-01 00:00:01',
  expires_at timestamp DEFAULT '1970-01-01 00:00:01',
  revoked boolean DEFAULT false,
  raw_key text,
  PRIMARY KEY (key_id)
);
CREATE INDEX idx_expires_at ON issued_certs (expires_at);
CREATE INDEX idx_revoked_expires_at ON issued_certs (revoked, expires_at);

-- +migrate Down
DROP TABLE issued_certs CASCADE;
