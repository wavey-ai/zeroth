ALTER TABLE zeroth_local_credentials ADD COLUMN password_scheme TEXT NOT NULL DEFAULT 'pbkdf2-sha256';
ALTER TABLE zeroth_local_credentials ADD COLUMN password_params_json TEXT NOT NULL DEFAULT '{}';
ALTER TABLE zeroth_local_credentials ADD COLUMN password_version INTEGER NOT NULL DEFAULT 1;
