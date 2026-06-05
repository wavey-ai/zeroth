ALTER TABLE zeroth_clients
    ADD COLUMN visible_login_methods_json TEXT NOT NULL DEFAULT '[]';
