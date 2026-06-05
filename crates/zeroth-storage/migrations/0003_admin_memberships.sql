CREATE TABLE IF NOT EXISTS zeroth_admin_memberships (
    user_id TEXT PRIMARY KEY,
    role TEXT NOT NULL DEFAULT 'admin',
    granted_by TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    disabled_at INTEGER,
    FOREIGN KEY (user_id) REFERENCES zeroth_users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_zeroth_admin_memberships_active
    ON zeroth_admin_memberships(disabled_at, updated_at DESC);
