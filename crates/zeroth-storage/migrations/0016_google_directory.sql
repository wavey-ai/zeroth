CREATE TABLE IF NOT EXISTS zeroth_google_directory (
    tenant_id TEXT PRIMARY KEY,
    enabled INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0,1)),
    managed_enforced INTEGER NOT NULL DEFAULT 0 CHECK (managed_enforced IN (0,1)),
    customer_id TEXT,
    delegated_admin_email TEXT,
    service_account_secret_binding TEXT,
    last_attempt_at INTEGER,
    last_success_at INTEGER,
    last_error_code TEXT,
    last_seen_count INTEGER,
    last_deactivated_count INTEGER,
    next_sync_at INTEGER,
    lease_id TEXT,
    lease_expires_at INTEGER,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    FOREIGN KEY (tenant_id) REFERENCES zeroth_tenants(id) ON DELETE RESTRICT
);
CREATE INDEX IF NOT EXISTS idx_zeroth_google_directory_due
    ON zeroth_google_directory(enabled,next_sync_at,tenant_id);
