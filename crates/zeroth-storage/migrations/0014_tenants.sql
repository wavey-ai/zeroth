CREATE TABLE IF NOT EXISTS zeroth_tenants (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    disabled INTEGER NOT NULL DEFAULT 0 CHECK (disabled IN (0, 1)),
    enterprise_provider TEXT CHECK (enterprise_provider IN ('entra', 'google_workspace')),
    entra_tenant_id TEXT,
    google_workspace_domains_json TEXT NOT NULL DEFAULT '[]',
    oidc_client_id TEXT,
    client_secret_binding TEXT,
    retention_days INTEGER CHECK (retention_days BETWEEN 1 AND 3650),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    UNIQUE (id, enterprise_provider)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_zeroth_clients_tenant_policy
    ON zeroth_clients(id, account_sharing_mode, account_tenant_id, enterprise_provider);

CREATE TABLE IF NOT EXISTS zeroth_tenant_clients (
    client_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    sharing_mode TEXT NOT NULL DEFAULT 'tenant' CHECK (sharing_mode = 'tenant'),
    enterprise_provider TEXT NOT NULL CHECK (enterprise_provider IN ('entra', 'google_workspace')),
    FOREIGN KEY (tenant_id, enterprise_provider)
        REFERENCES zeroth_tenants(id, enterprise_provider)
        ON UPDATE CASCADE ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (client_id, sharing_mode, tenant_id, enterprise_provider)
        REFERENCES zeroth_clients(id, account_sharing_mode, account_tenant_id, enterprise_provider)
        ON UPDATE NO ACTION ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
);

CREATE INDEX IF NOT EXISTS idx_zeroth_tenant_clients_tenant
    ON zeroth_tenant_clients(tenant_id, client_id);

CREATE TABLE IF NOT EXISTS zeroth_tenant_audit_readers (
    tenant_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    can_export INTEGER NOT NULL DEFAULT 0 CHECK (can_export IN (0, 1)),
    PRIMARY KEY (tenant_id, user_id),
    FOREIGN KEY (tenant_id) REFERENCES zeroth_tenants(id) ON DELETE RESTRICT,
    FOREIGN KEY (user_id) REFERENCES zeroth_users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS zeroth_audit_write_guards (
    id TEXT PRIMARY KEY,
    valid INTEGER NOT NULL CHECK (valid = 1)
);
