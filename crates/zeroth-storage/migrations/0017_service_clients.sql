CREATE TABLE IF NOT EXISTS zeroth_service_clients (
    id TEXT PRIMARY KEY CHECK (id GLOB 'svc_*'),
    tenant_id TEXT NOT NULL REFERENCES zeroth_tenants(id),
    name TEXT NOT NULL,
    audiences_json TEXT NOT NULL,
    scopes_json TEXT NOT NULL,
    public_jwks_json TEXT NOT NULL,
    disabled INTEGER NOT NULL DEFAULT 0 CHECK (disabled IN (0,1)),
    revision INTEGER NOT NULL CHECK (revision BETWEEN 1 AND 2147483646),
    token_ttl_seconds INTEGER NOT NULL CHECK (token_ttl_seconds BETWEEN 60 AND 600),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_zeroth_service_clients_tenant ON zeroth_service_clients(tenant_id,id);
CREATE TABLE IF NOT EXISTS zeroth_service_assertions (
    client_id TEXT NOT NULL REFERENCES zeroth_service_clients(id),
    jti_hash TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY(client_id,jti_hash)
);
CREATE INDEX IF NOT EXISTS idx_zeroth_service_assertions_expiry ON zeroth_service_assertions(expires_at);
CREATE TABLE IF NOT EXISTS zeroth_service_tokens (
    token_hash TEXT PRIMARY KEY,
    client_id TEXT NOT NULL REFERENCES zeroth_service_clients(id),
    tenant_id TEXT NOT NULL REFERENCES zeroth_tenants(id),
    client_revision INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_zeroth_service_tokens_expiry ON zeroth_service_tokens(expires_at);
