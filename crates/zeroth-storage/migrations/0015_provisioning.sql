CREATE TABLE IF NOT EXISTS zeroth_directory_sources (
    tenant_id TEXT PRIMARY KEY,
    provider_id TEXT NOT NULL CHECK (provider_id IN ('entra','google_workspace')),
    authority_id TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0,1)),
    token_binding TEXT,
    last_activity_at INTEGER,
    last_full_sync_at INTEGER,
    last_error_code TEXT,
    sync_fence TEXT,
    config_version INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    UNIQUE (tenant_id,provider_id,authority_id),
    FOREIGN KEY (tenant_id) REFERENCES zeroth_tenants(id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS zeroth_directory_users (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    provider_id TEXT NOT NULL CHECK (provider_id IN ('entra','google_workspace')),
    authority_id TEXT NOT NULL,
    external_id TEXT NOT NULL,
    user_name TEXT NOT NULL,
    user_name_key TEXT NOT NULL,
    display_name TEXT,
    profile_json TEXT NOT NULL DEFAULT '{}',
    active INTEGER NOT NULL CHECK (active IN (0,1)),
    deleted INTEGER NOT NULL DEFAULT 0 CHECK (deleted IN (0,1)),
    user_id TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    UNIQUE (tenant_id,provider_id,authority_id,external_id),
    UNIQUE (tenant_id,provider_id,authority_id,user_id),
    FOREIGN KEY (tenant_id,provider_id,authority_id)
        REFERENCES zeroth_directory_sources(tenant_id,provider_id,authority_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_zeroth_directory_live_username
    ON zeroth_directory_users(tenant_id,provider_id,authority_id,user_name_key)
    WHERE deleted=0 AND provider_id='entra';
CREATE INDEX IF NOT EXISTS idx_zeroth_directory_user_link
    ON zeroth_directory_users(tenant_id,user_id,active,deleted);

-- These are signed, immutable upstream object references. Mailboxes and OIDC
-- pairwise Entra sub values are never a substitute for signed tenant+object ID.
-- Opaque local IDs survive account erasure and never cascade away denial evidence.
CREATE TABLE IF NOT EXISTS zeroth_directory_links (
    tenant_id TEXT NOT NULL,
    provider_id TEXT NOT NULL CHECK (provider_id IN ('entra','google_workspace')),
    authority_id TEXT NOT NULL,
    external_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (tenant_id,provider_id,authority_id,external_id),
    UNIQUE (tenant_id,provider_id,authority_id,user_id),
    FOREIGN KEY (tenant_id) REFERENCES zeroth_tenants(id) ON DELETE RESTRICT
);
