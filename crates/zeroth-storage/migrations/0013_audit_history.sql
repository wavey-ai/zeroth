ALTER TABLE zeroth_audit_events ADD COLUMN schema_version INTEGER NOT NULL DEFAULT 0;
ALTER TABLE zeroth_audit_events ADD COLUMN organization_id TEXT;
ALTER TABLE zeroth_audit_events ADD COLUMN actor_type TEXT;
ALTER TABLE zeroth_audit_events ADD COLUMN actor_id TEXT;
ALTER TABLE zeroth_audit_events ADD COLUMN target_type TEXT;
ALTER TABLE zeroth_audit_events ADD COLUMN target_id TEXT;
ALTER TABLE zeroth_audit_events ADD COLUMN outcome TEXT NOT NULL DEFAULT 'unknown';
ALTER TABLE zeroth_audit_events ADD COLUMN reason_code TEXT;
ALTER TABLE zeroth_audit_events ADD COLUMN request_id TEXT;
ALTER TABLE zeroth_audit_events ADD COLUMN recorded_at INTEGER;
ALTER TABLE zeroth_audit_events ADD COLUMN event_json TEXT;

CREATE INDEX IF NOT EXISTS idx_zeroth_audit_events_recorded_id
    ON zeroth_audit_events(COALESCE(recorded_at, created_at) DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_zeroth_audit_events_org_recorded_id
    ON zeroth_audit_events(organization_id, COALESCE(recorded_at, created_at) DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_zeroth_audit_events_actor_recorded_id
    ON zeroth_audit_events(actor_id, COALESCE(recorded_at, created_at) DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_zeroth_audit_events_target_recorded_id
    ON zeroth_audit_events(target_id, COALESCE(recorded_at, created_at) DESC, id DESC);

CREATE TABLE IF NOT EXISTS zeroth_audit_outbox (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE,
    event_json TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS zeroth_audit_consumers (
    id TEXT PRIMARY KEY,
    last_sequence INTEGER NOT NULL DEFAULT 0,
    updated_at INTEGER NOT NULL
);
