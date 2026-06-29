CREATE TABLE IF NOT EXISTS zeroth_rate_limits (
    scope TEXT NOT NULL,
    subject_hash TEXT NOT NULL,
    bucket_start INTEGER NOT NULL,
    count INTEGER NOT NULL,
    blocked_until INTEGER,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (scope, subject_hash, bucket_start)
);

CREATE INDEX IF NOT EXISTS idx_zeroth_rate_limits_updated_at
    ON zeroth_rate_limits(updated_at);
