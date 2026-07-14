ALTER TABLE zeroth_magic_links ADD COLUMN poll_token_hash TEXT;
ALTER TABLE zeroth_magic_links ADD COLUMN consumed_session_id TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS idx_zeroth_magic_links_poll_token_hash
    ON zeroth_magic_links(poll_token_hash);
