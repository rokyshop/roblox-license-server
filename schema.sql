CREATE TABLE licenses (
    license TEXT PRIMARY KEY,
    owner_id BIGINT,
    allowed_ids TEXT,
    last_used BIGINT,
    attempts INT DEFAULT 0,
    banned_until BIGINT
);
