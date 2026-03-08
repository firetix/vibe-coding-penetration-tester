-- 001_initial_schema.sqlite.sql
-- Core tables for VibePenTester (SQLite dialect).

CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    supabase_user_id VARCHAR(255) NOT NULL UNIQUE,
    email           VARCHAR(255),
    display_name    VARCHAR(255),
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS scans (
    id              VARCHAR(36) PRIMARY KEY,
    user_id         INTEGER NOT NULL REFERENCES users(id),
    target_url      TEXT NOT NULL,
    scan_mode       VARCHAR(32) NOT NULL DEFAULT 'quick',
    status          VARCHAR(32) NOT NULL DEFAULT 'pending',
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS scan_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id         VARCHAR(36) NOT NULL REFERENCES scans(id),
    event_type      VARCHAR(64) NOT NULL,
    data            TEXT,
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS findings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id         VARCHAR(36) NOT NULL REFERENCES scans(id),
    title           VARCHAR(512) NOT NULL,
    severity        VARCHAR(32),
    detail          TEXT,
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for common queries
CREATE INDEX IF NOT EXISTS idx_scans_user_id ON scans(user_id);
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
CREATE INDEX IF NOT EXISTS idx_scan_events_scan_id ON scan_events(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
