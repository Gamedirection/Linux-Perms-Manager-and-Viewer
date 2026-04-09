-- Schema v1: core index tables

CREATE TABLE IF NOT EXISTS scan_roots (
    path            TEXT PRIMARY KEY NOT NULL,
    last_full_scan  TEXT,
    file_count      INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS path_entries (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    path            TEXT NOT NULL UNIQUE,
    entry_type      TEXT NOT NULL,   -- Directory | File | Symlink | Other
    owner_uid       INTEGER NOT NULL,
    owner_gid       INTEGER NOT NULL,
    mode            INTEGER NOT NULL, -- raw u32
    has_acl         INTEGER NOT NULL DEFAULT 0,
    acl_json        TEXT,
    special_bits    INTEGER NOT NULL DEFAULT 0, -- packed: bit0=suid, bit1=sgid, bit2=sticky
    is_mount_point  INTEGER NOT NULL DEFAULT 0,
    size_bytes      INTEGER NOT NULL DEFAULT 0,
    scan_source     TEXT NOT NULL,   -- Full | Partial | Estimated
    scanned_at      TEXT NOT NULL    -- ISO 8601 UTC
);

CREATE INDEX IF NOT EXISTS idx_path_entries_owner_uid ON path_entries(owner_uid);
CREATE INDEX IF NOT EXISTS idx_path_entries_owner_gid ON path_entries(owner_gid);
CREATE INDEX IF NOT EXISTS idx_path_entries_mode      ON path_entries(mode);

CREATE TABLE IF NOT EXISTS audit_findings (
    id              TEXT PRIMARY KEY NOT NULL, -- UUID
    severity        TEXT NOT NULL,   -- Critical | High | Medium | Low | Info
    category        TEXT NOT NULL,
    path            TEXT NOT NULL,
    description     TEXT NOT NULL,
    recommendation  TEXT NOT NULL,
    found_at        TEXT NOT NULL,   -- ISO 8601 UTC
    dismissed       INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_audit_findings_severity ON audit_findings(severity);
CREATE INDEX IF NOT EXISTS idx_audit_findings_path     ON audit_findings(path);

CREATE TABLE IF NOT EXISTS change_log (
    id              TEXT PRIMARY KEY NOT NULL, -- UUID
    ts              TEXT NOT NULL,
    operator_uid    INTEGER NOT NULL,
    action          TEXT NOT NULL,   -- chmod | chown | chgrp
    target          TEXT NOT NULL,
    recursive       INTEGER NOT NULL DEFAULT 0,
    dry_run         INTEGER NOT NULL DEFAULT 0,
    elevated        INTEGER NOT NULL DEFAULT 0,
    old_mode        TEXT,
    new_mode        TEXT,
    old_owner       TEXT,
    new_owner       TEXT,
    result          TEXT NOT NULL,   -- success | failure
    paths_affected  INTEGER NOT NULL DEFAULT 0,
    error_msg       TEXT
);
