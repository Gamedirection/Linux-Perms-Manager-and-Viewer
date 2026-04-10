use std::path::Path;

use anyhow::Result;
use rusqlite::{Connection, params};

use crate::domain::path_entry::PathEntry;

pub const SCHEMA_VERSION: u32 = 1;

/// Open (or create) the SQLite index at the given path and apply migrations.
pub fn open(path: &Path) -> Result<Connection> {
    let conn = Connection::open(path)?;
    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")?;
    migrate(&conn)?;
    Ok(conn)
}

fn migrate(conn: &Connection) -> Result<()> {
    conn.execute_batch("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL);")?;

    let version: u32 = conn
        .query_row("SELECT version FROM schema_version LIMIT 1", [], |r| {
            r.get(0)
        })
        .unwrap_or(0);

    if version < SCHEMA_VERSION {
        conn.execute_batch(include_str!("schema_v1.sql"))?;
        if version == 0 {
            conn.execute("INSERT INTO schema_version VALUES (?1)", [SCHEMA_VERSION])?;
        } else {
            conn.execute("UPDATE schema_version SET version = ?1", [SCHEMA_VERSION])?;
        }
    }

    Ok(())
}

/// Insert a batch of `PathEntry` records in a single transaction.
///
/// Existing rows are replaced (UPSERT by path). This lets re-scans update
/// stale entries efficiently.
pub fn insert_entries(conn: &Connection, entries: &[PathEntry]) -> Result<usize> {
    use serde_json;

    let tx = conn.unchecked_transaction()?;
    let mut inserted = 0usize;

    {
        let mut stmt = tx.prepare_cached(
            "INSERT OR REPLACE INTO path_entries
             (path, entry_type, owner_uid, owner_gid, mode, has_acl, acl_json,
              special_bits, is_mount_point, size_bytes, scan_source, scanned_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
        )?;

        for entry in entries {
            let entry_type = format!("{:?}", entry.entry_type);
            let scan_source = format!("{:?}", entry.scan_source);
            let has_acl = entry.acl.as_ref().is_some_and(|a| a.has_extended_entries()) as i32;
            let acl_json = entry
                .acl
                .as_ref()
                .map(|a| serde_json::to_string(a).unwrap_or_default());

            let special = (entry.special_bits.setuid as u8)
                | ((entry.special_bits.setgid as u8) << 1)
                | ((entry.special_bits.sticky as u8) << 2);

            stmt.execute(params![
                entry.path.to_string_lossy().as_ref(),
                entry_type,
                entry.owner_uid,
                entry.owner_gid,
                entry.mode.0,
                has_acl,
                acl_json,
                special as i32,
                entry.is_mount_point as i32,
                entry.size_bytes as i64,
                scan_source,
                entry.scan_time.to_rfc3339(),
            ])?;
            inserted += 1;
        }
    }

    tx.commit()?;
    Ok(inserted)
}

/// Update or insert a scan root record.
pub fn upsert_scan_root(conn: &Connection, path: &Path, file_count: usize) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO scan_roots (path, last_full_scan, file_count)
         VALUES (?1, datetime('now'), ?2)",
        params![path.to_string_lossy().as_ref(), file_count as i64],
    )?;
    Ok(())
}

/// Count path entries in the index.
pub fn count_entries(conn: &Connection) -> Result<usize> {
    let n: i64 = conn.query_row("SELECT COUNT(*) FROM path_entries", [], |r| r.get(0))?;
    Ok(n as usize)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::path_entry::{EntryType, ScanSource, SpecialBits};
    use crate::domain::permission::UnixMode;
    use chrono::Utc;
    use tempfile::NamedTempFile;

    fn make_entry(path: &str, mode: u32, uid: u32, gid: u32) -> PathEntry {
        PathEntry {
            path: path.into(),
            entry_type: EntryType::Directory,
            owner_uid: uid,
            owner_gid: gid,
            mode: UnixMode(mode),
            acl: None,
            special_bits: SpecialBits::from_mode(mode),
            scan_time: Utc::now(),
            scan_source: ScanSource::Full,
            is_mount_point: false,
            sensitive_label: None,
            size_bytes: 4096,
        }
    }

    #[test]
    fn open_and_migrate() {
        let file = NamedTempFile::new().unwrap();
        let conn = open(file.path()).unwrap();
        let version: u32 = conn
            .query_row("SELECT version FROM schema_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);
    }

    #[test]
    fn insert_and_count() {
        let file = NamedTempFile::new().unwrap();
        let conn = open(file.path()).unwrap();

        let entries = vec![
            make_entry("/home/alice", 0o750, 1000, 1000),
            make_entry("/home/bob", 0o755, 1001, 1001),
        ];
        let inserted = insert_entries(&conn, &entries).unwrap();
        assert_eq!(inserted, 2);
        assert_eq!(count_entries(&conn).unwrap(), 2);
    }

    #[test]
    fn upsert_replaces_existing() {
        let file = NamedTempFile::new().unwrap();
        let conn = open(file.path()).unwrap();

        let e1 = make_entry("/home/alice", 0o750, 1000, 1000);
        insert_entries(&conn, &[e1]).unwrap();

        // Same path, different mode — should replace
        let e2 = make_entry("/home/alice", 0o700, 1000, 1000);
        insert_entries(&conn, &[e2]).unwrap();

        assert_eq!(count_entries(&conn).unwrap(), 1);
        let mode: i64 = conn
            .query_row(
                "SELECT mode FROM path_entries WHERE path = '/home/alice'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(mode as u32, 0o700);
    }
}
