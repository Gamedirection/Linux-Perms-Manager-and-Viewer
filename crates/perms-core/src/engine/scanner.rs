use anyhow::Result;
use chrono::Utc;
use nix::sys::stat::{SFlag, lstat};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use walkdir::WalkDir;

use crate::domain::acl::{AclEntry, AclSet, AclTag};
use crate::domain::path_entry::{
    EntryType, PathEntry, ScanSource, SpecialBits, classify_sensitive,
};
use crate::domain::permission::UnixMode;

/// Events emitted by the scanner to the UI.
#[derive(Debug)]
pub enum ScanEvent {
    Progress { scanned: usize, path: PathBuf },
    Entry(PathEntry),
    Error { path: PathBuf, message: String },
    Complete { total: usize },
    Cancelled,
}

/// Configuration for a scan run.
pub struct ScanConfig {
    pub roots: Vec<PathBuf>,
    /// Follow symlinks during traversal (false = safer default).
    pub follow_symlinks: bool,
    /// Skip hidden files/dirs (names starting with '.').
    pub skip_hidden: bool,
    /// Paths to exclude from traversal.
    pub exclude: Vec<PathBuf>,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            roots: Vec::new(),
            follow_symlinks: false,
            skip_hidden: false,
            exclude: Vec::new(),
        }
    }
}

/// Run a filesystem scan, sending events to `tx`.
///
/// The caller holds the receiver end. Send `true` to `cancel_rx` to abort.
/// The scan runs synchronously in the calling thread — callers should spawn
/// this on a dedicated thread.
pub fn run_scan(
    config: ScanConfig,
    tx: mpsc::Sender<ScanEvent>,
    cancel_rx: mpsc::Receiver<()>,
) -> Result<()> {
    let mut total = 0usize;

    for root in &config.roots {
        let walker = WalkDir::new(root)
            .follow_links(config.follow_symlinks)
            .same_file_system(true); // don't cross mount boundaries

        for entry in walker {
            // Check for cancellation without blocking.
            if cancel_rx.try_recv().is_ok() {
                let _ = tx.send(ScanEvent::Cancelled);
                return Ok(());
            }

            let dir_entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    let path = e.path().map(|p| p.to_path_buf()).unwrap_or_default();
                    let _ = tx.send(ScanEvent::Error {
                        path,
                        message: e.to_string(),
                    });
                    continue;
                }
            };

            let path = dir_entry.path().to_path_buf();

            // Apply exclusion list.
            if config.exclude.iter().any(|ex| path.starts_with(ex)) {
                continue;
            }

            // Skip hidden if configured.
            if config.skip_hidden {
                if let Some(name) = path.file_name() {
                    if name.to_string_lossy().starts_with('.') {
                        continue;
                    }
                }
            }

            match stat_entry(&path) {
                Ok(entry) => {
                    total += 1;
                    if total % 100 == 0 {
                        let _ = tx.send(ScanEvent::Progress {
                            scanned: total,
                            path: path.clone(),
                        });
                    }
                    let _ = tx.send(ScanEvent::Entry(entry));
                }
                Err(e) => {
                    let _ = tx.send(ScanEvent::Error {
                        path,
                        message: e.to_string(),
                    });
                }
            }
        }
    }

    let _ = tx.send(ScanEvent::Complete { total });
    Ok(())
}

/// Stat a single path and build a `PathEntry`.
/// Uses `lstat` — never follows symlinks.
pub fn stat_entry(path: &Path) -> Result<PathEntry> {
    let stat = lstat(path)?;
    let raw_mode = stat.st_mode;

    let entry_type = sflag_to_entry_type(SFlag::from_bits_truncate(raw_mode));
    let mode = UnixMode(raw_mode & 0o7777);
    let special_bits = SpecialBits::from_mode(raw_mode);
    let sensitive_label = classify_sensitive(&path.to_path_buf());

    let acl = read_acl(path);

    Ok(PathEntry {
        path: path.to_path_buf(),
        entry_type,
        owner_uid: stat.st_uid,
        owner_gid: stat.st_gid,
        mode,
        acl,
        special_bits,
        scan_time: Utc::now(),
        scan_source: ScanSource::Full,
        is_mount_point: false, // populated separately if needed
        sensitive_label,
        size_bytes: stat.st_size as u64,
    })
}

fn sflag_to_entry_type(flags: SFlag) -> EntryType {
    if flags.contains(SFlag::S_IFDIR) {
        EntryType::Directory
    } else if flags.contains(SFlag::S_IFREG) {
        EntryType::File
    } else if flags.contains(SFlag::S_IFLNK) {
        EntryType::Symlink
    } else {
        EntryType::Other
    }
}

// ── POSIX ACL reading via getxattr ────────────────────────────────────────────
//
// Linux stores POSIX ACLs as a binary blob under two xattr keys:
//   system.posix_acl_access   — access ACL
//   system.posix_acl_default  — default ACL (directories only)
//
// Binary format (little-endian):
//   u32 version (must be 0x0002)
//   Repeated entries:
//     u16 tag
//     u16 perm  (bottom 3 bits: r=4, w=2, x=1)
//     u32 id    (UID for User, GID for Group; 0xFFFFFFFF for UserObj/GroupObj/etc.)
//
// Tag values:
//   0x0001 = ACL_USER_OBJ
//   0x0002 = ACL_USER
//   0x0004 = ACL_GROUP_OBJ
//   0x0008 = ACL_GROUP
//   0x0010 = ACL_MASK
//   0x0020 = ACL_OTHER

const XATTR_ACL_ACCESS: &str = "system.posix_acl_access";
const XATTR_ACL_DEFAULT: &str = "system.posix_acl_default";

const ACL_VERSION: u32 = 0x0002;

const TAG_USER_OBJ: u16 = 0x0001;
const TAG_USER: u16 = 0x0002;
const TAG_GROUP_OBJ: u16 = 0x0004;
const TAG_GROUP: u16 = 0x0008;
const TAG_MASK: u16 = 0x0010;
const TAG_OTHER: u16 = 0x0020;

fn read_acl(path: &Path) -> Option<AclSet> {
    let access_bytes = getxattr(path, XATTR_ACL_ACCESS)?;
    let access_entries = parse_acl_blob(&access_bytes)?;

    let default_entries = getxattr(path, XATTR_ACL_DEFAULT)
        .and_then(|b| parse_acl_blob(&b))
        .unwrap_or_default();

    let mask = access_entries
        .iter()
        .find(|e| e.tag == AclTag::Mask)
        .map(|e| e.permissions);

    // Apply mask to compute effective permissions for User and Group entries.
    let access_entries = access_entries
        .into_iter()
        .map(|mut e| {
            e.effective = match &e.tag {
                AclTag::User(_) | AclTag::GroupObj | AclTag::Group(_) => {
                    mask.map(|m| e.permissions & m).unwrap_or(e.permissions)
                }
                _ => e.permissions,
            };
            e
        })
        .collect();

    Some(AclSet {
        access_entries,
        default_entries,
        mask,
    })
}

fn getxattr(path: &Path, name: &str) -> Option<Vec<u8>> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let path_cstr = CString::new(path.as_os_str().as_bytes()).ok()?;
    let name_cstr = CString::new(name).ok()?;

    // First call: get size
    let size = unsafe {
        libc_getxattr(
            path_cstr.as_ptr(),
            name_cstr.as_ptr(),
            std::ptr::null_mut(),
            0,
        )
    };
    if size <= 0 {
        return None;
    }

    let mut buf = vec![0u8; size as usize];
    let read = unsafe {
        libc_getxattr(
            path_cstr.as_ptr(),
            name_cstr.as_ptr(),
            buf.as_mut_ptr() as *mut libc::c_void,
            size as libc::size_t,
        )
    };
    if read <= 0 {
        return None;
    }
    buf.truncate(read as usize);
    Some(buf)
}

// Thin wrapper so we can mock in tests without pulling in the full libc crate.
unsafe fn libc_getxattr(
    path: *const libc::c_char,
    name: *const libc::c_char,
    value: *mut libc::c_void,
    size: libc::size_t,
) -> libc::ssize_t {
    unsafe { libc::getxattr(path, name, value, size) }
}

fn parse_acl_blob(blob: &[u8]) -> Option<Vec<AclEntry>> {
    if blob.len() < 4 {
        return None;
    }
    let version = u32::from_le_bytes(blob[0..4].try_into().ok()?);
    if version != ACL_VERSION {
        return None;
    }

    let mut entries = Vec::new();
    let mut offset = 4usize;

    while offset + 8 <= blob.len() {
        let tag = u16::from_le_bytes(blob[offset..offset + 2].try_into().ok()?);
        let perm = u16::from_le_bytes(blob[offset + 2..offset + 4].try_into().ok()?);
        let id = u32::from_le_bytes(blob[offset + 4..offset + 8].try_into().ok()?);
        offset += 8;

        let permissions = (perm & 0o7) as u8;
        let acl_tag = match tag {
            TAG_USER_OBJ => AclTag::UserObj,
            TAG_USER => AclTag::User(id),
            TAG_GROUP_OBJ => AclTag::GroupObj,
            TAG_GROUP => AclTag::Group(id),
            TAG_MASK => AclTag::Mask,
            TAG_OTHER => AclTag::Other,
            _ => continue, // unknown tag, skip
        };

        entries.push(AclEntry {
            tag: acl_tag,
            permissions,
            effective: permissions, // mask applied after full parse
        });
    }

    Some(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal ACL blob for testing the parser.
    fn acl_blob(entries: &[(u16, u8, u32)]) -> Vec<u8> {
        let mut blob = Vec::new();
        blob.extend_from_slice(&ACL_VERSION.to_le_bytes());
        for (tag, perm, id) in entries {
            blob.extend_from_slice(&tag.to_le_bytes());
            blob.extend_from_slice(&(*perm as u16).to_le_bytes());
            blob.extend_from_slice(&id.to_le_bytes());
        }
        blob
    }

    #[test]
    fn parses_minimal_acl() {
        let blob = acl_blob(&[
            (TAG_USER_OBJ, 0o7, 0xFFFFFFFF),
            (TAG_GROUP_OBJ, 0o5, 0xFFFFFFFF),
            (TAG_OTHER, 0o0, 0xFFFFFFFF),
        ]);
        let entries = parse_acl_blob(&blob).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].tag, AclTag::UserObj);
        assert_eq!(entries[0].permissions, 0o7);
    }

    #[test]
    fn parses_extended_acl_with_named_user() {
        let blob = acl_blob(&[
            (TAG_USER_OBJ, 0o7, 0xFFFFFFFF),
            (TAG_USER, 0o6, 1001),
            (TAG_GROUP_OBJ, 0o5, 0xFFFFFFFF),
            (TAG_MASK, 0o5, 0xFFFFFFFF),
            (TAG_OTHER, 0o0, 0xFFFFFFFF),
        ]);
        let entries = parse_acl_blob(&blob).unwrap();
        assert!(entries.iter().any(|e| e.tag == AclTag::User(1001)));
        let mask = entries.iter().find(|e| e.tag == AclTag::Mask).unwrap();
        assert_eq!(mask.permissions, 0o5);
    }

    #[test]
    fn rejects_wrong_version() {
        let mut blob = vec![0u8; 12];
        blob[0] = 0x01; // version 1, not 2
        assert!(parse_acl_blob(&blob).is_none());
    }

    #[test]
    fn stat_current_dir() {
        // Smoke test: stat this process's working directory.
        let result = stat_entry(Path::new("."));
        assert!(result.is_ok());
        let entry = result.unwrap();
        assert_eq!(entry.entry_type, EntryType::Directory);
    }
}
