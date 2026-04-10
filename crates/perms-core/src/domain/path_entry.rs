use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::acl::AclSet;
use super::permission::UnixMode;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EntryType {
    Directory,
    File,
    Symlink,
    Other,
}

/// How was this entry scanned?
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScanSource {
    /// Full stat + xattr read, privileged or user-readable.
    Full,
    /// stat only, no ACL data (xattr unavailable or unreadable).
    Partial,
    /// Inferred from parent/sibling data; no direct stat.
    Estimated,
}

/// Built-in sensitivity classification for well-known paths.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SensitiveLabel {
    pub label: String,
    pub severity: SensitiveSeverity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SensitiveSeverity {
    Critical,
    High,
    Medium,
}

/// Special Unix mode bits beyond rwx.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct SpecialBits {
    pub setuid: bool,
    pub setgid: bool,
    pub sticky: bool,
}

impl SpecialBits {
    pub fn from_mode(mode: u32) -> Self {
        Self {
            setuid: mode & 0o4000 != 0,
            setgid: mode & 0o2000 != 0,
            sticky: mode & 0o1000 != 0,
        }
    }

    pub fn any(&self) -> bool {
        self.setuid || self.setgid || self.sticky
    }
}

/// A filesystem entry as recorded in the scan index.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathEntry {
    pub path: PathBuf,
    pub entry_type: EntryType,
    pub owner_uid: u32,
    pub owner_gid: u32,
    pub mode: UnixMode,
    pub acl: Option<AclSet>,
    pub special_bits: SpecialBits,
    pub scan_time: DateTime<Utc>,
    pub scan_source: ScanSource,
    pub is_mount_point: bool,
    pub sensitive_label: Option<SensitiveLabel>,
    pub size_bytes: u64,
}

impl PathEntry {
    pub fn is_dir(&self) -> bool {
        self.entry_type == EntryType::Directory
    }

    pub fn is_file(&self) -> bool {
        self.entry_type == EntryType::File
    }

    pub fn has_acl(&self) -> bool {
        self.acl.as_ref().is_some_and(|a| a.has_extended_entries())
    }

    pub fn is_world_writable(&self) -> bool {
        self.mode.is_world_writable()
    }

    pub fn is_sensitive(&self) -> bool {
        self.sensitive_label.is_some()
    }
}

/// Match a path against the built-in sensitive path table.
pub fn classify_sensitive(path: &PathBuf) -> Option<SensitiveLabel> {
    let s = path.to_string_lossy();
    let (label, severity) = if s == "/etc" || s.starts_with("/etc/") {
        ("System Configuration", SensitiveSeverity::High)
    } else if s == "/root" || s.starts_with("/root/") {
        ("Root Home", SensitiveSeverity::Critical)
    } else if s.starts_with("/var/shadow") || s == "/etc/shadow" {
        ("Shadow Passwords", SensitiveSeverity::Critical)
    } else if s == "/usr/bin" || s.starts_with("/usr/bin/") {
        ("System Binaries", SensitiveSeverity::High)
    } else if s == "/usr/lib" || s.starts_with("/usr/lib/") {
        ("System Libraries", SensitiveSeverity::High)
    } else if s == "/boot" || s.starts_with("/boot/") {
        ("Bootloader", SensitiveSeverity::Critical)
    } else if s == "/srv" || s.starts_with("/srv/") {
        ("Service Data", SensitiveSeverity::Medium)
    } else if s.starts_with("/home/") {
        ("User Home", SensitiveSeverity::Medium)
    } else {
        return None;
    };
    Some(SensitiveLabel {
        label: label.to_string(),
        severity,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn special_bits_from_mode() {
        let bits = SpecialBits::from_mode(0o4755);
        assert!(bits.setuid);
        assert!(!bits.setgid);
        assert!(!bits.sticky);

        let bits = SpecialBits::from_mode(0o1777);
        assert!(!bits.setuid);
        assert!(!bits.setgid);
        assert!(bits.sticky);
    }

    #[test]
    fn sensitive_classification() {
        assert!(classify_sensitive(&PathBuf::from("/etc/ssh")).is_some());
        assert!(classify_sensitive(&PathBuf::from("/root/.bashrc")).is_some());
        assert!(classify_sensitive(&PathBuf::from("/home/alice")).is_some());
        assert!(classify_sensitive(&PathBuf::from("/tmp")).is_none());
        assert!(classify_sensitive(&PathBuf::from("/usr/bin/sudo")).is_some());
    }
}
