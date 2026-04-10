use crate::domain::path_entry::{EntryType, PathEntry};

use super::{AuditContext, AuditFinding, AuditRule, Severity};

/// Build the default MVP ruleset.
pub fn default_rules() -> Vec<Box<dyn AuditRule>> {
    vec![
        Box::new(WorldWritableDir),
        Box::new(WorldWritableFile),
        Box::new(UnexpectedSuid),
        Box::new(UnexpectedSgid),
        Box::new(OrphanedUid),
        Box::new(OrphanedGid),
        Box::new(WritableSystemPath),
        Box::new(HomeOtherReadable),
        Box::new(ExecutableWritableByNonAdmin),
    ]
}

// ── Rule: world-writable directory ───────────────────────────────────────────

pub struct WorldWritableDir;

impl AuditRule for WorldWritableDir {
    fn id(&self) -> &'static str {
        "world-writable-dir"
    }
    fn name(&self) -> &'static str {
        "World-Writable Directory"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }

    fn check(&self, entry: &PathEntry, _ctx: &AuditContext<'_>) -> Option<AuditFinding> {
        if entry.entry_type != EntryType::Directory {
            return None;
        }
        if !entry.mode.is_world_writable() {
            return None;
        }
        // Sticky bit mitigates risk (e.g. /tmp) — downgrade to High
        let severity = if entry.special_bits.sticky {
            Severity::High
        } else {
            Severity::Critical
        };
        Some(AuditFinding {
            rule_id: self.id(),
            severity,
            path: entry.path.clone(),
            description: format!(
                "Directory is world-writable (mode {}{})",
                entry.mode.to_octal(),
                if entry.special_bits.sticky {
                    ", sticky bit set"
                } else {
                    ""
                }
            ),
            recommendation: "Remove world-write permission unless intentional (e.g. /tmp). \
                If shared scratch space, ensure sticky bit is set."
                .into(),
        })
    }
}

// ── Rule: world-writable file ─────────────────────────────────────────────────

pub struct WorldWritableFile;

impl AuditRule for WorldWritableFile {
    fn id(&self) -> &'static str {
        "world-writable-file"
    }
    fn name(&self) -> &'static str {
        "World-Writable File"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }

    fn check(&self, entry: &PathEntry, _ctx: &AuditContext<'_>) -> Option<AuditFinding> {
        if entry.entry_type != EntryType::File {
            return None;
        }
        if !entry.mode.is_world_writable() {
            return None;
        }
        Some(AuditFinding {
            rule_id: self.id(),
            severity: self.severity(),
            path: entry.path.clone(),
            description: format!("File is world-writable (mode {})", entry.mode.to_octal()),
            recommendation: "Remove world-write permission. Files writable by all users are a \
                common vector for privilege escalation or data tampering."
                .into(),
        })
    }
}

// ── Rule: unexpected SUID ─────────────────────────────────────────────────────

/// Known-safe SUID binaries — extend this list as needed.
const KNOWN_SUID: &[&str] = &[
    "/usr/bin/sudo",
    "/usr/bin/su",
    "/usr/bin/passwd",
    "/usr/bin/newgrp",
    "/usr/bin/gpasswd",
    "/usr/bin/chsh",
    "/usr/bin/chfn",
    "/usr/lib/openssh/ssh-keysign",
    "/usr/libexec/ssh-keysign",
    "/bin/su",
    "/bin/sudo",
    "/usr/sbin/unix_chkpwd",
    "/sbin/unix_chkpwd",
];

pub struct UnexpectedSuid;

impl AuditRule for UnexpectedSuid {
    fn id(&self) -> &'static str {
        "suid-unexpected"
    }
    fn name(&self) -> &'static str {
        "Unexpected SUID Binary"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }

    fn check(&self, entry: &PathEntry, _ctx: &AuditContext<'_>) -> Option<AuditFinding> {
        if !entry.special_bits.setuid {
            return None;
        }
        let path_str = entry.path.to_string_lossy();
        if KNOWN_SUID.iter().any(|known| path_str == *known) {
            return None;
        }
        Some(AuditFinding {
            rule_id: self.id(),
            severity: self.severity(),
            path: entry.path.clone(),
            description: format!(
                "Unexpected SUID binary (mode {}): not in known-safe allowlist",
                entry.mode.to_octal()
            ),
            recommendation: "Verify this SUID binary is intentional. Remove the setuid bit if \
                the elevated execution is not required. SUID binaries run as the \
                file owner (often root) regardless of who executes them."
                .into(),
        })
    }
}

// ── Rule: unexpected SGID ─────────────────────────────────────────────────────

const KNOWN_SGID: &[&str] = &[
    "/usr/bin/write",
    "/usr/bin/wall",
    "/usr/bin/ssh-agent",
    "/usr/lib/openssh/ssh-keysign",
    "/usr/bin/crontab",
    "/usr/sbin/sendmail",
    "/var/mail",
];

pub struct UnexpectedSgid;

impl AuditRule for UnexpectedSgid {
    fn id(&self) -> &'static str {
        "sgid-unexpected"
    }
    fn name(&self) -> &'static str {
        "Unexpected SGID Binary or Directory"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn check(&self, entry: &PathEntry, _ctx: &AuditContext<'_>) -> Option<AuditFinding> {
        if !entry.special_bits.setgid {
            return None;
        }
        let path_str = entry.path.to_string_lossy();
        if KNOWN_SGID.iter().any(|known| path_str == *known) {
            return None;
        }
        // SGID on directories is common and usually intentional (group inheritance).
        // Only flag files.
        if entry.entry_type == EntryType::Directory {
            return None;
        }
        Some(AuditFinding {
            rule_id: self.id(),
            severity: self.severity(),
            path: entry.path.clone(),
            description: format!(
                "Unexpected SGID file (mode {}): not in known-safe allowlist",
                entry.mode.to_octal()
            ),
            recommendation: "Verify this SGID binary is intentional. Remove the setgid bit \
                if group-elevated execution is not required."
                .into(),
        })
    }
}

// ── Rule: orphaned UID ────────────────────────────────────────────────────────

pub struct OrphanedUid;

impl AuditRule for OrphanedUid {
    fn id(&self) -> &'static str {
        "orphaned-uid"
    }
    fn name(&self) -> &'static str {
        "Orphaned UID Ownership"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn check(&self, entry: &PathEntry, ctx: &AuditContext<'_>) -> Option<AuditFinding> {
        if ctx.userdb.uid_known(entry.owner_uid) {
            return None;
        }
        Some(AuditFinding {
            rule_id: self.id(),
            severity: self.severity(),
            path: entry.path.clone(),
            description: format!(
                "File owned by UID {} which has no corresponding /etc/passwd entry",
                entry.owner_uid
            ),
            recommendation: "This file may be left over from a deleted user account. \
                Assign ownership to an active account or remove the file \
                if it is no longer needed."
                .into(),
        })
    }
}

// ── Rule: orphaned GID ────────────────────────────────────────────────────────

pub struct OrphanedGid;

impl AuditRule for OrphanedGid {
    fn id(&self) -> &'static str {
        "orphaned-gid"
    }
    fn name(&self) -> &'static str {
        "Orphaned GID Ownership"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn check(&self, entry: &PathEntry, ctx: &AuditContext<'_>) -> Option<AuditFinding> {
        if ctx.userdb.gid_known(entry.owner_gid) {
            return None;
        }
        Some(AuditFinding {
            rule_id: self.id(),
            severity: self.severity(),
            path: entry.path.clone(),
            description: format!(
                "File owned by GID {} which has no corresponding /etc/group entry",
                entry.owner_gid
            ),
            recommendation: "This file may be left over from a deleted group. \
                Assign group ownership to an active group or remove the file."
                .into(),
        })
    }
}

// ── Rule: writable system path ────────────────────────────────────────────────

const SYSTEM_PATHS: &[&str] = &[
    "/etc",
    "/usr/bin",
    "/usr/lib",
    "/usr/sbin",
    "/sbin",
    "/bin",
    "/usr/libexec",
    "/lib",
    "/lib64",
    "/usr/lib64",
];

pub struct WritableSystemPath;

impl AuditRule for WritableSystemPath {
    fn id(&self) -> &'static str {
        "writable-system-path"
    }
    fn name(&self) -> &'static str {
        "Writable System Path"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }

    fn check(&self, entry: &PathEntry, _ctx: &AuditContext<'_>) -> Option<AuditFinding> {
        let path_str = entry.path.to_string_lossy();
        let is_system = SYSTEM_PATHS
            .iter()
            .any(|sys| path_str == *sys || path_str.starts_with(&format!("{sys}/")));
        if !is_system {
            return None;
        }
        // Flag if any non-root principal has write access.
        let owner_can_write = entry.mode.owner_bits() & 0o2 != 0 && entry.owner_uid != 0;
        let group_can_write = entry.mode.group_bits() & 0o2 != 0 && entry.owner_gid != 0;
        let world_can_write = entry.mode.is_world_writable();
        if !owner_can_write && !group_can_write && !world_can_write {
            return None;
        }
        Some(AuditFinding {
            rule_id: self.id(),
            severity: self.severity(),
            path: entry.path.clone(),
            description: format!(
                "System path is writable by non-root principal (mode {})",
                entry.mode.to_octal()
            ),
            recommendation: "System directories and binaries should only be writable by root. \
                Remove write permissions from group and other, and ensure the \
                owner is root."
                .into(),
        })
    }
}

// ── Rule: home directory readable by others ───────────────────────────────────

pub struct HomeOtherReadable;

impl AuditRule for HomeOtherReadable {
    fn id(&self) -> &'static str {
        "home-other-readable"
    }
    fn name(&self) -> &'static str {
        "Home Directory Readable by Others"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }

    fn check(&self, entry: &PathEntry, ctx: &AuditContext<'_>) -> Option<AuditFinding> {
        if entry.entry_type != EntryType::Directory {
            return None;
        }
        let path_str = entry.path.to_string_lossy();
        if !path_str.starts_with("/home/") {
            return None;
        }
        // Only check the home directory itself, not subdirectories
        let components: Vec<_> = entry.path.components().collect();
        if components.len() != 3 {
            return None; // /home/<user> has exactly 3 components
        }
        if !entry.mode.is_world_readable() && entry.mode.group_bits() & 0o4 == 0 {
            return None;
        }
        let owner_name = ctx
            .userdb
            .user_by_uid(entry.owner_uid)
            .map(|u| u.username.as_str())
            .unwrap_or("unknown");
        Some(AuditFinding {
            rule_id: self.id(),
            severity: self.severity(),
            path: entry.path.clone(),
            description: format!(
                "Home directory of '{}' is readable by other users (mode {})",
                owner_name,
                entry.mode.to_octal()
            ),
            recommendation: "Set home directory permissions to 0700 or 0750 (owner-only or \
                owner+group). World-readable home directories expose files to \
                all local users."
                .into(),
        })
    }
}

// ── Rule: executable file writable by non-admin ───────────────────────────────

pub struct ExecutableWritableByNonAdmin;

impl AuditRule for ExecutableWritableByNonAdmin {
    fn id(&self) -> &'static str {
        "executable-writable-non-admin"
    }
    fn name(&self) -> &'static str {
        "Executable Writable by Non-Admin"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }

    fn check(&self, entry: &PathEntry, _ctx: &AuditContext<'_>) -> Option<AuditFinding> {
        if entry.entry_type != EntryType::File {
            return None;
        }
        // Is it executable by anyone?
        let executable =
            (entry.mode.owner_bits() | entry.mode.group_bits() | entry.mode.other_bits()) & 0o1
                != 0;
        if !executable {
            return None;
        }
        // Is it writable by group or other (non-owner)?
        let group_writable = entry.mode.group_bits() & 0o2 != 0;
        let world_writable = entry.mode.is_world_writable();
        if !group_writable && !world_writable {
            return None;
        }
        // Only flag if the owner is not root (root-owned executables are expected to be group/world writable sometimes)
        if entry.owner_uid == 0 && !world_writable {
            return None;
        }
        Some(AuditFinding {
            rule_id: self.id(),
            severity: self.severity(),
            path: entry.path.clone(),
            description: format!(
                "Executable file is writable by non-owner (mode {}): \
                an attacker could replace it with malicious code",
                entry.mode.to_octal()
            ),
            recommendation:
                "Remove write permissions from group and/or other on executable files. \
                Executables should only be writable by their owner."
                    .into(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::path_entry::{EntryType, PathEntry, ScanSource, SpecialBits};
    use crate::domain::permission::UnixMode;
    use crate::domain::userdb::UserDb;
    use chrono::Utc;
    use std::path::PathBuf;

    fn entry(path: &str, mode: u32, uid: u32, gid: u32, etype: EntryType) -> PathEntry {
        PathEntry {
            path: PathBuf::from(path),
            entry_type: etype,
            owner_uid: uid,
            owner_gid: gid,
            mode: UnixMode(mode),
            acl: None,
            special_bits: SpecialBits::from_mode(mode),
            scan_time: Utc::now(),
            scan_source: ScanSource::Full,
            is_mount_point: false,
            sensitive_label: None,
            size_bytes: 0,
        }
    }

    fn db() -> UserDb {
        UserDb::from_str(
            "alice:x:1000:1000::/home/alice:/bin/bash\nroot:x:0:0::/root:/bin/bash\n",
            "alice:x:1000:\nroot:x:0:\n",
        )
    }

    fn ctx(db: &UserDb) -> AuditContext<'_> {
        AuditContext { userdb: db }
    }

    #[test]
    fn world_writable_dir_critical() {
        let db = db();
        let e = entry("/srv/shared", 0o777, 0, 0, EntryType::Directory);
        let finding = WorldWritableDir.check(&e, &ctx(&db)).unwrap();
        assert_eq!(finding.severity, Severity::Critical);
    }

    #[test]
    fn world_writable_dir_sticky_is_high() {
        let db = db();
        let e = entry("/tmp", 0o1777, 0, 0, EntryType::Directory);
        let finding = WorldWritableDir.check(&e, &ctx(&db)).unwrap();
        assert_eq!(finding.severity, Severity::High);
    }

    #[test]
    fn world_writable_file_flagged() {
        let db = db();
        let e = entry("/tmp/script.sh", 0o777, 1000, 1000, EntryType::File);
        assert!(WorldWritableFile.check(&e, &ctx(&db)).is_some());
    }

    #[test]
    fn suid_known_safe_not_flagged() {
        let db = db();
        let e = entry("/usr/bin/sudo", 0o4755, 0, 0, EntryType::File);
        assert!(UnexpectedSuid.check(&e, &ctx(&db)).is_none());
    }

    #[test]
    fn suid_unexpected_flagged() {
        let db = db();
        let e = entry("/home/alice/myprog", 0o4755, 1000, 1000, EntryType::File);
        assert!(UnexpectedSuid.check(&e, &ctx(&db)).is_some());
    }

    #[test]
    fn orphaned_uid_flagged() {
        let db = db();
        let e = entry("/var/data/file", 0o644, 9999, 0, EntryType::File);
        assert!(OrphanedUid.check(&e, &ctx(&db)).is_some());
    }

    #[test]
    fn orphaned_uid_known_not_flagged() {
        let db = db();
        let e = entry("/home/alice/file", 0o644, 1000, 1000, EntryType::File);
        assert!(OrphanedUid.check(&e, &ctx(&db)).is_none());
    }

    #[test]
    fn system_path_writable_by_group_flagged() {
        let db = db();
        // group can write to /usr/bin
        let e = entry("/usr/bin/mytool", 0o775, 0, 1000, EntryType::File);
        assert!(WritableSystemPath.check(&e, &ctx(&db)).is_some());
    }

    #[test]
    fn system_path_root_only_not_flagged() {
        let db = db();
        let e = entry("/usr/bin/ls", 0o755, 0, 0, EntryType::File);
        assert!(WritableSystemPath.check(&e, &ctx(&db)).is_none());
    }

    #[test]
    fn home_world_readable_flagged() {
        let db = db();
        let e = entry("/home/alice", 0o755, 1000, 1000, EntryType::Directory);
        assert!(HomeOtherReadable.check(&e, &ctx(&db)).is_some());
    }

    #[test]
    fn home_700_not_flagged() {
        let db = db();
        let e = entry("/home/alice", 0o700, 1000, 1000, EntryType::Directory);
        assert!(HomeOtherReadable.check(&e, &ctx(&db)).is_none());
    }

    #[test]
    fn home_subdir_not_flagged() {
        let db = db();
        // /home/alice/projects is a subdir, not the home dir itself
        let e = entry(
            "/home/alice/projects",
            0o755,
            1000,
            1000,
            EntryType::Directory,
        );
        assert!(HomeOtherReadable.check(&e, &ctx(&db)).is_none());
    }
}
