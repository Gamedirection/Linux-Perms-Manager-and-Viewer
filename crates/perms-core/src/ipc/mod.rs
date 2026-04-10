//! Shared IPC protocol types used by both `perms-ui` (client) and
//! `perms-helper` (server). The helper listens on a Unix socket and
//! deserialises these types from JSON Lines.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

// ── Request ───────────────────────────────────────────────────────────────────

/// A single permission-change operation requested by the UI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangeRequest {
    /// Target path.
    pub path: PathBuf,
    /// New mode bits (e.g. 0o755). `None` means do not change mode.
    pub new_mode: Option<u32>,
    /// New owner UID. `None` means do not change owner.
    pub new_uid: Option<u32>,
    /// New group GID. `None` means do not change group.
    pub new_gid: Option<u32>,
    /// Apply recursively to all children.
    pub recursive: bool,
    /// Compute diff only — do not write any changes.
    pub dry_run: bool,
}

// ── Result ────────────────────────────────────────────────────────────────────

/// Outcome for one path after applying a `ChangeRequest`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangeResult {
    pub path: PathBuf,
    /// Mode before the change (as an octal string like "0644").
    pub old_mode: Option<String>,
    /// Mode after the change (or what it would have been in dry-run).
    pub new_mode: Option<String>,
    pub old_uid: Option<u32>,
    pub new_uid: Option<u32>,
    pub old_gid: Option<u32>,
    pub new_gid: Option<u32>,
    /// `true` if the change was actually written (false for dry-run or error).
    pub applied: bool,
    /// Error message, if any.
    pub error: Option<String>,
}

impl ChangeResult {
    pub fn ok(
        path: PathBuf,
        old_mode: Option<String>,
        new_mode: Option<String>,
        old_uid: Option<u32>,
        new_uid: Option<u32>,
        old_gid: Option<u32>,
        new_gid: Option<u32>,
        applied: bool,
    ) -> Self {
        Self {
            path,
            old_mode,
            new_mode,
            old_uid,
            new_uid,
            old_gid,
            new_gid,
            applied,
            error: None,
        }
    }

    pub fn err(path: PathBuf, message: impl Into<String>) -> Self {
        Self {
            path,
            old_mode: None,
            new_mode: None,
            old_uid: None,
            new_uid: None,
            old_gid: None,
            new_gid: None,
            applied: false,
            error: Some(message.into()),
        }
    }
}

// ── Audit log entry ───────────────────────────────────────────────────────────

/// One line in the JSON Lines audit log at `~/.local/share/perms/changes.log`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// ISO-8601 timestamp.
    pub ts: String,
    pub path: PathBuf,
    pub old_mode: Option<String>,
    pub new_mode: Option<String>,
    pub old_uid: Option<u32>,
    pub new_uid: Option<u32>,
    pub old_gid: Option<u32>,
    pub new_gid: Option<u32>,
    pub recursive: bool,
    pub dry_run: bool,
    /// UID of the process that performed the change.
    pub effective_uid: u32,
    pub result: String,
}
