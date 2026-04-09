use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use perms_core::domain::UserDb;

/// Summary data collected during a filesystem scan, passed to dashboard widgets.
#[derive(Default, Clone)]
pub struct ScanSummary {
    pub total_entries: usize,
    /// Up to 20 world-writable paths found.
    pub world_writable: Vec<String>,
    /// Count of entries with extended POSIX ACLs.
    pub acl_count: usize,
    /// Up to 20 sensitive paths found (e.g. /etc, /root, /boot).
    pub sensitive_paths: Vec<String>,
    pub findings_critical: usize,
    pub findings_high: usize,
    pub findings_medium: usize,
    pub findings_low: usize,
    pub findings_info: usize,
    /// Up to 30 most recent audit findings: (severity, rule_id, path).
    pub recent_findings: Vec<(String, String, String)>,
    /// Top 10 file owners by entry count: (username, count).
    pub top_owners: Vec<(String, usize)>,
    pub scan_roots_used: Vec<String>,
}

/// Privilege level detected at startup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum PrivilegeLevel {
    /// Running as root directly (warning state).
    Root,
    /// Helper process is active and authenticated.
    Elevated,
    /// No elevation; partial visibility only.
    Unprivileged,
}

impl PrivilegeLevel {
    pub fn label(&self) -> &'static str {
        match self {
            PrivilegeLevel::Root => "Running as Root",
            PrivilegeLevel::Elevated => "Elevated",
            PrivilegeLevel::Unprivileged => "Unprivileged",
        }
    }

    pub fn css_class(&self) -> &'static str {
        match self {
            PrivilegeLevel::Root => "privilege-root",
            PrivilegeLevel::Elevated => "privilege-elevated",
            PrivilegeLevel::Unprivileged => "privilege-limited",
        }
    }

    pub fn detect() -> Self {
        if nix::unistd::geteuid().is_root() {
            PrivilegeLevel::Root
        } else {
            PrivilegeLevel::Unprivileged
        }
    }
}

/// Central shared state, wrapped in Arc<Mutex<>> for multi-thread access.
pub struct AppState {
    pub privilege: PrivilegeLevel,
    pub userdb: UserDb,
    #[allow(dead_code)]
    pub scan_roots: Vec<PathBuf>,
    /// Populated after a dashboard scan completes.
    pub scan_summary: Option<ScanSummary>,
}

impl AppState {
    pub fn load() -> Self {
        let userdb = UserDb::load().unwrap_or_else(|_| UserDb::from_str("", ""));
        let privilege = PrivilegeLevel::detect();
        Self {
            privilege,
            userdb,
            scan_roots: Vec::new(),
            scan_summary: None,
        }
    }
}

pub type SharedState = Arc<Mutex<AppState>>;

pub fn new_shared() -> SharedState {
    Arc::new(Mutex::new(AppState::load()))
}
