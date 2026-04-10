use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use anyhow::Result;
use perms_core::domain::UserDb;

// ── Persisted settings ────────────────────────────────────────────────────────

fn serde_default_roots() -> String {
    "/home,/etc".to_string()
}
fn serde_default_max_findings() -> usize {
    50
}
fn serde_default_theme_preset() -> String {
    "system".to_string()
}
fn serde_default_custom_theme_name() -> String {
    "Custom".to_string()
}
fn serde_default_custom_accent() -> String {
    "#7cc6ff".to_string()
}
fn serde_default_custom_success() -> String {
    "#73d98c".to_string()
}
fn serde_default_custom_warning() -> String {
    "#ffcc66".to_string()
}
fn serde_default_custom_danger() -> String {
    "#ff7a7a".to_string()
}
fn serde_default_custom_neutral() -> String {
    "#9fb0c2".to_string()
}
fn serde_default_custom_surface() -> String {
    "#111827".to_string()
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Settings {
    #[serde(default = "serde_default_roots")]
    pub default_roots: String,
    #[serde(default)]
    pub follow_symlinks: bool,
    #[serde(default)]
    pub skip_hidden: bool,
    #[serde(default = "serde_default_max_findings")]
    pub max_findings: usize,
    #[serde(default = "serde_default_theme_preset")]
    pub theme_preset: String,
    #[serde(default = "serde_default_custom_theme_name")]
    pub custom_theme_name: String,
    #[serde(default = "serde_default_custom_accent")]
    pub custom_accent: String,
    #[serde(default = "serde_default_custom_success")]
    pub custom_success: String,
    #[serde(default = "serde_default_custom_warning")]
    pub custom_warning: String,
    #[serde(default = "serde_default_custom_danger")]
    pub custom_danger: String,
    #[serde(default = "serde_default_custom_neutral")]
    pub custom_neutral: String,
    #[serde(default = "serde_default_custom_surface")]
    pub custom_surface: String,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            default_roots: serde_default_roots(),
            follow_symlinks: false,
            skip_hidden: false,
            max_findings: serde_default_max_findings(),
            theme_preset: serde_default_theme_preset(),
            custom_theme_name: serde_default_custom_theme_name(),
            custom_accent: serde_default_custom_accent(),
            custom_success: serde_default_custom_success(),
            custom_warning: serde_default_custom_warning(),
            custom_danger: serde_default_custom_danger(),
            custom_neutral: serde_default_custom_neutral(),
            custom_surface: serde_default_custom_surface(),
        }
    }
}

impl Settings {
    pub fn load() -> Self {
        let path = Self::file_path();
        if let Ok(text) = std::fs::read_to_string(&path) {
            if let Ok(s) = serde_json::from_str::<Settings>(&text) {
                return s;
            }
        }
        Self::default()
    }

    pub fn save(&self) {
        let path = Self::file_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        if let Ok(json) = serde_json::to_string_pretty(self) {
            std::fs::write(&path, json).ok();
        }
    }

    fn file_path() -> PathBuf {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        PathBuf::from(home).join(".local/share/perms/settings.json")
    }
}

/// Summary data collected during a filesystem scan, passed to dashboard widgets.
#[derive(Default, Clone)]
pub struct ScanSummary {
    pub total_entries: usize,
    /// Up to 20 world-writable paths found.
    pub world_writable: Vec<String>,
    /// Count of entries with extended POSIX ACLs.
    pub acl_count: usize,
    /// Up to 100 paths with extended POSIX ACLs found during the scan.
    pub acl_paths: Vec<String>,
    /// Up to 20 sensitive paths found (e.g. /etc, /root, /boot).
    pub sensitive_paths: Vec<String>,
    pub findings_critical: usize,
    pub findings_high: usize,
    pub findings_medium: usize,
    pub findings_low: usize,
    pub findings_info: usize,
    /// Up to 50 most recent audit findings: (severity, rule_id, path).
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
    pub settings: Settings,
}

impl AppState {
    pub fn load() -> Self {
        let userdb = UserDb::load().unwrap_or_else(|_| UserDb::from_str("", ""));
        let privilege = PrivilegeLevel::detect();
        let settings = Settings::load();
        Self {
            privilege,
            userdb,
            scan_roots: Vec::new(),
            scan_summary: None,
            settings,
        }
    }
}

pub type SharedState = Arc<Mutex<AppState>>;

pub fn new_shared() -> SharedState {
    Arc::new(Mutex::new(AppState::load()))
}

pub fn reload_userdb(state: &SharedState) -> Result<()> {
    let userdb = UserDb::load()?;
    state.lock().unwrap().userdb = userdb;
    Ok(())
}
