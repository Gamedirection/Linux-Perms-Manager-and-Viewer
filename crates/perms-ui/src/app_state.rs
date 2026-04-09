use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use perms_core::domain::UserDb;

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
}

impl AppState {
    pub fn load() -> Self {
        let userdb = UserDb::load().unwrap_or_else(|_| UserDb::from_str("", ""));
        let privilege = PrivilegeLevel::detect();
        Self {
            privilege,
            userdb,
            scan_roots: Vec::new(),
        }
    }
}

pub type SharedState = Arc<Mutex<AppState>>;

pub fn new_shared() -> SharedState {
    Arc::new(Mutex::new(AppState::load()))
}
