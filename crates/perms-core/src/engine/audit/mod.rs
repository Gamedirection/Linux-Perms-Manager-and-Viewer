use serde::{Deserialize, Serialize};

use crate::domain::path_entry::PathEntry;
use crate::domain::userdb::UserDb;

pub mod rules;

// ── Finding types ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Info => write!(f, "Info"),
            Severity::Low => write!(f, "Low"),
            Severity::Medium => write!(f, "Medium"),
            Severity::High => write!(f, "High"),
            Severity::Critical => write!(f, "Critical"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditFinding {
    pub rule_id: &'static str,
    pub severity: Severity,
    pub path: std::path::PathBuf,
    pub description: String,
    pub recommendation: String,
}

// ── Rule trait ────────────────────────────────────────────────────────────────

pub struct AuditContext<'a> {
    pub userdb: &'a UserDb,
}

pub trait AuditRule: Send + Sync {
    fn id(&self) -> &'static str;
    fn name(&self) -> &'static str;
    fn severity(&self) -> Severity;
    fn check(&self, entry: &PathEntry, ctx: &AuditContext<'_>) -> Option<AuditFinding>;
}

// ── Engine ────────────────────────────────────────────────────────────────────

pub struct AuditEngine {
    rules: Vec<Box<dyn AuditRule>>,
}

impl AuditEngine {
    /// Create an engine with the default MVP ruleset.
    pub fn default_ruleset() -> Self {
        Self {
            rules: rules::default_rules(),
        }
    }

    pub fn with_rules(rules: Vec<Box<dyn AuditRule>>) -> Self {
        Self { rules }
    }

    /// Run all rules against a single entry, returning any findings.
    pub fn check(&self, entry: &PathEntry, ctx: &AuditContext<'_>) -> Vec<AuditFinding> {
        self.rules
            .iter()
            .filter_map(|r| r.check(entry, ctx))
            .collect()
    }

    /// Run all rules across a slice of entries.
    pub fn check_all(&self, entries: &[PathEntry], ctx: &AuditContext<'_>) -> Vec<AuditFinding> {
        entries.iter().flat_map(|e| self.check(e, ctx)).collect()
    }
}
