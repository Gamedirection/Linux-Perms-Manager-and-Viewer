use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::domain::{PathEntry, UserDb};
use crate::engine::scanner::stat_entry;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshReviewFinding {
    pub path: PathBuf,
    pub title: String,
    pub severity: String,
    pub summary: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshReviewReport {
    pub findings: Vec<SshReviewFinding>,
    pub reviewed_paths: Vec<PathBuf>,
    pub notes: Vec<String>,
    pub privileged: bool,
}

pub fn generate_report() -> Result<SshReviewReport> {
    let userdb = UserDb::load().unwrap_or_else(|_| UserDb::from_str("", ""));
    let mut findings = Vec::new();
    let mut reviewed_paths = Vec::new();
    let mut notes = Vec::new();

    let mut candidate_dirs = vec![PathBuf::from("/etc/ssh")];
    for user in userdb.all_users() {
        candidate_dirs.push(user.home_dir.join(".ssh"));
    }
    candidate_dirs.sort();
    candidate_dirs.dedup();

    for dir in candidate_dirs {
        if !dir.exists() {
            continue;
        }
        reviewed_paths.push(dir.clone());
        review_ssh_tree(&dir, &mut findings, &mut notes);
    }

    Ok(SshReviewReport {
        findings,
        reviewed_paths,
        notes,
        privileged: nix::unistd::geteuid().is_root(),
    })
}

fn review_ssh_tree(dir: &Path, findings: &mut Vec<SshReviewFinding>, notes: &mut Vec<String>) {
    let root_entry = match stat_entry(dir) {
        Ok(entry) => entry,
        Err(err) => {
            notes.push(format!("Could not inspect {}: {err}", dir.display()));
            return;
        }
    };
    review_directory_permissions(&root_entry, findings);

    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.filter_map(|entry| entry.ok()) {
            let path = entry.path();
            let Ok(path_entry) = stat_entry(&path) else {
                continue;
            };

            if path_entry.is_dir() {
                review_directory_permissions(&path_entry, findings);
            } else {
                review_file_permissions(&path_entry, findings);
                review_ssh_config(&path_entry, findings, notes);
            }
        }
    }
}

fn review_directory_permissions(entry: &PathEntry, findings: &mut Vec<SshReviewFinding>) {
    let name = entry
        .path
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_else(|| entry.path.display().to_string());

    if name == ".ssh" && entry.mode.0 & 0o077 != 0 {
        findings.push(SshReviewFinding {
            path: entry.path.clone(),
            title: "User SSH directory is too open".to_string(),
            severity: "high".to_string(),
            summary: format!(
                "{} is mode {} and exposes user SSH material to group/other access.",
                entry.path.display(),
                entry.mode.to_octal()
            ),
            recommendation: "Restrict user SSH directories to 0700.".to_string(),
        });
    }
}

fn review_file_permissions(entry: &PathEntry, findings: &mut Vec<SshReviewFinding>) {
    let name = entry
        .path
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_default();
    let mode = entry.mode.0 & 0o777;

    if is_private_key_name(&name) && mode & 0o077 != 0 {
        findings.push(SshReviewFinding {
            path: entry.path.clone(),
            title: "Private SSH key is readable beyond the owner".to_string(),
            severity: "critical".to_string(),
            summary: format!(
                "{} is mode {}. Private keys should stay owner-only.",
                entry.path.display(),
                entry.mode.to_octal()
            ),
            recommendation: "Change private key permissions to 0600.".to_string(),
        });
    }

    if matches!(name.as_str(), "authorized_keys" | "config") && mode & 0o077 != 0 {
        findings.push(SshReviewFinding {
            path: entry.path.clone(),
            title: "Sensitive SSH file is too permissive".to_string(),
            severity: "high".to_string(),
            summary: format!(
                "{} is mode {} and should not be group/other accessible.",
                entry.path.display(),
                entry.mode.to_octal()
            ),
            recommendation: "Restrict the file to 0600.".to_string(),
        });
    }

    if name == "known_hosts" && mode & 0o002 != 0 {
        findings.push(SshReviewFinding {
            path: entry.path.clone(),
            title: "known_hosts is world-writable".to_string(),
            severity: "medium".to_string(),
            summary: format!(
                "{} is world-writable, which allows host trust tampering.",
                entry.path.display()
            ),
            recommendation: "Remove world write permission from known_hosts.".to_string(),
        });
    }
}

fn review_ssh_config(
    entry: &PathEntry,
    findings: &mut Vec<SshReviewFinding>,
    notes: &mut Vec<String>,
) {
    let Some(file_name) = entry
        .path
        .file_name()
        .map(|value| value.to_string_lossy().to_string())
    else {
        return;
    };
    if !matches!(file_name.as_str(), "sshd_config" | "config") {
        return;
    }

    let Ok(contents) = fs::read_to_string(&entry.path) else {
        notes.push(format!("Could not read {}", entry.path.display()));
        return;
    };

    let normalized = contents
        .lines()
        .map(str::trim)
        .filter(|line| !line.starts_with('#'))
        .collect::<Vec<_>>();

    if normalized
        .iter()
        .any(|line| line.eq_ignore_ascii_case("permitrootlogin yes"))
    {
        findings.push(SshReviewFinding {
            path: entry.path.clone(),
            title: "PermitRootLogin is enabled".to_string(),
            severity: "high".to_string(),
            summary: format!(
                "{} explicitly enables direct root logins over SSH.",
                entry.path.display()
            ),
            recommendation: "Prefer 'PermitRootLogin prohibit-password' or 'no'.".to_string(),
        });
    }

    if normalized
        .iter()
        .any(|line| line.eq_ignore_ascii_case("passwordauthentication yes"))
    {
        findings.push(SshReviewFinding {
            path: entry.path.clone(),
            title: "PasswordAuthentication is enabled".to_string(),
            severity: "medium".to_string(),
            summary: format!(
                "{} allows password-based SSH authentication.",
                entry.path.display()
            ),
            recommendation: "Disable password authentication when key-based login is available."
                .to_string(),
        });
    }
}

fn is_private_key_name(name: &str) -> bool {
    name.starts_with("id_")
        && !name.ends_with(".pub")
        && name != "id_rsa.pub"
        && name != "id_ed25519.pub"
}
