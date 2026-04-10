use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, anyhow, bail};

use crate::domain::PathEntry;
use crate::engine::scanner::stat_entry;
use crate::engine::ssh_review::SshReviewReport;

#[derive(Debug, Clone)]
pub struct CreateGroupRequest {
    pub name: String,
    pub system: bool,
}

#[derive(Debug, Clone)]
pub struct CreateUserRequest {
    pub username: String,
    pub primary_group: Option<String>,
    pub home_dir: Option<String>,
    pub shell: Option<String>,
    pub system: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElevationState {
    DirectRoot,
    Available,
    Unavailable,
}

impl ElevationState {
    pub fn label(&self) -> &'static str {
        match self {
            ElevationState::DirectRoot => "Root session active",
            ElevationState::Available => "Authenticate for root-only views",
            ElevationState::Unavailable => "pkexec helper unavailable",
        }
    }
}

pub fn detect_elevation_state() -> ElevationState {
    if nix::unistd::geteuid().is_root() {
        ElevationState::DirectRoot
    } else if helper_command().is_some() && command_exists("pkexec") {
        ElevationState::Available
    } else {
        ElevationState::Unavailable
    }
}

pub fn probe_elevation() -> Result<()> {
    if nix::unistd::geteuid().is_root() {
        return Ok(());
    }
    run_helper_command(["probe"])?;
    Ok(())
}

pub fn list_directory_entries(path: &Path, privileged: bool) -> Result<Vec<PathEntry>> {
    if privileged && !nix::unistd::geteuid().is_root() {
        return run_helper_json(["scan-dir", &path.to_string_lossy()]);
    }

    let mut entries = Vec::new();
    let mut children = std::fs::read_dir(path)
        .with_context(|| format!("reading directory {}", path.display()))?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .collect::<Vec<_>>();
    children.sort();

    for child in children {
        if let Ok(entry) = stat_entry(&child) {
            entries.push(entry);
        }
    }

    Ok(entries)
}

pub fn generate_ssh_review(privileged: bool) -> Result<SshReviewReport> {
    if privileged && !nix::unistd::geteuid().is_root() {
        return run_helper_json(["ssh-review"]);
    }
    crate::engine::ssh_review::generate_report()
}

pub fn create_group(request: &CreateGroupRequest) -> Result<()> {
    if nix::unistd::geteuid().is_root() {
        return invoke_groupadd(request);
    }

    run_helper_command([
        "create-group",
        request.name.as_str(),
        bool_flag(request.system),
    ])?;
    Ok(())
}

pub fn create_user(request: &CreateUserRequest) -> Result<()> {
    if nix::unistd::geteuid().is_root() {
        return invoke_useradd(request);
    }

    run_helper_command([
        "create-user",
        request.username.as_str(),
        optional_arg(request.primary_group.as_deref()),
        optional_arg(request.home_dir.as_deref()),
        optional_arg(request.shell.as_deref()),
        bool_flag(request.system),
    ])?;
    Ok(())
}

fn run_helper_json<T, I, S>(args: I) -> Result<T>
where
    T: serde::de::DeserializeOwned,
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let output = run_helper_command(args)?;
    serde_json::from_slice(&output.stdout).context("parsing helper JSON output")
}

fn run_helper_command<I, S>(args: I) -> Result<std::process::Output>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let helper = helper_command().ok_or_else(|| anyhow!("perms-helper binary not found"))?;
    if !command_exists("pkexec") {
        bail!("pkexec is not available on this system");
    }

    let output = Command::new("pkexec")
        .arg(helper)
        .args(args)
        .output()
        .context("launching pkexec helper")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("helper failed: {}", stderr.trim());
    }

    Ok(output)
}

fn helper_command() -> Option<PathBuf> {
    let mut candidates = Vec::new();

    if let Ok(env_path) = std::env::var("PERMS_HELPER_PATH") {
        candidates.push(PathBuf::from(env_path));
    }

    if let Ok(current) = std::env::current_exe() {
        if let Some(dir) = current.parent() {
            candidates.push(dir.join("perms-helper"));
            candidates.push(dir.join("../perms-helper"));
        }
    }

    candidates.push(PathBuf::from("/usr/libexec/perms-helper"));
    candidates.push(PathBuf::from("perms-helper"));

    candidates.into_iter().find(|candidate| {
        candidate.is_file()
            || (candidate.components().count() == 1 && command_exists("perms-helper"))
    })
}

fn invoke_groupadd(request: &CreateGroupRequest) -> Result<()> {
    let mut command = Command::new("groupadd");
    if request.system {
        command.arg("--system");
    }
    command.arg(&request.name);
    run_status_command(command, "groupadd")
}

fn invoke_useradd(request: &CreateUserRequest) -> Result<()> {
    let mut command = Command::new("useradd");
    if request.system {
        command.arg("--system");
    }
    if let Some(group) = request
        .primary_group
        .as_deref()
        .filter(|value| !value.is_empty())
    {
        command.args(["-g", group]);
    } else if !request.system {
        command.arg("-U");
    }
    if let Some(home_dir) = request
        .home_dir
        .as_deref()
        .filter(|value| !value.is_empty())
    {
        command.args(["-d", home_dir, "-m"]);
    } else if !request.system {
        command.arg("-m");
    }
    if let Some(shell) = request.shell.as_deref().filter(|value| !value.is_empty()) {
        command.args(["-s", shell]);
    }
    command.arg(&request.username);
    run_status_command(command, "useradd")
}

fn run_status_command(mut command: Command, label: &str) -> Result<()> {
    let output = command
        .output()
        .with_context(|| format!("launching {label}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("{label} failed: {}", stderr.trim());
    }
    Ok(())
}

fn optional_arg(value: Option<&str>) -> &str {
    value.filter(|value| !value.is_empty()).unwrap_or("-")
}

fn bool_flag(value: bool) -> &'static str {
    if value { "1" } else { "0" }
}

fn command_exists(cmd: &str) -> bool {
    match std::env::var_os("PATH") {
        Some(value) => std::env::split_paths(&value).any(|path| path.join(cmd).is_file()),
        None => false,
    }
}
