use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use perms_core::engine::scanner::stat_entry;
use perms_core::engine::ssh_review::generate_report;
use perms_core::engine::system_actions::{CreateGroupRequest, CreateUserRequest};

fn main() {
    if let Err(err) = run() {
        eprintln!("{err:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let Some(cmd) = args.next() else {
        bail!("missing helper command");
    };

    match cmd.as_str() {
        "probe" => {
            ensure_root()?;
            println!("ok");
        }
        "scan-dir" => {
            ensure_root()?;
            let path = PathBuf::from(args.next().context("missing directory path")?);
            let mut entries = Vec::new();
            let mut children = std::fs::read_dir(&path)
                .with_context(|| format!("reading {}", path.display()))?
                .filter_map(|entry| entry.ok())
                .map(|entry| entry.path())
                .collect::<Vec<_>>();
            children.sort();

            for child in children {
                if let Ok(entry) = stat_entry(&child) {
                    entries.push(entry);
                }
            }

            print_json(&entries)?;
        }
        "ssh-review" => {
            ensure_root()?;
            let report = generate_report()?;
            print_json(&report)?;
        }
        "create-group" => {
            ensure_root()?;
            let request = CreateGroupRequest {
                name: args.next().context("missing group name")?,
                system: parse_bool_flag(args.next().as_deref()),
            };
            perms_core::engine::system_actions::create_group(&request)?;
            println!("ok");
        }
        "create-user" => {
            ensure_root()?;
            let request = CreateUserRequest {
                username: args.next().context("missing username")?,
                primary_group: parse_optional_arg(args.next()),
                home_dir: parse_optional_arg(args.next()),
                shell: parse_optional_arg(args.next()),
                system: parse_bool_flag(args.next().as_deref()),
            };
            perms_core::engine::system_actions::create_user(&request)?;
            println!("ok");
        }
        other => bail!("unknown helper command: {other}"),
    }

    Ok(())
}

fn print_json<T: serde::Serialize>(value: &T) -> Result<()> {
    let json = serde_json::to_string(value)?;
    println!("{json}");
    Ok(())
}

fn ensure_root() -> Result<()> {
    if !nix::unistd::geteuid().is_root() {
        bail!("helper requires root privileges");
    }
    Ok(())
}

fn parse_optional_arg(value: Option<String>) -> Option<String> {
    match value.as_deref() {
        Some("-") | None => None,
        Some(value) if value.is_empty() => None,
        Some(_) => value,
    }
}

fn parse_bool_flag(value: Option<&str>) -> bool {
    matches!(value, Some("1") | Some("true") | Some("yes"))
}
