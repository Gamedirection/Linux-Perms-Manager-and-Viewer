use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;

use gtk4::prelude::*;
use libadwaita::prelude::*;

use crate::app_state::{PrivilegeLevel, ScanSummary};

// ── Approved-list persistence ─────────────────────────────────────────────────

fn approved_file_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    PathBuf::from(home).join(".local/share/perms/approved.json")
}

pub fn load_approved() -> Vec<String> {
    if let Ok(text) = std::fs::read_to_string(approved_file_path()) {
        if let Ok(v) = serde_json::from_str::<Vec<String>>(&text) {
            return v;
        }
    }
    Vec::new()
}

pub fn save_approved(list: &[String]) {
    let path = approved_file_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    if let Ok(json) = serde_json::to_string_pretty(list) {
        std::fs::write(&path, json).ok();
    }
}

// ── Shared row helpers ────────────────────────────────────────────────────────

fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn info_row(title: &str, value: &str) -> libadwaita::ActionRow {
    libadwaita::ActionRow::builder()
        .title(title)
        .subtitle(&escape(value))
        .build()
}

fn count_row(label: &str, count: usize, css_class: &str) -> libadwaita::ActionRow {
    let row = libadwaita::ActionRow::builder().title(label).build();
    let badge = gtk4::Label::builder()
        .label(&count.to_string())
        .css_classes(["monospace", "dashboard-count", css_class])
        .build();
    row.add_suffix(&badge);
    row
}

fn path_row(path: &str) -> libadwaita::ActionRow {
    libadwaita::ActionRow::builder()
        .title(&escape(path))
        .css_classes(["monospace"])
        .build()
}

fn placeholder_row(msg: &str) -> libadwaita::ActionRow {
    libadwaita::ActionRow::builder()
        .title(msg)
        .css_classes(["dim-label"])
        .build()
}

fn overall_risk(s: &ScanSummary) -> (&'static str, &'static str) {
    if s.findings_critical > 0 {
        ("CRITICAL", "severity-critical")
    } else if s.findings_high > 0 {
        ("HIGH", "severity-high")
    } else if s.findings_medium > 0 {
        ("MEDIUM", "severity-medium")
    } else if s.findings_low > 0 {
        ("LOW", "severity-low")
    } else {
        ("CLEAN", "severity-info")
    }
}

/// Navigate to `path` in the viewer: use the directory if it is one,
/// otherwise use the parent directory so the file is visible in context.
fn viewer_nav_path(path: &str) -> PathBuf {
    let p = PathBuf::from(path);
    if p.is_dir() {
        p
    } else {
        p.parent()
            .filter(|x| !x.as_os_str().is_empty())
            .map(|x| x.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("/"))
    }
}

// ── Best-practices guide data ─────────────────────────────────────────────────

struct RuleGuide {
    title: &'static str,
    severity: &'static str,
    severity_css: &'static str,
    what: &'static str,
    fix: &'static str,
}

const RULE_GUIDES: &[RuleGuide] = &[
    RuleGuide {
        title: "Non-Root-Writable System Path",
        severity: "Critical",
        severity_css: "severity-critical",
        what: "A file inside /usr, /bin, /sbin, /lib, or another system path is writable by \
               a non-root user or group. Attackers can replace binaries or inject code into \
               shared libraries to gain root.",
        fix: "chmod o-w <path> and verify group ownership. System paths should be \
              owned root:root with mode 755 (dirs) or 644/755 (files). \
              Run: find /usr /bin /sbin /lib -not -user root to audit.",
    },
    RuleGuide {
        title: "World-Writable Directory",
        severity: "Critical / High",
        severity_css: "severity-critical",
        what: "Any local user can create, rename, or delete files inside this directory. \
               Without the sticky bit this enables symlink attacks, log injection, and data \
               tampering. With the sticky bit (e.g. /tmp) the risk is reduced but still present.",
        fix: "Remove world-write: chmod o-w <dir>\n\
              If shared temp space is needed, use the sticky bit so users cannot delete each \
              other's files: chmod 1777 <dir>  (mode 1777 = rwxrwxrwt).\n\
              Prefer 1755 for dirs that only need world-read, not world-write.",
    },
    RuleGuide {
        title: "World-Writable File",
        severity: "High",
        severity_css: "severity-high",
        what: "Any user can overwrite this file. Config files, scripts, or cron jobs with \
               world-write are prime targets for persistent backdoors. Even a log file that \
               is world-writable can enable symlink attacks in certain scenarios.",
        fix: "chmod o-w <file>\n\
              Standard target modes: 644 (data/config), 755 (executable), 640/750 for \
              files that need group access but not world access.",
    },
    RuleGuide {
        title: "Executable Writable by Non-Admin",
        severity: "High",
        severity_css: "severity-high",
        what: "An executable is writable by a non-admin user or group. Anyone with write \
               access can replace it with malicious code that runs with the file's owner \
               privileges — including root if the binary is SUID.",
        fix: "chmod go-w <executable>\n\
              Executables should be mode 755 (world-execute, no world-write) or 750 if \
              only the owning group should run them. Never combine SUID with group/other write.",
    },
    RuleGuide {
        title: "Home Directory Readable by Others",
        severity: "High",
        severity_css: "severity-high",
        what: "A home directory has o+r or o+x, exposing its contents to every local user. \
               SSH private keys (~/.ssh/id_*), shell history, .netrc, .pgpass, \
               and application config files frequently contain credentials.",
        fix: "chmod 700 /home/<user>  — strict, only owner.\n\
              chmod 750 /home/<user>  — if the owning group needs access (e.g. web servers).\n\
              Many distros default to 755; tighten this on any multi-user system.\n\
              Check with: ls -ld /home/*",
    },
    RuleGuide {
        title: "Unexpected SUID Binary",
        severity: "High",
        severity_css: "severity-high",
        what: "The SUID bit causes the program to execute as its owner (often root) regardless \
               of who runs it. Unexpected SUID binaries are one of the most common local \
               privilege escalation vectors. Attackers actively look for these.",
        fix: "chmod u-s <file>  unless SUID is intentional (passwd, sudo, ping, mount…).\n\
              Audit periodically: find / -perm -4000 -type f 2>/dev/null\n\
              Maintain a whitelist of approved SUID binaries and alert on new ones.",
    },
    RuleGuide {
        title: "Unexpected SGID Binary or Directory",
        severity: "Medium",
        severity_css: "severity-medium",
        what: "SGID on an executable runs it as its group. SGID on a directory causes new \
               files inside to inherit that group automatically. Unexpected SGID on executables \
               can expose group-owned resources (mail spool, tty devices, etc.).",
        fix: "chmod g-s <path>  unless SGID is required.\n\
              Legitimate SGID dirs: shared project directories where all files should belong \
              to a common group. Always pair with a restrictive mode (2770, 2750).\n\
              Audit: find / -perm -2000 -type f 2>/dev/null",
    },
    RuleGuide {
        title: "Orphaned UID (No Matching User)",
        severity: "Medium",
        severity_css: "severity-medium",
        what: "The file's numeric UID has no entry in /etc/passwd. This usually happens when \
               a user account is deleted but their files remain. If that UID is later assigned \
               to a new user, the new user automatically inherits ownership of all orphaned files.",
        fix: "Reassign or remove the files:\n\
              find / -nouser -print  to locate all orphaned files.\n\
              chown <new_owner> <path>  or rm if no longer needed.\n\
              Best practice: when deleting a user, also delete or reassign their files \
              (userdel -r <user> handles home dir; audit for other locations).",
    },
    RuleGuide {
        title: "Orphaned GID (No Matching Group)",
        severity: "Medium",
        severity_css: "severity-medium",
        what: "The file's group GID has no entry in /etc/group. Same re-assignment risk as \
               orphaned UIDs — a future group with the same GID gains access to these files.",
        fix: "find / -nogroup -print  to locate all orphaned files.\n\
              chgrp <new_group> <path>  or reassign to an appropriate group.\n\
              When deleting a group, audit for files owned by that GID first.",
    },
];

// ── Cards ─────────────────────────────────────────────────────────────────────

pub fn privilege_card(level: PrivilegeLevel) -> gtk4::Widget {
    let group = libadwaita::PreferencesGroup::builder()
        .title("Privilege and Status")
        .build();

    let (status, detail, note) = match level {
        PrivilegeLevel::Root => (
            "Running as Root",
            "Full filesystem visibility.",
            "Avoid running the UI as root in production. \
             Use the polkit helper (Phase 5) for elevated operations instead.",
        ),
        PrivilegeLevel::Elevated => (
            "Elevated — Helper Active",
            "Full visibility via polkit helper.",
            "Operations performed by the helper are logged and require authentication.",
        ),
        PrivilegeLevel::Unprivileged => (
            "Unprivileged",
            "Partial visibility — some paths may be unreadable.",
            "Directories like /root, /etc/shadow, and other root-owned paths \
             will not be scanned. Run the polkit helper for full coverage.",
        ),
    };

    group.add(&info_row("Level", status));
    group.add(&info_row("Detail", detail));
    group.add(&info_row("Note", note));

    group.upcast()
}

pub fn scan_coverage_card(summary: Option<&ScanSummary>) -> gtk4::Widget {
    let group = libadwaita::PreferencesGroup::builder()
        .title("Scan Coverage")
        .build();

    let Some(s) = summary else {
        group.add(&placeholder_row("No scan data. Click 'Scan Now'."));
        return group.upcast();
    };

    group.add(&count_row(
        "Entries Scanned",
        s.total_entries,
        "severity-info",
    ));

    for root in &s.scan_roots_used {
        group.add(&path_row(root));
    }

    group.upcast()
}

/// Risk summary with clickable severity expanders showing matching findings.
pub fn risk_summary_card(
    summary: Option<&ScanSummary>,
    approved: &[String],
    viewer: Rc<dyn Fn(PathBuf)>,
) -> gtk4::Widget {
    let group = libadwaita::PreferencesGroup::builder()
        .title("Risk Summary")
        .build();

    let Some(s) = summary else {
        group.add(&placeholder_row("No scan data. Click 'Scan Now'."));
        return group.upcast();
    };

    // ── Overall risk badge ────────────────────────────────────────────────────
    let (risk_label, risk_css) = overall_risk(s);
    let overall_row = libadwaita::ActionRow::builder()
        .title("Overall Risk Level")
        .subtitle("Determined by the highest severity finding")
        .build();
    let badge = gtk4::Label::builder()
        .label(risk_label)
        .css_classes(["monospace", "dashboard-count", risk_css])
        .build();
    overall_row.add_suffix(&badge);
    group.add(&overall_row);

    // ── Per-severity rows (expandable for Critical/High/Medium) ───────────────
    let total_findings = s.findings_critical
        + s.findings_high
        + s.findings_medium
        + s.findings_low
        + s.findings_info;

    if total_findings == 0 {
        group.add(&placeholder_row("No findings. System looks clean. ✓"));
    }

    if s.findings_critical > 0 {
        group.add(&severity_expander(
            "Critical",
            "Immediate action required — active attack surface",
            s.findings_critical,
            "severity-critical",
            "Critical",
            &s.recent_findings,
            viewer.clone(),
        ));
    }
    if s.findings_high > 0 {
        group.add(&severity_expander(
            "High",
            "Address soon — exploitable under common threat models",
            s.findings_high,
            "severity-high",
            "High",
            &s.recent_findings,
            viewer.clone(),
        ));
    }
    if s.findings_medium > 0 {
        group.add(&severity_expander(
            "Medium",
            "Remediate in next maintenance window",
            s.findings_medium,
            "severity-medium",
            "Medium",
            &s.recent_findings,
            viewer.clone(),
        ));
    }
    if s.findings_low > 0 {
        group.add(&count_row_sub(
            "Low",
            "Best-practice improvements; low direct risk",
            s.findings_low,
            "severity-low",
        ));
    }
    if s.findings_info > 0 {
        group.add(&count_row_sub(
            "Info",
            "Informational — no immediate action needed",
            s.findings_info,
            "severity-info",
        ));
    }

    // ── Approved suppressions note ────────────────────────────────────────────
    let approved_count = s
        .recent_findings
        .iter()
        .filter(|(_, _, path)| approved.contains(path))
        .count();
    if approved_count > 0 {
        group.add(&info_row(
            "Suppressed by Approved List",
            &format!("{approved_count} finding(s) in recent results are from approved paths"),
        ));
    }

    // ── Best Practices Guide (expander) ──────────────────────────────────────
    let expander = libadwaita::ExpanderRow::builder()
        .title("Best Practices Guide")
        .subtitle("Tap to view remediation guidance for each audit rule")
        .build();

    for guide in RULE_GUIDES {
        let rule_row = libadwaita::ExpanderRow::builder()
            .title(guide.title)
            .build();

        let sev_row = libadwaita::ActionRow::builder().title("Severity").build();
        let sev_badge = gtk4::Label::builder()
            .label(guide.severity)
            .css_classes(["caption", guide.severity_css])
            .valign(gtk4::Align::Center)
            .build();
        sev_row.add_suffix(&sev_badge);
        rule_row.add_row(&sev_row);

        rule_row.add_row(
            &libadwaita::ActionRow::builder()
                .title("What it means")
                .subtitle(guide.what)
                .build(),
        );
        rule_row.add_row(
            &libadwaita::ActionRow::builder()
                .title("How to fix")
                .subtitle(guide.fix)
                .css_classes(["monospace"])
                .build(),
        );

        expander.add_row(&rule_row);
    }

    group.add(&expander);
    group.upcast()
}

/// World-writable paths card with clickable rows that open in Viewer.
pub fn world_writable_card(
    summary: Option<&ScanSummary>,
    approved: &[String],
    viewer: Rc<dyn Fn(PathBuf)>,
) -> gtk4::Widget {
    let group = libadwaita::PreferencesGroup::builder()
        .title("World-Writable Paths")
        .description(
            "Any local user can write to these paths. \
             Directories without the sticky bit (+t) are Critical; \
             files are High. Click a path to open it in the Viewer.",
        )
        .build();

    let Some(s) = summary else {
        group.add(&placeholder_row("No scan data. Click 'Scan Now'."));
        return group.upcast();
    };

    let unapproved_count = s
        .world_writable
        .iter()
        .filter(|p| !approved.contains(p))
        .count();
    let label = if s.world_writable.is_empty() {
        "Total Found"
    } else {
        "Total Found (unapproved)"
    };
    group.add(&count_row(
        label,
        unapproved_count,
        if unapproved_count == 0 {
            "severity-info"
        } else {
            "severity-critical"
        },
    ));

    if s.world_writable.is_empty() {
        group.add(&placeholder_row("None found. ✓"));
    } else {
        let mut shown = 0;
        for path in &s.world_writable {
            if shown >= 8 {
                break;
            }

            let row = if approved.contains(path) {
                let r = libadwaita::ActionRow::builder()
                    .title(&escape(path))
                    .css_classes(["monospace", "dim-label"])
                    .activatable(true)
                    .tooltip_text("Click to open in Viewer")
                    .build();
                let badge = gtk4::Label::builder()
                    .label("approved")
                    .css_classes(["caption", "mode-ok"])
                    .valign(gtk4::Align::Center)
                    .build();
                r.add_suffix(&badge);
                r
            } else {
                libadwaita::ActionRow::builder()
                    .title(&escape(path))
                    .css_classes(["monospace"])
                    .activatable(true)
                    .tooltip_text("Click to open in Viewer")
                    .build()
            };

            let path_str = path.clone();
            let v = viewer.clone();
            row.connect_activated(move |_| v(viewer_nav_path(&path_str)));
            group.add(&row);
            shown += 1;
        }
        if s.world_writable.len() > 8 {
            group.add(&placeholder_row(&format!(
                "… and {} more",
                s.world_writable.len() - 8
            )));
        }
        group.add(&info_row(
            "Best Practice",
            "chmod o-w <path>  — add sticky bit (+t) only for shared temp dirs.",
        ));
    }

    group.upcast()
}

/// ACL usage card with expandable clickable list of affected paths.
pub fn acl_usage_card(summary: Option<&ScanSummary>, viewer: Rc<dyn Fn(PathBuf)>) -> gtk4::Widget {
    let group = libadwaita::PreferencesGroup::builder()
        .title("ACL Usage")
        .description(
            "Extended POSIX ACLs grant per-user/per-group permissions beyond the standard \
             owner/group/other triplet. Click a path to open it in the Viewer.",
        )
        .build();

    let Some(s) = summary else {
        group.add(&placeholder_row("No scan data. Click 'Scan Now'."));
        return group.upcast();
    };

    group.add(&count_row(
        "Extended ACL Entries",
        s.acl_count,
        "severity-medium",
    ));

    let pct = if s.total_entries > 0 {
        format!(
            "{:.1}% of scanned entries",
            s.acl_count as f64 / s.total_entries as f64 * 100.0
        )
    } else {
        "0.0%".to_string()
    };
    group.add(&info_row("Coverage", &pct));

    if s.acl_count == 0 {
        group.add(&placeholder_row("No ACL entries found. ✓"));
    } else if !s.acl_paths.is_empty() {
        let show_count = s.acl_paths.len().min(20);
        let expander = libadwaita::ExpanderRow::builder()
            .title("Paths with ACLs")
            .subtitle(&format!(
                "{} paths captured — showing {}",
                s.acl_paths.len(),
                show_count
            ))
            .build();
        for path in s.acl_paths.iter().take(20) {
            let row = libadwaita::ActionRow::builder()
                .title(&escape(path))
                .css_classes(["monospace"])
                .activatable(true)
                .tooltip_text("Click to open in Viewer")
                .build();
            let path_str = path.clone();
            let v = viewer.clone();
            row.connect_activated(move |_| v(viewer_nav_path(&path_str)));
            expander.add_row(&row);
        }
        if s.acl_paths.len() > 20 {
            expander.add_row(&placeholder_row(&format!(
                "… {} more paths (use Export Report for full list)",
                s.acl_paths.len() - 20
            )));
        }
        group.add(&expander);
    }

    group.add(&info_row(
        "Best Practice",
        "Audit ACLs regularly with 'getfacl -R <dir>'. \
         Prefer standard mode bits where possible — ACLs add complexity and can be \
         overlooked by tools that do not parse them.",
    ));

    group.upcast()
}

pub fn sensitive_dirs_card(summary: Option<&ScanSummary>) -> gtk4::Widget {
    let group = libadwaita::PreferencesGroup::builder()
        .title("Sensitive Paths Found")
        .description(
            "Entries inside high-value locations (/etc, /root, /boot, /usr/bin, \
             /home/*, /var/log, etc.). These paths warrant extra scrutiny for unexpected \
             permissions.",
        )
        .build();

    let Some(s) = summary else {
        group.add(&placeholder_row("No scan data. Click 'Scan Now'."));
        return group.upcast();
    };

    if s.sensitive_paths.is_empty() {
        group.add(&placeholder_row(
            "No sensitive paths in the selected scan roots.",
        ));
    } else {
        group.add(&count_row(
            "Sensitive Entries",
            s.sensitive_paths.len(),
            "severity-medium",
        ));
        for path in s.sensitive_paths.iter().take(8) {
            group.add(&path_row(path));
        }
        if s.sensitive_paths.len() > 8 {
            group.add(&placeholder_row(&format!(
                "… and {} more",
                s.sensitive_paths.len() - 8
            )));
        }
        group.add(&info_row(
            "Tip",
            "Cross-reference these with the Risk Summary findings. \
             Any sensitive path with a Critical or High finding should be addressed first.",
        ));
    }

    group.upcast()
}

pub fn top_owners_card(summary: Option<&ScanSummary>) -> gtk4::Widget {
    let group = libadwaita::PreferencesGroup::builder()
        .title("Top File Owners")
        .description("Users with the most owned entries in the scanned directories.")
        .build();

    let Some(s) = summary else {
        group.add(&placeholder_row("No scan data. Click 'Scan Now'."));
        return group.upcast();
    };

    if s.top_owners.is_empty() {
        group.add(&placeholder_row("No data."));
    } else {
        for (name, count) in &s.top_owners {
            group.add(&count_row(name, *count, "severity-info"));
        }
        group.add(&info_row(
            "Best Practice",
            "Unexpected large owner counts may indicate misconfigurations \
             or services running with overly broad ownership.",
        ));
    }

    group.upcast()
}

/// Recent audit findings card with clickable rows that open the path in Viewer.
pub fn recent_findings_card(
    summary: Option<&ScanSummary>,
    approved: &[String],
    viewer: Rc<dyn Fn(PathBuf)>,
) -> gtk4::Widget {
    let group = libadwaita::PreferencesGroup::builder()
        .title("Recent Audit Findings")
        .description(
            "Latest findings from the scan. \
             Approved paths are dimmed. Click a row to open the path in the Viewer.",
        )
        .build();

    let Some(s) = summary else {
        group.add(&placeholder_row("No scan data. Click 'Scan Now'."));
        return group.upcast();
    };

    if s.recent_findings.is_empty() {
        group.add(&placeholder_row("No findings. ✓"));
        return group.upcast();
    }

    let mut shown = 0;
    for (severity, rule, path) in &s.recent_findings {
        if shown >= 15 {
            break;
        }

        let is_approved = approved.contains(path);

        let row = libadwaita::ActionRow::builder()
            .title(&rule_id_to_label(rule))
            .subtitle(&escape(path))
            .activatable(true)
            .tooltip_text("Click to open in Viewer")
            .build();

        if is_approved {
            row.add_css_class("dim-label");
        }

        let sev_css = severity_css(severity);
        let badge_label = if is_approved {
            "approved"
        } else {
            severity.as_str()
        };
        let badge_css = if is_approved { "mode-ok" } else { sev_css };
        let badge = gtk4::Label::builder()
            .label(badge_label)
            .css_classes(["caption", badge_css])
            .valign(gtk4::Align::Center)
            .build();
        row.add_prefix(&badge);

        let path_str = path.clone();
        let v = viewer.clone();
        row.connect_activated(move |_| v(viewer_nav_path(&path_str)));

        group.add(&row);
        shown += 1;
    }

    if s.recent_findings.len() > 15 {
        group.add(&placeholder_row(&format!(
            "… and {} more findings (use Export Report for full list)",
            s.recent_findings.len() - 15
        )));
    }

    group.upcast()
}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn count_row_sub(label: &str, subtitle: &str, count: usize, css: &str) -> libadwaita::ActionRow {
    let row = libadwaita::ActionRow::builder()
        .title(label)
        .subtitle(subtitle)
        .build();
    let badge = gtk4::Label::builder()
        .label(&count.to_string())
        .css_classes(["monospace", "dashboard-count", css])
        .build();
    row.add_suffix(&badge);
    row
}

/// Build an ExpanderRow for a severity level with matching findings listed as child rows.
fn severity_expander(
    label: &str,
    subtitle: &str,
    count: usize,
    css: &'static str,
    filter_sev: &str,
    findings: &[(String, String, String)],
    viewer: Rc<dyn Fn(PathBuf)>,
) -> libadwaita::ExpanderRow {
    let expander = libadwaita::ExpanderRow::builder()
        .title(&format!("{label} ({count})"))
        .subtitle(subtitle)
        .build();

    let badge = gtk4::Label::builder()
        .label(&count.to_string())
        .css_classes(["monospace", "dashboard-count", css])
        .build();
    expander.add_suffix(&badge);

    let mut shown = 0usize;
    for (_, rule, path) in findings.iter().filter(|(sev, _, _)| sev == filter_sev) {
        let row = libadwaita::ActionRow::builder()
            .title(&rule_id_to_label(rule))
            .subtitle(&escape(path))
            .activatable(true)
            .tooltip_text("Click to open in Viewer")
            .build();
        let path_str = path.clone();
        let v = viewer.clone();
        row.connect_activated(move |_| v(viewer_nav_path(&path_str)));
        expander.add_row(&row);
        shown += 1;
    }

    if shown == 0 {
        expander.add_row(
            &libadwaita::ActionRow::builder()
                .title(&format!(
                    "{count} finding(s) detected — use Export Report for full details"
                ))
                .css_classes(["dim-label"])
                .build(),
        );
    } else if count > shown {
        expander.add_row(
            &libadwaita::ActionRow::builder()
                .title(&format!("… {} more (sample limit reached)", count - shown))
                .css_classes(["dim-label"])
                .build(),
        );
    }

    expander
}

pub fn rule_id_to_label(id: &str) -> String {
    match id {
        "writable-system-path" => "Non-Root-Writable System Path".into(),
        "world-writable-dir" => "World-Writable Directory".into(),
        "world-writable-file" => "World-Writable File".into(),
        "executable-writable-non-admin" => "Executable Writable by Non-Admin".into(),
        "home-other-readable" => "Home Dir Readable by Others".into(),
        "suid-unexpected" => "Unexpected SUID Binary".into(),
        "sgid-unexpected" => "Unexpected SGID".into(),
        "orphaned-uid" => "Orphaned UID (No Matching User)".into(),
        "orphaned-gid" => "Orphaned GID (No Matching Group)".into(),
        other => other.to_string(),
    }
}

fn severity_css(severity: &str) -> &'static str {
    match severity {
        "Critical" => "severity-critical",
        "High" => "severity-high",
        "Medium" => "severity-medium",
        "Low" => "severity-low",
        _ => "severity-info",
    }
}

// ── Approved / Known-Safe Paths section ──────────────────────────────────────

pub fn approved_section(
    approved: Rc<RefCell<Vec<String>>>,
    on_change: Rc<dyn Fn()>,
) -> gtk4::Widget {
    let outer = gtk4::Box::new(gtk4::Orientation::Vertical, 0);
    outer.set_margin_start(12);
    outer.set_margin_end(12);
    outer.set_margin_top(4);
    outer.set_margin_bottom(16);

    // Late-bound self-rebuild so remove buttons can trigger it.
    let self_rebuild: Rc<RefCell<Option<Rc<dyn Fn()>>>> = Rc::new(RefCell::new(None));

    let rebuild = {
        let approved = approved.clone();
        let on_change = on_change.clone();
        let outer = outer.clone();
        let self_rebuild = self_rebuild.clone();
        Rc::new(move || {
            while let Some(c) = outer.first_child() {
                outer.remove(&c);
            }

            // ── Group ──────────────────────────────────────────────────────
            let group = libadwaita::PreferencesGroup::builder()
                .title("Approved / Known-Safe Paths")
                .description(
                    "Paths added here are excluded from alert counts and marked \
                     as approved in Audit Findings and World-Writable lists. \
                     Use this to suppress known false positives (e.g. /tmp, /var/spool/cron).",
                )
                .build();

            let paths = approved.borrow().clone();

            if paths.is_empty() {
                group.add(&placeholder_row(
                    "No approved paths yet. Add paths below to suppress known-safe findings.",
                ));
            }

            for path in &paths {
                let row = libadwaita::ActionRow::builder()
                    .title(&escape(path))
                    .css_classes(["monospace"])
                    .build();

                let remove_btn = gtk4::Button::builder()
                    .icon_name("list-remove-symbolic")
                    .tooltip_text("Remove from approved list")
                    .valign(gtk4::Align::Center)
                    .css_classes(["flat", "circular"])
                    .build();

                {
                    let path_c = path.clone();
                    let approved_c = approved.clone();
                    let self_rebuild_c = self_rebuild.clone();
                    let on_change_c = on_change.clone();
                    remove_btn.connect_clicked(move |_| {
                        approved_c.borrow_mut().retain(|p| p != &path_c);
                        save_approved(&approved_c.borrow());
                        if let Some(r) = self_rebuild_c.borrow().as_ref() {
                            r();
                        }
                        on_change_c();
                    });
                }
                row.add_suffix(&remove_btn);
                group.add(&row);
            }

            outer.append(&group);

            // ── Add path bar ──────────────────────────────────────────────
            let add_bar = gtk4::Box::new(gtk4::Orientation::Horizontal, 8);
            add_bar.set_margin_top(8);

            let add_entry = gtk4::Entry::builder()
                .placeholder_text("Path to approve (e.g. /tmp, /var/spool/cron, /run/user/1000)…")
                .hexpand(true)
                .css_classes(["monospace"])
                .build();

            let add_btn = gtk4::Button::builder()
                .label("Approve Path")
                .css_classes(["suggested-action"])
                .build();

            add_bar.append(&add_entry);
            add_bar.append(&add_btn);

            let do_add = {
                let approved_c = approved.clone();
                let self_rebuild_c = self_rebuild.clone();
                let on_change_c = on_change.clone();
                let add_entry_c = add_entry.clone();
                Rc::new(move || {
                    let raw = add_entry_c.text();
                    let path = raw.trim().to_string();
                    if path.is_empty() {
                        return;
                    }
                    {
                        let mut list = approved_c.borrow_mut();
                        if !list.contains(&path) {
                            list.push(path);
                        }
                    }
                    save_approved(&approved_c.borrow());
                    if let Some(r) = self_rebuild_c.borrow().as_ref() {
                        r();
                    }
                    on_change_c();
                })
            };

            {
                let do_add = do_add.clone();
                add_btn.connect_clicked(move |_| do_add());
            }
            {
                add_entry.connect_activate(move |_| do_add());
            }

            outer.append(&add_bar);
        })
    };

    *self_rebuild.borrow_mut() = Some(rebuild.clone());
    rebuild();

    outer.upcast()
}
