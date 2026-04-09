use gtk4::prelude::*;
use libadwaita::prelude::*;

use crate::app_state::{PrivilegeLevel, ScanSummary};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
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

// ── Cards ─────────────────────────────────────────────────────────────────────

pub fn privilege_card(level: PrivilegeLevel) -> gtk4::Widget {
    let group = libadwaita::PreferencesGroup::builder()
        .title("Privilege and Status")
        .build();

    let (status, detail) = match level {
        PrivilegeLevel::Root => (
            "Running as Root",
            "Full visibility. Avoid running the UI as root in production.",
        ),
        PrivilegeLevel::Elevated => (
            "Elevated — helper active",
            "Full visibility via polkit helper.",
        ),
        PrivilegeLevel::Unprivileged => (
            "Unprivileged",
            "Partial visibility. Some paths may be unreadable.",
        ),
    };

    group.add(&info_row("Level", status));
    group.add(&info_row("Note", detail));

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

    group.add(&count_row("Entries Scanned", s.total_entries, "severity-info"));

    for root in &s.scan_roots_used {
        group.add(&path_row(root));
    }

    group.upcast()
}

pub fn risk_summary_card(summary: Option<&ScanSummary>) -> gtk4::Widget {
    let group = libadwaita::PreferencesGroup::builder()
        .title("Risk Summary")
        .build();

    let Some(s) = summary else {
        group.add(&placeholder_row("No scan data. Click 'Scan Now'."));
        return group.upcast();
    };

    group.add(&count_row("Critical", s.findings_critical, "severity-critical"));
    group.add(&count_row("High", s.findings_high, "severity-high"));
    group.add(&count_row("Medium", s.findings_medium, "severity-medium"));
    group.add(&count_row("Low", s.findings_low, "severity-low"));
    group.add(&count_row("Info", s.findings_info, "severity-info"));

    group.upcast()
}

pub fn world_writable_card(summary: Option<&ScanSummary>) -> gtk4::Widget {
    let group = libadwaita::PreferencesGroup::builder()
        .title("World-Writable Paths")
        .build();

    let Some(s) = summary else {
        group.add(&placeholder_row("No scan data. Click 'Scan Now'."));
        return group.upcast();
    };

    group.add(&count_row("Total Found", s.world_writable.len(), "severity-critical"));

    if s.world_writable.is_empty() {
        group.add(&placeholder_row("None found. ✓"));
    } else {
        for path in s.world_writable.iter().take(5) {
            group.add(&path_row(path));
        }
        if s.world_writable.len() > 5 {
            group.add(&placeholder_row(&format!(
                "… and {} more",
                s.world_writable.len() - 5
            )));
        }
    }

    group.upcast()
}

pub fn acl_usage_card(summary: Option<&ScanSummary>) -> gtk4::Widget {
    let group = libadwaita::PreferencesGroup::builder()
        .title("ACL Usage")
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
        "0%".to_string()
    };
    group.add(&info_row("Coverage", &pct));

    group.upcast()
}

pub fn sensitive_dirs_card(summary: Option<&ScanSummary>) -> gtk4::Widget {
    let group = libadwaita::PreferencesGroup::builder()
        .title("Sensitive Paths Found")
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
        for path in s.sensitive_paths.iter().take(8) {
            group.add(&path_row(path));
        }
        if s.sensitive_paths.len() > 8 {
            group.add(&placeholder_row(&format!(
                "… and {} more",
                s.sensitive_paths.len() - 8
            )));
        }
    }

    group.upcast()
}

pub fn top_owners_card(summary: Option<&ScanSummary>) -> gtk4::Widget {
    let group = libadwaita::PreferencesGroup::builder()
        .title("Top File Owners")
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
    }

    group.upcast()
}

pub fn recent_findings_card(summary: Option<&ScanSummary>) -> gtk4::Widget {
    let group = libadwaita::PreferencesGroup::builder()
        .title("Recent Audit Findings")
        .build();

    let Some(s) = summary else {
        group.add(&placeholder_row("No scan data. Click 'Scan Now'."));
        return group.upcast();
    };

    if s.recent_findings.is_empty() {
        group.add(&placeholder_row("No findings. ✓"));
    } else {
        for (severity, rule, path) in s.recent_findings.iter().take(10) {
            let row = libadwaita::ActionRow::builder()
                .title(rule.as_str())
                .subtitle(&escape(path))
                .build();

            let sev_css = match severity.as_str() {
                "Critical" => "severity-critical",
                "High" => "severity-high",
                "Medium" => "severity-medium",
                "Low" => "severity-low",
                _ => "severity-info",
            };
            let badge = gtk4::Label::builder()
                .label(severity.as_str())
                .css_classes(["caption", sev_css])
                .valign(gtk4::Align::Center)
                .build();
            row.add_prefix(&badge);
            group.add(&row);
        }
        if s.recent_findings.len() > 10 {
            group.add(&placeholder_row(&format!(
                "… and {} more findings",
                s.recent_findings.len() - 10
            )));
        }
    }

    group.upcast()
}
