use gtk4::prelude::*;
use libadwaita::prelude::*;

use crate::app_state::SharedState;

pub fn build(state: SharedState) -> gtk4::Widget {
    let page = libadwaita::PreferencesPage::builder()
        .title("Settings")
        .build();

    // ── Scan Settings ─────────────────────────────────────────────────────────
    let scan_group = libadwaita::PreferencesGroup::builder()
        .title("Scan Defaults")
        .description(
            "These values pre-fill the Dashboard scan controls. \
             Changes take effect on the next scan and are saved automatically.",
        )
        .build();

    let roots_row = libadwaita::EntryRow::builder()
        .title("Default Scan Roots")
        .text(&state.lock().unwrap().settings.default_roots)
        .build();

    let symlinks_row = libadwaita::SwitchRow::builder()
        .title("Follow Symlinks")
        .subtitle("Include symlink targets (may loop on circular links)")
        .active(state.lock().unwrap().settings.follow_symlinks)
        .build();

    let hidden_row = libadwaita::SwitchRow::builder()
        .title("Skip Hidden Files")
        .subtitle("Ignore entries whose name starts with '.'")
        .active(state.lock().unwrap().settings.skip_hidden)
        .build();

    let max_row = libadwaita::EntryRow::builder()
        .title("Max Findings Captured")
        .text(&state.lock().unwrap().settings.max_findings.to_string())
        .input_purpose(gtk4::InputPurpose::Digits)
        .build();

    scan_group.add(&roots_row);
    scan_group.add(&symlinks_row);
    scan_group.add(&hidden_row);
    scan_group.add(&max_row);
    page.add(&scan_group);

    // ── About ─────────────────────────────────────────────────────────────────
    let about_group = libadwaita::PreferencesGroup::builder()
        .title("About")
        .build();

    let ver_row = libadwaita::ActionRow::builder()
        .title("perms")
        .subtitle("Linux Permissions Manager & Viewer — v0.1.0")
        .build();
    about_group.add(&ver_row);

    let approved_row = libadwaita::ActionRow::builder()
        .title("Approved List Location")
        .subtitle("~/.local/share/perms/approved.json")
        .css_classes(["monospace"])
        .build();
    about_group.add(&approved_row);

    let reports_row = libadwaita::ActionRow::builder()
        .title("Reports Location")
        .subtitle("~/.local/share/perms/reports/")
        .css_classes(["monospace"])
        .build();
    about_group.add(&reports_row);

    page.add(&about_group);

    // ── Auto-save on any change ───────────────────────────────────────────────
    macro_rules! auto_save {
        ($widget:ident, $signal:ident) => {{
            let state = state.clone();
            let roots_row = roots_row.clone();
            let symlinks_row = symlinks_row.clone();
            let hidden_row = hidden_row.clone();
            let max_row = max_row.clone();
            $widget.$signal(move |_| {
                let max: usize = max_row.text().parse().unwrap_or(50);
                let mut s = state.lock().unwrap();
                s.settings.default_roots = roots_row.text().to_string();
                s.settings.follow_symlinks = symlinks_row.is_active();
                s.settings.skip_hidden = hidden_row.is_active();
                s.settings.max_findings = max;
                s.settings.save();
            });
        }};
    }

    auto_save!(roots_row, connect_changed);
    auto_save!(symlinks_row, connect_active_notify);
    auto_save!(hidden_row, connect_active_notify);
    auto_save!(max_row, connect_changed);

    page.upcast()
}
