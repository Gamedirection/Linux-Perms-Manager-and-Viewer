use gtk4::prelude::*;
use libadwaita::prelude::*;

use crate::app_state::SharedState;

pub fn build(state: SharedState, apply_theme: std::rc::Rc<dyn Fn()>) -> gtk4::Widget {
    let initial_settings = state.lock().unwrap().settings.clone();

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
        .text(&initial_settings.default_roots)
        .build();

    let symlinks_row = libadwaita::SwitchRow::builder()
        .title("Follow Symlinks")
        .subtitle("Include symlink targets (may loop on circular links)")
        .active(initial_settings.follow_symlinks)
        .build();

    let hidden_row = libadwaita::SwitchRow::builder()
        .title("Skip Hidden Files")
        .subtitle("Ignore entries whose name starts with '.'")
        .active(initial_settings.skip_hidden)
        .build();

    let max_row = libadwaita::EntryRow::builder()
        .title("Max Findings Captured")
        .text(&initial_settings.max_findings.to_string())
        .input_purpose(gtk4::InputPurpose::Digits)
        .build();

    scan_group.add(&roots_row);
    scan_group.add(&symlinks_row);
    scan_group.add(&hidden_row);
    scan_group.add(&max_row);
    page.add(&scan_group);

    let theme_group = libadwaita::PreferencesGroup::builder()
        .title("Theme")
        .description("Choose an app theme preset or define a custom palette.")
        .build();

    let preset_labels = ["System", "Light", "Forest", "Graphite", "Sunset", "Custom"];
    let preset_model = gtk4::StringList::new(&preset_labels);
    let preset_row = libadwaita::ActionRow::builder()
        .title("Theme Preset")
        .subtitle("Applied immediately")
        .build();
    let preset_dropdown = gtk4::DropDown::builder()
        .model(&preset_model)
        .selected(theme_preset_index(&initial_settings.theme_preset))
        .build();
    preset_row.add_suffix(&preset_dropdown);
    preset_row.set_activatable_widget(Some(&preset_dropdown));

    let custom_name_row = libadwaita::EntryRow::builder()
        .title("Custom Theme Name")
        .text(&initial_settings.custom_theme_name)
        .visible(initial_settings.theme_preset == "custom")
        .build();
    let accent_row = color_row(
        "Accent",
        &initial_settings.custom_accent,
        initial_settings.theme_preset == "custom",
    );
    let success_row = color_row(
        "Success",
        &initial_settings.custom_success,
        initial_settings.theme_preset == "custom",
    );
    let warning_row = color_row(
        "Warning",
        &initial_settings.custom_warning,
        initial_settings.theme_preset == "custom",
    );
    let danger_row = color_row(
        "Danger",
        &initial_settings.custom_danger,
        initial_settings.theme_preset == "custom",
    );
    let neutral_row = color_row(
        "Neutral",
        &initial_settings.custom_neutral,
        initial_settings.theme_preset == "custom",
    );
    let surface_row = color_row(
        "Surface",
        &initial_settings.custom_surface,
        initial_settings.theme_preset == "custom",
    );

    theme_group.add(&preset_row);
    theme_group.add(&custom_name_row);
    theme_group.add(&accent_row);
    theme_group.add(&success_row);
    theme_group.add(&warning_row);
    theme_group.add(&danger_row);
    theme_group.add(&neutral_row);
    theme_group.add(&surface_row);
    page.add(&theme_group);

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

    let persist_settings: std::rc::Rc<dyn Fn()> = {
        let state = state.clone();
        let roots_row = roots_row.clone();
        let symlinks_row = symlinks_row.clone();
        let hidden_row = hidden_row.clone();
        let max_row = max_row.clone();
        let preset_dropdown = preset_dropdown.clone();
        let custom_name_row = custom_name_row.clone();
        let accent_row = accent_row.clone();
        let success_row = success_row.clone();
        let warning_row = warning_row.clone();
        let danger_row = danger_row.clone();
        let neutral_row = neutral_row.clone();
        let surface_row = surface_row.clone();
        let apply_theme = apply_theme.clone();
        std::rc::Rc::new(move || {
            let max: usize = max_row.text().parse().unwrap_or(50);
            let mut s = state.lock().unwrap();
            s.settings.default_roots = roots_row.text().to_string();
            s.settings.follow_symlinks = symlinks_row.is_active();
            s.settings.skip_hidden = hidden_row.is_active();
            s.settings.max_findings = max;
            s.settings.theme_preset = theme_preset_id(preset_dropdown.selected()).to_string();
            s.settings.custom_theme_name = custom_name_row.text().to_string();
            s.settings.custom_accent = accent_row.text().to_string();
            s.settings.custom_success = success_row.text().to_string();
            s.settings.custom_warning = warning_row.text().to_string();
            s.settings.custom_danger = danger_row.text().to_string();
            s.settings.custom_neutral = neutral_row.text().to_string();
            s.settings.custom_surface = surface_row.text().to_string();
            s.settings.save();
            drop(s);
            apply_theme();
        })
    };

    macro_rules! auto_save {
        ($widget:ident, $signal:ident) => {{
            let persist_settings = persist_settings.clone();
            $widget.$signal(move |_| persist_settings());
        }};
    }

    auto_save!(roots_row, connect_changed);
    auto_save!(symlinks_row, connect_active_notify);
    auto_save!(hidden_row, connect_active_notify);
    auto_save!(max_row, connect_changed);
    auto_save!(preset_dropdown, connect_selected_notify);
    auto_save!(custom_name_row, connect_changed);
    auto_save!(accent_row, connect_changed);
    auto_save!(success_row, connect_changed);
    auto_save!(warning_row, connect_changed);
    auto_save!(danger_row, connect_changed);
    auto_save!(neutral_row, connect_changed);
    auto_save!(surface_row, connect_changed);

    {
        let custom_rows = vec![
            custom_name_row.clone().upcast::<gtk4::Widget>(),
            accent_row.clone().upcast::<gtk4::Widget>(),
            success_row.clone().upcast::<gtk4::Widget>(),
            warning_row.clone().upcast::<gtk4::Widget>(),
            danger_row.clone().upcast::<gtk4::Widget>(),
            neutral_row.clone().upcast::<gtk4::Widget>(),
            surface_row.clone().upcast::<gtk4::Widget>(),
        ];
        preset_dropdown.connect_selected_notify(move |dropdown| {
            let visible = theme_preset_id(dropdown.selected()) == "custom";
            for row in &custom_rows {
                row.set_visible(visible);
            }
        });
    }

    page.upcast()
}

fn color_row(title: &str, value: &str, visible: bool) -> libadwaita::EntryRow {
    libadwaita::EntryRow::builder()
        .title(title)
        .text(value)
        .visible(visible)
        .build()
}

fn theme_preset_index(id: &str) -> u32 {
    match id {
        "light" => 1,
        "forest" => 2,
        "graphite" => 3,
        "sunset" => 4,
        "custom" => 5,
        _ => 0,
    }
}

fn theme_preset_id(index: u32) -> &'static str {
    match index {
        1 => "light",
        2 => "forest",
        3 => "graphite",
        4 => "sunset",
        5 => "custom",
        _ => "system",
    }
}
