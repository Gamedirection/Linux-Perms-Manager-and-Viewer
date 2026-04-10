use std::cell::{Cell, RefCell};
use std::path::PathBuf;
use std::rc::Rc;

use gtk4::gio;
use gtk4::prelude::*;
use libadwaita::prelude::*;

use perms_core::domain::PathEntry;
use perms_core::domain::permission::UnixMode;
use perms_core::engine::scanner::stat_entry;
use perms_core::ipc::{AuditEntry, ChangeRequest, ChangeResult};

use crate::app_state::SharedState;
use crate::model::PathObject;

// ── Risk classification ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq)]
enum RiskLevel {
    Normal,
    High,
}

fn assess_risk(entries: &[PathEntry], new_mode: Option<u32>, recursive: bool) -> RiskLevel {
    if let Some(mode) = new_mode {
        if UnixMode(mode).is_world_writable() {
            return RiskLevel::High;
        }
    }
    if recursive && entries.len() > 20 {
        return RiskLevel::High;
    }
    for entry in entries {
        if entry.sensitive_label.is_some() {
            return RiskLevel::High;
        }
    }
    RiskLevel::Normal
}

// ── Audit log ─────────────────────────────────────────────────────────────────

fn audit_log_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    let dir = PathBuf::from(home).join(".local/share/perms");
    std::fs::create_dir_all(&dir).ok();
    dir.join("changes.log")
}

fn write_audit_entry(entry: &AuditEntry) {
    use std::io::Write;
    if let Ok(line) = serde_json::to_string(entry) {
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(audit_log_path())
        {
            let _ = writeln!(f, "{line}");
        }
    }
}

fn now_iso() -> String {
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

fn effective_uid() -> u32 {
    nix::unistd::geteuid().as_raw()
}

// ── Apply logic ───────────────────────────────────────────────────────────────

/// Apply a single change request directly via nix syscalls.
/// Returns a list of ChangeResults (one per affected path).
fn apply_request(req: &ChangeRequest, entry: &PathEntry) -> Vec<ChangeResult> {
    use nix::unistd::{Gid, Uid};
    use walkdir::WalkDir;

    let paths: Vec<PathBuf> = if req.recursive {
        WalkDir::new(&req.path)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
            .map(|e| e.path().to_path_buf())
            .collect()
    } else {
        vec![req.path.clone()]
    };

    let mut results = Vec::new();

    for path in paths {
        let old_stat = match stat_entry(&path) {
            Ok(s) => s,
            Err(e) => {
                results.push(ChangeResult::err(path, format!("stat: {e}")));
                continue;
            }
        };

        let old_mode_str = old_stat.mode.to_octal();
        let old_uid = old_stat.owner_uid;
        let old_gid = old_stat.owner_gid;

        if req.dry_run {
            results.push(ChangeResult::ok(
                path,
                Some(old_mode_str),
                req.new_mode.map(|m| format!("{:04o}", m & 0o7777)),
                Some(old_uid),
                req.new_uid,
                Some(old_gid),
                req.new_gid,
                false,
            ));
            continue;
        }

        // chmod
        if let Some(new_mode_raw) = req.new_mode {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(new_mode_raw & 0o7777);
            if let Err(e) = std::fs::set_permissions(&path, perms) {
                results.push(ChangeResult::err(path, format!("chmod: {e}")));
                continue;
            }
        }

        // chown
        if req.new_uid.is_some() || req.new_gid.is_some() {
            let uid = req.new_uid.map(Uid::from_raw);
            let gid = req.new_gid.map(Gid::from_raw);
            if let Err(e) = nix::unistd::chown(&path, uid, gid) {
                results.push(ChangeResult::err(path, format!("chown: {e}")));
                continue;
            }
        }

        results.push(ChangeResult::ok(
            path,
            Some(old_mode_str),
            req.new_mode.map(|m| format!("{:04o}", m & 0o7777)),
            Some(old_uid),
            req.new_uid,
            Some(old_gid),
            req.new_gid,
            true,
        ));
    }

    results
}

// ── Confirmation dialog ───────────────────────────────────────────────────────

fn show_confirm_dialog(
    parent_window: Option<gtk4::Window>,
    summary: String,
    risk: RiskLevel,
    on_confirm: impl Fn() + 'static,
) {
    let dialog = gtk4::Window::builder()
        .title(if risk == RiskLevel::High {
            "High-Risk Operation"
        } else {
            "Confirm Changes"
        })
        .modal(true)
        .default_width(420)
        .resizable(false)
        .build();

    if let Some(p) = &parent_window {
        dialog.set_transient_for(Some(p));
    }

    let vbox = gtk4::Box::new(gtk4::Orientation::Vertical, 16);
    vbox.set_margin_top(24);
    vbox.set_margin_bottom(24);
    vbox.set_margin_start(24);
    vbox.set_margin_end(24);

    if risk == RiskLevel::High {
        let warn = gtk4::Label::builder()
            .label("⚠  High-Risk Operation")
            .css_classes(["title-3", "severity-high"])
            .halign(gtk4::Align::Start)
            .build();
        vbox.append(&warn);
    }

    let body = gtk4::Label::builder()
        .label(&summary)
        .wrap(true)
        .halign(gtk4::Align::Start)
        .build();
    vbox.append(&body);

    // Typed confirm entry for high-risk
    let type_entry = gtk4::Entry::builder()
        .placeholder_text("Type APPLY to confirm")
        .visible(risk == RiskLevel::High)
        .build();
    if risk == RiskLevel::High {
        vbox.append(
            &gtk4::Label::builder()
                .label("Type <b>APPLY</b> to confirm:")
                .use_markup(true)
                .halign(gtk4::Align::Start)
                .build(),
        );
        vbox.append(&type_entry);
    }

    // Buttons
    let btn_row = gtk4::Box::new(gtk4::Orientation::Horizontal, 8);
    btn_row.set_halign(gtk4::Align::End);

    let cancel_btn = gtk4::Button::builder().label("Cancel").build();
    let confirm_btn = gtk4::Button::builder()
        .label("Apply")
        .css_classes(if risk == RiskLevel::High {
            vec!["destructive-action"]
        } else {
            vec!["suggested-action"]
        })
        .sensitive(risk == RiskLevel::Normal) // high-risk starts disabled
        .build();

    btn_row.append(&cancel_btn);
    btn_row.append(&confirm_btn);
    vbox.append(&btn_row);

    dialog.set_child(Some(&vbox));

    // Enable confirm button only when "APPLY" is typed
    if risk == RiskLevel::High {
        let confirm_btn_c = confirm_btn.clone();
        type_entry.connect_changed(move |entry| {
            confirm_btn_c.set_sensitive(entry.text().as_str() == "APPLY");
        });
    }

    // Cancel
    let dialog_c = dialog.clone();
    cancel_btn.connect_clicked(move |_| dialog_c.close());

    // Confirm
    let dialog_c = dialog.clone();
    confirm_btn.connect_clicked(move |_| {
        dialog_c.close();
        on_confirm();
    });

    dialog.present();
}

// ── Mode editor widget ────────────────────────────────────────────────────────

struct ModeEditor {
    widget: gtk4::Box,
    octal_entry: gtk4::Entry,
    /// r/w/x checkboxes: [owner_r, owner_w, owner_x, group_r, group_w, group_x, other_r, other_w, other_x]
    checks: Vec<gtk4::CheckButton>,
}

impl ModeEditor {
    fn build() -> Self {
        let vbox = gtk4::Box::new(gtk4::Orientation::Vertical, 8);

        // Octal entry row
        let octal_row = gtk4::Box::new(gtk4::Orientation::Horizontal, 8);
        octal_row.append(&gtk4::Label::new(Some("Mode (octal):")));
        let octal_entry = gtk4::Entry::builder()
            .max_length(4)
            .width_chars(6)
            .placeholder_text("0755")
            .css_classes(["monospace"])
            .build();
        octal_row.append(&octal_entry);
        vbox.append(&octal_row);

        // Checkbox grid
        let grid = gtk4::Grid::builder()
            .row_spacing(4)
            .column_spacing(8)
            .build();

        // Header labels
        for (col, lbl) in ["r", "w", "x"].into_iter().enumerate() {
            grid.attach(
                &gtk4::Label::builder()
                    .label(lbl)
                    .css_classes(["dim-label", "monospace"])
                    .halign(gtk4::Align::Center)
                    .build(),
                col as i32 + 1,
                0,
                1,
                1,
            );
        }

        let groups = [
            ("Owner", "mode-owner"),
            ("Group", "mode-group"),
            ("Other", "mode-other"),
        ];
        let mut checks: Vec<gtk4::CheckButton> = Vec::with_capacity(9);

        for (row, (label, css)) in groups.into_iter().enumerate() {
            let lbl = gtk4::Label::builder()
                .label(label)
                .css_classes([css])
                .halign(gtk4::Align::Start)
                .build();
            grid.attach(&lbl, 0, row as i32 + 1, 1, 1);

            for col in 0..3 {
                let chk = gtk4::CheckButton::new();
                grid.attach(&chk, col + 1, row as i32 + 1, 1, 1);
                checks.push(chk);
            }
        }

        vbox.append(&grid);

        // Wire bidirectional sync
        let syncing: Rc<Cell<bool>> = Rc::new(Cell::new(false));

        // Checkboxes → octal entry
        for (i, chk) in checks.iter().enumerate() {
            let octal_entry_c = octal_entry.clone();
            let checks_c: Vec<_> = checks.clone();
            let syncing_c = syncing.clone();
            chk.connect_toggled(move |_| {
                if syncing_c.get() {
                    return;
                }
                syncing_c.set(true);
                let mode = mode_from_checks(&checks_c);
                octal_entry_c.set_text(&format!("{:04o}", mode));
                syncing_c.set(false);
                let _ = i; // used in closure capture
            });
        }

        // Octal entry → checkboxes
        {
            let checks_c = checks.clone();
            let syncing_c = syncing.clone();
            octal_entry.connect_changed(move |entry| {
                if syncing_c.get() {
                    return;
                }
                let text = entry.text();
                let trimmed = text.trim_start_matches('0');
                if let Ok(mode) =
                    u32::from_str_radix(if trimmed.is_empty() { "0" } else { trimmed }, 8)
                {
                    syncing_c.set(true);
                    apply_mode_to_checks(mode, &checks_c);
                    syncing_c.set(false);
                }
            });
        }

        Self {
            widget: vbox,
            octal_entry,
            checks,
        }
    }

    fn current_mode(&self) -> Option<u32> {
        let text = self.octal_entry.text();
        let trimmed = text.trim_start_matches('0');
        u32::from_str_radix(if trimmed.is_empty() { "0" } else { trimmed }, 8).ok()
    }

    fn set_mode(&self, mode: u32) {
        self.octal_entry.set_text(&format!("{:04o}", mode & 0o7777));
    }

    fn clear(&self) {
        self.octal_entry.set_text("");
        for chk in &self.checks {
            chk.set_active(false);
        }
    }
}

fn mode_from_checks(checks: &[gtk4::CheckButton]) -> u32 {
    let bits: [u32; 9] = [
        0o400, 0o200, 0o100, 0o040, 0o020, 0o010, 0o004, 0o002, 0o001,
    ];
    checks.iter().zip(bits.iter()).fold(
        0u32,
        |acc, (chk, &bit)| {
            if chk.is_active() { acc | bit } else { acc }
        },
    )
}

fn apply_mode_to_checks(mode: u32, checks: &[gtk4::CheckButton]) {
    let bits: [u32; 9] = [
        0o400, 0o200, 0o100, 0o040, 0o020, 0o010, 0o004, 0o002, 0o001,
    ];
    for (chk, &bit) in checks.iter().zip(bits.iter()) {
        chk.set_active(mode & bit != 0);
    }
}

// ── Management controller (cross-tab nav) ─────────────────────────────────────

pub struct ManagementController {
    pub navigate: Rc<dyn Fn(PathBuf)>,
}

impl ManagementController {
    pub fn navigate_to(&self, dir: PathBuf) {
        (self.navigate)(dir);
    }
}

// ── Main build ────────────────────────────────────────────────────────────────

pub fn build(state: SharedState) -> (gtk4::Widget, ManagementController) {
    let outer = gtk4::Box::new(gtk4::Orientation::Vertical, 0);
    outer.set_vexpand(true);
    outer.set_hexpand(true);

    // ── Path toolbar ──────────────────────────────────────────────────────────
    let path_entry = gtk4::Entry::builder()
        .text("/home")
        .hexpand(true)
        .placeholder_text("Directory to browse")
        .css_classes(["monospace"])
        .build();

    let up_btn = gtk4::Button::builder()
        .icon_name("go-up-symbolic")
        .tooltip_text("Parent directory")
        .build();

    let load_btn = gtk4::Button::builder()
        .label("Load")
        .css_classes(["suggested-action"])
        .build();

    let select_all_btn = gtk4::Button::builder().label("Select All").build();
    let clear_btn = gtk4::Button::builder().label("Clear").build();

    let sel_label = gtk4::Label::builder()
        .label("0 selected")
        .css_classes(["dim-label"])
        .build();

    let toolbar = gtk4::Box::new(gtk4::Orientation::Horizontal, 8);
    toolbar.set_margin_top(8);
    toolbar.set_margin_bottom(4);
    toolbar.set_margin_start(8);
    toolbar.set_margin_end(8);
    toolbar.append(&up_btn);
    toolbar.append(&path_entry);
    toolbar.append(&load_btn);
    toolbar.append(&select_all_btn);
    toolbar.append(&clear_btn);
    toolbar.append(&sel_label);
    outer.append(&toolbar);

    // ── Horizontal paned: file list | edit panel ──────────────────────────────
    let paned = gtk4::Paned::builder()
        .orientation(gtk4::Orientation::Horizontal)
        .position(500)
        .vexpand(true)
        .hexpand(true)
        .build();

    // ── Left: file list ───────────────────────────────────────────────────────
    let list_store = gio::ListStore::new::<PathObject>();
    let multi_sel = gtk4::MultiSelection::new(Some(list_store.clone()));

    // ── Shared directory loader ───────────────────────────────────────────────
    // Used by the Load button, up button, double-click navigation, apply reload,
    // and the ManagementController (called from Viewer's "Edit in Management").
    let load_dir_fn: Rc<dyn Fn(PathBuf)> = {
        let list_store = list_store.clone();
        let path_entry = path_entry.clone();
        Rc::new(move |dir: PathBuf| {
            path_entry.set_text(&dir.to_string_lossy());
            list_store.remove_all();
            let rd = match std::fs::read_dir(&dir) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("management: read_dir {dir:?}: {e}");
                    return;
                }
            };
            let mut paths: Vec<PathBuf> = rd.filter_map(|e| e.ok()).map(|e| e.path()).collect();
            paths.sort();
            for path in paths {
                if let Ok(entry) = stat_entry(&path) {
                    list_store.append(&PathObject::new(entry));
                }
            }
        })
    };

    let factory = gtk4::SignalListItemFactory::new();
    factory.connect_setup(|_, item| {
        let item = item.downcast_ref::<gtk4::ListItem>().unwrap();
        let row = gtk4::Box::new(gtk4::Orientation::Horizontal, 8);
        row.set_margin_top(4);
        row.set_margin_bottom(4);
        row.set_margin_start(8);
        row.set_margin_end(8);

        let name_lbl = gtk4::Label::builder()
            .halign(gtk4::Align::Start)
            .hexpand(true)
            .ellipsize(gtk4::pango::EllipsizeMode::Middle)
            .css_classes(["monospace"])
            .build();
        let mode_lbl = gtk4::Label::builder()
            .halign(gtk4::Align::End)
            .css_classes(["monospace", "dim-label"])
            .build();
        let owner_lbl = gtk4::Label::builder()
            .halign(gtk4::Align::End)
            .css_classes(["dim-label"])
            .build();

        row.append(&name_lbl);
        row.append(&mode_lbl);
        row.append(&owner_lbl);
        item.set_child(Some(&row));
    });

    factory.connect_bind(|_, item| {
        let item = item.downcast_ref::<gtk4::ListItem>().unwrap();
        if let Some(obj) = item.item().and_downcast::<PathObject>() {
            if let Some(entry) = obj.entry() {
                if let Some(row) = item.child().and_downcast::<gtk4::Box>() {
                    let name = entry
                        .path
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_else(|| entry.path.to_string_lossy().to_string());

                    if let Some(n) = row.first_child().and_downcast::<gtk4::Label>() {
                        let prefix = match entry.entry_type {
                            perms_core::domain::path_entry::EntryType::Directory => "📁 ",
                            perms_core::domain::path_entry::EntryType::Symlink => "🔗 ",
                            _ => "📄 ",
                        };
                        n.set_label(&format!("{prefix}{name}"));
                    }
                    if let Some(first) = row.first_child() {
                        if let Some(m) = first.next_sibling().and_downcast::<gtk4::Label>() {
                            m.set_label(&entry.mode.to_octal());
                        }
                        if let Some(first2) = first.next_sibling() {
                            if let Some(o) = first2.next_sibling().and_downcast::<gtk4::Label>() {
                                o.set_label(&format!("uid:{}", entry.owner_uid));
                            }
                        }
                    }
                }
            }
        }
    });

    let list_view = gtk4::ListView::builder()
        .model(&multi_sel)
        .factory(&factory)
        .vexpand(true)
        .hexpand(true)
        .show_separators(true)
        .build();

    // Double-click (or Enter) on a directory navigates into it.
    list_view.connect_activate({
        let load_dir_fn = load_dir_fn.clone();
        let list_store = list_store.clone();
        move |_, pos| {
            if let Some(obj) = list_store.item(pos).and_downcast::<PathObject>() {
                if let Some(entry) = obj.entry() {
                    if entry.is_dir() {
                        load_dir_fn(entry.path.clone());
                    }
                }
            }
        }
    });

    let list_scroll = gtk4::ScrolledWindow::builder()
        .vexpand(true)
        .hexpand(true)
        .child(&list_view)
        .build();

    paned.set_start_child(Some(&list_scroll));

    // ── Right: edit panel ─────────────────────────────────────────────────────
    let edit_scroll = gtk4::ScrolledWindow::builder()
        .vexpand(true)
        .hexpand(true)
        .hscrollbar_policy(gtk4::PolicyType::Never)
        .build();

    let edit_box = gtk4::Box::new(gtk4::Orientation::Vertical, 16);
    edit_box.set_margin_top(16);
    edit_box.set_margin_bottom(16);
    edit_box.set_margin_start(16);
    edit_box.set_margin_end(16);

    // Selection info
    let sel_info = gtk4::Label::builder()
        .label("Select files from the list to edit their permissions.")
        .css_classes(["dim-label"])
        .halign(gtk4::Align::Start)
        .wrap(true)
        .build();
    edit_box.append(&sel_info);

    // Mode editor
    let mode_group = libadwaita::PreferencesGroup::builder()
        .title("Mode")
        .build();
    let mode_editor = ModeEditor::build();
    let mode_editor = Rc::new(mode_editor);
    mode_group.add(&mode_editor.widget);
    edit_box.append(&mode_group);

    // Owner / Group entries
    let ownership_group = libadwaita::PreferencesGroup::builder()
        .title("Ownership")
        .build();

    let owner_row = libadwaita::ActionRow::builder()
        .title("Owner (username)")
        .build();
    let owner_entry = gtk4::Entry::builder()
        .placeholder_text("leave blank to keep")
        .hexpand(true)
        .valign(gtk4::Align::Center)
        .css_classes(["monospace"])
        .build();
    owner_row.add_suffix(&owner_entry);
    ownership_group.add(&owner_row);

    let group_row = libadwaita::ActionRow::builder()
        .title("Group (name)")
        .build();
    let group_entry = gtk4::Entry::builder()
        .placeholder_text("leave blank to keep")
        .hexpand(true)
        .valign(gtk4::Align::Center)
        .css_classes(["monospace"])
        .build();
    group_row.add_suffix(&group_entry);
    ownership_group.add(&group_row);

    edit_box.append(&ownership_group);

    // Options
    let opts_group = libadwaita::PreferencesGroup::builder()
        .title("Options")
        .build();

    let recursive_row = libadwaita::ActionRow::builder()
        .title("Recursive")
        .subtitle("Apply to all files and subdirectories")
        .build();
    let recursive_switch = gtk4::Switch::builder().valign(gtk4::Align::Center).build();
    recursive_row.add_suffix(&recursive_switch);
    opts_group.add(&recursive_row);

    let dryrun_row = libadwaita::ActionRow::builder()
        .title("Dry Run")
        .subtitle("Preview changes without applying them")
        .build();
    let dryrun_switch = gtk4::Switch::builder()
        .valign(gtk4::Align::Center)
        .active(false)
        .build();
    dryrun_row.add_suffix(&dryrun_switch);
    opts_group.add(&dryrun_row);

    edit_box.append(&opts_group);

    // Preview box (populated by Preview button)
    let preview_group = libadwaita::PreferencesGroup::builder()
        .title("Preview")
        .build();
    let preview_placeholder = libadwaita::ActionRow::builder()
        .title("Click 'Preview' to see what will change.")
        .css_classes(["dim-label"])
        .build();
    preview_group.add(&preview_placeholder);
    let preview_group = Rc::new(preview_group);
    edit_box.append(preview_group.as_ref());

    // Action buttons
    let btn_row = gtk4::Box::new(gtk4::Orientation::Horizontal, 8);
    btn_row.set_halign(gtk4::Align::End);
    let preview_btn = gtk4::Button::builder().label("Preview").build();
    let apply_btn = gtk4::Button::builder()
        .label("Apply")
        .css_classes(["suggested-action"])
        .build();
    btn_row.append(&preview_btn);
    btn_row.append(&apply_btn);
    edit_box.append(&btn_row);

    edit_scroll.set_child(Some(&edit_box));
    paned.set_end_child(Some(&edit_scroll));
    outer.append(&paned);

    // ── Bottom: audit log strip ───────────────────────────────────────────────
    let log_frame_label = gtk4::Label::builder()
        .label("Recent Changes (audit log)")
        .css_classes(["dim-label", "caption"])
        .halign(gtk4::Align::Start)
        .margin_start(8)
        .margin_top(4)
        .build();
    outer.append(&log_frame_label);

    let log_box = gtk4::Box::new(gtk4::Orientation::Vertical, 2);
    log_box.set_margin_start(8);
    log_box.set_margin_end(8);
    log_box.set_margin_bottom(8);

    let log_placeholder = gtk4::Label::builder()
        .label("No changes applied in this session.")
        .css_classes(["dim-label", "caption"])
        .halign(gtk4::Align::Start)
        .build();
    log_box.append(&log_placeholder);
    let log_box = Rc::new(log_box);
    outer.append(log_box.as_ref());

    // ── Shared state across closures ──────────────────────────────────────────
    // All selected PathEntry objects from the list
    let selected_entries: Rc<RefCell<Vec<PathEntry>>> = Rc::new(RefCell::new(Vec::new()));

    // ── Load / Up buttons ─────────────────────────────────────────────────────
    {
        let load_dir_fn = load_dir_fn.clone();
        let path_entry = path_entry.clone();
        load_btn.connect_clicked(move |_| {
            let root = PathBuf::from(path_entry.text().as_str());
            load_dir_fn(root);
        });
    }
    {
        let load_dir_fn = load_dir_fn.clone();
        let path_entry = path_entry.clone();
        up_btn.connect_clicked(move |_| {
            let current = PathBuf::from(path_entry.text().as_str());
            if let Some(parent) = current.parent() {
                load_dir_fn(parent.to_path_buf());
            }
        });
    }

    // ── Select All / Clear ────────────────────────────────────────────────────
    {
        let multi_sel = multi_sel.clone();
        select_all_btn.connect_clicked(move |_| {
            multi_sel.select_all();
        });
    }
    {
        let multi_sel = multi_sel.clone();
        clear_btn.connect_clicked(move |_| {
            multi_sel.unselect_all();
        });
    }

    // ── Selection changed → update edit panel ─────────────────────────────────
    {
        let selected_entries = selected_entries.clone();
        let sel_label = sel_label.clone();
        let sel_info = sel_info.clone();
        let mode_editor = mode_editor.clone();
        let owner_entry = owner_entry.clone();
        let group_entry = group_entry.clone();
        let multi_sel = multi_sel.clone();
        let list_store = list_store.clone();
        let state = state.clone();

        multi_sel.connect_selection_changed(move |model, _, _| {
            let n_total = model.n_items();
            let mut entries: Vec<PathEntry> = Vec::new();

            for i in 0..n_total {
                if model.is_selected(i) {
                    if let Some(obj) = list_store.item(i).and_downcast::<PathObject>() {
                        if let Some(e) = obj.entry() {
                            entries.push(e);
                        }
                    }
                }
            }

            let n = entries.len();
            sel_label.set_label(&format!("{n} selected"));

            if n == 0 {
                sel_info.set_label("Select files from the list to edit their permissions.");
                mode_editor.clear();
                owner_entry.set_text("");
                group_entry.set_text("");
            } else if n == 1 {
                let e = &entries[0];
                sel_info.set_label(&format!("Editing: {}", e.path.to_string_lossy()));
                mode_editor.set_mode(e.mode.0);

                // Resolve owner/group names
                let s = state.lock().unwrap();
                let owner_name = s
                    .userdb
                    .user_by_uid(e.owner_uid)
                    .map(|u| u.username.clone())
                    .unwrap_or_default();
                let group_name = s
                    .userdb
                    .group_by_gid(e.owner_gid)
                    .map(|g| g.name.clone())
                    .unwrap_or_default();
                drop(s);
                owner_entry.set_text(&owner_name);
                group_entry.set_text(&group_name);
            } else {
                sel_info.set_label(&format!("Editing {n} files — mode/owner applied to all."));
                // Use mode of first selected for initial value
                mode_editor.set_mode(entries[0].mode.0);
                owner_entry.set_text("");
                group_entry.set_text("");
            }

            *selected_entries.borrow_mut() = entries;
        });
    }

    // ── Preview button ────────────────────────────────────────────────────────
    {
        let selected_entries = selected_entries.clone();
        let mode_editor = mode_editor.clone();
        let preview_group = preview_group.clone();
        let dryrun_switch = dryrun_switch.clone();

        preview_btn.connect_clicked(move |_| {
            // Clear old preview rows
            while let Some(child) = preview_group.first_child() {
                // PreferencesGroup manages its own children — use the GLib object model
                // We remove by calling ListBox operations indirectly via reconstruction.
                // Simpler: mark placeholder visible/invisible, then add rows.
                // Actually PreferencesGroup doesn't expose remove().
                // We'll rebuild the group content via a Box inside.
                let _ = child;
                break;
            }

            let entries = selected_entries.borrow().clone();
            if entries.is_empty() {
                return;
            }

            let new_mode = mode_editor.current_mode();
            let is_dry = dryrun_switch.is_active();

            // Build preview rows: old mode → new mode for each selected entry
            // Since we can't remove children from PreferencesGroup directly,
            // we'll update the placeholder label with text summary.
            // A real impl would use a ListBox directly for preview.
            let mut lines: Vec<String> = Vec::new();
            for e in &entries {
                if let Some(nm) = new_mode {
                    let old = e.mode.to_octal();
                    let new_s = format!("{:04o}", nm & 0o7777);
                    if old != new_s {
                        lines.push(format!(
                            "{}: chmod {} → {}{}",
                            e.path.to_string_lossy(),
                            old,
                            new_s,
                            if is_dry { " (dry run)" } else { "" },
                        ));
                    } else {
                        lines.push(format!(
                            "{}: mode unchanged ({})",
                            e.path.to_string_lossy(),
                            old,
                        ));
                    }
                }
            }

            // Update the placeholder row's title with the first preview line
            // and subtitle count. This is a simplification — a proper implementation
            // would rebuild the group's content.
            // For now we replace the group title to show summary.
            let summary = if lines.is_empty() {
                "No changes to apply.".to_string()
            } else {
                format!("{} changes pending.\n{}", lines.len(), lines.join("\n"))
            };
            preview_group.set_description(Some(&summary));
        });
    }

    // ── Apply button ──────────────────────────────────────────────────────────
    {
        let selected_entries = selected_entries.clone();
        let mode_editor = mode_editor.clone();
        let owner_entry = owner_entry.clone();
        let group_entry = group_entry.clone();
        let recursive_switch = recursive_switch.clone();
        let dryrun_switch = dryrun_switch.clone();
        let state = state.clone();
        let log_box = log_box.clone();
        let load_dir_fn_reload = load_dir_fn.clone();
        let path_entry_reload = path_entry.clone();

        apply_btn.connect_clicked(move |btn| {
            let entries = selected_entries.borrow().clone();
            if entries.is_empty() {
                return;
            }

            let new_mode = mode_editor.current_mode();
            let owner_text = owner_entry.text().to_string();
            let group_text = group_entry.text().to_string();
            let recursive = recursive_switch.is_active();
            let dry_run = dryrun_switch.is_active();

            // Resolve owner/group names to IDs
            let (new_uid, new_gid) = {
                let s = state.lock().unwrap();
                let uid = if owner_text.is_empty() {
                    None
                } else {
                    match s.userdb.user_by_name(&owner_text) {
                        Some(u) => Some(u.uid),
                        None => {
                            // Try numeric
                            owner_text.parse::<u32>().ok()
                        }
                    }
                };
                let gid = if group_text.is_empty() {
                    None
                } else {
                    match s.userdb.group_by_name(&group_text) {
                        Some(g) => Some(g.gid),
                        None => group_text.parse::<u32>().ok(),
                    }
                };
                (uid, gid)
            };

            // Nothing to do?
            if new_mode.is_none() && new_uid.is_none() && new_gid.is_none() {
                return;
            }

            // Risk assessment
            let risk = assess_risk(&entries, new_mode, recursive);

            // Build human-readable summary for confirm dialog
            let n = entries.len();
            let mut summary_parts: Vec<String> = Vec::new();
            if let Some(m) = new_mode {
                summary_parts.push(format!("chmod {:04o}", m & 0o7777));
            }
            if let Some(uid) = new_uid {
                summary_parts.push(format!("chown uid:{uid}"));
            }
            if let Some(gid) = new_gid {
                summary_parts.push(format!("chgrp gid:{gid}"));
            }
            let ops = summary_parts.join(", ");

            let body = format!(
                "{ops} on {n} item{}{}.{}",
                if n == 1 { "" } else { "s" },
                if recursive { " (recursive)" } else { "" },
                if dry_run {
                    "\n\n[Dry run — no changes will be written]"
                } else {
                    ""
                },
            );

            // Get parent window for dialog
            let parent_win = btn.root().and_downcast::<gtk4::Window>();

            // Build apply closure
            let entries_c = entries.clone();
            let log_box_c = log_box.clone();
            let state_c = state.clone();
            let load_dir_fn_c = load_dir_fn_reload.clone();
            let path_entry_c = path_entry_reload.clone();

            let on_confirm = move || {
                let mut all_results: Vec<ChangeResult> = Vec::new();

                for entry in &entries_c {
                    let req = ChangeRequest {
                        path: entry.path.clone(),
                        new_mode,
                        new_uid,
                        new_gid,
                        recursive,
                        dry_run,
                    };
                    let mut results = apply_request(&req, entry);

                    // Write audit log
                    for res in &results {
                        let audit = AuditEntry {
                            ts: now_iso(),
                            path: res.path.clone(),
                            old_mode: res.old_mode.clone(),
                            new_mode: res.new_mode.clone(),
                            old_uid: res.old_uid,
                            new_uid: res.new_uid,
                            old_gid: res.old_gid,
                            new_gid: res.new_gid,
                            recursive,
                            dry_run,
                            effective_uid: effective_uid(),
                            result: res.error.as_deref().unwrap_or("ok").to_string(),
                        };
                        write_audit_entry(&audit);
                    }

                    all_results.append(&mut results);
                }

                // Update audit log strip UI
                let ok_count = all_results.iter().filter(|r| r.error.is_none()).count();
                let err_count = all_results.iter().filter(|r| r.error.is_some()).count();
                let log_summary = gtk4::Label::builder()
                    .label(&format!(
                        "[{}] {} ok, {} error(s){}",
                        now_iso(),
                        ok_count,
                        err_count,
                        if dry_run { " (dry run)" } else { "" },
                    ))
                    .css_classes(["caption", "monospace"])
                    .halign(gtk4::Align::Start)
                    .build();

                // Show errors if any
                if err_count > 0 {
                    log_summary.add_css_class("severity-high");
                }

                // Prepend to log_box (show newest first)
                log_box_c.prepend(&log_summary);

                // Reload directory listing to reflect changes
                if !dry_run {
                    let root = PathBuf::from(path_entry_c.text().as_str());
                    load_dir_fn_c(root);
                }
            };

            show_confirm_dialog(parent_win, body, risk, on_confirm);
        });
    }

    let controller = ManagementController {
        navigate: load_dir_fn,
    };
    (outer.upcast(), controller)
}
