use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;

use gtk4::gio;
use gtk4::prelude::*;
use perms_core::engine::scanner::stat_entry;

use crate::app_state::SharedState;
use crate::components::build_detail_panel;
use crate::model::PathObject;

/// Build the directory browser view.
/// Returns (root_widget, navigate_to_fn) so the parent can drive navigation.
pub fn build(state: SharedState) -> gtk4::Widget {
    let current_path: Rc<RefCell<PathBuf>> = Rc::new(RefCell::new(
        dirs_home().unwrap_or_else(|| PathBuf::from("/")),
    ));

    // ── Path bar ──────────────────────────────────────────────────────────────
    let path_entry = gtk4::Entry::builder()
        .hexpand(true)
        .placeholder_text("/path/to/browse")
        .css_classes(["monospace"])
        .build();
    path_entry.set_text(&current_path.borrow().to_string_lossy());

    let go_button = gtk4::Button::builder()
        .label("Go")
        .css_classes(["suggested-action"])
        .build();

    let up_button = gtk4::Button::builder()
        .icon_name("go-up-symbolic")
        .tooltip_text("Parent directory")
        .build();

    let path_bar = gtk4::Box::new(gtk4::Orientation::Horizontal, 6);
    path_bar.set_margin_top(8);
    path_bar.set_margin_bottom(4);
    path_bar.set_margin_start(8);
    path_bar.set_margin_end(8);
    path_bar.append(&up_button);
    path_bar.append(&path_entry);
    path_bar.append(&go_button);

    // ── List model ────────────────────────────────────────────────────────────
    let store = gio::ListStore::new::<PathObject>();

    // ── Column view ───────────────────────────────────────────────────────────
    let selection = gtk4::SingleSelection::new(Some(store.clone()));
    let column_view = gtk4::ColumnView::builder()
        .model(&selection)
        .hexpand(true)
        .vexpand(true)
        .show_row_separators(true)
        .show_column_separators(true)
        .build();

    add_column(&column_view, "Name", 280, |obj| {
        let entry = obj.entry().unwrap();
        let icon = match entry.entry_type {
            perms_core::domain::EntryType::Directory => "folder-symbolic",
            perms_core::domain::EntryType::Symlink => "emblem-symbolic-link",
            _ => "text-x-generic-symbolic",
        };
        let icon_img = gtk4::Image::from_icon_name(icon);
        let name = entry.path.file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let label = gtk4::Label::builder().label(&name).halign(gtk4::Align::Start).build();
        let row = gtk4::Box::new(gtk4::Orientation::Horizontal, 6);
        row.append(&icon_img);
        row.append(&label);
        row.upcast()
    });

    add_column(&column_view, "Mode", 120, |obj| {
        let entry = obj.entry().unwrap();
        gtk4::Label::builder()
            .label(format!("{} {}", entry.mode.to_symbolic(), entry.mode.to_octal()))
            .css_classes(["monospace"])
            .halign(gtk4::Align::Start)
            .build()
            .upcast()
    });

    add_column(&column_view, "Owner", 100, |obj| {
        let entry = obj.entry().unwrap();
        gtk4::Label::builder()
            .label(entry.owner_uid.to_string())
            .halign(gtk4::Align::Start)
            .build()
            .upcast()
    });

    add_column(&column_view, "Group", 100, |obj| {
        let entry = obj.entry().unwrap();
        gtk4::Label::builder()
            .label(entry.owner_gid.to_string())
            .halign(gtk4::Align::Start)
            .build()
            .upcast()
    });

    add_column(&column_view, "Flags", 80, |obj| {
        let entry = obj.entry().unwrap();
        let mut flags = Vec::new();
        if entry.special_bits.setuid { flags.push("suid"); }
        if entry.special_bits.setgid { flags.push("sgid"); }
        if entry.special_bits.sticky { flags.push("sticky"); }
        if entry.has_acl()           { flags.push("acl"); }
        if entry.mode.is_world_writable() { flags.push("⚠ww"); }
        gtk4::Label::builder()
            .label(flags.join(" "))
            .css_classes(["monospace"])
            .halign(gtk4::Align::Start)
            .build()
            .upcast()
    });

    let list_scroll = gtk4::ScrolledWindow::builder()
        .hscrollbar_policy(gtk4::PolicyType::Automatic)
        .vscrollbar_policy(gtk4::PolicyType::Automatic)
        .hexpand(true)
        .vexpand(true)
        .child(&column_view)
        .build();

    // ── Detail panel placeholder ──────────────────────────────────────────────
    let detail_holder = gtk4::Box::new(gtk4::Orientation::Vertical, 0);
    detail_holder.set_size_request(380, -1);
    let no_selection_label = gtk4::Label::builder()
        .label("Select an entry to inspect")
        .css_classes(["dim-label"])
        .valign(gtk4::Align::Center)
        .halign(gtk4::Align::Center)
        .vexpand(true)
        .build();
    detail_holder.append(&no_selection_label);

    // ── Split view ────────────────────────────────────────────────────────────
    let split = gtk4::Paned::new(gtk4::Orientation::Horizontal);
    split.set_position(560);

    let left = gtk4::Box::new(gtk4::Orientation::Vertical, 0);
    left.append(&path_bar);
    left.append(&list_scroll);
    split.set_start_child(Some(&left));
    split.set_end_child(Some(&detail_holder));
    split.set_resize_end_child(true);
    split.set_shrink_end_child(false);

    // ── Load directory ────────────────────────────────────────────────────────
    let _state_clone = state.clone();
    let store_clone = store.clone();
    let path_clone = current_path.clone();

    let load_dir = {
        let store = store_clone.clone();
        let path_ref = path_clone.clone();
        let path_entry_widget = path_entry.clone();
        let detail_holder = detail_holder.clone();
        Rc::new(move |dir: PathBuf| {
            store.remove_all();

            // Clear detail panel
            while let Some(child) = detail_holder.first_child() {
                detail_holder.remove(&child);
            }
            detail_holder.append(&gtk4::Label::builder()
                .label("Select an entry to inspect")
                .css_classes(["dim-label"])
                .valign(gtk4::Align::Center)
                .halign(gtk4::Align::Center)
                .vexpand(true)
                .build());

            path_entry_widget.set_text(&dir.to_string_lossy());
            *path_ref.borrow_mut() = dir.clone();

            match std::fs::read_dir(&dir) {
                Ok(rd) => {
                    let mut entries: Vec<_> = rd
                        .filter_map(|e| e.ok())
                        .map(|e| e.path())
                        .collect();
                    entries.sort();

                    for path in entries {
                        match stat_entry(&path) {
                            Ok(pe) => store.append(&PathObject::new(pe)),
                            Err(_) => {}
                        }
                    }
                }
                Err(e) => {
                    // Show error in detail panel
                    while let Some(child) = detail_holder.first_child() {
                        detail_holder.remove(&child);
                    }
                    detail_holder.append(&gtk4::Label::builder()
                        .label(format!("Cannot read directory:\n{e}"))
                        .css_classes(["dim-label", "error-label"])
                        .valign(gtk4::Align::Center)
                        .halign(gtk4::Align::Center)
                        .vexpand(true)
                        .wrap(true)
                        .build());
                }
            }
        })
    };

    // Initial load — extract to a local so the Ref<> drops before load_dir runs,
    // otherwise borrow_mut() inside load_dir panics (RefCell already borrowed).
    let initial_path = current_path.borrow().clone();
    load_dir(initial_path);

    // Go button / Enter key
    {
        let load = load_dir.clone();
        let path_entry_w = path_entry.clone();
        go_button.connect_clicked(move |_| {
            let p = PathBuf::from(path_entry_w.text().as_str());
            load(p);
        });
    }
    {
        let load = load_dir.clone();
        path_entry.connect_activate(move |e| {
            let p = PathBuf::from(e.text().as_str());
            load(p);
        });
    }

    // Up button
    {
        let load = load_dir.clone();
        let path_ref = current_path.clone();
        up_button.connect_clicked(move |_| {
            let p = path_ref.borrow().clone();
            if let Some(parent) = p.parent() {
                load(parent.to_path_buf());
            }
        });
    }

    // Double-click to navigate into directory
    {
        let load = load_dir.clone();
        let selection_clone = selection.clone();
        column_view.connect_activate(move |_, pos| {
            if let Some(obj) = selection_clone.item(pos) {
                if let Ok(path_obj) = obj.downcast::<PathObject>() {
                    if let Some(entry) = path_obj.entry() {
                        if entry.is_dir() {
                            load(entry.path.clone());
                        }
                    }
                }
            }
        });
    }

    // Single-click to show detail
    {
        let detail_holder = detail_holder.clone();
        let state = state.clone();
        selection.connect_selection_changed(move |sel, _, _| {
            if let Some(obj) = sel.selected_item() {
                if let Ok(path_obj) = obj.downcast::<PathObject>() {
                    if let Some(entry) = path_obj.entry() {
                        while let Some(child) = detail_holder.first_child() {
                            detail_holder.remove(&child);
                        }
                        let userdb_ref = state.lock().unwrap();
                        let panel = build_detail_panel(&entry, &userdb_ref.userdb);
                        drop(userdb_ref);
                        detail_holder.append(&panel);
                    }
                }
            }
        });
    }

    split.upcast()
}

fn dirs_home() -> Option<PathBuf> {
    std::env::var("HOME").ok().map(PathBuf::from)
}

/// Add a column to a ColumnView using a SignalListItemFactory.
fn add_column<F>(cv: &gtk4::ColumnView, title: &str, width: i32, build_widget: F)
where
    F: Fn(PathObject) -> gtk4::Widget + 'static,
{
    let factory = gtk4::SignalListItemFactory::new();
    factory.connect_setup(|_, item| {
        let item = item.downcast_ref::<gtk4::ListItem>().unwrap();
        let label = gtk4::Label::new(None);
        item.set_child(Some(&label));
    });
    factory.connect_bind(move |_, item| {
        let item = item.downcast_ref::<gtk4::ListItem>().unwrap();
        if let Some(obj) = item.item() {
            if let Ok(path_obj) = obj.downcast::<PathObject>() {
                let widget = build_widget(path_obj);
                item.set_child(Some(&widget));
            }
        }
    });

    let col = gtk4::ColumnViewColumn::builder()
        .title(title)
        .factory(&factory)
        .fixed_width(width)
        .resizable(true)
        .build();

    cv.append_column(&col);
}
