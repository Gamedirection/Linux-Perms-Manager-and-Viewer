use std::path::PathBuf;

use gtk4::gio;
use gtk4::prelude::*;
use perms_core::domain::{AccessSource, Certainty};
use perms_core::engine::{effective_access, scanner::stat_entry};

use crate::app_state::SharedState;
use crate::model::PathObject;

pub fn build(state: SharedState) -> gtk4::Widget {
    let outer = gtk4::Box::new(gtk4::Orientation::Vertical, 0);
    outer.set_vexpand(true);
    outer.set_hexpand(true);

    // ── User selector toolbar ─────────────────────────────────────────────────
    let names: Vec<String> = {
        let s = state.lock().unwrap();
        let mut users: Vec<_> = s.userdb.all_users().collect();
        users.sort_by_key(|u| u.uid);
        users.iter().map(|u| format!("{} ({})", u.username, u.uid)).collect()
    };

    let str_list = gtk4::StringList::new(&names.iter().map(|s| s.as_str()).collect::<Vec<_>>());
    let user_dropdown = gtk4::DropDown::builder()
        .model(&str_list)
        .build();

    let scan_root_entry = gtk4::Entry::builder()
        .text("/home")
        .hexpand(true)
        .placeholder_text("Directory to scan for access")
        .css_classes(["monospace"])
        .build();

    let scan_btn = gtk4::Button::builder()
        .label("Show Access")
        .css_classes(["suggested-action"])
        .build();

    let toolbar = gtk4::Box::new(gtk4::Orientation::Horizontal, 8);
    toolbar.set_margin_top(8);
    toolbar.set_margin_bottom(4);
    toolbar.set_margin_start(8);
    toolbar.set_margin_end(8);
    toolbar.append(&gtk4::Label::new(Some("User:")));
    toolbar.append(&user_dropdown);
    toolbar.append(&gtk4::Label::new(Some("in")));
    toolbar.append(&scan_root_entry);
    toolbar.append(&scan_btn);

    outer.append(&toolbar);

    // ── Status label ──────────────────────────────────────────────────────────
    let status_label = gtk4::Label::builder()
        .label("Select a user and directory, then click 'Show Access'.")
        .css_classes(["dim-label"])
        .halign(gtk4::Align::Start)
        .margin_top(4)
        .margin_start(8)
        .margin_bottom(4)
        .build();
    outer.append(&status_label);

    // ── Results list ──────────────────────────────────────────────────────────
    // Use plain gtk::Box rows — libadwaita::ActionRow is a ListBoxRow subclass
    // and must NOT be placed inside gtk::ListView (no ListBox parent → assertion panic).
    let results_store = gio::ListStore::new::<PathObject>();
    let selection = gtk4::NoSelection::new(Some(results_store.clone()));

    let factory = gtk4::SignalListItemFactory::new();
    factory.connect_setup(|_, item| {
        let item = item.downcast_ref::<gtk4::ListItem>().unwrap();

        let row = gtk4::Box::new(gtk4::Orientation::Vertical, 2);
        row.set_margin_top(6);
        row.set_margin_bottom(6);
        row.set_margin_start(12);
        row.set_margin_end(12);

        let title = gtk4::Label::builder()
            .halign(gtk4::Align::Start)
            .css_classes(["monospace"])
            .build();
        let subtitle = gtk4::Label::builder()
            .halign(gtk4::Align::Start)
            .css_classes(["dim-label", "caption", "monospace"])
            .build();

        row.append(&title);
        row.append(&subtitle);
        item.set_child(Some(&row));
    });

    factory.connect_bind(|_, item| {
        let item = item.downcast_ref::<gtk4::ListItem>().unwrap();
        if let Some(obj) = item.item() {
            if let Ok(path_obj) = obj.downcast::<PathObject>() {
                if let Some(entry) = path_obj.entry() {
                    if let Some(row) = item.child().and_downcast::<gtk4::Box>() {
                        // title = first child label
                        if let Some(title) = row.first_child().and_downcast::<gtk4::Label>() {
                            title.set_label(&entry.path.to_string_lossy());
                        }
                        // subtitle = second child label
                        if let Some(title_w) = row.first_child() {
                            if let Some(sub) = title_w.next_sibling().and_downcast::<gtk4::Label>() {
                                sub.set_label(&format!(
                                    "{}  {}  uid:{}  gid:{}",
                                    entry.mode.to_symbolic(),
                                    entry.mode.to_octal(),
                                    entry.owner_uid,
                                    entry.owner_gid,
                                ));
                            }
                        }
                    }
                }
            }
        }
    });

    let list_view = gtk4::ListView::builder()
        .model(&selection)
        .factory(&factory)
        .vexpand(true)
        .hexpand(true)
        .show_separators(true)
        .build();

    let scroll = gtk4::ScrolledWindow::builder()
        .vexpand(true)
        .hexpand(true)
        .child(&list_view)
        .build();

    outer.append(&scroll);

    // ── Scan handler ──────────────────────────────────────────────────────────
    {
        let user_list = {
            let s = state.lock().unwrap();
            let mut users: Vec<_> = s.userdb.all_users().cloned().collect();
            users.sort_by_key(|u| u.uid);
            users
        };

        scan_btn.connect_clicked(move |_| {
            results_store.remove_all();

            let idx = user_dropdown.selected() as usize;
            let root = PathBuf::from(scan_root_entry.text().as_str());
            let Some(user) = user_list.get(idx) else { return; };

            status_label.set_label(&format!(
                "Scanning {} for '{}'…",
                root.display(), user.username
            ));

            let paths: Vec<PathBuf> = match std::fs::read_dir(&root) {
                Ok(rd) => rd.filter_map(|e| e.ok()).map(|e| e.path()).collect(),
                Err(e) => {
                    status_label.set_label(&format!("Error: {e}"));
                    return;
                }
            };

            let mut accessible = 0usize;
            let total = paths.len();

            for path in paths {
                if let Ok(entry) = stat_entry(&path) {
                    let access = effective_access::evaluate(user, &entry);
                    let granted = access.can_read == Certainty::Exact
                        && !matches!(access.source, AccessSource::Denied);
                    if granted || entry.owner_uid == user.uid {
                        results_store.append(&PathObject::new(entry));
                        accessible += 1;
                    }
                }
            }

            status_label.set_label(&format!(
                "{accessible} of {total} entries accessible to '{}' in {}",
                user.username,
                root.display()
            ));
        });
    }

    outer.upcast()
}
