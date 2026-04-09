use std::path::PathBuf;

use gtk4::gio;
use gtk4::prelude::*;
use libadwaita::prelude::*;
use perms_core::domain::Certainty;
#[allow(unused_imports)]
use perms_core::domain::AccessSource;
use perms_core::engine::{effective_access, scanner::stat_entry};

use crate::app_state::SharedState;
use crate::model::PathObject;

pub fn build(state: SharedState) -> gtk4::Widget {
    let outer = gtk4::Box::new(gtk4::Orientation::Vertical, 0);

    // ── User selector ─────────────────────────────────────────────────────────
    let names: Vec<String> = {
        let s = state.lock().unwrap();
        let mut users: Vec<_> = s.userdb.all_users().collect();
        users.sort_by_key(|u| u.uid);
        users.iter().map(|u| format!("{} ({})", u.username, u.uid)).collect()
    };

    let str_list = gtk4::StringList::new(&names.iter().map(|s| s.as_str()).collect::<Vec<_>>());
    let user_dropdown = gtk4::DropDown::builder()
        .model(&str_list)
        .hexpand(false)
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

    // ── Results list ──────────────────────────────────────────────────────────
    let results_store = gio::ListStore::new::<PathObject>();
    let selection = gtk4::NoSelection::new(Some(results_store.clone()));
    let list_view_factory = gtk4::SignalListItemFactory::new();

    list_view_factory.connect_setup(|_, item| {
        let item = item.downcast_ref::<gtk4::ListItem>().unwrap();
        let row = libadwaita::ActionRow::new();
        item.set_child(Some(&row));
    });

    list_view_factory.connect_bind(|_, item| {
        let item = item.downcast_ref::<gtk4::ListItem>().unwrap();
        if let Some(obj) = item.item() {
            if let Ok(path_obj) = obj.downcast::<PathObject>() {
                if let Some(entry) = path_obj.entry() {
                    if let Some(row) = item.child().and_downcast::<libadwaita::ActionRow>() {
                        row.set_title(&entry.path.to_string_lossy());
                        row.set_subtitle(&format!(
                            "{} {}  owner:{}  group:{}",
                            entry.mode.to_symbolic(),
                            entry.mode.to_octal(),
                            entry.owner_uid,
                            entry.owner_gid,
                        ));
                    }
                }
            }
        }
    });

    let list_view = gtk4::ListView::builder()
        .model(&selection)
        .factory(&list_view_factory)
        .build();

    let status_label = gtk4::Label::builder()
        .label("Select a user and directory, then click 'Show Access'.")
        .css_classes(["dim-label"])
        .halign(gtk4::Align::Center)
        .margin_top(12)
        .build();

    let scroll = gtk4::ScrolledWindow::builder()
        .vexpand(true)
        .hexpand(true)
        .child(&list_view)
        .build();

    outer.append(&status_label);
    outer.append(&scroll);

    // ── Scan handler ──────────────────────────────────────────────────────────
    {
        let state = state.clone();
        let results_store = results_store.clone();
        let status_label = status_label.clone();
        let user_store_list = {
            let s = state.lock().unwrap();
            let mut users: Vec<_> = s.userdb.all_users().cloned().collect();
            users.sort_by_key(|u| u.uid);
            users
        };

        scan_btn.connect_clicked(move |_| {
            results_store.remove_all();
            let idx = user_dropdown.selected() as usize;
            let root = PathBuf::from(scan_root_entry.text().as_str());

            let Some(user) = user_store_list.get(idx) else { return; };

            status_label.set_label(&format!(
                "Scanning {} for access by '{}'...",
                root.display(),
                user.username
            ));

            let mut accessible = 0usize;
            let mut total = 0usize;

            // Shallow scan of root directory (non-recursive for responsiveness)
            let paths: Vec<PathBuf> = match std::fs::read_dir(&root) {
                Ok(rd) => rd.filter_map(|e| e.ok()).map(|e| e.path()).collect(),
                Err(e) => {
                    status_label.set_label(&format!("Error: {e}"));
                    return;
                }
            };

            for path in paths {
                match stat_entry(&path) {
                    Ok(entry) => {
                        total += 1;
                        let access = effective_access::evaluate(user, &entry);
                        let can_read = access.can_read == Certainty::Exact
                            && !matches!(
                                access.source,
                                perms_core::domain::AccessSource::Denied
                            );
                        if can_read || entry.owner_uid == user.uid {
                            results_store.append(&PathObject::new(entry));
                            accessible += 1;
                        }
                    }
                    Err(_) => {}
                }
            }

            status_label.set_label(&format!(
                "{} of {} entries accessible to '{}' in {}",
                accessible,
                total,
                user.username,
                root.display()
            ));
        });
    }

    outer.upcast()
}
