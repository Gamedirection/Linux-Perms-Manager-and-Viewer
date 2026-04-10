use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;

use gtk4::gio;
use gtk4::prelude::*;
use perms_core::domain::Certainty;
use perms_core::domain::{AclTag, PathEntry, SystemGroup, SystemUser};
use perms_core::engine::effective_access;
use perms_core::engine::system_actions::{
    ElevationState, detect_elevation_state, list_directory_entries, probe_elevation,
};

use crate::app_state::SharedState;
use crate::components::build_detail_panel;
use crate::model::PathObject;

#[derive(Clone)]
enum ViewSubject {
    CurrentSession,
    Root,
    User(SystemUser),
    Group(SystemGroup),
}

pub fn build(
    state: SharedState,
    on_manage: Rc<RefCell<Option<Box<dyn Fn(PathBuf)>>>>,
    focus_mgmt: Rc<RefCell<Option<Box<dyn Fn()>>>>,
) -> (gtk4::Widget, Rc<dyn Fn(PathBuf)>) {
    let current_path: Rc<RefCell<PathBuf>> = Rc::new(RefCell::new(
        dirs_home().unwrap_or_else(|| PathBuf::from("/")),
    ));
    let root_view_enabled = Rc::new(RefCell::new(nix::unistd::geteuid().is_root()));

    let users = {
        let s = state.lock().unwrap();
        let mut users = s.userdb.all_users().cloned().collect::<Vec<_>>();
        users.sort_by_key(|user| user.uid);
        users
    };
    let groups = {
        let s = state.lock().unwrap();
        let mut groups = s.userdb.all_groups().cloned().collect::<Vec<_>>();
        groups.sort_by_key(|group| group.gid);
        groups
    };

    let user_names = users
        .iter()
        .map(|user| format!("{} ({})", user.username, user.uid))
        .collect::<Vec<_>>();
    let group_names = groups
        .iter()
        .map(|group| format!("{} ({})", group.name, group.gid))
        .collect::<Vec<_>>();
    let can_authenticate_root = detect_elevation_state() == ElevationState::Available;

    let current_selection: Rc<RefCell<Option<PathBuf>>> = Rc::new(RefCell::new(None));

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

    let subject_modes = gtk4::StringList::new(&["Current", "Root", "User", "Group"]);
    let subject_dropdown = gtk4::DropDown::builder()
        .model(&subject_modes)
        .selected(0)
        .build();

    let user_dropdown_model = gtk4::StringList::new(
        &user_names
            .iter()
            .map(|name| name.as_str())
            .collect::<Vec<_>>(),
    );
    let user_dropdown = gtk4::DropDown::builder()
        .model(&user_dropdown_model)
        .visible(false)
        .build();

    let group_dropdown_model = gtk4::StringList::new(
        &group_names
            .iter()
            .map(|name| name.as_str())
            .collect::<Vec<_>>(),
    );
    let group_dropdown = gtk4::DropDown::builder()
        .model(&group_dropdown_model)
        .visible(false)
        .build();

    let auth_root_btn = gtk4::Button::builder()
        .label("Authenticate Root View")
        .tooltip_text("Use the polkit helper to browse root-only paths")
        .css_classes(["suggested-action"])
        .build();
    if detect_elevation_state() == ElevationState::DirectRoot {
        auth_root_btn.set_label("Root Active");
        auth_root_btn.set_sensitive(false);
    } else if !can_authenticate_root {
        auth_root_btn.set_label("Root Helper Unavailable");
        auth_root_btn.set_sensitive(false);
    }

    let edit_in_mgmt_btn = gtk4::Button::builder()
        .label("Edit in Management")
        .tooltip_text("Open selected entry in the Management tab")
        .sensitive(false)
        .build();

    let path_bar = gtk4::Box::new(gtk4::Orientation::Horizontal, 6);
    path_bar.set_margin_top(8);
    path_bar.set_margin_bottom(4);
    path_bar.set_margin_start(8);
    path_bar.set_margin_end(8);
    path_bar.append(&up_button);
    path_bar.append(&path_entry);
    path_bar.append(&go_button);
    path_bar.append(&subject_dropdown);
    path_bar.append(&user_dropdown);
    path_bar.append(&group_dropdown);
    path_bar.append(&auth_root_btn);
    path_bar.append(&edit_in_mgmt_btn);

    let status_label = gtk4::Label::builder()
        .halign(gtk4::Align::Start)
        .css_classes(["dim-label"])
        .margin_start(8)
        .margin_end(8)
        .margin_bottom(4)
        .build();

    let store = gio::ListStore::new::<PathObject>();
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
        let name = entry
            .path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let label = gtk4::Label::builder()
            .label(&name)
            .halign(gtk4::Align::Start)
            .build();
        let row = gtk4::Box::new(gtk4::Orientation::Horizontal, 6);
        row.append(&icon_img);
        row.append(&label);
        row.upcast()
    });

    add_column(&column_view, "Mode", 120, |obj| {
        let entry = obj.entry().unwrap();
        gtk4::Label::builder()
            .label(format!(
                "{} {}",
                entry.mode.to_symbolic(),
                entry.mode.to_octal()
            ))
            .css_classes(["monospace"])
            .halign(gtk4::Align::Start)
            .build()
            .upcast()
    });

    {
        let state = state.clone();
        add_column(&column_view, "Owner", 140, move |obj| {
            let entry = obj.entry().unwrap();
            let label = state
                .lock()
                .unwrap()
                .userdb
                .user_by_uid(entry.owner_uid)
                .map(|user| format!("{} ({})", user.username, entry.owner_uid))
                .unwrap_or_else(|| entry.owner_uid.to_string());
            gtk4::Label::builder()
                .label(label)
                .halign(gtk4::Align::Start)
                .build()
                .upcast()
        });
    }

    {
        let state = state.clone();
        add_column(&column_view, "Group", 140, move |obj| {
            let entry = obj.entry().unwrap();
            let label = state
                .lock()
                .unwrap()
                .userdb
                .group_by_gid(entry.owner_gid)
                .map(|group| format!("{} ({})", group.name, entry.owner_gid))
                .unwrap_or_else(|| entry.owner_gid.to_string());
            gtk4::Label::builder()
                .label(label)
                .halign(gtk4::Align::Start)
                .build()
                .upcast()
        });
    }

    add_column(&column_view, "Flags", 90, |obj| {
        let entry = obj.entry().unwrap();
        let mut flags = Vec::new();
        if entry.special_bits.setuid {
            flags.push("suid");
        }
        if entry.special_bits.setgid {
            flags.push("sgid");
        }
        if entry.special_bits.sticky {
            flags.push("sticky");
        }
        if entry.has_acl() {
            flags.push("acl");
        }
        if entry.mode.is_world_writable() {
            flags.push("ww");
        }
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

    let detail_holder = gtk4::Box::new(gtk4::Orientation::Vertical, 0);
    detail_holder.set_vexpand(true);
    detail_holder.set_hexpand(true);
    detail_holder.set_size_request(380, -1);
    detail_holder.append(&empty_detail_label("Select an entry to inspect"));

    let split = gtk4::Paned::new(gtk4::Orientation::Horizontal);
    split.set_vexpand(true);
    split.set_hexpand(true);
    split.set_position(560);

    let left = gtk4::Box::new(gtk4::Orientation::Vertical, 0);
    left.append(&path_bar);
    left.append(&status_label);
    left.append(&list_scroll);
    split.set_start_child(Some(&left));
    split.set_end_child(Some(&detail_holder));
    split.set_resize_end_child(true);
    split.set_shrink_end_child(false);

    let load_dir = {
        let store = store.clone();
        let path_ref = current_path.clone();
        let path_entry_widget = path_entry.clone();
        let detail_holder = detail_holder.clone();
        let status_label = status_label.clone();
        let subject_dropdown = subject_dropdown.clone();
        let user_dropdown = user_dropdown.clone();
        let group_dropdown = group_dropdown.clone();
        let root_view_enabled = root_view_enabled.clone();
        let current_selection = current_selection.clone();
        let edit_in_mgmt_btn = edit_in_mgmt_btn.clone();
        let users = users.clone();
        let groups = groups.clone();
        Rc::new(move |dir: PathBuf| {
            store.remove_all();
            *current_selection.borrow_mut() = None;
            edit_in_mgmt_btn.set_sensitive(false);
            replace_detail_panel(
                &detail_holder,
                &empty_detail_label("Select an entry to inspect"),
            );

            path_entry_widget.set_text(&dir.to_string_lossy());
            *path_ref.borrow_mut() = dir.clone();

            let subject = selected_subject(
                subject_dropdown.selected(),
                user_dropdown.selected(),
                group_dropdown.selected(),
                &users,
                &groups,
            );

            let requires_privileged =
                !matches!(subject, ViewSubject::CurrentSession) && *root_view_enabled.borrow();

            if matches!(subject, ViewSubject::Root) && !*root_view_enabled.borrow() {
                status_label.set_label("Root view requires authentication through the helper.");
                replace_detail_panel(
                    &detail_holder,
                    &empty_detail_label("Authenticate root view to inspect root-only locations."),
                );
                return;
            }

            let entries = match list_directory_entries(&dir, requires_privileged) {
                Ok(entries) => entries,
                Err(err) => {
                    status_label.set_label(&format!("Cannot read {}: {err}", dir.display()));
                    replace_detail_panel(
                        &detail_holder,
                        &empty_detail_label(&format!("Cannot read directory:\n{err}")),
                    );
                    return;
                }
            };

            let filtered = filter_entries(entries, &subject);
            let total = filtered.len();
            for entry in filtered {
                store.append(&PathObject::new(entry));
            }

            let mode_label = match &subject {
                ViewSubject::CurrentSession => "current session".to_string(),
                ViewSubject::Root => "root".to_string(),
                ViewSubject::User(user) => format!("user {}", user.username),
                ViewSubject::Group(group) => format!("group {}", group.name),
            };
            let privilege_note = if requires_privileged {
                " via helper"
            } else {
                ""
            };
            status_label.set_label(&format!(
                "{total} entries visible in {} as {mode_label}{privilege_note}",
                dir.display()
            ));
        })
    };
    let reload_current = {
        let load = load_dir.clone();
        let current_path = current_path.clone();
        Rc::new(move || load(current_path.borrow().clone()))
    };

    let initial_path = current_path.borrow().clone();
    load_dir(initial_path);

    {
        let load = load_dir.clone();
        let path_entry_w = path_entry.clone();
        go_button.connect_clicked(move |_| {
            load(PathBuf::from(path_entry_w.text().as_str()));
        });
    }
    {
        let load = load_dir.clone();
        path_entry.connect_activate(move |entry| {
            load(PathBuf::from(entry.text().as_str()));
        });
    }
    {
        let load = load_dir.clone();
        let path_ref = current_path.clone();
        up_button.connect_clicked(move |_| {
            let path = path_ref.borrow().clone();
            if let Some(parent) = path.parent() {
                load(parent.to_path_buf());
            }
        });
    }
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
    {
        let detail_holder = detail_holder.clone();
        let state = state.clone();
        let current_selection = current_selection.clone();
        let edit_in_mgmt_btn = edit_in_mgmt_btn.clone();
        selection.connect_selection_changed(move |sel, _, _| {
            if let Some(obj) = sel.selected_item() {
                if let Ok(path_obj) = obj.downcast::<PathObject>() {
                    if let Some(entry) = path_obj.entry() {
                        *current_selection.borrow_mut() = Some(entry.path.clone());
                        edit_in_mgmt_btn.set_sensitive(true);

                        let detail_holder = detail_holder.clone();
                        let state = state.clone();
                        gtk4::glib::idle_add_local_once(move || {
                            let panel = build_detail_panel(&entry, &state.lock().unwrap().userdb);
                            replace_detail_panel(&detail_holder, &panel);
                        });
                        return;
                    }
                }
            }

            *current_selection.borrow_mut() = None;
            edit_in_mgmt_btn.set_sensitive(false);
        });
    }
    {
        let current_selection = current_selection.clone();
        edit_in_mgmt_btn.connect_clicked(move |_| {
            let path = match current_selection.borrow().clone() {
                Some(path) => path,
                None => return,
            };
            let dir = if path.is_dir() {
                path
            } else {
                path.parent().map(|p| p.to_path_buf()).unwrap_or(path)
            };
            if let Some(cb) = on_manage.borrow().as_ref() {
                cb(dir);
            }
            if let Some(cb) = focus_mgmt.borrow().as_ref() {
                cb();
            }
        });
    }
    {
        let reload_current = reload_current.clone();
        let user_dropdown = user_dropdown.clone();
        let group_dropdown = group_dropdown.clone();
        subject_dropdown.connect_selected_notify(move |dropdown| {
            let selected = dropdown.selected();
            user_dropdown.set_visible(selected == 2);
            group_dropdown.set_visible(selected == 3);
            reload_current();
        });
    }
    {
        let reload_current = reload_current.clone();
        user_dropdown.connect_selected_notify(move |_| {
            reload_current();
        });
    }
    {
        let reload_current = reload_current.clone();
        group_dropdown.connect_selected_notify(move |_| {
            reload_current();
        });
    }
    {
        let reload_current = reload_current.clone();
        let root_view_enabled = root_view_enabled.clone();
        let status_label = status_label.clone();
        let auth_root_btn = auth_root_btn.clone();
        auth_root_btn
            .clone()
            .connect_clicked(move |_| match probe_elevation() {
                Ok(_) => {
                    *root_view_enabled.borrow_mut() = true;
                    auth_root_btn.set_label("Root Authenticated");
                    auth_root_btn.set_sensitive(false);
                    status_label.set_label("Root helper authentication succeeded.");
                    reload_current();
                }
                Err(err) => {
                    status_label.set_label(&format!("Root authentication failed: {err}"));
                }
            });
    }

    let dir_navigate: Rc<dyn Fn(PathBuf)> = load_dir;
    (split.upcast(), dir_navigate)
}

fn empty_detail_label(text: &str) -> gtk4::Widget {
    gtk4::Label::builder()
        .label(text)
        .css_classes(["dim-label"])
        .valign(gtk4::Align::Center)
        .halign(gtk4::Align::Center)
        .vexpand(true)
        .wrap(true)
        .build()
        .upcast()
}

fn replace_detail_panel(detail_holder: &gtk4::Box, child: &impl IsA<gtk4::Widget>) {
    while let Some(existing) = detail_holder.first_child() {
        detail_holder.remove(&existing);
    }
    detail_holder.append(child);
}

fn filter_entries(entries: Vec<PathEntry>, subject: &ViewSubject) -> Vec<PathEntry> {
    entries
        .into_iter()
        .filter(|entry| match subject {
            ViewSubject::CurrentSession | ViewSubject::Root => true,
            ViewSubject::User(user) => {
                if user.uid == 0 {
                    true
                } else {
                    let access = effective_access::evaluate(user, entry);
                    matches!(access.can_read, Certainty::Exact)
                        || matches!(access.can_write, Certainty::Exact)
                        || matches!(access.can_execute, Certainty::Exact)
                        || entry.owner_uid == user.uid
                }
            }
            ViewSubject::Group(group) => group_has_any_access(group, entry),
        })
        .collect()
}

fn group_has_any_access(group: &SystemGroup, entry: &PathEntry) -> bool {
    if entry.mode.0 & 0o007 != 0 {
        return true;
    }

    if entry.owner_gid == group.gid && entry.mode.0 & 0o070 != 0 {
        return true;
    }

    entry.acl.as_ref().is_some_and(|acl| {
        acl.access_entries
            .iter()
            .any(|acl_entry| match acl_entry.tag {
                AclTag::Group(gid) if gid == group.gid => acl_entry.effective != 0,
                AclTag::GroupObj if entry.owner_gid == group.gid => acl_entry.effective != 0,
                _ => false,
            })
    })
}

fn selected_subject(
    mode_index: u32,
    user_index: u32,
    group_index: u32,
    users: &[SystemUser],
    groups: &[SystemGroup],
) -> ViewSubject {
    match mode_index {
        1 => ViewSubject::Root,
        2 => users
            .get(user_index as usize)
            .cloned()
            .map(ViewSubject::User)
            .unwrap_or(ViewSubject::CurrentSession),
        3 => groups
            .get(group_index as usize)
            .cloned()
            .map(ViewSubject::Group)
            .unwrap_or(ViewSubject::CurrentSession),
        _ => ViewSubject::CurrentSession,
    }
}

fn dirs_home() -> Option<PathBuf> {
    std::env::var("HOME").ok().map(PathBuf::from)
}

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
