use std::cell::RefCell;
use std::rc::Rc;

use gtk4::gio;
use gtk4::prelude::*;
use libadwaita::prelude::*;
use perms_core::domain::{SystemGroup, UserDb};
use perms_core::engine::system_actions::{
    CreateGroupRequest, CreateUserRequest, create_group, create_user,
};

use crate::app_state::{SharedState, reload_userdb};

pub fn build(state: SharedState) -> gtk4::Widget {
    let outer = gtk4::Box::new(gtk4::Orientation::Vertical, 0);
    outer.set_vexpand(true);
    outer.set_hexpand(true);

    let status_label = gtk4::Label::builder()
        .label("Review groups, memberships, and create new users/groups.")
        .halign(gtk4::Align::Start)
        .css_classes(["dim-label"])
        .margin_top(8)
        .margin_start(8)
        .margin_end(8)
        .margin_bottom(4)
        .build();

    let refresh_btn = gtk4::Button::builder().label("Refresh Groups").build();
    let toolbar = gtk4::Box::new(gtk4::Orientation::Horizontal, 8);
    toolbar.set_margin_top(8);
    toolbar.set_margin_bottom(4);
    toolbar.set_margin_start(8);
    toolbar.set_margin_end(8);
    toolbar.append(&refresh_btn);

    outer.append(&toolbar);
    outer.append(&status_label);

    let groups = Rc::new(RefCell::new(Vec::<SystemGroup>::new()));
    let group_store = gio::ListStore::new::<gtk4::StringObject>();
    let selection = gtk4::SingleSelection::new(Some(group_store.clone()));

    let factory = gtk4::SignalListItemFactory::new();
    factory.connect_setup(|_, item| {
        let item = item.downcast_ref::<gtk4::ListItem>().unwrap();
        let label = gtk4::Label::builder()
            .halign(gtk4::Align::Start)
            .margin_top(8)
            .margin_bottom(8)
            .margin_start(12)
            .margin_end(12)
            .css_classes(["monospace"])
            .build();
        item.set_child(Some(&label));
    });
    factory.connect_bind(|_, item| {
        let item = item.downcast_ref::<gtk4::ListItem>().unwrap();
        if let Some(string) = item.item().and_downcast::<gtk4::StringObject>() {
            if let Some(label) = item.child().and_downcast::<gtk4::Label>() {
                label.set_label(&string.string());
            }
        }
    });

    let group_list = gtk4::ListView::builder()
        .model(&selection)
        .factory(&factory)
        .vexpand(true)
        .hexpand(true)
        .show_separators(true)
        .build();

    let left = gtk4::ScrolledWindow::builder()
        .child(&group_list)
        .vexpand(true)
        .hexpand(true)
        .build();

    let detail_holder = gtk4::Box::new(gtk4::Orientation::Vertical, 0);
    detail_holder.set_vexpand(true);
    detail_holder.set_hexpand(true);
    detail_holder.append(&placeholder("Select a group to inspect memberships."));

    let split = gtk4::Paned::new(gtk4::Orientation::Horizontal);
    split.set_position(320);
    split.set_start_child(Some(&left));
    split.set_end_child(Some(&detail_holder));
    split.set_vexpand(true);
    split.set_hexpand(true);

    outer.append(&split);

    let create_box = gtk4::Box::new(gtk4::Orientation::Horizontal, 12);
    create_box.set_margin_top(8);
    create_box.set_margin_bottom(12);
    create_box.set_margin_start(12);
    create_box.set_margin_end(12);

    let group_group = libadwaita::PreferencesGroup::builder()
        .title("Create Group")
        .build();
    let group_name_row = libadwaita::EntryRow::builder().title("Group name").build();
    let group_system_row = libadwaita::SwitchRow::builder()
        .title("System group")
        .subtitle("Use gid allocation for system accounts")
        .build();
    let create_group_btn = gtk4::Button::builder()
        .label("Create Group")
        .css_classes(["suggested-action"])
        .halign(gtk4::Align::End)
        .build();
    let create_group_row = libadwaita::ActionRow::builder().title("").build();
    create_group_row.add_suffix(&create_group_btn);
    group_group.add(&group_name_row);
    group_group.add(&group_system_row);
    group_group.add(&create_group_row);

    let user_group = libadwaita::PreferencesGroup::builder()
        .title("Create User")
        .build();
    let username_row = libadwaita::EntryRow::builder().title("Username").build();
    let primary_group_row = libadwaita::EntryRow::builder()
        .title("Primary group")
        .text("")
        .build();
    let home_row = libadwaita::EntryRow::builder()
        .title("Home directory")
        .text("")
        .build();
    let shell_row = libadwaita::EntryRow::builder()
        .title("Shell")
        .text("/bin/bash")
        .build();
    let system_user_row = libadwaita::SwitchRow::builder()
        .title("System user")
        .subtitle("Use system uid range")
        .build();
    let create_user_btn = gtk4::Button::builder()
        .label("Create User")
        .css_classes(["suggested-action"])
        .halign(gtk4::Align::End)
        .build();
    let create_user_row = libadwaita::ActionRow::builder().title("").build();
    create_user_row.add_suffix(&create_user_btn);
    user_group.add(&username_row);
    user_group.add(&primary_group_row);
    user_group.add(&home_row);
    user_group.add(&shell_row);
    user_group.add(&system_user_row);
    user_group.add(&create_user_row);

    create_box.append(&group_group);
    create_box.append(&user_group);
    outer.append(&create_box);

    let refresh_groups: Rc<dyn Fn()> = {
        let state = state.clone();
        let groups = groups.clone();
        let group_store = group_store.clone();
        let selection = selection.clone();
        let detail_holder = detail_holder.clone();
        let status_label = status_label.clone();
        Rc::new(move || {
            let _ = reload_userdb(&state);
            let userdb = state.lock().unwrap().userdb.clone();
            let group_values = userdb.all_groups_sorted();
            let labels = group_values
                .iter()
                .map(|group| format!("{} ({})", group.name, group.gid))
                .collect::<Vec<_>>();
            groups.replace(group_values);
            group_store.remove_all();
            for label in labels {
                group_store.append(&gtk4::StringObject::new(&label));
            }
            if selection.n_items() > 0 {
                selection.set_selected(0);
            } else {
                replace_detail(&detail_holder, &placeholder("No groups found."));
            }
            status_label.set_label(&format!("{} groups loaded.", groups.borrow().len()));
        })
    };
    refresh_groups();

    {
        let refresh_groups = refresh_groups.clone();
        refresh_btn.connect_clicked(move |_| refresh_groups());
    }
    {
        let state = state.clone();
        let groups = groups.clone();
        let detail_holder = detail_holder.clone();
        selection.connect_selection_changed(move |selection, _, _| {
            let index = selection.selected() as usize;
            let group = groups.borrow().get(index).cloned();
            let Some(group) = group else {
                return;
            };
            let userdb = state.lock().unwrap().userdb.clone();
            let panel = build_group_panel(&group, &userdb);
            replace_detail(&detail_holder, &panel);
        });
    }
    {
        let status_label = status_label.clone();
        let refresh_groups = refresh_groups.clone();
        create_group_btn.connect_clicked(move |_| {
            let name = group_name_row.text().trim().to_string();
            if name.is_empty() {
                status_label.set_label("Group name is required.");
                return;
            }
            let request = CreateGroupRequest {
                name: name.clone(),
                system: group_system_row.is_active(),
            };
            match create_group(&request) {
                Ok(_) => {
                    group_name_row.set_text("");
                    group_system_row.set_active(false);
                    status_label.set_label(&format!("Created group '{name}'."));
                    refresh_groups();
                }
                Err(err) => status_label.set_label(&format!("Create group failed: {err}")),
            }
        });
    }
    {
        let status_label = status_label.clone();
        let refresh_groups = refresh_groups.clone();
        create_user_btn.connect_clicked(move |_| {
            let username = username_row.text().trim().to_string();
            if username.is_empty() {
                status_label.set_label("Username is required.");
                return;
            }
            let request = CreateUserRequest {
                username: username.clone(),
                primary_group: optional_text(&primary_group_row),
                home_dir: optional_text(&home_row),
                shell: optional_text(&shell_row),
                system: system_user_row.is_active(),
            };
            match create_user(&request) {
                Ok(_) => {
                    username_row.set_text("");
                    primary_group_row.set_text("");
                    home_row.set_text("");
                    shell_row.set_text("/bin/bash");
                    system_user_row.set_active(false);
                    status_label.set_label(&format!("Created user '{username}'."));
                    refresh_groups();
                }
                Err(err) => status_label.set_label(&format!("Create user failed: {err}")),
            }
        });
    }

    outer.upcast()
}

fn build_group_panel(group: &SystemGroup, userdb: &UserDb) -> gtk4::ScrolledWindow {
    let scroll = gtk4::ScrolledWindow::builder()
        .hscrollbar_policy(gtk4::PolicyType::Never)
        .vscrollbar_policy(gtk4::PolicyType::Automatic)
        .vexpand(true)
        .hexpand(true)
        .build();

    let vbox = gtk4::Box::new(gtk4::Orientation::Vertical, 12);
    vbox.set_margin_top(16);
    vbox.set_margin_bottom(16);
    vbox.set_margin_start(16);
    vbox.set_margin_end(16);

    let header = gtk4::Label::builder()
        .label(&format!("{} ({})", group.name, group.gid))
        .halign(gtk4::Align::Start)
        .css_classes(["title-3"])
        .build();
    vbox.append(&header);

    let members_group = libadwaita::PreferencesGroup::builder()
        .title("Members")
        .description("Primary memberships are inferred from passwd; supplementary memberships come from group assignments.")
        .build();
    let members = userdb.resolved_group_members(group);
    if members.is_empty() {
        members_group.add(&plain_row("(no members)", ""));
    } else {
        for (user, is_primary) in members {
            members_group.add(&plain_row(
                &format!("{} ({})", user.username, user.uid),
                if is_primary {
                    "primary"
                } else {
                    "supplementary"
                },
            ));
        }
    }
    vbox.append(&members_group);

    scroll.set_child(Some(&vbox));
    scroll
}

fn replace_detail(holder: &gtk4::Box, widget: &impl IsA<gtk4::Widget>) {
    while let Some(child) = holder.first_child() {
        holder.remove(&child);
    }
    holder.append(widget);
}

fn placeholder(text: &str) -> gtk4::Widget {
    gtk4::Label::builder()
        .label(text)
        .wrap(true)
        .vexpand(true)
        .valign(gtk4::Align::Center)
        .halign(gtk4::Align::Center)
        .css_classes(["dim-label"])
        .build()
        .upcast()
}

fn plain_row(title: &str, subtitle: &str) -> libadwaita::ActionRow {
    libadwaita::ActionRow::builder()
        .title(title)
        .subtitle(subtitle)
        .build()
}

fn optional_text(row: &libadwaita::EntryRow) -> Option<String> {
    let value = row.text().trim().to_string();
    if value.is_empty() { None } else { Some(value) }
}
