use gtk4::prelude::*;
use libadwaita::prelude::*;
use perms_core::domain::{PathEntry, SystemGroup, SystemUser, UserDb};
use perms_core::engine::effective_access;

use crate::components::perm_badge::{coloured_dot, mode_badge_colored};

/// Build the right-hand detail panel for a selected PathEntry.
pub fn build_detail_panel(entry: &PathEntry, userdb: &UserDb) -> gtk4::ScrolledWindow {
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

    // ── Path header ──────────────────────────────────────────────────────────
    let path_label = gtk4::Label::builder()
        .label(entry.path.to_string_lossy().as_ref())
        .css_classes(["title-3", "monospace"])
        .halign(gtk4::Align::Start)
        .wrap(true)
        .build();
    vbox.append(&path_label);

    if let Some(sens) = &entry.sensitive_label {
        let sens_label = gtk4::Label::builder()
            .label(format!("⚠ {}", sens.label))
            .css_classes(["sensitive-badge"])
            .halign(gtk4::Align::Start)
            .build();
        vbox.append(&sens_label);
    }

    // ── Ownership and Permissions group ───────────────────────────────────────
    let meta_group = libadwaita::PreferencesGroup::builder()
        .title("Ownership and Permissions")
        .build();

    // Pre-resolve names and clone user/group for click handlers
    let owner_user = userdb.user_by_uid(entry.owner_uid).cloned();
    let owner_group = userdb.group_by_gid(entry.owner_gid).cloned();

    let owner_name = owner_user
        .as_ref()
        .map(|u| format!("{} ({})", u.username, u.uid))
        .unwrap_or_else(|| format!("⚠ Unknown UID {}", entry.owner_uid));

    let group_name = owner_group
        .as_ref()
        .map(|g| format!("{} ({})", g.name, g.gid))
        .unwrap_or_else(|| format!("⚠ Unknown GID {}", entry.owner_gid));

    // Clickable owner row
    {
        let row = libadwaita::ActionRow::builder()
            .title("Owner")
            .subtitle(&owner_name)
            .activatable(true)
            .build();
        row.add_suffix(&gtk4::Image::from_icon_name("go-next-symbolic"));
        let user_data = owner_user.clone();
        // clone all groups so we can show supplementary memberships
        let all_groups = userdb.all_groups_sorted();
        row.connect_activated(move |r| {
            let win = r.root().and_downcast::<gtk4::Window>();
            show_user_dialog(win.as_ref(), user_data.as_ref(), &all_groups);
        });
        meta_group.add(&row);
    }

    // Clickable group row
    {
        let row = libadwaita::ActionRow::builder()
            .title("Group")
            .subtitle(&group_name)
            .activatable(true)
            .build();
        row.add_suffix(&gtk4::Image::from_icon_name("go-next-symbolic"));
        let group_data = owner_group.clone();
        let userdb = userdb.clone();
        row.connect_activated(move |r| {
            let win = r.root().and_downcast::<gtk4::Window>();
            show_group_dialog(win.as_ref(), group_data.as_ref(), &userdb);
        });
        meta_group.add(&row);
    }

    meta_group.add(&plain_row("Type", &format!("{:?}", entry.entry_type)));

    // Mode row — colorized badge + rich tooltip
    let mode_row = libadwaita::ActionRow::builder().title("Mode").build();
    let tooltip = mode_tooltip(entry, &owner_name, &group_name);
    let badge = mode_badge_colored(entry.mode);
    badge.set_tooltip_text(Some(&tooltip));
    mode_row.set_tooltip_text(Some(&tooltip));
    mode_row.add_suffix(&badge);
    meta_group.add(&mode_row);

    if entry.special_bits.setuid || entry.special_bits.setgid || entry.special_bits.sticky {
        let mut bits = Vec::new();
        if entry.special_bits.setuid {
            bits.push("setuid");
        }
        if entry.special_bits.setgid {
            bits.push("setgid");
        }
        if entry.special_bits.sticky {
            bits.push("sticky");
        }
        meta_group.add(&plain_row("Special bits", &bits.join(", ")));
    }

    if entry.has_acl() {
        meta_group.add(&plain_row("ACL", "Extended ACL present"));
    }

    vbox.append(&meta_group);

    // ── Who has access legend ─────────────────────────────────────────────────
    let legend = gtk4::Box::new(gtk4::Orientation::Horizontal, 12);
    legend.set_margin_start(4);
    legend.set_margin_bottom(2);
    for (class, text) in [
        ("mode-owner", "● Read (r)"),
        ("mode-group", "● Write (w)"),
        ("mode-other", "● Execute (x)"),
        ("access-no", "● None"),
    ] {
        legend.append(
            &gtk4::Label::builder()
                .label(text)
                .css_classes(["caption", class])
                .build(),
        );
    }
    vbox.append(&legend);

    // ── Who has access ────────────────────────────────────────────────────────
    let access_group = libadwaita::PreferencesGroup::builder()
        .title("Who Has Access")
        .build();

    let mut users: Vec<_> = userdb.all_users().collect();
    users.sort_by_key(|u| u.uid);

    for user in users {
        let access = effective_access::evaluate(user, entry);
        let denied = matches!(access.source, perms_core::domain::AccessSource::Denied);

        let rwx_bits = match &access.source {
            perms_core::domain::AccessSource::Root => 0o7u8,
            perms_core::domain::AccessSource::Owner => entry.mode.owner_bits(),
            perms_core::domain::AccessSource::GroupMembership { .. } => entry.mode.group_bits(),
            perms_core::domain::AccessSource::WorldBits => entry.mode.other_bits(),
            perms_core::domain::AccessSource::AclUserEntry
            | perms_core::domain::AccessSource::AclGroupEntry { .. }
            | perms_core::domain::AccessSource::AclMaskLimited => {
                let r = (access.can_read == perms_core::domain::Certainty::Exact) as u8 * 4;
                let w = (access.can_write == perms_core::domain::Certainty::Exact) as u8 * 2;
                let x = (access.can_execute == perms_core::domain::Certainty::Exact) as u8;
                r | w | x
            }
            perms_core::domain::AccessSource::Denied => 0,
        };

        let has_read = !denied && rwx_bits & 4 != 0;
        let has_write = !denied && rwx_bits & 2 != 0;
        let has_exec = !denied && rwx_bits & 1 != 0;

        if !has_read && user.uid != entry.owner_uid {
            continue;
        }

        let row = libadwaita::ActionRow::builder()
            .title(format!("{} ({})", user.username, user.uid))
            .subtitle(source_label(&access.source))
            .build();

        let rwx_box = gtk4::Box::new(gtk4::Orientation::Horizontal, 4);
        rwx_box.append(&coloured_dot(has_read, "mode-owner"));
        rwx_box.append(&coloured_dot(has_write, "mode-group"));
        rwx_box.append(&coloured_dot(has_exec, "mode-other"));
        rwx_box.set_valign(gtk4::Align::Center);
        row.add_suffix(&rwx_box);

        let explanation: String = access
            .explanation
            .iter()
            .map(|s| s.text.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        row.set_tooltip_text(Some(&explanation));

        access_group.add(&row);
    }

    vbox.append(&access_group);

    // ── ACL entries ───────────────────────────────────────────────────────────
    if let Some(acl) = &entry.acl {
        if acl.has_extended_entries() {
            let acl_group = libadwaita::PreferencesGroup::builder()
                .title("ACL Entries")
                .build();

            for acl_entry in &acl.access_entries {
                let tag_str = acl_tag_label(&acl_entry.tag, userdb);
                let perm_str = acl_entry.permission_string();
                let effective = if acl_entry.permissions != acl_entry.effective {
                    let e = acl_entry.effective;
                    format!(
                        "{perm_str} (effective: {}{}{})",
                        if e & 4 != 0 { 'r' } else { '-' },
                        if e & 2 != 0 { 'w' } else { '-' },
                        if e & 1 != 0 { 'x' } else { '-' },
                    )
                } else {
                    perm_str
                };
                acl_group.add(&plain_row(&tag_str, &effective));
            }

            if let Some(mask) = acl.mask {
                acl_group.add(&plain_row(
                    "Mask",
                    &format!(
                        "{}{}{}",
                        if mask & 4 != 0 { 'r' } else { '-' },
                        if mask & 2 != 0 { 'w' } else { '-' },
                        if mask & 1 != 0 { 'x' } else { '-' },
                    ),
                ));
            }

            vbox.append(&acl_group);
        }
    }

    scroll.set_child(Some(&vbox));
    scroll
}

// ── User detail dialog ────────────────────────────────────────────────────────

fn show_user_dialog(
    parent: Option<&gtk4::Window>,
    user: Option<&SystemUser>,
    all_groups: &[SystemGroup],
) {
    let Some(user) = user else { return };

    let win = gtk4::Window::builder()
        .title(format!("User — {}", user.username))
        .modal(true)
        .default_width(420)
        .default_height(480)
        .resizable(false)
        .build();
    if let Some(p) = parent {
        win.set_transient_for(Some(p));
    }

    let scroll = gtk4::ScrolledWindow::builder()
        .hscrollbar_policy(gtk4::PolicyType::Never)
        .vexpand(true)
        .build();

    let vbox = gtk4::Box::new(gtk4::Orientation::Vertical, 12);
    vbox.set_margin_top(20);
    vbox.set_margin_bottom(20);
    vbox.set_margin_start(20);
    vbox.set_margin_end(20);

    let header = gtk4::Label::builder()
        .label(&format!("{}", user.username))
        .css_classes(["title-2"])
        .halign(gtk4::Align::Start)
        .build();
    vbox.append(&header);

    let info_group = libadwaita::PreferencesGroup::builder()
        .title("Identity")
        .build();
    info_group.add(&plain_row("Username", &user.username));
    info_group.add(&plain_row("UID", &user.uid.to_string()));
    info_group.add(&plain_row("Home", &user.home_dir.to_string_lossy()));
    info_group.add(&plain_row("Shell", &user.shell));
    if !user.gecos.trim_matches(',').is_empty() {
        info_group.add(&plain_row("Description", user.gecos.trim_end_matches(',')));
    }
    vbox.append(&info_group);

    // Group memberships
    let group_group = libadwaita::PreferencesGroup::builder()
        .title("Group Memberships")
        .build();

    let primary = all_groups
        .iter()
        .find(|g| g.gid == user.primary_gid)
        .map(|g| format!("{} ({}) — primary", g.name, g.gid))
        .unwrap_or_else(|| format!("GID {} — primary", user.primary_gid));
    group_group.add(&plain_row("Primary", &primary));

    let mut supplementary: Vec<_> = all_groups
        .iter()
        .filter(|g| g.gid != user.primary_gid && user.supplementary_gids.contains(&g.gid))
        .collect();
    supplementary.sort_by_key(|g| g.gid);

    for g in supplementary {
        group_group.add(&plain_row(&g.name, &format!("GID {}", g.gid)));
    }

    if user.supplementary_gids.is_empty() {
        group_group.add(&plain_row("Supplementary", "none"));
    }

    vbox.append(&group_group);

    scroll.set_child(Some(&vbox));
    win.set_child(Some(&scroll));
    win.present();
}

// ── Group detail dialog ───────────────────────────────────────────────────────

fn show_group_dialog(parent: Option<&gtk4::Window>, group: Option<&SystemGroup>, userdb: &UserDb) {
    let Some(group) = group else { return };

    let win = gtk4::Window::builder()
        .title(format!("Group — {}", group.name))
        .modal(true)
        .default_width(400)
        .default_height(400)
        .resizable(false)
        .build();
    if let Some(p) = parent {
        win.set_transient_for(Some(p));
    }

    let scroll = gtk4::ScrolledWindow::builder()
        .hscrollbar_policy(gtk4::PolicyType::Never)
        .vexpand(true)
        .build();

    let vbox = gtk4::Box::new(gtk4::Orientation::Vertical, 12);
    vbox.set_margin_top(20);
    vbox.set_margin_bottom(20);
    vbox.set_margin_start(20);
    vbox.set_margin_end(20);

    let header = gtk4::Label::builder()
        .label(&group.name)
        .css_classes(["title-2"])
        .halign(gtk4::Align::Start)
        .build();
    vbox.append(&header);

    let info_group = libadwaita::PreferencesGroup::builder()
        .title("Identity")
        .build();
    info_group.add(&plain_row("Group name", &group.name));
    info_group.add(&plain_row("GID", &group.gid.to_string()));
    vbox.append(&info_group);

    // Members
    let members_group = libadwaita::PreferencesGroup::builder()
        .title("Members")
        .build();

    // Users whose primary group is this one
    for (user, is_primary) in userdb.resolved_group_members(group) {
        members_group.add(&plain_row(
            &format!("{} ({})", user.username, user.uid),
            if is_primary {
                "primary group"
            } else {
                "supplementary"
            },
        ));
    }

    if members_group.first_child().is_none() {
        members_group.add(&plain_row("(no members)", ""));
    }

    vbox.append(&members_group);

    scroll.set_child(Some(&vbox));
    win.set_child(Some(&scroll));
    win.present();
}

// ── Mode tooltip ──────────────────────────────────────────────────────────────

fn mode_tooltip(entry: &PathEntry, owner_name: &str, group_name: &str) -> String {
    let mode = entry.mode;
    let sym = mode.to_symbolic();
    let octal = mode.to_octal();

    fn describe(bits: u8) -> &'static str {
        match bits {
            0o7 => "read, write, execute",
            0o6 => "read, write  (no execute)",
            0o5 => "read, execute  (no write)",
            0o4 => "read only",
            0o3 => "write, execute  (no read)",
            0o2 => "write only",
            0o1 => "execute only",
            0o0 => "no permissions",
            _ => "unknown",
        }
    }

    fn bits_str(bits: u8) -> String {
        format!(
            "{}{}{}",
            if bits & 4 != 0 { 'r' } else { '-' },
            if bits & 2 != 0 { 'w' } else { '-' },
            if bits & 1 != 0 { 'x' } else { '-' },
        )
    }

    fn bit_sum(bits: u8) -> String {
        let parts: Vec<&str> = [
            (bits & 4 != 0, "4(r)"),
            (bits & 2 != 0, "2(w)"),
            (bits & 1 != 0, "1(x)"),
        ]
        .into_iter()
        .filter(|(set, _)| *set)
        .map(|(_, s)| s)
        .collect();
        if parts.is_empty() {
            "0".into()
        } else {
            parts.join("+")
        }
    }

    let owner_short = owner_name.split(" (").next().unwrap_or(owner_name);
    let group_short = group_name.split(" (").next().unwrap_or(group_name);

    let ob = mode.owner_bits();
    let gb = mode.group_bits();
    let xb = mode.other_bits();

    // Octal digit 0 = special bits
    let octal_chars: Vec<char> = octal.chars().collect();
    let special_digit = octal_chars.first().copied().unwrap_or('0');
    let special_desc = match special_digit {
        '0' => "no special bits",
        '1' => "sticky bit",
        '2' => "setgid",
        '3' => "setgid + sticky",
        '4' => "setuid",
        '5' => "setuid + sticky",
        '6' => "setuid + setgid",
        '7' => "setuid + setgid + sticky",
        _ => "unknown",
    };

    let mut lines = vec![
        format!("  {sym}  ({octal})\n"),
        format!("  Symbolic groups:  [owner] [group] [other]\n"),
        "  Octal breakdown:".into(),
        format!(
            "    {}  →  special bits  ({special_desc})",
            octal_chars.first().unwrap_or(&'0')
        ),
        format!(
            "    {}  →  owner  {}  {}  =  {}",
            octal_chars.get(1).unwrap_or(&'0'),
            bits_str(ob),
            bit_sum(ob),
            describe(ob)
        ),
        format!(
            "    {}  →  group  {}  {}  =  {}",
            octal_chars.get(2).unwrap_or(&'0'),
            bits_str(gb),
            bit_sum(gb),
            describe(gb)
        ),
        format!(
            "    {}  →  other  {}  {}  =  {}\n",
            octal_chars.get(3).unwrap_or(&'0'),
            bits_str(xb),
            bit_sum(xb),
            describe(xb)
        ),
        "  Effective permissions:".into(),
        format!(
            "    Owner  {owner_short:<14} {}  — {}",
            bits_str(ob),
            describe(ob)
        ),
        format!(
            "    Group  {group_short:<14} {}  — {}",
            bits_str(gb),
            describe(gb)
        ),
        format!(
            "    Other  {:<14} {}  — {}",
            "everyone",
            bits_str(xb),
            describe(xb)
        ),
    ];

    // Special bits
    let mut special = Vec::new();
    if entry.special_bits.setuid {
        special.push(format!(
            "\n  setuid  — {} runs as its owner ({owner_short})",
            if entry.is_dir() {
                "new files inherit owner"
            } else {
                "executable"
            }
        ));
    }
    if entry.special_bits.setgid {
        special.push(format!(
            "\n  setgid  — {} inherit group ({group_short})",
            if entry.is_dir() {
                "new files created here"
            } else {
                "executable runs as"
            }
        ));
    }
    if entry.special_bits.sticky {
        special.push("\n  sticky  — only owner or root can delete/rename entries".into());
    }
    lines.extend(special);

    if mode.is_world_writable() {
        lines.push(String::new());
        lines.push("  ⚠ World-writable: any local user can modify this.".into());
    }

    lines.join("\n")
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn plain_row(title: &str, value: &str) -> libadwaita::ActionRow {
    let row = libadwaita::ActionRow::builder().title(title).build();
    let val = gtk4::Label::builder()
        .label(value)
        .css_classes(["dim-label"])
        .valign(gtk4::Align::Center)
        .wrap(true)
        .build();
    row.add_suffix(&val);
    row
}

fn source_label(source: &perms_core::domain::AccessSource) -> String {
    use perms_core::domain::AccessSource;
    match source {
        AccessSource::Owner => "owner".into(),
        AccessSource::GroupMembership { gid } => format!("group ({})", gid),
        AccessSource::WorldBits => "world/other".into(),
        AccessSource::AclUserEntry => "ACL user entry".into(),
        AccessSource::AclGroupEntry { gid } => format!("ACL group ({})", gid),
        AccessSource::AclMaskLimited => "ACL (mask limited)".into(),
        AccessSource::Root => "root".into(),
        AccessSource::Denied => "denied".into(),
    }
}

fn acl_tag_label(tag: &perms_core::domain::AclTag, userdb: &UserDb) -> String {
    use perms_core::domain::AclTag;
    match tag {
        AclTag::UserObj => "User (owner)".into(),
        AclTag::User(uid) => {
            let name = userdb
                .user_by_uid(*uid)
                .map(|u| u.username.clone())
                .unwrap_or_else(|| uid.to_string());
            format!("User: {name}")
        }
        AclTag::GroupObj => "Group (owning)".into(),
        AclTag::Group(gid) => {
            let name = userdb
                .group_by_gid(*gid)
                .map(|g| g.name.clone())
                .unwrap_or_else(|| gid.to_string());
            format!("Group: {name}")
        }
        AclTag::Mask => "Mask".into(),
        AclTag::Other => "Other".into(),
    }
}
