use gtk4::prelude::*;
use libadwaita::prelude::*;
use perms_core::domain::{PathEntry, UserDb};
use perms_core::engine::effective_access;

use crate::components::perm_badge::access_dot;
use crate::components::perm_badge::mode_badge;

/// Build the right-hand detail panel for a selected PathEntry.
/// Returns a scrollable widget ready to embed.
pub fn build_detail_panel(entry: &PathEntry, userdb: &UserDb) -> gtk4::ScrolledWindow {
    let scroll = gtk4::ScrolledWindow::builder()
        .hscrollbar_policy(gtk4::PolicyType::Never)
        .vscrollbar_policy(gtk4::PolicyType::Automatic)
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

    // Sensitive label if applicable
    if let Some(sens) = &entry.sensitive_label {
        let sens_label = gtk4::Label::builder()
            .label(format!("⚠ {}", sens.label))
            .css_classes(["sensitive-badge"])
            .halign(gtk4::Align::Start)
            .build();
        vbox.append(&sens_label);
    }

    // ── Ownership & mode group ────────────────────────────────────────────────
    let meta_group = libadwaita::PreferencesGroup::builder()
        .title("Ownership & Permissions")
        .build();

    let owner_name = userdb
        .user_by_uid(entry.owner_uid)
        .map(|u| format!("{} ({})", u.username, u.uid))
        .unwrap_or_else(|| format!("⚠ Unknown UID {}", entry.owner_uid));

    let group_name = userdb
        .group_by_gid(entry.owner_gid)
        .map(|g| format!("{} ({})", g.name, g.gid))
        .unwrap_or_else(|| format!("⚠ Unknown GID {}", entry.owner_gid));

    meta_group.add(&action_row("Owner", &owner_name));
    meta_group.add(&action_row("Group", &group_name));
    meta_group.add(&action_row("Type", &format!("{:?}", entry.entry_type)));

    let mode_row = libadwaita::ActionRow::builder()
        .title("Mode")
        .build();
    mode_row.add_suffix(&mode_badge(entry.mode));
    meta_group.add(&mode_row);

    if entry.special_bits.setuid || entry.special_bits.setgid || entry.special_bits.sticky {
        let mut bits = Vec::new();
        if entry.special_bits.setuid { bits.push("setuid"); }
        if entry.special_bits.setgid { bits.push("setgid"); }
        if entry.special_bits.sticky { bits.push("sticky"); }
        meta_group.add(&action_row("Special bits", &bits.join(", ")));
    }

    if entry.has_acl() {
        meta_group.add(&action_row("ACL", "Extended ACL present"));
    }

    vbox.append(&meta_group);

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
                // Effective bits from the ACL entry are already on can_read/write/execute
                // Reconstruct from certainty — Exact means granted
                let r = (access.can_read == perms_core::domain::Certainty::Exact) as u8 * 4;
                let w = (access.can_write == perms_core::domain::Certainty::Exact) as u8 * 2;
                let x = (access.can_execute == perms_core::domain::Certainty::Exact) as u8;
                r | w | x
            }
            perms_core::domain::AccessSource::Denied => 0,
        };

        let has_read  = !denied && rwx_bits & 4 != 0;
        let has_write = !denied && rwx_bits & 2 != 0;
        let has_exec  = !denied && rwx_bits & 1 != 0;

        if !has_read && user.uid != entry.owner_uid {
            continue; // skip users with no access (too noisy)
        }

        let row = libadwaita::ActionRow::builder()
            .title(format!("{} ({})", user.username, user.uid))
            .subtitle(source_label(&access.source))
            .build();

        let rwx_box = gtk4::Box::new(gtk4::Orientation::Horizontal, 4);
        rwx_box.append(&access_dot(has_read));
        rwx_box.append(&access_dot(has_write));
        rwx_box.append(&access_dot(has_exec));
        rwx_box.set_valign(gtk4::Align::Center);
        row.add_suffix(&rwx_box);

        // Tooltip with explanation chain
        let explanation: String = access.explanation.iter()
            .map(|s| s.text.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        row.set_tooltip_text(Some(&explanation));

        access_group.add(&row);
    }

    vbox.append(&access_group);

    // ── ACL detail (if present) ───────────────────────────────────────────────
    if let Some(acl) = &entry.acl {
        if acl.has_extended_entries() {
            let acl_group = libadwaita::PreferencesGroup::builder()
                .title("ACL Entries")
                .build();

            for acl_entry in &acl.access_entries {
                let tag_str = acl_tag_label(&acl_entry.tag, userdb);
                let perm_str = acl_entry.permission_string();
                let effective = if acl_entry.permissions != acl_entry.effective {
                    format!("{perm_str} (effective: {})", {
                        let e = acl_entry.effective;
                        format!(
                            "{}{}{}",
                            if e & 4 != 0 { 'r' } else { '-' },
                            if e & 2 != 0 { 'w' } else { '-' },
                            if e & 1 != 0 { 'x' } else { '-' },
                        )
                    })
                } else {
                    perm_str
                };
                acl_group.add(&action_row(&tag_str, &effective));
            }

            if let Some(mask) = acl.mask {
                acl_group.add(&action_row(
                    "Mask",
                    &format!("{}{}{}", if mask & 4 != 0 { 'r' } else { '-' },
                                       if mask & 2 != 0 { 'w' } else { '-' },
                                       if mask & 1 != 0 { 'x' } else { '-' }),
                ));
            }

            vbox.append(&acl_group);
        }
    }

    scroll.set_child(Some(&vbox));
    scroll
}

fn action_row(title: &str, value: &str) -> libadwaita::ActionRow {
    let row = libadwaita::ActionRow::builder()
        .title(title)
        .build();
    let val = gtk4::Label::builder()
        .label(value)
        .css_classes(["dim-label"])
        .valign(gtk4::Align::Center)
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
            let name = userdb.user_by_uid(*uid)
                .map(|u| u.username.clone())
                .unwrap_or_else(|| uid.to_string());
            format!("User: {name}")
        }
        AclTag::GroupObj => "Group (owning)".into(),
        AclTag::Group(gid) => {
            let name = userdb.group_by_gid(*gid)
                .map(|g| g.name.clone())
                .unwrap_or_else(|| gid.to_string());
            format!("Group: {name}")
        }
        AclTag::Mask => "Mask".into(),
        AclTag::Other => "Other".into(),
    }
}
