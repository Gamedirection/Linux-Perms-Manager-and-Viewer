use crate::domain::{
    acl::AclTag,
    path_entry::PathEntry,
    permission::{AccessSource, Certainty, EffectiveAccess, ExplanationStep},
    user::SystemUser,
};

/// Evaluate effective access for a user on a path entry.
///
/// The returned `EffectiveAccess` always includes a human-readable explanation
/// chain describing exactly why access was granted or denied.
pub fn evaluate(user: &SystemUser, entry: &PathEntry) -> EffectiveAccess {
    let mut explanation = Vec::new();

    explanation.push(ExplanationStep::new(format!(
        "Evaluating access for '{}' (uid={}) on '{}'",
        user.username,
        user.uid,
        entry.path.display()
    )));

    // Root bypasses all permission checks.
    if user.uid == 0 {
        explanation.push(ExplanationStep::new("User is root — unrestricted access"));
        return EffectiveAccess {
            uid: user.uid,
            path: entry.path.clone(),
            can_read: Certainty::Exact,
            can_write: Certainty::Exact,
            can_execute: Certainty::Exact,
            source: AccessSource::Root,
            explanation,
        };
    }

    // Check ACLs when present and extended (i.e. more than just UserObj/GroupObj/Other).
    if let Some(acl) = &entry.acl {
        if acl.has_extended_entries() {
            explanation.push(ExplanationStep::new("Path has extended ACL — evaluating ACL entries"));

            // Named user entry takes highest priority.
            if let Some(acl_entry) = acl.user_entry(user.uid) {
                let eff = acl_entry.effective;
                explanation.push(ExplanationStep::new(format!(
                    "Matched named-user ACL entry for uid={} — granted={} effective={}",
                    user.uid,
                    bits_str(acl_entry.permissions),
                    bits_str(eff),
                )));
                if acl_entry.permissions != eff {
                    explanation.push(ExplanationStep::new(format!(
                        "ACL mask (0o{:o}) reduced granted permissions",
                        acl.mask.unwrap_or(0o7),
                    )));
                }
                return EffectiveAccess {
                    uid: user.uid,
                    path: entry.path.clone(),
                    can_read: cert(eff & 0o4 != 0),
                    can_write: cert(eff & 0o2 != 0),
                    can_execute: cert(eff & 0o1 != 0),
                    source: AccessSource::AclUserEntry,
                    explanation,
                };
            }

            // Named group entries: union all matching, then apply mask.
            let matching_groups: Vec<_> =
                acl.group_entries_for(user.all_gids()).collect();

            if !matching_groups.is_empty() {
                let union_granted = matching_groups.iter().fold(0u8, |a, e| a | e.permissions);
                let mask = acl.mask.unwrap_or(0o7);
                let effective = union_granted & mask;

                for ge in &matching_groups {
                    if let AclTag::Group(gid) = ge.tag {
                        explanation.push(ExplanationStep::new(format!(
                            "Matched group ACL entry for gid={} — granted={}",
                            gid,
                            bits_str(ge.permissions),
                        )));
                    }
                }
                explanation.push(ExplanationStep::new(format!(
                    "Union of group permissions: {} — after mask (0o{:o}): {}",
                    bits_str(union_granted),
                    mask,
                    bits_str(effective),
                )));

                let gid = if let AclTag::Group(g) = matching_groups[0].tag { g } else { 0 };
                return EffectiveAccess {
                    uid: user.uid,
                    path: entry.path.clone(),
                    can_read: cert(effective & 0o4 != 0),
                    can_write: cert(effective & 0o2 != 0),
                    can_execute: cert(effective & 0o1 != 0),
                    source: AccessSource::AclGroupEntry { gid },
                    explanation,
                };
            }

            // Fall through to ACL Other entry.
            let other = acl.other_permissions();
            explanation.push(ExplanationStep::new(format!(
                "No matching user or group ACL entry — using ACL Other: {}",
                bits_str(other),
            )));
            return EffectiveAccess {
                uid: user.uid,
                path: entry.path.clone(),
                can_read: cert(other & 0o4 != 0),
                can_write: cert(other & 0o2 != 0),
                can_execute: cert(other & 0o1 != 0),
                source: AccessSource::Denied,
                explanation,
            };
        }
    }

    // Standard mode bits.
    explanation.push(ExplanationStep::new("No extended ACL — evaluating standard mode bits"));

    let mode = entry.mode;

    if entry.owner_uid == user.uid {
        let bits = mode.owner_bits();
        explanation.push(ExplanationStep::new(format!(
            "User is owner (uid={}) — owner bits: {}",
            user.uid,
            bits_str(bits),
        )));
        return EffectiveAccess {
            uid: user.uid,
            path: entry.path.clone(),
            can_read: cert(bits & 0o4 != 0),
            can_write: cert(bits & 0o2 != 0),
            can_execute: cert(bits & 0o1 != 0),
            source: AccessSource::Owner,
            explanation,
        };
    }

    if user.all_gids().any(|g| g == entry.owner_gid) {
        let bits = mode.group_bits();
        explanation.push(ExplanationStep::new(format!(
            "User is member of owning group (gid={}) — group bits: {}",
            entry.owner_gid,
            bits_str(bits),
        )));
        return EffectiveAccess {
            uid: user.uid,
            path: entry.path.clone(),
            can_read: cert(bits & 0o4 != 0),
            can_write: cert(bits & 0o2 != 0),
            can_execute: cert(bits & 0o1 != 0),
            source: AccessSource::GroupMembership { gid: entry.owner_gid },
            explanation,
        };
    }

    let bits = mode.other_bits();
    explanation.push(ExplanationStep::new(format!(
        "User is not owner or group member — other bits: {}",
        bits_str(bits),
    )));
    EffectiveAccess {
        uid: user.uid,
        path: entry.path.clone(),
        can_read: cert(bits & 0o4 != 0),
        can_write: cert(bits & 0o2 != 0),
        can_execute: cert(bits & 0o1 != 0),
        source: if bits == 0 { AccessSource::Denied } else { AccessSource::WorldBits },
        explanation,
    }
}

fn cert(granted: bool) -> Certainty {
    if granted { Certainty::Exact } else { Certainty::Exact }
    // Both cases return Exact here because we computed directly from stat data.
    // Certainty::Unknown is reserved for cases with missing data (handled upstream).
}

fn bits_str(bits: u8) -> String {
    format!(
        "{}{}{}",
        if bits & 0o4 != 0 { 'r' } else { '-' },
        if bits & 0o2 != 0 { 'w' } else { '-' },
        if bits & 0o1 != 0 { 'x' } else { '-' },
    )
}

// Dummy UnixMode impl needed for owner_bits/group_bits/other_bits in tests.
#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use chrono::Utc;

    use super::*;
    use crate::domain::path_entry::{EntryType, ScanSource, SpecialBits};
    use crate::domain::permission::UnixMode;

    fn make_user(uid: u32, primary_gid: u32, extra_gids: Vec<u32>) -> SystemUser {
        SystemUser {
            uid,
            username: format!("user{uid}"),
            primary_gid,
            supplementary_gids: extra_gids,
            home_dir: PathBuf::from("/home/test"),
            shell: "/bin/bash".into(),
            gecos: String::new(),
        }
    }

    fn make_entry(mode: u32, owner_uid: u32, owner_gid: u32) -> PathEntry {
        PathEntry {
            path: PathBuf::from("/test/path"),
            entry_type: EntryType::Directory,
            owner_uid,
            owner_gid,
            mode: UnixMode(mode),
            acl: None,
            special_bits: SpecialBits::from_mode(mode),
            scan_time: Utc::now(),
            scan_source: ScanSource::Full,
            is_mount_point: false,
            sensitive_label: None,
            size_bytes: 0,
        }
    }

    #[test]
    fn owner_access() {
        let user = make_user(1000, 1000, vec![]);
        let entry = make_entry(0o750, 1000, 1000);
        let result = evaluate(&user, &entry);
        assert!(matches!(result.source, AccessSource::Owner));
        assert_eq!(result.can_read, Certainty::Exact);
        assert_eq!(result.can_write, Certainty::Exact);
        assert_eq!(result.can_execute, Certainty::Exact);
    }

    #[test]
    fn group_access() {
        let user = make_user(1001, 1001, vec![1000]);
        let entry = make_entry(0o750, 1000, 1000); // group bits: r-x
        let result = evaluate(&user, &entry);
        assert!(matches!(result.source, AccessSource::GroupMembership { gid: 1000 }));
        assert_eq!(result.can_read, Certainty::Exact);
        assert_eq!(result.can_execute, Certainty::Exact);
    }

    #[test]
    fn denied_other() {
        let user = make_user(1002, 1002, vec![]);
        let entry = make_entry(0o750, 1000, 1000);
        let result = evaluate(&user, &entry);
        assert!(matches!(result.source, AccessSource::Denied));
    }

    #[test]
    fn root_always_access() {
        let user = make_user(0, 0, vec![]);
        let entry = make_entry(0o000, 999, 999);
        let result = evaluate(&user, &entry);
        assert!(matches!(result.source, AccessSource::Root));
        assert_eq!(result.can_read, Certainty::Exact);
    }

    #[test]
    fn world_readable() {
        let user = make_user(1002, 1002, vec![]);
        let entry = make_entry(0o744, 1000, 1000); // other: r--
        let result = evaluate(&user, &entry);
        assert!(matches!(result.source, AccessSource::WorldBits));
        assert_eq!(result.can_read, Certainty::Exact);
    }
}
