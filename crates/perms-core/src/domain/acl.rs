use serde::{Deserialize, Serialize};

/// An ACL entry tag — what principal does this entry apply to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AclTag {
    UserObj,       // owning user (matches mode owner bits)
    User(u32),     // named user by UID
    GroupObj,      // owning group (matches mode group bits)
    Group(u32),    // named group by GID
    Mask,          // effective permission mask
    Other,         // everyone else
}

/// A single ACL entry: tag + permission bits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AclEntry {
    pub tag: AclTag,
    /// Raw permission bits: r=4, w=2, x=1.
    pub permissions: u8,
    /// Effective permissions after mask is applied.
    /// For Mask and Other entries, same as permissions.
    pub effective: u8,
}

impl AclEntry {
    pub fn can_read(&self) -> bool {
        self.effective & 0o4 != 0
    }

    pub fn can_write(&self) -> bool {
        self.effective & 0o2 != 0
    }

    pub fn can_execute(&self) -> bool {
        self.effective & 0o1 != 0
    }

    pub fn permission_string(&self) -> String {
        format!(
            "{}{}{}",
            if self.effective & 0o4 != 0 { 'r' } else { '-' },
            if self.effective & 0o2 != 0 { 'w' } else { '-' },
            if self.effective & 0o1 != 0 { 'x' } else { '-' },
        )
    }
}

/// Full ACL for a path: access entries + optional default entries (dirs only).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AclSet {
    pub access_entries: Vec<AclEntry>,
    pub default_entries: Vec<AclEntry>,
    pub mask: Option<u8>,
}

impl AclSet {
    pub fn has_extended_entries(&self) -> bool {
        self.access_entries
            .iter()
            .any(|e| matches!(e.tag, AclTag::User(_) | AclTag::Group(_)))
    }

    pub fn has_default_acl(&self) -> bool {
        !self.default_entries.is_empty()
    }

    /// Find a named-user ACL entry for the given UID.
    pub fn user_entry(&self, uid: u32) -> Option<&AclEntry> {
        self.access_entries
            .iter()
            .find(|e| e.tag == AclTag::User(uid))
    }

    /// All named-group ACL entries whose GID is in the provided set.
    pub fn group_entries_for<'a>(
        &'a self,
        gids: impl Iterator<Item = u32> + 'a,
    ) -> impl Iterator<Item = &'a AclEntry> {
        let gids: Vec<u32> = gids.collect();
        self.access_entries
            .iter()
            .filter(move |e| matches!(&e.tag, AclTag::Group(g) if gids.contains(g)))
    }

    /// The Other entry's effective permissions.
    pub fn other_permissions(&self) -> u8 {
        self.access_entries
            .iter()
            .find(|e| e.tag == AclTag::Other)
            .map(|e| e.effective)
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_acl() -> AclSet {
        AclSet {
            access_entries: vec![
                AclEntry { tag: AclTag::UserObj, permissions: 0o7, effective: 0o7 },
                AclEntry { tag: AclTag::User(1001), permissions: 0o6, effective: 0o4 }, // masked
                AclEntry { tag: AclTag::GroupObj, permissions: 0o5, effective: 0o4 },
                AclEntry { tag: AclTag::Group(27), permissions: 0o6, effective: 0o4 },
                AclEntry { tag: AclTag::Mask, permissions: 0o5, effective: 0o5 },
                AclEntry { tag: AclTag::Other, permissions: 0o0, effective: 0o0 },
            ],
            default_entries: Vec::new(),
            mask: Some(0o5),
        }
    }

    #[test]
    fn user_entry_lookup() {
        let acl = make_acl();
        assert!(acl.user_entry(1001).is_some());
        assert!(acl.user_entry(9999).is_none());
    }

    #[test]
    fn group_entries_for() {
        let acl = make_acl();
        let matches: Vec<_> = acl.group_entries_for([27u32, 100].into_iter()).collect();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].tag, AclTag::Group(27));
    }

    #[test]
    fn mask_limits_effective() {
        let acl = make_acl();
        let entry = acl.user_entry(1001).unwrap();
        assert_eq!(entry.permissions, 0o6); // granted rw
        assert_eq!(entry.effective, 0o4);   // but mask limits to r only
        assert!(entry.can_read());
        assert!(!entry.can_write());
    }

    #[test]
    fn has_extended_entries() {
        let acl = make_acl();
        assert!(acl.has_extended_entries());
    }
}
