use std::collections::HashMap;
use std::fs;
use std::path::Path;

use anyhow::Result;

use super::group::{SystemGroup, parse_group};
use super::user::{SystemUser, parse_passwd};

/// In-memory database of all system users and groups, with supplementary GIDs resolved.
#[derive(Clone)]
pub struct UserDb {
    users_by_uid: HashMap<u32, SystemUser>,
    users_by_name: HashMap<String, u32>,
    groups_by_gid: HashMap<u32, SystemGroup>,
    groups_by_name: HashMap<String, u32>,
}

impl UserDb {
    /// Load from the given passwd/group file paths (injectable for testing).
    pub fn load_from(passwd_path: &Path, group_path: &Path) -> Result<Self> {
        let passwd = fs::read_to_string(passwd_path)?;
        let group = fs::read_to_string(group_path)?;
        Ok(Self::from_str(&passwd, &group))
    }

    /// Load from the standard system paths /etc/passwd and /etc/group.
    pub fn load() -> Result<Self> {
        Self::load_from(Path::new("/etc/passwd"), Path::new("/etc/group"))
    }

    /// Build from raw file contents (used in tests without filesystem access).
    pub fn from_str(passwd: &str, group: &str) -> Self {
        let mut users = parse_passwd(passwd);
        let groups = parse_group(group);

        // Build group lookup
        let groups_by_gid: HashMap<u32, SystemGroup> =
            groups.iter().cloned().map(|g| (g.gid, g)).collect();
        let groups_by_name: HashMap<String, u32> =
            groups.iter().map(|g| (g.name.clone(), g.gid)).collect();

        // Resolve supplementary GIDs for each user from group membership
        for user in &mut users {
            user.supplementary_gids = groups
                .iter()
                .filter(|g| g.gid != user.primary_gid && g.members.contains(&user.username))
                .map(|g| g.gid)
                .collect();
        }

        let users_by_uid: HashMap<u32, SystemUser> =
            users.iter().cloned().map(|u| (u.uid, u)).collect();
        let users_by_name: HashMap<String, u32> =
            users.iter().map(|u| (u.username.clone(), u.uid)).collect();

        Self {
            users_by_uid,
            users_by_name,
            groups_by_gid,
            groups_by_name,
        }
    }

    pub fn user_by_uid(&self, uid: u32) -> Option<&SystemUser> {
        self.users_by_uid.get(&uid)
    }

    pub fn user_by_name(&self, name: &str) -> Option<&SystemUser> {
        self.users_by_name
            .get(name)
            .and_then(|uid| self.users_by_uid.get(uid))
    }

    pub fn group_by_gid(&self, gid: u32) -> Option<&SystemGroup> {
        self.groups_by_gid.get(&gid)
    }

    pub fn group_by_name(&self, name: &str) -> Option<&SystemGroup> {
        self.groups_by_name
            .get(name)
            .and_then(|gid| self.groups_by_gid.get(gid))
    }

    pub fn all_users(&self) -> impl Iterator<Item = &SystemUser> {
        self.users_by_uid.values()
    }

    pub fn all_groups(&self) -> impl Iterator<Item = &SystemGroup> {
        self.groups_by_gid.values()
    }

    pub fn all_users_sorted(&self) -> Vec<SystemUser> {
        let mut users = self.all_users().cloned().collect::<Vec<_>>();
        users.sort_by_key(|user| user.uid);
        users
    }

    pub fn all_groups_sorted(&self) -> Vec<SystemGroup> {
        let mut groups = self.all_groups().cloned().collect::<Vec<_>>();
        groups.sort_by_key(|group| group.gid);
        groups
    }

    pub fn resolved_group_members(&self, group: &SystemGroup) -> Vec<(SystemUser, bool)> {
        let mut members = self
            .all_users()
            .filter_map(|user| {
                if user.primary_gid == group.gid {
                    Some((user.clone(), true))
                } else if group.members.contains(&user.username)
                    || user.supplementary_gids.contains(&group.gid)
                {
                    Some((user.clone(), false))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        members.sort_by_key(|(user, is_primary)| (!*is_primary, user.uid));
        members
    }

    pub fn uid_known(&self, uid: u32) -> bool {
        self.users_by_uid.contains_key(&uid)
    }

    pub fn gid_known(&self, gid: u32) -> bool {
        self.groups_by_gid.contains_key(&gid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWD: &str = "\
root:x:0:0:root:/root:/bin/bash
alice:x:1000:1000:Alice:/home/alice:/bin/bash
bob:x:1001:1001:Bob:/home/bob:/bin/zsh
";

    const GROUP: &str = "\
root:x:0:
alice:x:1000:
bob:x:1001:
sudo:x:27:alice,bob
docker:x:999:alice
";

    fn db() -> UserDb {
        UserDb::from_str(PASSWD, GROUP)
    }

    #[test]
    fn resolves_supplementary_gids() {
        let db = db();
        let alice = db.user_by_name("alice").unwrap();
        // alice is in sudo (27) and docker (999)
        assert!(alice.supplementary_gids.contains(&27));
        assert!(alice.supplementary_gids.contains(&999));
        // alice's primary group (1000) should not appear in supplementary
        assert!(!alice.supplementary_gids.contains(&1000));
    }

    #[test]
    fn lookup_by_uid_and_name() {
        let db = db();
        assert_eq!(db.user_by_uid(1000).unwrap().username, "alice");
        assert_eq!(db.user_by_name("bob").unwrap().uid, 1001);
    }

    #[test]
    fn group_lookup() {
        let db = db();
        assert_eq!(db.group_by_gid(27).unwrap().name, "sudo");
        assert_eq!(db.group_by_name("docker").unwrap().gid, 999);
    }

    #[test]
    fn unknown_uid_gid() {
        let db = db();
        assert!(!db.uid_known(9999));
        assert!(!db.gid_known(9999));
        assert!(db.uid_known(1000));
    }

    #[test]
    fn all_gids_complete() {
        let db = db();
        let alice = db.user_by_name("alice").unwrap();
        let all: Vec<u32> = alice.all_gids().collect();
        // primary (1000) + sudo (27) + docker (999)
        assert!(all.contains(&1000));
        assert!(all.contains(&27));
        assert!(all.contains(&999));
    }
}
