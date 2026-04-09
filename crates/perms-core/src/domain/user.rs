use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemUser {
    pub uid: u32,
    pub username: String,
    pub primary_gid: u32,
    pub supplementary_gids: Vec<u32>,
    pub home_dir: PathBuf,
    pub shell: String,
    pub gecos: String,
}

impl SystemUser {
    /// All GIDs the user belongs to (primary + supplementary).
    pub fn all_gids(&self) -> impl Iterator<Item = u32> + '_ {
        std::iter::once(self.primary_gid).chain(self.supplementary_gids.iter().copied())
    }

    pub fn is_root(&self) -> bool {
        self.uid == 0
    }
}

/// Parse all users from /etc/passwd.
pub fn parse_passwd(contents: &str) -> Vec<SystemUser> {
    contents
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
        .filter_map(parse_passwd_line)
        .collect()
}

fn parse_passwd_line(line: &str) -> Option<SystemUser> {
    let fields: Vec<&str> = line.splitn(7, ':').collect();
    if fields.len() < 7 {
        return None;
    }
    Some(SystemUser {
        username: fields[0].to_string(),
        uid: fields[2].parse().ok()?,
        primary_gid: fields[3].parse().ok()?,
        gecos: fields[4].to_string(),
        home_dir: PathBuf::from(fields[5]),
        shell: fields[6].to_string(),
        supplementary_gids: Vec::new(), // populated after group parsing
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_PASSWD: &str = "\
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
alice:x:1000:1000:Alice Smith,,,:/home/alice:/bin/bash
bob:x:1001:1001::/home/bob:/bin/zsh
";

    #[test]
    fn parses_standard_users() {
        let users = parse_passwd(SAMPLE_PASSWD);
        assert_eq!(users.len(), 4);

        let alice = users.iter().find(|u| u.username == "alice").unwrap();
        assert_eq!(alice.uid, 1000);
        assert_eq!(alice.primary_gid, 1000);
        assert_eq!(alice.home_dir, PathBuf::from("/home/alice"));
        assert_eq!(alice.shell, "/bin/bash");
        assert_eq!(alice.gecos, "Alice Smith,,,");

        let root = users.iter().find(|u| u.username == "root").unwrap();
        assert!(root.is_root());
    }

    #[test]
    fn all_gids_includes_primary() {
        let user = SystemUser {
            uid: 1000,
            username: "alice".into(),
            primary_gid: 1000,
            supplementary_gids: vec![100, 27],
            home_dir: "/home/alice".into(),
            shell: "/bin/bash".into(),
            gecos: String::new(),
        };
        let gids: Vec<u32> = user.all_gids().collect();
        assert_eq!(gids, vec![1000, 100, 27]);
    }
}
