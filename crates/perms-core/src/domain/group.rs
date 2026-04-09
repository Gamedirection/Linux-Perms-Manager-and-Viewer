use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemGroup {
    pub gid: u32,
    pub name: String,
    pub members: Vec<String>, // usernames
}

/// Parse all groups from /etc/group.
pub fn parse_group(contents: &str) -> Vec<SystemGroup> {
    contents
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
        .filter_map(parse_group_line)
        .collect()
}

fn parse_group_line(line: &str) -> Option<SystemGroup> {
    let fields: Vec<&str> = line.splitn(4, ':').collect();
    if fields.len() < 4 {
        return None;
    }
    let members = if fields[3].is_empty() {
        Vec::new()
    } else {
        fields[3].split(',').map(|s| s.to_string()).collect()
    };
    Some(SystemGroup {
        name: fields[0].to_string(),
        gid: fields[2].parse().ok()?,
        members,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_GROUP: &str = "\
root:x:0:
sudo:x:27:alice,bob
users:x:100:alice
docker:x:999:alice,ci
";

    #[test]
    fn parses_groups() {
        let groups = parse_group(SAMPLE_GROUP);
        assert_eq!(groups.len(), 4);

        let sudo = groups.iter().find(|g| g.name == "sudo").unwrap();
        assert_eq!(sudo.gid, 27);
        assert_eq!(sudo.members, vec!["alice", "bob"]);

        let root = groups.iter().find(|g| g.name == "root").unwrap();
        assert!(root.members.is_empty());
    }
}
