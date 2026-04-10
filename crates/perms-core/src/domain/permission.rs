use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Raw Unix mode bits (u32 from stat).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnixMode(pub u32);

impl UnixMode {
    pub fn owner_bits(self) -> u8 {
        ((self.0 >> 6) & 0o7) as u8
    }

    pub fn group_bits(self) -> u8 {
        ((self.0 >> 3) & 0o7) as u8
    }

    pub fn other_bits(self) -> u8 {
        (self.0 & 0o7) as u8
    }

    pub fn to_octal(self) -> String {
        format!("{:04o}", self.0 & 0o7777)
    }

    /// Returns symbolic representation like "rwxr-x---"
    pub fn to_symbolic(self) -> String {
        let bits = [
            (self.owner_bits(), 's', 'S', self.0 & 0o4000 != 0),
            (self.group_bits(), 's', 'S', self.0 & 0o2000 != 0),
            (self.other_bits(), 't', 'T', self.0 & 0o1000 != 0),
        ];

        let mut out = String::with_capacity(9);
        for (rwx, exec_special, noexec_special, special) in bits {
            out.push(if rwx & 0o4 != 0 { 'r' } else { '-' });
            out.push(if rwx & 0o2 != 0 { 'w' } else { '-' });
            out.push(if special {
                if rwx & 0o1 != 0 {
                    exec_special
                } else {
                    noexec_special
                }
            } else if rwx & 0o1 != 0 {
                'x'
            } else {
                '-'
            });
        }
        out
    }

    pub fn is_world_readable(self) -> bool {
        self.other_bits() & 0o4 != 0
    }

    pub fn is_world_writable(self) -> bool {
        self.other_bits() & 0o2 != 0
    }

    pub fn is_world_executable(self) -> bool {
        self.other_bits() & 0o1 != 0
    }
}

/// How certain we are about an access result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Certainty {
    /// Computed directly from stat/ACL data we have.
    Exact,
    /// Inferred from available data; parent dir traversal may be incomplete.
    Estimated,
    /// Insufficient data to determine.
    Unknown,
}

/// What rule granted or denied access.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AccessSource {
    Root,
    Owner,
    GroupMembership { gid: u32 },
    WorldBits,
    AclUserEntry,
    AclGroupEntry { gid: u32 },
    AclMaskLimited,
    Denied,
}

/// One step in the human-readable explanation chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExplanationStep {
    pub text: String,
}

impl ExplanationStep {
    pub fn new(text: impl Into<String>) -> Self {
        Self { text: text.into() }
    }
}

/// Result of evaluating effective access for a user on a path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EffectiveAccess {
    pub uid: u32,
    pub path: PathBuf,
    pub can_read: Certainty,
    pub can_write: Certainty,
    pub can_execute: Certainty,
    pub source: AccessSource,
    pub explanation: Vec<ExplanationStep>,
}

impl EffectiveAccess {
    pub fn has_any_access(&self) -> bool {
        matches!(
            (self.can_read, self.can_write, self.can_execute),
            (Certainty::Exact, _, _) | (_, Certainty::Exact, _) | (_, _, Certainty::Exact)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn symbolic_conversion() {
        assert_eq!(UnixMode(0o755).to_symbolic(), "rwxr-xr-x");
        assert_eq!(UnixMode(0o644).to_symbolic(), "rw-r--r--");
        assert_eq!(UnixMode(0o700).to_symbolic(), "rwx------");
        assert_eq!(UnixMode(0o000).to_symbolic(), "---------");
    }

    #[test]
    fn octal_conversion() {
        assert_eq!(UnixMode(0o755).to_octal(), "0755");
        assert_eq!(UnixMode(0o644).to_octal(), "0644");
    }

    #[test]
    fn world_writable_detection() {
        assert!(UnixMode(0o777).is_world_writable());
        assert!(UnixMode(0o757).is_world_writable());
        assert!(!UnixMode(0o755).is_world_writable());
        assert!(!UnixMode(0o750).is_world_writable());
    }

    #[test]
    fn setuid_in_symbolic() {
        // setuid + exec on owner
        assert_eq!(UnixMode(0o4755).to_symbolic(), "rwsr-xr-x");
        // setuid + no exec on owner
        assert_eq!(UnixMode(0o4644).to_symbolic(), "rwSr--r--");
        // sticky on other + exec
        assert_eq!(UnixMode(0o1755).to_symbolic(), "rwxr-xr-t");
    }
}
