# Linux Permissions Manager — Development Plan

> Last updated: 2026-04-09
> Stack: Rust + GTK4/libadwaita
> Working title: `perms`

---

## Key Architectural Decisions

| Decision | Choice | Rationale |
|---|---|---|
| UI toolkit | GTK4/libadwaita | Linux-native, Wayland-first, GNOME HIG |
| Widget resize | Fixed grid for MVP | Drag-resize is weeks of work with little early value |
| ACL editing | Read-only MVP, edit in v1.1 | Mask/default ACL correctness is non-trivial |
| Privilege model | polkit + helper binary | Standard Linux pattern; no sudo in production |
| Index | SQLite | Proven, queryable, portable, good Rust support |
| Live indexing | Periodic + on-demand | inotify limits make live indexing unreliable on large trees |
| IPC | Unix socket + typed structs | No shell string execution in helper; typed protocol |
| KDE | Supported, not themed | Don't split toolkit effort; acknowledge in docs |

---

## Process Model

```
perms (UI process, runs as user)
  GTK4 / libadwaita frontend
  Domain engine (Rust library)
  SQLite index (user-owned)
  IPC client
        │
        │ Unix socket / D-Bus
        ▼
perms-helper (privileged binary)
  Launched via polkit/pkexec
  Minimal surface: read + write ops
  Validates all requests
  Logs all privileged actions
```

---

## Workspace Structure

```
perms/
├── Cargo.toml                    ← workspace manifest
├── crates/
│   ├── perms-core/               ← no GTK; pure domain logic
│   │   └── src/
│   │       ├── domain/           ← user, group, path_entry, permission, acl
│   │       ├── engine/           ← scanner, effective_access, explainer, audit/
│   │       ├── store/            ← SQLite index + schema
│   │       ├── export/           ← CSV
│   │       └── ipc/              ← shared request/response protocol types
│   ├── perms-ui/                 ← GTK4/libadwaita frontend
│   │   └── src/
│   │       ├── tabs/
│   │       │   ├── dashboard/    ← widget_host + widgets/
│   │       │   ├── viewer/       ← directory_view, user_view, view_as_user
│   │       │   ├── management/   ← edit_panel, bulk_edit, dry_run
│   │       │   └── settings/
│   │       ├── components/       ← permission_badge, user_chip, risk_badge, etc.
│   │       └── state/            ← app_state
│   └── perms-helper/             ← privileged binary, minimal surface
│       └── src/
│           ├── auth.rs           ← polkit validation
│           ├── ipc.rs            ← socket server
│           ├── read_ops.rs
│           └── write_ops.rs
├── packaging/
│   ├── PKGBUILD
│   ├── org.perms.helper.policy   ← polkit policy
│   └── ...
└── tests/
    ├── integration/
    └── fixtures/                 ← test filesystem trees with known permissions
```

---

## Domain Model (Core Types)

```rust
// Identities
SystemUser { uid, username, primary_gid, supplementary_gids, home_dir, shell, gecos }
SystemGroup { gid, name, members: Vec<uid> }

// Filesystem
PathEntry { path, entry_type, owner_uid, owner_gid, mode: UnixMode,
            acl: Option<AclSet>, special_bits, scan_time, scan_source,
            is_mount_point, sensitive_label }

UnixMode { raw: u32 }  // methods: owner_rwx(), group_rwx(), other_rwx(), to_symbolic()

AclSet { entries: Vec<AclEntry>, default_entries, mask: Option<u8> }
AclEntry { tag: AclTag, permissions: u8, effective: u8 }

// Access evaluation
EffectiveAccess { uid, path, can_read: Certainty, can_write: Certainty,
                  can_execute: Certainty, source: AccessSource,
                  explanation: Vec<ExplanationStep> }

Certainty { Exact, Estimated, Unknown }
AccessSource { Owner, GroupMembership(gid), WorldBits, AclUserEntry,
               AclGroupEntry(gid), AclMaskLimited, Denied, Root }

// Audit
AuditFinding { id, severity, category: FindingCategory, path, description,
               recommendation, details }
```

---

## Effective Access Algorithm

```
1. uid == 0 → root_access (bypass all)
2. ACL present?
   a. User-specific ACL entry → effective = permissions & mask
   b. Union all matching group ACL entries → effective = union & mask
   c. ACL other entry
3. No ACL → standard mode bits
   a. owner_uid == uid → owner bits
   b. any gid in user.all_gids() == owner_gid → group bits
   c. → other bits

All results carry Vec<ExplanationStep> (human-readable audit chain)
```

---

## Audit Rules (MVP)

| Rule ID | Severity | Trigger |
|---|---|---|
| `world-writable-dir` | Critical | mode & 0o002, is directory |
| `world-writable-file` | High | mode & 0o002, is file |
| `suid-unexpected` | High | setuid set, not in known-safe allowlist |
| `sgid-unexpected` | Medium | setgid set, not in known-safe allowlist |
| `home-other-readable` | High | /home/X readable by other than X |
| `orphaned-uid` | Medium | owner UID not in /etc/passwd |
| `orphaned-gid` | Medium | owner GID not in /etc/group |
| `writable-system-path` | Critical | write perm on /etc, /usr/bin, /usr/lib by non-root |
| `executable-writable-non-admin` | High | exec file writable by non-admin |
| `acl-default-expands-access` | Medium | default ACL grants more than mode bits |
| `sensitive-path-exposed` | High | sensitive path accessible beyond expected principals |

---

## Sensitive Path Labels (Built-in)

```
/etc          → "System Configuration"
/root         → "Root Home"
/var/shadow   → "Shadow Passwords"
/usr/bin      → "System Binaries"
/usr/lib      → "System Libraries"
/boot         → "Bootloader"
/srv          → "Service Data"
/home/*       → "User Home"
```

---

## Scan Pipeline

```
User selects roots
  → ScanWorker (rayon thread pool)
  → walkdir traversal
  → stat() + getxattr() per entry
  → batch insert SQLite (1000-entry batches)
  → AuditEngine over new entries
  → UI receives progress events via channel
  → Index marked complete
```

No inotify in MVP. Invalidation: on launch compare root mtime against last scan time, prompt re-scan if stale (default threshold: 1 hour).

---

## Edit Session Flow

```
1. Select paths → open Edit panel
2. Configure: mode, owner, group, recursive toggle
3. Preview → diff table (old → new per path) + risk score
4. High-risk → typed confirmation required
5. Apply → helper executes (or dry-run returns diff)
6. Results shown per-path
7. Audit log entry written
```

### Confirmation levels

| Risk | Trigger | Confirmation |
|---|---|---|
| Low | Single file, user-owned | Single click |
| Medium | Multiple files or group change | Dialog |
| High | Recursive, world bits, or system path | Type path/count |
| Critical | System path + recursive + write grant | Elevation + typed |

---

## Logging Format

```
~/.local/share/perms/audit.log  (JSON Lines)

{ "id", "ts", "operator_uid", "action", "target", "recursive",
  "dry_run", "elevated", "old_mode", "new_mode", "result", "paths_affected" }
```

---

## Dashboard Widgets (MVP)

| Priority | Widget | Size |
|---|---|---|
| 1 | Risk Summary | small |
| 2 | World-Writable Paths | small |
| 3 | Privilege Status | large |
| 4 | Scan Coverage | medium |
| 5 | Users With Broad Access | medium |
| 6 | ACL Usage Overview | medium |
| 7 | Top Sensitive Directories | medium |
| 8 | Recent Changes | medium |

Profiles stored as TOML in `~/.local/share/perms/dashboards/`.
Built-in defaults: `security.toml`, `support.toml`, `admin.toml`.

---

## Export

- MVP: CSV
- Post-MVP: JSON, PDF, audit report bundles

---

## Packaging Targets

| Format | Tool | Priority |
|---|---|---|
| PKGBUILD | manual | Immediate (dev machine) |
| .deb | `cargo-deb` | Phase 6 |
| .rpm | `cargo-generate-rpm` | Phase 6 |
| AppImage | `linuxdeploy` | Phase 6 |
| Flatpak | `flatpak-builder` | Post-MVP |

Note: helper binary must install to `/usr/libexec/perms-helper` with polkit policy at `/usr/share/polkit-1/actions/org.perms.helper.policy`.

---

## Testing Strategy

- **Unit tests**: `perms-core` only, no GTK dependency, fixture-based
- **Integration tests**: full scan pipeline against `tests/fixtures/` tree
- **Distro matrix**: Arch (continuous), Debian/Fedora (weekly VM), Ubuntu/NixOS (pre-release)
- **Polkit integration**: Vagrant VMs only (Docker cannot run polkit)

---

## Phased Roadmap

### Phase 0 — Dev Environment ✅ (current)
- [ ] Workspace scaffold: three crates compile
- [ ] GTK4/libadwaita window builds and opens
- [ ] `perms-core` unit tests pass (user/group parsing, mode parsing)
- [ ] SQLite schema + migrations working
- [ ] PKGBUILD installs correctly

### Phase 1 — Core Engine ✅
- [x] Full user/group DB from /etc/passwd, /etc/group (UserDb, supplementary GID resolution)
- [x] Filesystem stat + mode parsing via `nix` (lstat, SFlag)
- [x] ACL xattr reading + binary format parser (getxattr, little-endian blob parser)
- [x] walkdir scan with progress channel (ScanEvent, cancel support)
- [x] SQLite batch insert pipeline (WAL, UPSERT, transactions)
- [x] Effective access evaluator + explanation chain (Phase 0)
- [x] 9 MVP audit rules (world-writable dir/file, suid, sgid, orphaned uid/gid, writable system path, home readable, exec-writable)

### Phase 2 — Viewer
- [ ] Directory tree browser (GTK ColumnView)
- [ ] Directory detail panel (mode, owner, group, ACL, who has access)
- [ ] User selector + accessible paths list
- [ ] Explanation chain renderer
- [ ] Sensitive path labels + visual treatment
- [ ] Limited mode indicators

### Phase 3 — Dashboard
- [ ] Widget host (fixed grid, toggleable)
- [ ] 8 MVP widgets
- [ ] Scan progress bar with cancel
- [ ] Dashboard profiles (save/load TOML)

### Phase 4 — Management
- [ ] Polkit helper launch + Unix socket IPC
- [ ] chmod/chown edit panel
- [ ] Dry-run + diff preview
- [ ] Bulk select + edit
- [ ] Risk classification + confirmation dialogs
- [ ] Audit log (JSON Lines)

### Phase 5 — Advanced Viewer + Export
- [ ] "View as user" mode
- [ ] Two-user comparison
- [ ] CSV export
- [ ] Settings tab (scan roots, exclusions, re-scan triggers)
- [ ] First-run setup wizard

### Phase 6 — Polish + Packaging
- [ ] Full dark theme pass
- [ ] Tooltips, legends, inline help text
- [ ] .deb packaging test on Debian/Ubuntu VM
- [ ] PKGBUILD AUR submission
- [ ] README + install docs

---

## Post-MVP Roadmap

| Version | Feature |
|---|---|
| v1.1 | ACL editing with mask/default handling |
| v1.1 | inotify live change detection |
| v1.2 | SSH remote host (read-only first) |
| v1.2 | JSON + PDF export |
| v1.3 | Remote helper agent over SSH |
| v1.3 | Favorites/watchlists |
| v1.4 | Policy baselines + drift detection |
| v1.4 | Rollback for in-app changes |
| v2.0 | Multi-host comparison |
| v2.0 | NAS-scale auditing |
| v2.0 | Alerting integrations |
| v2.1 | Encrypted audit metadata storage |
