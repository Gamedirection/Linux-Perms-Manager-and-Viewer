# Changelog

## v0.0.4 — Phase 4: Management Tab

### Added
- **Management tab** — full permission editing UI:
  - Directory browser with multi-select (Ctrl+click / Shift+click via `gtk4::MultiSelection`)
  - Mode editor: octal `Entry` + 9 `CheckButton`s in a color-coded Owner/Group/Other grid; bidirectional sync via `Rc<Cell<bool>>` guard
  - Owner and Group name fields with username/group name → UID/GID resolution from `UserDb`
  - Recursive toggle (applies changes to all children via `walkdir`)
  - Dry-run toggle (computes diff without writing anything)
  - Before/after diff preview (`PreferencesGroup` description updated with change summary)
  - Apply button with two-tier confirmation:
    - **Normal risk**: simple confirm dialog
    - **High risk** (world-writable result, recursive >20 entries, or sensitive path): typed confirmation requiring `APPLY`
  - Actual apply via `std::fs::set_permissions` (chmod) + `nix::unistd::chown`
  - Error collection per path; errors shown in audit log strip
  - Directory listing reloaded after apply to show updated permissions
  - Audit log strip at bottom of tab shows results for the current session
- **`perms-core::ipc`** — `ChangeRequest`, `ChangeResult`, `AuditEntry` protocol types (Serde JSON-serialisable, ready for Phase 5 polkit helper)
- **JSON Lines audit log** — appended to `~/.local/share/perms/changes.log` on every apply (including dry-runs and errors)
- Added `serde_json`, `chrono`, `walkdir` to `perms-ui` dependencies

### Fixed
- Used `std::fs::set_permissions` for chmod (nix 0.30 removed path-based `chmod`)

---

## v0.0.3 — Phase 3: Dashboard

### Added
- **Dashboard tab** with 8 audit widgets in a 2-column grid:
  - Privilege & Status — shows current process privilege level and limitations
  - Scan Coverage — displays roots and total entries scanned
  - Risk Summary — finding counts by severity (Critical / High / Medium / Low / Info)
  - World-Writable Paths — count and first 5 examples
  - ACL Usage — count and percentage of entries with extended POSIX ACLs
  - Sensitive Paths Found — up to 8 sensitive paths from the scan roots
  - Top File Owners — top 10 UIDs by entry count with username resolution
  - Recent Audit Findings — last 10 audit findings with severity badge, rule name, and path
- Background filesystem scan via `run_scan()` running in a dedicated thread
- Progress bar with pulse animation during scan
- Cancel button that signals the scanner to abort mid-scan
- Configurable scan roots entry (comma-separated, defaults to `/home,/etc`)
- `ScanSummary` struct in `AppState` — persists dashboard data for the session
- `UserDb` now implements `Clone` to allow passing to background threads
- Severity CSS classes: `.severity-critical`, `.severity-high`, `.severity-medium`, `.severity-low`, `.severity-info`
- Dashboard metric count style: `.dashboard-count`

### Changed
- App now starts on the Dashboard tab instead of Viewer

---

## v0.0.2 — Phase 2: Viewer + Detail Panel

### Added
- **Directory view** — ColumnView with 5 columns (Name/icon, Mode, Owner, Group, Flags)
- **Detail panel** — right pane with ownership info, colorized rwx badge, and access dots
- Clickable Owner/Group rows opening user and group popup dialogs
- Green/Yellow/Red colorization of rwx bits by owner/group/other grouping (`mode-owner`, `mode-group`, `mode-other` CSS classes)
- `mode_badge_colored()` — colored symbolic + octal badge widget
- Octal breakdown tooltip on the Mode row (e.g. `0755 = special 0 + owner 7(r+w+x) + ...`)
- Who Has Access section with access dots per user
- **User view** — select a user and directory to list accessible entries
- Privilege badge in header bar

### Fixed
- `RefCell already borrowed` panic in directory view — extracted borrow before calling load_dir
- `gtk_list_box_row_grab_focus` CRITICAL in user view — replaced ActionRow-in-ListView with plain Box+Label rows
- `gtk_list_box_row_grab_focus` CRITICAL in directory view — deferred widget rebuild with `idle_add_local_once`
- Detail panel squished — added `vexpand`/`hexpand` throughout widget hierarchy
- Markup `&` error in PreferencesGroup title

---

## v0.0.1 — Phase 0 + Phase 1: Foundation

### Added
- Rust workspace with `perms-core`, `perms-ui`, `perms-helper` crates
- Domain types: `SystemUser`, `SystemGroup`, `PathEntry`, `UnixMode`, `AclEntry`/`AclSet`
- `UserDb` — loads /etc/passwd and /etc/group, resolves supplementary GIDs
- Binary POSIX ACL parser via `getxattr` syscall
- Full effective access evaluation engine (root → ACL user → ACL group+mask → standard bits)
- 9 audit rules: WorldWritable, Suid/Sgid, Orphaned ownership, WritableSystemPath, HomeOtherReadable, ExecutableWritableByNonAdmin
- SQLite scan index with WAL mode, schema migrations
- GTK4/libadwaita dark-mode application shell with 4 tab placeholders
- CSS permission colour scheme (danger=red, warn=yellow, ok=green, access dots)
- `perms-helper` stub binary (Phase 4 polkit helper placeholder)
