# perms — Linux Permissions Manager and Viewer

A Linux-native desktop application for visualizing, auditing, and managing filesystem permissions, built with Rust + GTK4/libadwaita.

## Features (current)

### Dashboard tab
- 8 live audit widgets: Privilege Status, Scan Coverage, Risk Summary, World-Writable Paths, ACL Usage, Sensitive Paths, Top File Owners, Recent Audit Findings
- Background filesystem scan with real-time progress bar and cancel support
- Configurable scan roots (comma-separated, e.g. `/home,/etc`)
- Scan results persist in-session for widget display

### Viewer tab
- **Directory view** — browse the filesystem with a 5-column ColumnView (Name, Mode, Owner, Group, Flags); click any entry to open a rich detail panel
- **Detail panel** — colorized rwx permission badge (green/yellow/red for owner/group/other), clickable owner/group rows that open user and group detail popups, tooltip with full octal breakdown (e.g. `0755 = 0 special + 7 owner(r+w+x) + 5 group(r+x) + 5 other(r+x)`)
- **User view** — select any system user and a directory to see all entries that user can access, with effective access evaluation

### Management tab
- File browser with **multi-select** (Ctrl+click / Shift+click)
- **Mode editor** — octal entry and 9 rwx checkboxes (Owner/Group/Other rows, color-coded) with bidirectional sync
- **Owner / Group** fields with username/group name resolution
- **Recursive** toggle — apply changes to all children via walkdir
- **Dry-run** mode — compute and preview all changes without writing anything
- **Before/after preview** — shows old mode → new mode for all selected entries
- **Risk assessment** — world-writable result, large recursive operations, or sensitive paths trigger typed-confirmation (`APPLY`) dialog
- **Apply** — `std::fs::set_permissions` (chmod) + `nix::unistd::chown` with error collection
- **Audit log** — JSON Lines appended to `~/.local/share/perms/changes.log`; recent entries shown in bottom strip
- **IPC protocol types** (`perms-core::ipc`) — `ChangeRequest` / `ChangeResult` / `AuditEntry` ready for Phase 5 polkit helper integration

### Domain engine (perms-core)
- Full POSIX effective access evaluation (root bypass → ACL named user → ACL group union + mask → standard mode bits)
- Binary POSIX ACL parsing via `getxattr` (no external tools)
- 9 audit rules: WorldWritable, UnexpectedSuid/Sgid, OrphanedUid/Gid, WritableSystemPath, HomeOtherReadable, ExecutableWritableByNonAdmin
- Sensitive path classification (/etc, /root, /boot, /usr/bin, /home/*, /var/log, etc.)
- SQLite scan index with WAL mode (Phase 1 schema in place)

## Development

### Requirements
- Rust (2024 edition)
- GTK4 ≥ 4.18 development libraries
- libadwaita ≥ 1.6 development libraries

### Build and run
```bash
cargo build
cargo run -p perms-ui
```

### Workspace structure
```
crates/
  perms-core/    # Domain logic, no GTK — scanner, audit engine, ACL parser, SQLite store
  perms-ui/      # GTK4/libadwaita frontend
  perms-helper/  # Privileged helper binary stub (Phase 4)
```

## Roadmap

| Phase | Status | Description |
|-------|--------|-------------|
| 0 | Done | Workspace scaffold, domain types, SQLite schema |
| 1 | Done | Scanner pipeline, UserDb, ACL parser, audit engine |
| 2 | Done | Viewer tab (directory browser + detail panel + user view) |
| 3 | Done | Dashboard with 8 widgets, scan progress, scan cancel |
| 4 | Done | Management tab — chmod/chown editing, dry-run, risk dialogs, audit log |
| 5 | Planned | View-as-user mode, two-user comparison, CSV export, Settings |
| 6 | Planned | Polish, packaging (.deb, .rpm, Flatpak, AUR) |
