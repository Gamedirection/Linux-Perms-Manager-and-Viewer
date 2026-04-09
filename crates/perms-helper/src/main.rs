// perms-helper: privileged binary, launched via polkit.
// Phase 4 will implement the Unix socket IPC server.
// For now: refuse to run without being called by the UI process.

fn main() {
    eprintln!("perms-helper: not yet implemented (Phase 4)");
    std::process::exit(1);
}
