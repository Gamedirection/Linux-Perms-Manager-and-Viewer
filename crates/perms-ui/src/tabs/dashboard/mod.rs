mod widgets;

use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use gtk4::glib;
use gtk4::prelude::*;

use perms_core::engine::audit::{AuditContext, AuditEngine, Severity};
use perms_core::engine::scanner::{run_scan, ScanConfig, ScanEvent};

use crate::app_state::{ScanSummary, SharedState};
use widgets::*;

/// Messages from the background scan thread to the GTK main thread.
/// Queued via Arc<Mutex<VecDeque>> and drained by a glib timer on the main thread.
enum DashboardMsg {
    Progress(usize),
    Complete(ScanSummary),
    Cancelled,
    Error(String),
}

pub fn build(state: SharedState) -> gtk4::Widget {
    let outer = gtk4::Box::new(gtk4::Orientation::Vertical, 0);
    outer.set_vexpand(true);
    outer.set_hexpand(true);

    // ── Scan toolbar ──────────────────────────────────────────────────────────
    let roots_entry = gtk4::Entry::builder()
        .text("/home,/etc")
        .hexpand(true)
        .placeholder_text("Comma-separated scan roots")
        .css_classes(["monospace"])
        .build();

    let scan_btn = gtk4::Button::builder()
        .label("Scan Now")
        .css_classes(["suggested-action"])
        .build();

    let cancel_btn = gtk4::Button::builder()
        .label("Cancel")
        .css_classes(["destructive-action"])
        .visible(false)
        .build();

    let toolbar = gtk4::Box::new(gtk4::Orientation::Horizontal, 8);
    toolbar.set_margin_top(8);
    toolbar.set_margin_bottom(4);
    toolbar.set_margin_start(8);
    toolbar.set_margin_end(8);
    toolbar.append(&gtk4::Label::new(Some("Scan roots:")));
    toolbar.append(&roots_entry);
    toolbar.append(&scan_btn);
    toolbar.append(&cancel_btn);
    outer.append(&toolbar);

    // ── Progress bar ──────────────────────────────────────────────────────────
    let progress_bar = gtk4::ProgressBar::builder()
        .show_text(true)
        .text("Idle")
        .visible(false)
        .margin_start(8)
        .margin_end(8)
        .margin_bottom(4)
        .build();
    outer.append(&progress_bar);

    // ── Status label ──────────────────────────────────────────────────────────
    let status_label = gtk4::Label::builder()
        .label("Click 'Scan Now' to populate the dashboard.")
        .css_classes(["dim-label"])
        .halign(gtk4::Align::Start)
        .margin_start(8)
        .margin_bottom(4)
        .build();
    outer.append(&status_label);

    // ── Scrollable widget grid ────────────────────────────────────────────────
    let scroll = gtk4::ScrolledWindow::builder()
        .vexpand(true)
        .hexpand(true)
        .build();

    let content = gtk4::Box::new(gtk4::Orientation::Vertical, 12);
    content.set_margin_top(12);
    content.set_margin_bottom(12);
    content.set_margin_start(12);
    content.set_margin_end(12);

    scroll.set_child(Some(&content));
    outer.append(&scroll);

    // Initial render — no scan data yet
    {
        let privilege = state.lock().unwrap().privilege;
        populate_grid(&content, privilege, None);
    }

    // ── Cancel sender (main-thread only) ──────────────────────────────────────
    let cancel_flag: Rc<RefCell<Arc<AtomicBool>>> =
        Rc::new(RefCell::new(Arc::new(AtomicBool::new(false))));

    {
        let cancel_flag = cancel_flag.clone();
        cancel_btn.connect_clicked(move |_| {
            cancel_flag.borrow().store(true, Ordering::SeqCst);
        });
    }

    // ── Scan button handler ───────────────────────────────────────────────────
    {
        let state = state.clone();
        let cancel_flag = cancel_flag.clone();
        let progress_bar = progress_bar.clone();
        let status_label = status_label.clone();
        let cancel_btn = cancel_btn.clone();
        let scan_btn_ref = scan_btn.clone();
        let content = content.clone();
        let roots_entry = roots_entry.clone();

        scan_btn.connect_clicked(move |scan_btn| {
            let roots: Vec<PathBuf> = roots_entry
                .text()
                .split(',')
                .map(|s| PathBuf::from(s.trim()))
                .filter(|p| !p.as_os_str().is_empty())
                .collect();

            if roots.is_empty() {
                status_label.set_label("No scan roots specified.");
                return;
            }

            // Fresh cancel flag for this run
            let flag = Arc::new(AtomicBool::new(false));
            *cancel_flag.borrow_mut() = Arc::clone(&flag);
            let scan_cancel = Arc::clone(&flag);

            // UI: busy state
            scan_btn.set_sensitive(false);
            cancel_btn.set_visible(true);
            progress_bar.set_visible(true);
            progress_bar.set_fraction(0.0);
            progress_bar.set_text(Some("Scanning…"));
            status_label.set_label("Scanning…");

            // Shared message queue: background thread → GTK timer
            let queue: Arc<Mutex<VecDeque<DashboardMsg>>> =
                Arc::new(Mutex::new(VecDeque::new()));
            let queue_bg = Arc::clone(&queue);
            let queue_ui = Arc::clone(&queue);

            // Clone what background threads need
            let userdb = state.lock().unwrap().userdb.clone();
            let roots_display: Vec<String> =
                roots.iter().map(|p| p.to_string_lossy().to_string()).collect();

            // ── Scanner thread ────────────────────────────────────────────────
            let (scan_tx, scan_rx) = std::sync::mpsc::channel::<ScanEvent>();
            let (cancel_tx, cancel_rx) = std::sync::mpsc::channel::<()>();

            // Forward AtomicBool cancel into the mpsc cancel channel
            let cancel_fwd = Arc::clone(&scan_cancel);
            std::thread::spawn(move || {
                // Poll the flag and send cancel signal when set
                loop {
                    if cancel_fwd.load(Ordering::SeqCst) {
                        let _ = cancel_tx.send(());
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
            });

            let config = ScanConfig {
                roots,
                follow_symlinks: false,
                skip_hidden: false,
                exclude: Vec::new(),
            };
            std::thread::spawn(move || {
                let _ = run_scan(config, scan_tx, cancel_rx);
            });

            // ── Accumulator thread ────────────────────────────────────────────
            std::thread::spawn(move || {
                let audit = AuditEngine::default_ruleset();
                let ctx = AuditContext { userdb: &userdb };

                let mut summary = ScanSummary {
                    scan_roots_used: roots_display,
                    ..Default::default()
                };
                let mut owner_counts: HashMap<u32, usize> = HashMap::new();
                let mut progress_ticks = 0usize;

                loop {
                    let msg = match scan_rx.recv() {
                        Ok(m) => m,
                        Err(_) => {
                            queue_bg.lock().unwrap().push_back(DashboardMsg::Error(
                                "Scan channel closed unexpectedly.".into(),
                            ));
                            break;
                        }
                    };

                    match msg {
                        ScanEvent::Entry(entry) => {
                            summary.total_entries += 1;
                            progress_ticks += 1;

                            if entry.mode.is_world_writable()
                                && summary.world_writable.len() < 20
                            {
                                summary
                                    .world_writable
                                    .push(entry.path.to_string_lossy().to_string());
                            }

                            if entry.has_acl() {
                                summary.acl_count += 1;
                            }

                            if entry.sensitive_label.is_some()
                                && summary.sensitive_paths.len() < 20
                            {
                                summary
                                    .sensitive_paths
                                    .push(entry.path.to_string_lossy().to_string());
                            }

                            for finding in audit.check(&entry, &ctx) {
                                match finding.severity {
                                    Severity::Critical => summary.findings_critical += 1,
                                    Severity::High => summary.findings_high += 1,
                                    Severity::Medium => summary.findings_medium += 1,
                                    Severity::Low => summary.findings_low += 1,
                                    Severity::Info => summary.findings_info += 1,
                                }
                                if summary.recent_findings.len() < 30 {
                                    summary.recent_findings.push((
                                        finding.severity.to_string(),
                                        finding.rule_id.to_string(),
                                        entry.path.to_string_lossy().to_string(),
                                    ));
                                }
                            }

                            *owner_counts.entry(entry.owner_uid).or_insert(0) += 1;

                            if progress_ticks % 200 == 0 {
                                queue_bg
                                    .lock()
                                    .unwrap()
                                    .push_back(DashboardMsg::Progress(summary.total_entries));
                            }
                        }
                        ScanEvent::Complete { .. } => {
                            // Resolve top owners by entry count
                            let mut owners: Vec<(u32, usize)> =
                                owner_counts.into_iter().collect();
                            owners.sort_by(|a, b| b.1.cmp(&a.1));
                            summary.top_owners = owners
                                .into_iter()
                                .take(10)
                                .map(|(uid, count)| {
                                    let name = ctx
                                        .userdb
                                        .user_by_uid(uid)
                                        .map(|u| u.username.clone())
                                        .unwrap_or_else(|| format!("uid:{uid}"));
                                    (name, count)
                                })
                                .collect();

                            queue_bg
                                .lock()
                                .unwrap()
                                .push_back(DashboardMsg::Complete(summary));
                            break;
                        }
                        ScanEvent::Cancelled => {
                            queue_bg.lock().unwrap().push_back(DashboardMsg::Cancelled);
                            break;
                        }
                        ScanEvent::Error { .. } | ScanEvent::Progress { .. } => {}
                    }
                }
            });

            // ── GTK timer: drain queue on main thread every 50 ms ─────────────
            let state = state.clone();
            let content = content.clone();
            let progress_bar = progress_bar.clone();
            let status_label = status_label.clone();
            let cancel_btn = cancel_btn.clone();
            let scan_btn = scan_btn_ref.clone();

            glib::timeout_add_local(Duration::from_millis(50), move || {
                let mut q = queue_ui.lock().unwrap();

                while let Some(msg) = q.pop_front() {
                    match msg {
                        DashboardMsg::Progress(count) => {
                            progress_bar.pulse();
                            progress_bar.set_text(Some(&format!("{count} entries…")));
                        }
                        DashboardMsg::Complete(summary) => {
                            let total = summary.total_entries;
                            let roots_str = summary.scan_roots_used.join(", ");

                            state.lock().unwrap().scan_summary = Some(summary.clone());

                            while let Some(child) = content.first_child() {
                                content.remove(&child);
                            }
                            let privilege = state.lock().unwrap().privilege;
                            populate_grid(&content, privilege, Some(&summary));

                            status_label.set_label(&format!(
                                "Scan complete — {total} entries in {roots_str}"
                            ));
                            progress_bar.set_visible(false);
                            cancel_btn.set_visible(false);
                            scan_btn.set_sensitive(true);

                            return glib::ControlFlow::Break;
                        }
                        DashboardMsg::Cancelled => {
                            status_label.set_label("Scan cancelled.");
                            progress_bar.set_visible(false);
                            cancel_btn.set_visible(false);
                            scan_btn.set_sensitive(true);
                            return glib::ControlFlow::Break;
                        }
                        DashboardMsg::Error(msg) => {
                            status_label.set_label(&format!("Scan error: {msg}"));
                            progress_bar.set_visible(false);
                            cancel_btn.set_visible(false);
                            scan_btn.set_sensitive(true);
                            return glib::ControlFlow::Break;
                        }
                    }
                }

                glib::ControlFlow::Continue
            });
        });
    }

    outer.upcast()
}

/// Render the 2-column widget grid inside `content`.
fn populate_grid(
    content: &gtk4::Box,
    privilege: crate::app_state::PrivilegeLevel,
    summary: Option<&ScanSummary>,
) {
    let row = |w1: gtk4::Widget, w2: gtk4::Widget| -> gtk4::Box {
        let r = gtk4::Box::new(gtk4::Orientation::Horizontal, 12);
        r.set_hexpand(true);
        w1.set_hexpand(true);
        w2.set_hexpand(true);
        r.append(&w1);
        r.append(&w2);
        r
    };

    content.append(&row(privilege_card(privilege), scan_coverage_card(summary)));
    content.append(&row(risk_summary_card(summary), world_writable_card(summary)));
    content.append(&row(acl_usage_card(summary), sensitive_dirs_card(summary)));
    content.append(&row(top_owners_card(summary), recent_findings_card(summary)));
}
