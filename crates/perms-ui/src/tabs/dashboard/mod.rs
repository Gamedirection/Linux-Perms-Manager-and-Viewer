mod report_window;
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
enum DashboardMsg {
    Progress(usize),
    Complete(ScanSummary),
    Cancelled,
    Error(String),
}

pub fn build(
    state: SharedState,
    on_viewer: Rc<RefCell<Option<Box<dyn Fn(PathBuf)>>>>,
    focus_viewer: Rc<RefCell<Option<Box<dyn Fn()>>>>,
) -> gtk4::Widget {
    let outer = gtk4::Box::new(gtk4::Orientation::Vertical, 0);
    outer.set_vexpand(true);
    outer.set_hexpand(true);

    // ── Combined viewer navigation callback (navigate + focus) ────────────────
    let viewer_nav: Rc<dyn Fn(PathBuf)> = {
        let on_viewer = on_viewer.clone();
        let focus_viewer = focus_viewer.clone();
        Rc::new(move |path: PathBuf| {
            if let Some(f) = on_viewer.borrow().as_ref() {
                f(path);
            }
            if let Some(f) = focus_viewer.borrow().as_ref() {
                f();
            }
        })
    };

    // ── Scan toolbar ──────────────────────────────────────────────────────────
    let default_roots = state.lock().unwrap().settings.default_roots.clone();

    let roots_entry = gtk4::Entry::builder()
        .text(&default_roots)
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

    let report_btn = gtk4::Button::builder()
        .label("Export Report")
        .tooltip_text("Open full report window with export options")
        .sensitive(false)
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
    toolbar.append(&report_btn);
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

    // ── Scrollable content ────────────────────────────────────────────────────
    let scroll = gtk4::ScrolledWindow::builder()
        .vexpand(true)
        .hexpand(true)
        .build();

    let content = gtk4::Box::new(gtk4::Orientation::Vertical, 0);
    content.set_margin_top(12);
    content.set_margin_bottom(12);
    content.set_margin_start(12);
    content.set_margin_end(12);

    let grid_area = gtk4::Box::new(gtk4::Orientation::Vertical, 12);
    content.append(&grid_area);

    let sep = gtk4::Separator::new(gtk4::Orientation::Horizontal);
    sep.set_margin_top(16);
    sep.set_margin_bottom(4);
    content.append(&sep);

    scroll.set_child(Some(&content));
    outer.append(&scroll);

    // ── Approved list (persisted) ─────────────────────────────────────────────
    let approved: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(load_approved()));

    // ── Grid rebuild closure ──────────────────────────────────────────────────
    let rebuild_grid = {
        let grid_area = grid_area.clone();
        let approved = approved.clone();
        let state = state.clone();
        let viewer_nav = viewer_nav.clone();
        Rc::new(move || {
            while let Some(child) = grid_area.first_child() {
                grid_area.remove(&child);
            }
            let privilege = state.lock().unwrap().privilege;
            let summary = state.lock().unwrap().scan_summary.clone();
            let approved_list = approved.borrow().clone();
            populate_grid(
                &grid_area,
                privilege,
                summary.as_ref(),
                &approved_list,
                &viewer_nav,
            );
        })
    };

    rebuild_grid();

    let approved_widget = approved_section(approved.clone(), rebuild_grid.clone());
    content.append(&approved_widget);

    // ── Cancel flag ───────────────────────────────────────────────────────────
    let cancel_flag: Rc<RefCell<Arc<AtomicBool>>> =
        Rc::new(RefCell::new(Arc::new(AtomicBool::new(false))));

    {
        let cancel_flag = cancel_flag.clone();
        cancel_btn.connect_clicked(move |_| {
            cancel_flag.borrow().store(true, Ordering::SeqCst);
        });
    }

    // ── Report button: open full report window ────────────────────────────────
    {
        let state = state.clone();
        let viewer_nav = viewer_nav.clone();
        report_btn.connect_clicked(move |_| {
            if let Some(summary) = state.lock().unwrap().scan_summary.clone() {
                report_window::show(summary, viewer_nav.clone());
            }
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
        let roots_entry = roots_entry.clone();
        let rebuild_grid = rebuild_grid.clone();
        let report_btn = report_btn.clone();

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

            report_btn.set_sensitive(false);

            let flag = Arc::new(AtomicBool::new(false));
            *cancel_flag.borrow_mut() = Arc::clone(&flag);
            let scan_cancel = Arc::clone(&flag);

            scan_btn.set_sensitive(false);
            cancel_btn.set_visible(true);
            progress_bar.set_visible(true);
            progress_bar.set_fraction(0.0);
            progress_bar.set_text(Some("Scanning…"));
            status_label.set_label("Scanning…");

            let queue: Arc<Mutex<VecDeque<DashboardMsg>>> =
                Arc::new(Mutex::new(VecDeque::new()));
            let queue_bg = Arc::clone(&queue);
            let queue_ui = Arc::clone(&queue);

            let userdb = state.lock().unwrap().userdb.clone();
            let roots_display: Vec<String> =
                roots.iter().map(|p| p.to_string_lossy().to_string()).collect();

            // Read scan config from settings
            let follow_symlinks = state.lock().unwrap().settings.follow_symlinks;
            let skip_hidden = state.lock().unwrap().settings.skip_hidden;

            let (scan_tx, scan_rx) = std::sync::mpsc::channel::<ScanEvent>();
            let (cancel_tx, cancel_rx) = std::sync::mpsc::channel::<()>();

            let cancel_fwd = Arc::clone(&scan_cancel);
            std::thread::spawn(move || {
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
                follow_symlinks,
                skip_hidden,
                exclude: Vec::new(),
            };
            std::thread::spawn(move || {
                let _ = run_scan(config, scan_tx, cancel_rx);
            });

            // ── Accumulator thread ────────────────────────────────────────
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
                                if summary.acl_paths.len() < 100 {
                                    summary
                                        .acl_paths
                                        .push(entry.path.to_string_lossy().to_string());
                                }
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
                                if summary.recent_findings.len() < 50 {
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

            // ── GTK timer: drain queue every 50 ms ────────────────────────
            let state = state.clone();
            let progress_bar = progress_bar.clone();
            let status_label = status_label.clone();
            let cancel_btn = cancel_btn.clone();
            let scan_btn = scan_btn_ref.clone();
            let rebuild_grid = rebuild_grid.clone();
            let report_btn = report_btn.clone();

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

                            state.lock().unwrap().scan_summary = Some(summary);
                            rebuild_grid();

                            status_label.set_label(&format!(
                                "Scan complete — {total} entries in {roots_str}"
                            ));
                            progress_bar.set_visible(false);
                            cancel_btn.set_visible(false);
                            scan_btn.set_sensitive(true);
                            report_btn.set_sensitive(true);

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

fn populate_grid(
    container: &gtk4::Box,
    privilege: crate::app_state::PrivilegeLevel,
    summary: Option<&ScanSummary>,
    approved: &[String],
    viewer_nav: &Rc<dyn Fn(PathBuf)>,
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

    container.append(&row(
        privilege_card(privilege),
        scan_coverage_card(summary),
    ));
    container.append(&row(
        risk_summary_card(summary, approved, viewer_nav.clone()),
        world_writable_card(summary, approved, viewer_nav.clone()),
    ));
    container.append(&row(
        acl_usage_card(summary, viewer_nav.clone()),
        sensitive_dirs_card(summary),
    ));
    container.append(&row(
        top_owners_card(summary),
        recent_findings_card(summary, approved, viewer_nav.clone()),
    ));
}
