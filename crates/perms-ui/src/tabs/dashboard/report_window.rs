use std::path::PathBuf;
use std::rc::Rc;

use gtk4::prelude::*;
use libadwaita::prelude::*;
use rust_xlsxwriter::Workbook;

use crate::app_state::ScanSummary;

/// Open a full-detail audit report window with export buttons.
pub fn show(summary: ScanSummary, viewer_nav: Rc<dyn Fn(PathBuf)>) {
    let win = libadwaita::Window::builder()
        .title("Audit Report — Full Details")
        .default_width(1000)
        .default_height(750)
        .build();

    // ── Header bar ────────────────────────────────────────────────────────────
    let header = libadwaita::HeaderBar::new();

    let csv_btn = gtk4::Button::builder()
        .label("CSV")
        .tooltip_text("Export findings as CSV")
        .build();
    let html_btn = gtk4::Button::builder()
        .label("HTML")
        .tooltip_text("Export full report as HTML and open in browser")
        .build();
    let xlsx_btn = gtk4::Button::builder()
        .label("XLSX")
        .tooltip_text("Export report as Excel spreadsheet")
        .build();
    let pdf_btn = gtk4::Button::builder()
        .label("PDF")
        .tooltip_text("Export HTML report and open in browser (File → Print → Save as PDF)")
        .build();

    header.pack_end(&pdf_btn);
    header.pack_end(&xlsx_btn);
    header.pack_end(&html_btn);
    header.pack_end(&csv_btn);

    // ── Stack with section tabs ───────────────────────────────────────────────
    let stack = gtk4::Stack::builder()
        .transition_type(gtk4::StackTransitionType::SlideLeftRight)
        .vexpand(true)
        .hexpand(true)
        .build();

    stack.add_titled(&build_summary_page(&summary), Some("summary"), "Summary");
    stack.add_titled(
        &build_findings_page(&summary, viewer_nav.clone()),
        Some("findings"),
        &format!("Findings ({})", summary.recent_findings.len()),
    );
    stack.add_titled(
        &build_ww_page(&summary, viewer_nav.clone()),
        Some("ww"),
        &format!("World-Writable ({})", summary.world_writable.len()),
    );
    stack.add_titled(
        &build_acl_page(&summary, viewer_nav.clone()),
        Some("acl"),
        &format!("ACL Paths ({})", summary.acl_paths.len()),
    );
    stack.add_titled(&build_owners_page(&summary), Some("owners"), "Owners");

    let switcher = gtk4::StackSwitcher::builder().stack(&stack).build();

    // ── Wire export buttons ───────────────────────────────────────────────────
    {
        let s = summary.clone();
        csv_btn.connect_clicked(move |_| match export_csv(&s) {
            Ok(p) => open_path(&p),
            Err(e) => eprintln!("CSV export error: {e}"),
        });
    }
    {
        let s = summary.clone();
        html_btn.connect_clicked(move |_| match export_html(&s) {
            Ok(p) => open_path(&p),
            Err(e) => eprintln!("HTML export error: {e}"),
        });
    }
    {
        let s = summary.clone();
        xlsx_btn.connect_clicked(move |_| match export_xlsx(&s) {
            Ok(p) => open_path(&p),
            Err(e) => eprintln!("XLSX export error: {e}"),
        });
    }
    {
        // PDF: export HTML and open in browser
        let s = summary.clone();
        pdf_btn.connect_clicked(move |_| match export_html(&s) {
            Ok(p) => open_path(&p),
            Err(e) => eprintln!("PDF/HTML export error: {e}"),
        });
    }

    // ── Layout ────────────────────────────────────────────────────────────────
    let body = gtk4::Box::new(gtk4::Orientation::Vertical, 0);
    body.append(&switcher);
    body.append(&stack);

    let toolbar_view = libadwaita::ToolbarView::new();
    toolbar_view.add_top_bar(&header);
    toolbar_view.set_content(Some(&body));

    win.set_content(Some(&toolbar_view));
    win.present();
}

// ── Section page builders ─────────────────────────────────────────────────────

fn build_summary_page(s: &ScanSummary) -> gtk4::Widget {
    let scroll = gtk4::ScrolledWindow::builder()
        .vexpand(true)
        .hexpand(true)
        .build();

    let vbox = gtk4::Box::new(gtk4::Orientation::Vertical, 12);
    vbox.set_margin_top(16);
    vbox.set_margin_bottom(16);
    vbox.set_margin_start(16);
    vbox.set_margin_end(16);

    let info_grp = libadwaita::PreferencesGroup::builder()
        .title("Scan Information")
        .build();
    info_grp.add(&text_row("Scan Roots", &s.scan_roots_used.join(", ")));
    info_grp.add(&text_row("Total Entries", &s.total_entries.to_string()));
    vbox.append(&info_grp);

    let risk_grp = libadwaita::PreferencesGroup::builder()
        .title("Risk Summary")
        .build();
    risk_grp.add(&badge_row(
        "Critical",
        s.findings_critical,
        "severity-critical",
    ));
    risk_grp.add(&badge_row("High", s.findings_high, "severity-high"));
    risk_grp.add(&badge_row("Medium", s.findings_medium, "severity-medium"));
    risk_grp.add(&badge_row("Low", s.findings_low, "severity-low"));
    risk_grp.add(&badge_row("Info", s.findings_info, "severity-info"));
    vbox.append(&risk_grp);

    scroll.set_child(Some(&vbox));
    scroll.upcast()
}

fn build_findings_page(s: &ScanSummary, viewer: Rc<dyn Fn(PathBuf)>) -> gtk4::Widget {
    let scroll = gtk4::ScrolledWindow::builder()
        .vexpand(true)
        .hexpand(true)
        .build();
    let vbox = gtk4::Box::new(gtk4::Orientation::Vertical, 12);
    vbox.set_margin_top(16);
    vbox.set_margin_bottom(16);
    vbox.set_margin_start(16);
    vbox.set_margin_end(16);

    let grp = libadwaita::PreferencesGroup::builder()
        .title(&format!(
            "Audit Findings — {} captured",
            s.recent_findings.len()
        ))
        .description("Click any row to open the path in the Viewer.")
        .build();

    if s.recent_findings.is_empty() {
        grp.add(&dim_row("No findings. ✓"));
    }
    for (severity, rule, path) in &s.recent_findings {
        let row = libadwaita::ActionRow::builder()
            .title(&esc(rule))
            .subtitle(&esc(path))
            .activatable(true)
            .tooltip_text("Click to open in Viewer")
            .css_classes(["monospace"])
            .build();
        let sev_badge = gtk4::Label::builder()
            .label(severity.as_str())
            .css_classes(["caption", sev_css(severity)])
            .valign(gtk4::Align::Center)
            .build();
        row.add_prefix(&sev_badge);
        let p = path.clone();
        let v = viewer.clone();
        row.connect_activated(move |_| v(nav_path(&p)));
        grp.add(&row);
    }
    vbox.append(&grp);
    scroll.set_child(Some(&vbox));
    scroll.upcast()
}

fn build_ww_page(s: &ScanSummary, viewer: Rc<dyn Fn(PathBuf)>) -> gtk4::Widget {
    let scroll = gtk4::ScrolledWindow::builder()
        .vexpand(true)
        .hexpand(true)
        .build();
    let vbox = gtk4::Box::new(gtk4::Orientation::Vertical, 12);
    vbox.set_margin_top(16);
    vbox.set_margin_bottom(16);
    vbox.set_margin_start(16);
    vbox.set_margin_end(16);

    let grp = libadwaita::PreferencesGroup::builder()
        .title(&format!(
            "World-Writable Paths — {} found",
            s.world_writable.len()
        ))
        .description("Click any path to open it in the Viewer.")
        .build();

    if s.world_writable.is_empty() {
        grp.add(&dim_row("None found. ✓"));
    }
    for path in &s.world_writable {
        let row = libadwaita::ActionRow::builder()
            .title(&esc(path))
            .activatable(true)
            .tooltip_text("Click to open in Viewer")
            .css_classes(["monospace"])
            .build();
        let p = path.clone();
        let v = viewer.clone();
        row.connect_activated(move |_| v(nav_path(&p)));
        grp.add(&row);
    }
    vbox.append(&grp);
    scroll.set_child(Some(&vbox));
    scroll.upcast()
}

fn build_acl_page(s: &ScanSummary, viewer: Rc<dyn Fn(PathBuf)>) -> gtk4::Widget {
    let scroll = gtk4::ScrolledWindow::builder()
        .vexpand(true)
        .hexpand(true)
        .build();
    let vbox = gtk4::Box::new(gtk4::Orientation::Vertical, 12);
    vbox.set_margin_top(16);
    vbox.set_margin_bottom(16);
    vbox.set_margin_start(16);
    vbox.set_margin_end(16);

    let grp = libadwaita::PreferencesGroup::builder()
        .title(&format!("ACL Paths — {} captured", s.acl_paths.len()))
        .description("Paths with extended POSIX ACLs. Click to open in Viewer.")
        .build();

    if s.acl_paths.is_empty() {
        grp.add(&dim_row("No ACL paths captured."));
    }
    for path in &s.acl_paths {
        let row = libadwaita::ActionRow::builder()
            .title(&esc(path))
            .activatable(true)
            .tooltip_text("Click to open in Viewer")
            .css_classes(["monospace"])
            .build();
        let p = path.clone();
        let v = viewer.clone();
        row.connect_activated(move |_| v(nav_path(&p)));
        grp.add(&row);
    }
    vbox.append(&grp);
    scroll.set_child(Some(&vbox));
    scroll.upcast()
}

fn build_owners_page(s: &ScanSummary) -> gtk4::Widget {
    let scroll = gtk4::ScrolledWindow::builder()
        .vexpand(true)
        .hexpand(true)
        .build();
    let vbox = gtk4::Box::new(gtk4::Orientation::Vertical, 12);
    vbox.set_margin_top(16);
    vbox.set_margin_bottom(16);
    vbox.set_margin_start(16);
    vbox.set_margin_end(16);

    let grp = libadwaita::PreferencesGroup::builder()
        .title("Top File Owners")
        .build();

    for (name, count) in &s.top_owners {
        let row = libadwaita::ActionRow::builder()
            .title(name.as_str())
            .build();
        let badge = gtk4::Label::builder()
            .label(&count.to_string())
            .css_classes(["monospace", "dashboard-count", "severity-info"])
            .build();
        row.add_suffix(&badge);
        grp.add(&row);
    }
    vbox.append(&grp);
    scroll.set_child(Some(&vbox));
    scroll.upcast()
}

// ── Row helpers ───────────────────────────────────────────────────────────────

fn text_row(title: &str, value: &str) -> libadwaita::ActionRow {
    libadwaita::ActionRow::builder()
        .title(title)
        .subtitle(&esc(value))
        .build()
}

fn badge_row(label: &str, count: usize, css: &str) -> libadwaita::ActionRow {
    let row = libadwaita::ActionRow::builder().title(label).build();
    let badge = gtk4::Label::builder()
        .label(&count.to_string())
        .css_classes(["monospace", "dashboard-count", css])
        .build();
    row.add_suffix(&badge);
    row
}

fn dim_row(msg: &str) -> libadwaita::ActionRow {
    libadwaita::ActionRow::builder()
        .title(msg)
        .css_classes(["dim-label"])
        .build()
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn sev_css(s: &str) -> &'static str {
    match s {
        "Critical" => "severity-critical",
        "High" => "severity-high",
        "Medium" => "severity-medium",
        "Low" => "severity-low",
        _ => "severity-info",
    }
}

fn nav_path(path: &str) -> PathBuf {
    let p = PathBuf::from(path);
    if p.is_dir() {
        p
    } else {
        p.parent()
            .filter(|x| !x.as_os_str().is_empty())
            .map(|x| x.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("/"))
    }
}

fn open_path(path: &PathBuf) {
    let _ = std::process::Command::new("xdg-open").arg(path).spawn();
}

fn report_dir() -> Result<PathBuf, String> {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    let dir = PathBuf::from(home).join(".local/share/perms/reports");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    Ok(dir)
}

// ── Export functions ──────────────────────────────────────────────────────────

fn export_csv(s: &ScanSummary) -> Result<PathBuf, String> {
    use std::io::Write as IoWrite;

    let dir = report_dir()?;
    let now = chrono::Local::now();
    let path = dir.join(format!("report_{}.csv", now.format("%Y%m%d_%H%M%S")));

    let mut f = std::fs::File::create(&path).map_err(|e| e.to_string())?;
    writeln!(f, "section,severity,rule,path").map_err(|e| e.to_string())?;

    for (sev, rule, p) in &s.recent_findings {
        writeln!(f, "finding,{sev},{rule},{p}").map_err(|e| e.to_string())?;
    }
    for p in &s.world_writable {
        writeln!(f, "world-writable,,world-writable,{p}").map_err(|e| e.to_string())?;
    }
    for p in &s.acl_paths {
        writeln!(f, "acl,,acl,{p}").map_err(|e| e.to_string())?;
    }
    Ok(path)
}

fn export_html(s: &ScanSummary) -> Result<PathBuf, String> {
    use std::fmt::Write as FmtWrite;

    let dir = report_dir()?;
    let now = chrono::Local::now();
    let path = dir.join(format!("report_{}.html", now.format("%Y%m%d_%H%M%S")));

    let mut buf = String::new();
    writeln!(buf, "<!DOCTYPE html><html><head><meta charset='utf-8'>").ok();
    writeln!(
        buf,
        "<title>Audit Report — {}</title>",
        now.format("%Y-%m-%d")
    )
    .ok();
    writeln!(buf, "<style>").ok();
    writeln!(
        buf,
        "body{{font-family:monospace;background:#1e1e2e;color:#cdd6f4;padding:2rem;}}"
    )
    .ok();
    writeln!(
        buf,
        "h1,h2{{color:#cba6f7;}} table{{border-collapse:collapse;width:100%;margin-bottom:2rem;}}"
    )
    .ok();
    writeln!(buf, "th{{background:#313244;padding:8px;text-align:left;}} td{{padding:6px 8px;border-bottom:1px solid #45475a;}}").ok();
    writeln!(buf, ".critical{{color:#f38ba8;}} .high{{color:#fab387;}} .medium{{color:#f9e2af;}} .low{{color:#89b4fa;}} .info{{color:#a6adc8;}}").ok();
    writeln!(buf, "</style></head><body>").ok();
    writeln!(buf, "<h1>Linux Permissions Audit Report</h1>").ok();
    writeln!(
        buf,
        "<p><b>Date:</b> {} | <b>Roots:</b> {} | <b>Entries:</b> {}</p>",
        now.format("%Y-%m-%d %H:%M:%S"),
        html_esc(&s.scan_roots_used.join(", ")),
        s.total_entries
    )
    .ok();

    writeln!(
        buf,
        "<h2>Risk Summary</h2><table><tr><th>Severity</th><th>Count</th></tr>"
    )
    .ok();
    writeln!(
        buf,
        "<tr><td class='critical'>Critical</td><td>{}</td></tr>",
        s.findings_critical
    )
    .ok();
    writeln!(
        buf,
        "<tr><td class='high'>High</td><td>{}</td></tr>",
        s.findings_high
    )
    .ok();
    writeln!(
        buf,
        "<tr><td class='medium'>Medium</td><td>{}</td></tr>",
        s.findings_medium
    )
    .ok();
    writeln!(
        buf,
        "<tr><td class='low'>Low</td><td>{}</td></tr>",
        s.findings_low
    )
    .ok();
    writeln!(
        buf,
        "<tr><td class='info'>Info</td><td>{}</td></tr></table>",
        s.findings_info
    )
    .ok();

    if !s.recent_findings.is_empty() {
        writeln!(
            buf,
            "<h2>Audit Findings ({} captured)</h2>",
            s.recent_findings.len()
        )
        .ok();
        writeln!(
            buf,
            "<table><tr><th>Severity</th><th>Rule</th><th>Path</th></tr>"
        )
        .ok();
        for (sev, rule, p) in &s.recent_findings {
            let css = sev.to_lowercase();
            writeln!(
                buf,
                "<tr><td class='{css}'>{}</td><td>{}</td><td>{}</td></tr>",
                html_esc(sev),
                html_esc(rule),
                html_esc(p)
            )
            .ok();
        }
        writeln!(buf, "</table>").ok();
    }

    if !s.world_writable.is_empty() {
        writeln!(
            buf,
            "<h2>World-Writable Paths ({} found)</h2><table><tr><th>Path</th></tr>",
            s.world_writable.len()
        )
        .ok();
        for p in &s.world_writable {
            writeln!(buf, "<tr><td>{}</td></tr>", html_esc(p)).ok();
        }
        writeln!(buf, "</table>").ok();
    }

    if !s.acl_paths.is_empty() {
        writeln!(
            buf,
            "<h2>ACL Paths ({} captured)</h2><table><tr><th>Path</th></tr>",
            s.acl_paths.len()
        )
        .ok();
        for p in &s.acl_paths {
            writeln!(buf, "<tr><td>{}</td></tr>", html_esc(p)).ok();
        }
        writeln!(buf, "</table>").ok();
    }

    if !s.top_owners.is_empty() {
        writeln!(
            buf,
            "<h2>Top File Owners</h2><table><tr><th>User</th><th>Files</th></tr>"
        )
        .ok();
        for (user, count) in &s.top_owners {
            writeln!(buf, "<tr><td>{}</td><td>{count}</td></tr>", html_esc(user)).ok();
        }
        writeln!(buf, "</table>").ok();
    }

    writeln!(buf, "</body></html>").ok();
    std::fs::write(&path, buf).map_err(|e| e.to_string())?;
    Ok(path)
}

fn export_xlsx(s: &ScanSummary) -> Result<PathBuf, String> {
    let dir = report_dir()?;
    let now = chrono::Local::now();
    let path = dir.join(format!("report_{}.xlsx", now.format("%Y%m%d_%H%M%S")));

    let mut wb = Workbook::new();

    // Findings sheet
    {
        let ws = wb.add_worksheet();
        ws.set_name("Findings").map_err(|e| e.to_string())?;
        ws.write(0, 0, "Severity").map_err(|e| e.to_string())?;
        ws.write(0, 1, "Rule").map_err(|e| e.to_string())?;
        ws.write(0, 2, "Path").map_err(|e| e.to_string())?;
        for (i, (sev, rule, p)) in s.recent_findings.iter().enumerate() {
            let r = (i + 1) as u32;
            ws.write(r, 0, sev.as_str()).map_err(|e| e.to_string())?;
            ws.write(r, 1, rule.as_str()).map_err(|e| e.to_string())?;
            ws.write(r, 2, p.as_str()).map_err(|e| e.to_string())?;
        }
    }

    // World-Writable sheet
    {
        let ws = wb.add_worksheet();
        ws.set_name("World-Writable").map_err(|e| e.to_string())?;
        ws.write(0, 0, "Path").map_err(|e| e.to_string())?;
        for (i, p) in s.world_writable.iter().enumerate() {
            ws.write((i + 1) as u32, 0, p.as_str())
                .map_err(|e| e.to_string())?;
        }
    }

    // ACL Paths sheet
    {
        let ws = wb.add_worksheet();
        ws.set_name("ACL Paths").map_err(|e| e.to_string())?;
        ws.write(0, 0, "Path").map_err(|e| e.to_string())?;
        for (i, p) in s.acl_paths.iter().enumerate() {
            ws.write((i + 1) as u32, 0, p.as_str())
                .map_err(|e| e.to_string())?;
        }
    }

    // Owners sheet
    {
        let ws = wb.add_worksheet();
        ws.set_name("Top Owners").map_err(|e| e.to_string())?;
        ws.write(0, 0, "User").map_err(|e| e.to_string())?;
        ws.write(0, 1, "Files").map_err(|e| e.to_string())?;
        for (i, (user, count)) in s.top_owners.iter().enumerate() {
            let r = (i + 1) as u32;
            ws.write(r, 0, user.as_str()).map_err(|e| e.to_string())?;
            ws.write(r, 1, *count as u64).map_err(|e| e.to_string())?;
        }
    }

    wb.save(&path).map_err(|e| e.to_string())?;
    Ok(path)
}

fn html_esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
