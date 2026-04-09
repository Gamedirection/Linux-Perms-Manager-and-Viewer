mod app_state;
mod components;
mod model;
mod tabs;

use gtk4::prelude::*;
use gtk4::CssProvider;
use libadwaita::ColorScheme;
use libadwaita::StyleManager;

use app_state::new_shared;
use tabs::{build_dashboard, build_management, build_settings, viewer};

fn main() {
    let app = libadwaita::Application::builder()
        .application_id("org.perms.app")
        .build();

    app.connect_activate(build_ui);
    std::process::exit(app.run().into());
}

fn build_ui(app: &libadwaita::Application) {
    // Request dark mode via AdwStyleManager (not the deprecated GTK setting)
    StyleManager::default().set_color_scheme(ColorScheme::PreferDark);

    // Load CSS
    let provider = CssProvider::new();
    provider.load_from_string(include_str!("../resources/style.css"));
    gtk4::style_context_add_provider_for_display(
        &gtk4::gdk::Display::default().unwrap(),
        &provider,
        gtk4::STYLE_PROVIDER_PRIORITY_APPLICATION,
    );

    // Shared state
    let state = new_shared();

    // ── Header bar ────────────────────────────────────────────────────────────
    let header = libadwaita::HeaderBar::new();

    let privilege_label = {
        let s = state.lock().unwrap();
        let level = s.privilege;
        drop(s);
        gtk4::Label::builder()
            .label(level.label())
            .css_classes([level.css_class()])
            .build()
    };
    header.pack_end(&privilege_label);

    // ── Tab view ──────────────────────────────────────────────────────────────
    let tab_view = libadwaita::TabView::new();
    let tab_bar = libadwaita::TabBar::builder().view(&tab_view).build();

    let dashboard_tab = tab_view.append(&build_dashboard(state.clone()));
    dashboard_tab.set_title("Dashboard");

    let viewer_widget = viewer::build(state.clone());
    let viewer_tab = tab_view.append(&viewer_widget);
    viewer_tab.set_title("Viewer");

    let mgmt = tab_view.append(&build_management(state.clone()));
    mgmt.set_title("Management");

    let settings = tab_view.append(&build_settings(state.clone()));
    settings.set_title("Settings");

    tab_view.set_selected_page(&dashboard_tab);

    // ── Prevent tab closing ───────────────────────────────────────────────────
    // Mark every page non-closeable (hides the × button).
    for page in [&dashboard_tab, &viewer_tab, &mgmt, &settings] {
        page.set_property("closeable", false);
    }

    // Safety net: if a close somehow gets requested, always deny it.
    tab_view.connect_close_page(|view, page| {
        view.close_page_finish(page, false);
        gtk4::glib::Propagation::Stop
    });

    // ── Tab drag-out → new window ─────────────────────────────────────────────
    // When the user drags a tab out of the window, libadwaita emits
    // `create-window`. Returning a valid TabView moves the tab there.
    // Returning NULL crashes; not connecting the signal disables drag-out.
    tab_view.connect_create_window({
        let app = app.clone();
        move |_source_view| {
            let new_tab_view = make_detached_tab_view();

            let new_tab_bar =
                libadwaita::TabBar::builder().view(&new_tab_view).build();
            let new_header = libadwaita::HeaderBar::new();

            let inner = gtk4::Box::new(gtk4::Orientation::Vertical, 0);
            inner.append(&new_tab_bar);
            inner.append(&new_tab_view);

            let tv = libadwaita::ToolbarView::new();
            tv.add_top_bar(&new_header);
            tv.set_content(Some(&inner));

            let win = libadwaita::ApplicationWindow::builder()
                .application(&app)
                .title("perms — detached")
                .default_width(1000)
                .default_height(700)
                .content(&tv)
                .build();
            win.present();

            Some(new_tab_view)
        }
    });

    // ── Layout ────────────────────────────────────────────────────────────────
    let content = gtk4::Box::new(gtk4::Orientation::Vertical, 0);
    content.append(&tab_bar);
    content.append(&tab_view);

    let toolbar_view = libadwaita::ToolbarView::new();
    toolbar_view.add_top_bar(&header);
    toolbar_view.set_content(Some(&content));

    let window = libadwaita::ApplicationWindow::builder()
        .application(app)
        .title("perms")
        .default_width(1280)
        .default_height(800)
        .content(&toolbar_view)
        .build();

    window.present();
}

/// Build a bare TabView for a detached window.
/// Also prevents tabs inside it from being closed.
fn make_detached_tab_view() -> libadwaita::TabView {
    let tv = libadwaita::TabView::new();
    tv.connect_close_page(|view, page| {
        view.close_page_finish(page, false);
        gtk4::glib::Propagation::Stop
    });
    // Forward drag-out from detached windows too, so they never crash.
    tv.connect_create_window(|_| {
        // Nested drag-out: just block it (don't crash).
        // Returning None disables the drag silently.
        // We can't recursively create windows without an app ref here,
        // so we return a throw-away view that the user will never see a window for.
        // Instead: inhibit via close_page and produce nothing.
        None
    });
    tv
}
