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
        let lbl = gtk4::Label::builder()
            .label(level.label())
            .css_classes([level.css_class()])
            .build();
        lbl
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
