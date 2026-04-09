use gtk4::prelude::*;
use libadwaita::prelude::*;

fn main() {
    // Ensure GTK and libadwaita are initialized together.
    let app = libadwaita::Application::builder()
        .application_id("org.perms.app")
        .build();

    app.connect_activate(build_ui);

    std::process::exit(app.run().into());
}

fn build_ui(app: &libadwaita::Application) {
    let window = libadwaita::ApplicationWindow::builder()
        .application(app)
        .title("perms")
        .default_width(1200)
        .default_height(800)
        .build();

    // Top-level layout: header bar + tab view
    let header = libadwaita::HeaderBar::new();

    // Privilege status pill — placeholder label for Phase 0
    let privilege_label = gtk4::Label::new(Some("Unprivileged"));
    privilege_label.add_css_class("privilege-badge");
    header.pack_end(&privilege_label);

    // Tab bar
    let tab_view = libadwaita::TabView::new();
    let tab_bar = libadwaita::TabBar::builder()
        .view(&tab_view)
        .build();

    // Dashboard placeholder
    let dashboard_page = make_placeholder_page("Dashboard", "Widgets load here in Phase 3.");
    let dashboard_tab = tab_view.append(&dashboard_page);
    dashboard_tab.set_title("Dashboard");

    // Viewer placeholder
    let viewer_page = make_placeholder_page("Viewer", "Directory and user inspection in Phase 2.");
    let viewer_tab = tab_view.append(&viewer_page);
    viewer_tab.set_title("Viewer");

    // Management placeholder
    let management_page = make_placeholder_page("Management", "Permission editing in Phase 4.");
    let management_tab = tab_view.append(&management_page);
    management_tab.set_title("Management");

    // Settings placeholder
    let settings_page = make_placeholder_page("Settings", "Configuration in Phase 5.");
    let settings_tab = tab_view.append(&settings_page);
    settings_tab.set_title("Settings");

    // Main layout
    let content = gtk4::Box::new(gtk4::Orientation::Vertical, 0);
    content.append(&tab_bar);
    content.append(&tab_view);

    let toolbar_view = libadwaita::ToolbarView::new();
    toolbar_view.add_top_bar(&header);
    toolbar_view.set_content(Some(&content));

    window.set_content(Some(&toolbar_view));
    window.present();
}

fn make_placeholder_page(title: &str, subtitle: &str) -> gtk4::Box {
    let label = gtk4::Label::builder()
        .label(format!("<b>{title}</b>\n{subtitle}"))
        .use_markup(true)
        .justify(gtk4::Justification::Center)
        .build();
    label.add_css_class("dim-label");

    let container = gtk4::Box::new(gtk4::Orientation::Vertical, 0);
    container.set_valign(gtk4::Align::Center);
    container.set_halign(gtk4::Align::Center);
    container.append(&label);
    container
}
