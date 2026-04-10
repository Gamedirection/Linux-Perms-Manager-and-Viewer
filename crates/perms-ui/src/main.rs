mod app_state;
mod components;
mod model;
mod tabs;

use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;

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
    StyleManager::default().set_color_scheme(ColorScheme::PreferDark);

    let provider = CssProvider::new();
    provider.load_from_string(include_str!("../resources/style.css"));
    gtk4::style_context_add_provider_for_display(
        &gtk4::gdk::Display::default().unwrap(),
        &provider,
        gtk4::STYLE_PROVIDER_PRIORITY_APPLICATION,
    );

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

    let reset_tabs_btn = gtk4::Button::builder()
        .label("Reset Tabs")
        .tooltip_text("Return all detached tabs to this window")
        .build();
    header.pack_start(&reset_tabs_btn);

    // ── Tab view ──────────────────────────────────────────────────────────────
    let tab_view = libadwaita::TabView::new();
    let tab_bar = libadwaita::TabBar::builder().view(&tab_view).build();

    // Late-bound callbacks for cross-tab navigation (management and viewer).
    let on_manage_fn: Rc<RefCell<Option<Box<dyn Fn(PathBuf)>>>> =
        Rc::new(RefCell::new(None));
    let focus_mgmt_fn: Rc<RefCell<Option<Box<dyn Fn()>>>> =
        Rc::new(RefCell::new(None));
    let on_viewer_fn: Rc<RefCell<Option<Box<dyn Fn(PathBuf)>>>> =
        Rc::new(RefCell::new(None));
    let focus_viewer_fn: Rc<RefCell<Option<Box<dyn Fn()>>>> =
        Rc::new(RefCell::new(None));

    let dashboard_tab = tab_view.append(&build_dashboard(
        state.clone(),
        on_viewer_fn.clone(),
        focus_viewer_fn.clone(),
    ));
    dashboard_tab.set_title("Dashboard");

    let (viewer_widget, viewer_navigate) =
        viewer::build(state.clone(), on_manage_fn.clone(), focus_mgmt_fn.clone());
    let viewer_tab = tab_view.append(&viewer_widget);
    viewer_tab.set_title("Viewer");

    let (mgmt_widget, mgmt_ctrl) = build_management(state.clone());
    let mgmt_page = tab_view.append(&mgmt_widget);
    mgmt_page.set_title("Management");

    let settings = tab_view.append(&build_settings(state.clone()));
    settings.set_title("Settings");

    tab_view.set_selected_page(&dashboard_tab);

    // Wire management navigate callback.
    let mgmt_ctrl = Rc::new(mgmt_ctrl);
    {
        let mgmt_ctrl = mgmt_ctrl.clone();
        *on_manage_fn.borrow_mut() = Some(Box::new(move |dir: PathBuf| {
            mgmt_ctrl.navigate_to(dir);
        }));
    }

    // ── Block tab closing ─────────────────────────────────────────────────────
    // The × is hidden via CSS; this is the runtime safety net.
    tab_view.connect_close_page(|view, page| {
        view.close_page_finish(page, false);
        gtk4::glib::Propagation::Stop
    });

    // ── Track detached windows ────────────────────────────────────────────────
    // Each entry: (detached TabView, detached ApplicationWindow).
    // Shared by the create-window handler, the close-request handlers, and Reset.
    let detached: Rc<RefCell<Vec<(libadwaita::TabView, libadwaita::ApplicationWindow)>>> =
        Rc::new(RefCell::new(Vec::new()));

    // Wire focus-management callback now that detached list exists.
    {
        let tab_view_c = tab_view.clone();
        let mgmt_page_c = mgmt_page.clone();
        let detached_c = detached.clone();
        *focus_mgmt_fn.borrow_mut() = Some(Box::new(move || {
            // Check if mgmt_page is still in the main tab view.
            let n = tab_view_c.n_pages();
            let mut found = false;
            for i in 0..n {
                let page = tab_view_c.nth_page(i);
                if page == mgmt_page_c {
                    tab_view_c.set_selected_page(&page);
                    found = true;
                    break;
                }
            }
            if !found {
                // Search detached windows for the management page.
                for (det_view, win) in detached_c.borrow().iter() {
                    let m = det_view.n_pages();
                    for j in 0..m {
                        let page = det_view.nth_page(j);
                        if page == mgmt_page_c {
                            det_view.set_selected_page(&page);
                            win.present();
                            return;
                        }
                    }
                }
            }
        }));
    }

    // Wire viewer navigate callback.
    {
        let viewer_navigate = viewer_navigate.clone();
        *on_viewer_fn.borrow_mut() = Some(Box::new(move |path: PathBuf| {
            viewer_navigate(path);
        }));
    }

    // Wire focus-viewer callback.
    {
        let tab_view_c = tab_view.clone();
        let viewer_page_c = viewer_tab.clone();
        let detached_c = detached.clone();
        *focus_viewer_fn.borrow_mut() = Some(Box::new(move || {
            let n = tab_view_c.n_pages();
            let mut found = false;
            for i in 0..n {
                let page = tab_view_c.nth_page(i);
                if page == viewer_page_c {
                    tab_view_c.set_selected_page(&page);
                    found = true;
                    break;
                }
            }
            if !found {
                for (det_view, win) in detached_c.borrow().iter() {
                    let m = det_view.n_pages();
                    for j in 0..m {
                        let page = det_view.nth_page(j);
                        if page == viewer_page_c {
                            det_view.set_selected_page(&page);
                            win.present();
                            return;
                        }
                    }
                }
            }
        }));
    }

    // ── Tab drag-out → new window ─────────────────────────────────────────────
    tab_view.connect_create_window({
        let app = app.clone();
        let main_view = tab_view.clone();
        let detached = detached.clone();

        move |_| {
            let new_view = libadwaita::TabView::new();

            // Prevent closing inside the detached window too.
            new_view.connect_close_page(|v, p| {
                v.close_page_finish(p, false);
                gtk4::glib::Propagation::Stop
            });

            let new_tab_bar = libadwaita::TabBar::builder().view(&new_view).build();
            let new_header = libadwaita::HeaderBar::new();

            let inner = gtk4::Box::new(gtk4::Orientation::Vertical, 0);
            inner.append(&new_tab_bar);
            inner.append(&new_view);

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

            // When the floating window is closed, move its tabs back to main.
            win.connect_close_request({
                let new_view = new_view.clone();
                let main_view = main_view.clone();
                let detached = detached.clone();

                move |_win| {
                    // Move every remaining page back to the main window.
                    while new_view.n_pages() > 0 {
                        let page = new_view.nth_page(0);
                        let pos = main_view.n_pages() as i32;
                        new_view.transfer_page(&page, &main_view, pos);
                    }
                    // Remove this entry from the tracking list.
                    detached.borrow_mut().retain(|(tv, _)| tv != &new_view);
                    gtk4::glib::Propagation::Proceed
                }
            });

            detached.borrow_mut().push((new_view.clone(), win.clone()));
            win.present();

            Some(new_view)
        }
    });

    // ── Reset Tabs button ─────────────────────────────────────────────────────
    reset_tabs_btn.connect_clicked({
        let main_view = tab_view.clone();
        let detached = detached.clone();

        move |_| {
            // Clone the list so we can mutate it via close_request handlers.
            let snapshot: Vec<(libadwaita::TabView, libadwaita::ApplicationWindow)> =
                detached.borrow().clone();

            for (det_view, win) in &snapshot {
                // Move all pages before closing so close_request finds nothing to do.
                while det_view.n_pages() > 0 {
                    let page = det_view.nth_page(0);
                    let pos = main_view.n_pages() as i32;
                    det_view.transfer_page(&page, &main_view, pos);
                }
                // close() triggers close_request, which will find 0 pages and
                // clean up the entry from the tracking list.
                win.close();
            }
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
