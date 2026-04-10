pub mod directory_view;
pub mod user_view;

use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;

use gtk4::prelude::*;
use crate::app_state::SharedState;

/// Build the Viewer tab.
/// Returns `(widget, navigate_fn)` where `navigate_fn` switches to the Directory
/// sub-view and loads the given path.
pub fn build(
    state: SharedState,
    on_manage: Rc<RefCell<Option<Box<dyn Fn(PathBuf)>>>>,
    focus_mgmt: Rc<RefCell<Option<Box<dyn Fn()>>>>,
) -> (gtk4::Widget, Rc<dyn Fn(PathBuf)>) {
    let stack = gtk4::Stack::builder()
        .transition_type(gtk4::StackTransitionType::SlideLeftRight)
        .vexpand(true)
        .hexpand(true)
        .build();

    let (dir_widget, load_dir) = directory_view::build(state.clone(), on_manage, focus_mgmt);
    stack.add_titled(&dir_widget, Some("directory"), "Directory");
    stack.add_titled(
        &user_view::build(state.clone()),
        Some("user"),
        "User",
    );

    let switcher = gtk4::StackSwitcher::builder()
        .stack(&stack)
        .halign(gtk4::Align::Center)
        .build();

    let vbox = gtk4::Box::new(gtk4::Orientation::Vertical, 0);
    vbox.set_vexpand(true);
    vbox.set_hexpand(true);
    vbox.append(&switcher);
    vbox.append(&stack);

    // Navigate: switch to Directory sub-view and load the given path.
    let navigate: Rc<dyn Fn(PathBuf)> = {
        let stack = stack.clone();
        Rc::new(move |path: PathBuf| {
            stack.set_visible_child_name("directory");
            load_dir(path);
        })
    };

    (vbox.upcast(), navigate)
}
