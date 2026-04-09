pub mod directory_view;
pub mod user_view;

use gtk4::prelude::*;
use crate::app_state::SharedState;

pub fn build(state: SharedState) -> gtk4::Widget {
    let stack = gtk4::Stack::builder()
        .transition_type(gtk4::StackTransitionType::SlideLeftRight)
        .vexpand(true)
        .hexpand(true)
        .build();

    stack.add_titled(
        &directory_view::build(state.clone()),
        Some("directory"),
        "Directory",
    );
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

    vbox.upcast()
}
