pub mod dashboard;
pub mod viewer;

use gtk4::prelude::*;

use crate::app_state::SharedState;

pub fn build_dashboard(state: SharedState) -> gtk4::Widget {
    dashboard::build(state)
}

pub fn build_management(_state: SharedState) -> gtk4::Widget {
    let label = gtk4::Label::builder()
        .label("<b>Management</b>\nPermission editing in Phase 4.")
        .use_markup(true)
        .justify(gtk4::Justification::Center)
        .css_classes(["dim-label"])
        .vexpand(true)
        .valign(gtk4::Align::Center)
        .halign(gtk4::Align::Center)
        .build();
    label.upcast()
}

pub fn build_settings(_state: SharedState) -> gtk4::Widget {
    let label = gtk4::Label::builder()
        .label("<b>Settings</b>\nConfiguration in Phase 5.")
        .use_markup(true)
        .justify(gtk4::Justification::Center)
        .css_classes(["dim-label"])
        .vexpand(true)
        .valign(gtk4::Align::Center)
        .halign(gtk4::Align::Center)
        .build();
    label.upcast()
}
