use gtk4::prelude::*;
use perms_core::domain::permission::UnixMode;

/// Returns a small label styled with colour according to the permission bits.
/// r=blue, w=yellow, x=green, -=dim.
pub fn mode_badge(mode: UnixMode) -> gtk4::Label {
    let sym = mode.to_symbolic();
    let octal = mode.to_octal();

    let label = gtk4::Label::builder()
        .label(format!("{sym}  {octal}"))
        .css_classes(["monospace", "mode-badge"])
        .halign(gtk4::Align::Start)
        .build();

    // Colour hint based on risk level
    if mode.is_world_writable() {
        label.add_css_class("mode-danger");
    } else if mode.is_world_readable() {
        label.add_css_class("mode-warn");
    } else {
        label.add_css_class("mode-ok");
    }

    label
}

/// A coloured dot label for access indicators.
/// granted=true → green "●", false → red "●"
pub fn access_dot(granted: bool) -> gtk4::Label {
    let label = gtk4::Label::builder()
        .label("●")
        .build();
    if granted {
        label.add_css_class("access-yes");
    } else {
        label.add_css_class("access-no");
    }
    label
}
