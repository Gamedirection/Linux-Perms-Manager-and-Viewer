use gtk4::prelude::*;
use perms_core::domain::permission::UnixMode;

/// Returns a `gtk4::Box` with rwx bits split into three colour-coded segments:
///   owner=green (mode-owner), group=yellow (mode-group), other=red (mode-other)
/// followed by a coloured octal breakdown (e.g. 0 7 5 5).
pub fn mode_badge_colored(mode: UnixMode) -> gtk4::Box {
    let sym = mode.to_symbolic(); // e.g. "rwxr-xr-x"
    // sym is 9 chars: [0..3] owner, [3..6] group, [6..9] other
    let owner_str = &sym[0..3];
    let group_str = &sym[3..6];
    let other_str = &sym[6..9];

    let octal = mode.to_octal(); // e.g. "0755"
    // octal is 4 chars: [0] special digit, [1] owner, [2] group, [3] other
    let special_digit = &octal[0..1];
    let owner_digit = &octal[1..2];
    let group_digit = &octal[2..3];
    let other_digit = &octal[3..4];

    let hbox = gtk4::Box::new(gtk4::Orientation::Horizontal, 4);
    hbox.add_css_class("monospace");

    let make_seg = |text: &str, class: &str| -> gtk4::Label {
        gtk4::Label::builder()
            .label(text)
            .css_classes(["monospace", class])
            .build()
    };

    let sep = || -> gtk4::Label {
        gtk4::Label::builder()
            .label("|")
            .css_classes(["monospace", "mode-separator"])
            .build()
    };

    // Symbolic part: owner | group | other
    hbox.append(&make_seg(owner_str, "mode-owner"));
    hbox.append(&sep());
    hbox.append(&make_seg(group_str, "mode-group"));
    hbox.append(&sep());
    hbox.append(&make_seg(other_str, "mode-other"));

    // Spacer
    hbox.append(
        &gtk4::Label::builder()
            .label("  ")
            .css_classes(["monospace"])
            .build(),
    );

    // Octal part: special (dim) + owner + group + other
    hbox.append(&make_seg(special_digit, "mode-separator"));
    hbox.append(&make_seg(owner_digit, "mode-owner"));
    hbox.append(&make_seg(group_digit, "mode-group"));
    hbox.append(&make_seg(other_digit, "mode-other"));

    hbox
}

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

/// A coloured dot: `granted_class` when true, "access-no" (dim) when false.
/// Use `coloured_dot(has_read, "access-yes")` etc.
pub fn coloured_dot(granted: bool, granted_class: &str) -> gtk4::Label {
    let label = gtk4::Label::builder().label("●").build();
    label.add_css_class(if granted { granted_class } else { "access-no" });
    label
}

/// Convenience: blue read dot.
#[allow(dead_code)]
pub fn access_dot(granted: bool) -> gtk4::Label {
    coloured_dot(granted, "access-yes")
}
