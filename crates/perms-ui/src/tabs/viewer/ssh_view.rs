use std::rc::Rc;

use gtk4::gio;
use gtk4::prelude::*;
use perms_core::engine::ssh_review::{SshReviewFinding, SshReviewReport};
use perms_core::engine::system_actions::{
    ElevationState, detect_elevation_state, generate_ssh_review, probe_elevation,
};

pub fn build() -> gtk4::Widget {
    let outer = gtk4::Box::new(gtk4::Orientation::Vertical, 0);
    outer.set_vexpand(true);
    outer.set_hexpand(true);

    let privileged_enabled = Rc::new(std::cell::RefCell::new(nix::unistd::geteuid().is_root()));

    let toolbar = gtk4::Box::new(gtk4::Orientation::Horizontal, 8);
    toolbar.set_margin_top(8);
    toolbar.set_margin_bottom(4);
    toolbar.set_margin_start(8);
    toolbar.set_margin_end(8);

    let scan_btn = gtk4::Button::builder()
        .label("Review SSH")
        .css_classes(["suggested-action"])
        .build();
    let auth_btn = gtk4::Button::builder()
        .label("Authenticate Root Review")
        .build();
    if detect_elevation_state() == ElevationState::DirectRoot {
        auth_btn.set_label("Root Active");
        auth_btn.set_sensitive(false);
    }

    toolbar.append(&scan_btn);
    toolbar.append(&auth_btn);
    outer.append(&toolbar);

    let status_label = gtk4::Label::builder()
        .label("Review SSH configs, keys, and permissions across visible accounts.")
        .halign(gtk4::Align::Start)
        .css_classes(["dim-label"])
        .margin_start(8)
        .margin_end(8)
        .margin_bottom(4)
        .build();
    outer.append(&status_label);

    let store = gio::ListStore::new::<gtk4::StringObject>();
    let selection = gtk4::NoSelection::new(Some(store.clone()));

    let factory = gtk4::SignalListItemFactory::new();
    factory.connect_setup(|_, item| {
        let item = item.downcast_ref::<gtk4::ListItem>().unwrap();
        let row = gtk4::Box::new(gtk4::Orientation::Vertical, 4);
        row.set_margin_top(8);
        row.set_margin_bottom(8);
        row.set_margin_start(12);
        row.set_margin_end(12);

        let title = gtk4::Label::builder()
            .halign(gtk4::Align::Start)
            .wrap(true)
            .build();
        let subtitle = gtk4::Label::builder()
            .halign(gtk4::Align::Start)
            .wrap(true)
            .css_classes(["dim-label", "monospace"])
            .build();
        row.append(&title);
        row.append(&subtitle);
        item.set_child(Some(&row));
    });
    factory.connect_bind(|_, item| {
        let item = item.downcast_ref::<gtk4::ListItem>().unwrap();
        let Some(string_obj) = item.item().and_downcast::<gtk4::StringObject>() else {
            return;
        };
        let value = string_obj.string();
        let text = value.splitn(2, '\n').collect::<Vec<_>>();
        if let Some(row) = item.child().and_downcast::<gtk4::Box>() {
            if let Some(title) = row.first_child().and_downcast::<gtk4::Label>() {
                title.set_label(text.first().copied().unwrap_or_default());
            }
            if let Some(first) = row.first_child() {
                if let Some(subtitle) = first.next_sibling().and_downcast::<gtk4::Label>() {
                    subtitle.set_label(text.get(1).copied().unwrap_or_default());
                }
            }
        }
    });

    let list = gtk4::ListView::builder()
        .model(&selection)
        .factory(&factory)
        .vexpand(true)
        .hexpand(true)
        .show_separators(true)
        .build();

    let scroll = gtk4::ScrolledWindow::builder()
        .child(&list)
        .vexpand(true)
        .hexpand(true)
        .build();
    outer.append(&scroll);

    let populate = {
        let store = store.clone();
        let status_label = status_label.clone();
        let privileged_enabled = privileged_enabled.clone();
        Rc::new(
            move || match generate_ssh_review(*privileged_enabled.borrow()) {
                Ok(report) => fill_ssh_store(&store, &status_label, report),
                Err(err) => status_label.set_label(&format!("SSH review failed: {err}")),
            },
        )
    };

    {
        let populate = populate.clone();
        scan_btn.connect_clicked(move |_| populate());
    }
    {
        let populate = populate.clone();
        let privileged_enabled = privileged_enabled.clone();
        let status_label = status_label.clone();
        let auth_btn = auth_btn.clone();
        auth_btn
            .clone()
            .connect_clicked(move |_| match probe_elevation() {
                Ok(_) => {
                    *privileged_enabled.borrow_mut() = true;
                    auth_btn.set_label("Root Authenticated");
                    auth_btn.set_sensitive(false);
                    status_label.set_label("Root review authentication succeeded.");
                    populate();
                }
                Err(err) => status_label.set_label(&format!("Root authentication failed: {err}")),
            });
    }

    outer.upcast()
}

fn fill_ssh_store(store: &gio::ListStore, status_label: &gtk4::Label, report: SshReviewReport) {
    store.remove_all();

    if report.findings.is_empty() {
        status_label.set_label(&format!(
            "SSH review complete: no findings across {} reviewed paths.",
            report.reviewed_paths.len()
        ));
        for note in report.notes {
            store.append(&gtk4::StringObject::new(&format!("Note\n{note}")));
        }
        return;
    }

    status_label.set_label(&format!(
        "SSH review complete: {} findings across {} reviewed paths{}.",
        report.findings.len(),
        report.reviewed_paths.len(),
        if report.privileged {
            " with root visibility"
        } else {
            ""
        }
    ));

    for finding in report.findings {
        store.append(&gtk4::StringObject::new(&render_finding(&finding)));
    }
}

fn render_finding(finding: &SshReviewFinding) -> String {
    format!(
        "[{}] {} - {}\n{}\nRecommendation: {}",
        finding.severity.to_uppercase(),
        finding.title,
        finding.path.display(),
        finding.summary,
        finding.recommendation
    )
}
