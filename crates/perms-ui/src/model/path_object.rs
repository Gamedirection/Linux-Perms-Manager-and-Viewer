use gtk4::glib;
use gtk4::glib::subclass::prelude::ObjectSubclassIsExt;
use perms_core::domain::PathEntry;
use std::cell::RefCell;

mod imp {
    use super::*;
    use gtk4::glib::subclass::prelude::*;

    #[derive(Default)]
    pub struct PathObject {
        pub entry: RefCell<Option<PathEntry>>,
    }

    #[glib::object_subclass]
    impl ObjectSubclass for PathObject {
        const NAME: &'static str = "PermsPathObject";
        type Type = super::PathObject;
        type ParentType = glib::Object;
    }

    impl ObjectImpl for PathObject {}
}

glib::wrapper! {
    pub struct PathObject(ObjectSubclass<imp::PathObject>);
}

impl PathObject {
    pub fn new(entry: PathEntry) -> Self {
        let obj: Self = glib::Object::new();
        *obj.imp().entry.borrow_mut() = Some(entry);
        obj
    }

    pub fn entry(&self) -> Option<PathEntry> {
        self.imp().entry.borrow().clone()
    }
}
