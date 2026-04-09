use gtk4::glib;
use gtk4::glib::subclass::prelude::ObjectSubclassIsExt;
use perms_core::domain::SystemUser;
use std::cell::RefCell;

mod imp {
    use super::*;
    use gtk4::glib::subclass::prelude::*;

    #[derive(Default)]
    pub struct UserObject {
        pub user: RefCell<Option<SystemUser>>,
    }

    #[glib::object_subclass]
    impl ObjectSubclass for UserObject {
        const NAME: &'static str = "PermsUserObject";
        type Type = super::UserObject;
        type ParentType = glib::Object;
    }

    impl ObjectImpl for UserObject {}
}

glib::wrapper! {
    pub struct UserObject(ObjectSubclass<imp::UserObject>);
}

impl UserObject {
    pub fn new(user: SystemUser) -> Self {
        let obj: Self = glib::Object::new();
        *obj.imp().user.borrow_mut() = Some(user);
        obj
    }

    pub fn user(&self) -> Option<SystemUser> {
        self.imp().user.borrow().clone()
    }

    pub fn display_name(&self) -> String {
        self.imp()
            .user
            .borrow()
            .as_ref()
            .map(|u| format!("{} ({})", u.username, u.uid))
            .unwrap_or_default()
    }
}
