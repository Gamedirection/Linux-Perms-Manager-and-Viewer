pub mod dashboard;
pub mod management;
pub mod settings_tab;
pub mod viewer;

use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;

use crate::app_state::SharedState;

pub use management::ManagementController;

pub fn build_dashboard(
    state: SharedState,
    on_viewer: Rc<RefCell<Option<Box<dyn Fn(PathBuf)>>>>,
    focus_viewer: Rc<RefCell<Option<Box<dyn Fn()>>>>,
) -> gtk4::Widget {
    dashboard::build(state, on_viewer, focus_viewer)
}

pub fn build_management(state: SharedState) -> (gtk4::Widget, ManagementController) {
    management::build(state)
}

pub fn build_settings(state: SharedState) -> gtk4::Widget {
    settings_tab::build(state)
}
