//! Exact Kernel resource authority captured at a dispatch or lifecycle boundary.
//!
//! Helpers in the filesystem and credential subsystems are intentionally not
//! allowed to recapture the dispatcher binding. The outer boundary installs the
//! caller's already captured objects here for the duration of the operation.

use std::cell::RefCell;
use std::sync::Arc;

#[derive(Clone)]
pub(super) struct CapturedResources {
    credentials: Arc<crate::kernel::Credentials>,
    fs_context: Arc<crate::kernel::FsContext>,
}

impl CapturedResources {
    pub(super) fn from_context(context: &crate::kernel::KernelContext) -> Self {
        Self {
            credentials: context.resources().credentials(),
            fs_context: context.resources().fs_context(),
        }
    }

    pub(super) fn credentials(&self) -> Arc<crate::kernel::Credentials> {
        Arc::clone(&self.credentials)
    }

    pub(super) fn fs_context(&self) -> Arc<crate::kernel::FsContext> {
        Arc::clone(&self.fs_context)
    }
}

thread_local! {
    static CAPTURED_RESOURCES: RefCell<Vec<CapturedResources>> =
        const { RefCell::new(Vec::new()) };
}

pub(super) fn with_captured_resources<R>(
    context: &crate::kernel::KernelContext,
    operation: impl FnOnce() -> R,
) -> R {
    with_resources(CapturedResources::from_context(context), operation)
}

pub(super) fn with_resources<R>(resources: CapturedResources, operation: impl FnOnce() -> R) -> R {
    struct Pop;

    impl Drop for Pop {
        fn drop(&mut self) {
            CAPTURED_RESOURCES.with(|stack| {
                stack.borrow_mut().pop();
            });
        }
    }

    CAPTURED_RESOURCES.with(|stack| stack.borrow_mut().push(resources));
    let _pop = Pop;
    operation()
}

pub(super) fn credentials() -> Option<Arc<crate::kernel::Credentials>> {
    CAPTURED_RESOURCES.with(|stack| stack.borrow().last().map(CapturedResources::credentials))
}

pub(super) fn fs_context() -> Option<Arc<crate::kernel::FsContext>> {
    CAPTURED_RESOURCES.with(|stack| stack.borrow().last().map(CapturedResources::fs_context))
}
