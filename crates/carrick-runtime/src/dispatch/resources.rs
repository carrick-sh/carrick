//! Exact Kernel resource authority captured at a dispatch or lifecycle boundary.
//!
//! Helpers in the filesystem and credential subsystems are intentionally not
//! allowed to recapture the dispatcher binding. The outer boundary installs the
//! caller's already captured objects here for the duration of the operation.

use std::cell::{Cell, RefCell};
use std::sync::Arc;

#[derive(Clone)]
pub(super) struct CapturedResources {
    credentials: Arc<crate::kernel::Credentials>,
    fs_context: Arc<crate::kernel::FsContext>,
    files: Arc<crate::kernel::FileTable>,
    mm: Arc<crate::kernel::Mm>,
}

impl CapturedResources {
    pub(super) fn from_context(context: &crate::kernel::KernelContext) -> Self {
        Self {
            credentials: context.resources().credentials(),
            fs_context: context.resources().fs_context(),
            files: context.resources().files(),
            mm: context.shared().mm(),
        }
    }

    pub(super) fn credentials(&self) -> Arc<crate::kernel::Credentials> {
        Arc::clone(&self.credentials)
    }

    pub(super) fn fs_context(&self) -> Arc<crate::kernel::FsContext> {
        Arc::clone(&self.fs_context)
    }

    pub(super) fn files(&self) -> Arc<crate::kernel::FileTable> {
        Arc::clone(&self.files)
    }

    pub(super) fn mm(&self) -> Arc<crate::kernel::Mm> {
        Arc::clone(&self.mm)
    }
}

thread_local! {
    static CAPTURED_RESOURCES: RefCell<Vec<CapturedResources>> =
        const { RefCell::new(Vec::new()) };
    static ACTIVE_CONTEXT: Cell<*const crate::kernel::KernelContext> =
        const { Cell::new(std::ptr::null()) };
    static RETIRING_FILE_TABLES: RefCell<Vec<Arc<crate::kernel::FileTable>>> =
        const { RefCell::new(Vec::new()) };
}

pub(super) fn with_captured_resources<R>(
    context: &crate::kernel::KernelContext,
    operation: impl FnOnce() -> R,
) -> R {
    if ACTIVE_CONTEXT.with(|active| std::ptr::eq(active.get(), context)) {
        return operation();
    }

    struct Restore(*const crate::kernel::KernelContext);

    impl Drop for Restore {
        fn drop(&mut self) {
            ACTIVE_CONTEXT.with(|active| active.set(self.0));
        }
    }

    let previous = ACTIVE_CONTEXT.with(|active| active.replace(context));
    let _restore = Restore(previous);
    with_resources(CapturedResources::from_context(context), operation)
}

pub(super) fn with_resources<R>(resources: CapturedResources, operation: impl FnOnce() -> R) -> R {
    let _file_table_lease = resources
        .files
        .acquire_functional_lease()
        .unwrap_or_else(|| {
            tracing::error!(
                file_table = ?resources.files.id(),
                "captured operation reached a draining FileTable generation"
            );
            std::process::abort();
        });
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

pub(super) fn with_retiring_file_table<R>(
    files: Arc<crate::kernel::FileTable>,
    operation: impl FnOnce() -> R,
) -> R {
    struct Pop;

    impl Drop for Pop {
        fn drop(&mut self) {
            RETIRING_FILE_TABLES.with(|stack| {
                stack.borrow_mut().pop();
            });
        }
    }

    RETIRING_FILE_TABLES.with(|stack| stack.borrow_mut().push(files));
    let _pop = Pop;
    operation()
}

pub(super) fn credentials() -> Option<Arc<crate::kernel::Credentials>> {
    CAPTURED_RESOURCES.with(|stack| stack.borrow().last().map(CapturedResources::credentials))
}

pub(super) fn fs_context() -> Option<Arc<crate::kernel::FsContext>> {
    CAPTURED_RESOURCES.with(|stack| stack.borrow().last().map(CapturedResources::fs_context))
}

pub(super) fn files() -> Option<Arc<crate::kernel::FileTable>> {
    RETIRING_FILE_TABLES
        .with(|stack| stack.borrow().last().cloned())
        .or_else(|| {
            CAPTURED_RESOURCES.with(|stack| stack.borrow().last().map(CapturedResources::files))
        })
}

pub(super) fn mm() -> Option<Arc<crate::kernel::Mm>> {
    CAPTURED_RESOURCES.with(|stack| stack.borrow().last().map(CapturedResources::mm))
}
