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
    // Pointer identity is sufficient because the marker exists only for this
    // dynamic borrow: that KernelContext cannot be dropped or replaced at the
    // same address until the scope unwinds and Restore clears the marker.
    // The dispatch boundary is the one place that reliably runs ON the guest
    // thread with its kernel object in hand, so it is where the thread claims
    // the `guest_cpu` slot its Task later totals for RUSAGE_SELF.
    context.thread().bind_own_cpu_slot();
    if ACTIVE_CONTEXT.with(|active| std::ptr::eq(active.get(), context)) {
        // Already inside this context's dispatch scope: a nested call is part
        // of the window the OUTER frame is already charging, so it must not
        // charge again.
        return operation();
    }
    // The outermost dispatch scope is exactly one guest syscall's service
    // window, and it runs on the guest thread — so it is where that thread's
    // SYSTEM time comes from. Measured on the host thread's own CPU clock, not
    // the wall clock, so a syscall that BLOCKS (`wait4`, `epoll_wait`,
    // `futex`) contributes nothing, matching Linux: a blocked task accrues no
    // kernel CPU. See `Thread::system_ns`.
    let started_ns = carrick_host::guest_cpu::this_thread_cpu_ns();
    let result = with_resource_scope(CapturedResources::from_context(context), context, operation);
    context
        .thread()
        .charge_system_ns(carrick_host::guest_cpu::this_thread_cpu_ns().saturating_sub(started_ns));
    result
}

/// Run `operation` against the kernel context whose dispatch scope is active
/// on this thread, if any. Syscalls that must answer *about the calling Linux
/// process* — rather than about the host process, which under HVPatch holds
/// every Linux process at once — read the calling task through here.
///
/// Returns `None` outside any dispatch scope, which is the honest answer: the
/// caller then has no task to describe and must say so rather than substitute
/// some other process's numbers.
pub(crate) fn with_active_context<R>(
    operation: impl FnOnce(&crate::kernel::KernelContext) -> R,
) -> Option<R> {
    ACTIVE_CONTEXT.with(|active| {
        let context = active.get();
        // SAFETY: the scope guard that publishes this pointer keeps the
        // referent borrowed for as long as it is non-null here, and restores
        // the previous value on both return and unwind.
        (!context.is_null()).then(|| operation(unsafe { &*context }))
    })
}

pub(super) fn with_resources<R>(resources: CapturedResources, operation: impl FnOnce() -> R) -> R {
    with_resource_scope(resources, std::ptr::null(), operation)
}

fn with_resource_scope<R>(
    resources: CapturedResources,
    context: *const crate::kernel::KernelContext,
    operation: impl FnOnce() -> R,
) -> R {
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
    struct Restore {
        context: *const crate::kernel::KernelContext,
    }

    impl Drop for Restore {
        fn drop(&mut self) {
            CAPTURED_RESOURCES.with(|stack| {
                stack.borrow_mut().pop();
            });
            ACTIVE_CONTEXT.with(|active| active.set(self.context));
        }
    }

    let previous = ACTIVE_CONTEXT.with(|active| active.replace(context));
    CAPTURED_RESOURCES.with(|stack| stack.borrow_mut().push(resources));
    let _restore = Restore { context: previous };
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retained_scope_cannot_hide_a_nested_exact_context() {
        let first = crate::dispatch::SyscallDispatcher::new();
        let first_context = first.capture_one_task_context().expect("first context");
        let second = crate::dispatch::SyscallDispatcher::new();
        let second_context = second.capture_one_task_context().expect("second context");
        let second_resources = CapturedResources::from_context(&second_context);

        with_captured_resources(&first_context, || {
            let first_credentials = credentials().expect("first credentials");
            assert!(Arc::ptr_eq(
                &first_credentials,
                &first_context.resources().credentials()
            ));
            assert_eq!(CAPTURED_RESOURCES.with(|stack| stack.borrow().len()), 1);

            with_captured_resources(&first_context, || {
                assert_eq!(CAPTURED_RESOURCES.with(|stack| stack.borrow().len()), 1);
            });

            with_resources(second_resources, || {
                let second_credentials = credentials().expect("retained credentials");
                assert!(Arc::ptr_eq(
                    &second_credentials,
                    &second_context.resources().credentials()
                ));
                with_captured_resources(&first_context, || {
                    let nested_credentials = credentials().expect("nested exact credentials");
                    assert!(Arc::ptr_eq(
                        &nested_credentials,
                        &first_context.resources().credentials()
                    ));
                });
                let restored_credentials = credentials().expect("restored retained credentials");
                assert!(Arc::ptr_eq(
                    &restored_credentials,
                    &second_context.resources().credentials()
                ));
            });

            let restored_credentials = credentials().expect("restored first credentials");
            assert!(Arc::ptr_eq(
                &restored_credentials,
                &first_context.resources().credentials()
            ));
        });
        assert!(credentials().is_none());
        assert!(ACTIVE_CONTEXT.with(|active| active.get().is_null()));
    }
}
