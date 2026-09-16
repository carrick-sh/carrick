//! Connect an exact boot context to the owned carrier-wide descriptor ceiling.

use std::sync::Arc;

use carrick_hal::FdCeilingPublisher;

use carrick_kernel::dispatch::SyscallDispatcher;
use carrick_kernel::kernel::KernelContext;

pub(super) fn register(
    dispatcher: &SyscallDispatcher,
    context: &KernelContext,
    publisher: Option<Arc<dyn FdCeilingPublisher>>,
) {
    let authority = context.kernel().fd_ceiling();
    // A resource budget can count syscalls as well as CPU. Until all such
    // accounting is lowered into EL1, every budget keeps host dispatch.
    // Disabling before registration also covers roots in an already live VM:
    // the carrier publisher cannot temporarily enable a restrictive root.
    if !carrick_kernel::syscall_shim_enabled()
        || dispatcher.requires_syscall_traps()
        || context.container().budget().is_some()
    {
        authority.disable();
    }
    if let Some(publisher) = publisher {
        authority.register(publisher);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    #[derive(Debug, Default)]
    struct Publisher(Mutex<Vec<&'static str>>);

    impl FdCeilingPublisher for Publisher {
        fn raise(&self, _maximum: u32) {
            self.0.lock().push("raise");
        }
        fn disable(&self) {
            self.0.lock().push("disable");
        }
    }

    struct VisibleObserver;
    impl carrick_kernel::observe::SyscallObserver for VisibleObserver {
        fn wants_fast_path_visibility(&self) -> carrick_kernel::observe::FastPathVisibility {
            carrick_kernel::observe::FastPathVisibility::Required
        }
    }

    #[test]
    fn restrictive_observer_closes_publisher_before_initial_raise() {
        let mut dispatcher = SyscallDispatcher::new();
        dispatcher.install_observer(Arc::new(VisibleObserver));
        let context = dispatcher.capture_one_task_context().expect("context");
        let publisher = Arc::new(Publisher::default());
        register(&dispatcher, &context, Some(publisher.clone()));
        assert_eq!(&*publisher.0.lock(), &["disable", "raise"]);
    }

    #[test]
    fn resource_budget_closes_publisher_before_initial_raise() {
        let bootstrap = carrick_kernel::kernel::RootBootstrap::for_reference_model(
            61901,
            crate::thread::ThreadId::synthetic_for_tests(61901),
            "budget".into(),
        )
        .expect("bootstrap")
        .with_container(Arc::new(
            carrick_kernel::kernel::Container::for_reference_model().with_resource_budget(
                Arc::new(carrick_kernel::observe::ResourceBudget::new().max_syscalls(10)),
            ),
        ));
        let (_kernel, context) =
            carrick_kernel::kernel::Kernel::bootstrap_root(bootstrap).expect("kernel");
        let publisher = Arc::new(Publisher::default());
        register(&SyscallDispatcher::new(), &context, Some(publisher.clone()));
        assert_eq!(&*publisher.0.lock(), &["disable", "raise"]);
    }
}
