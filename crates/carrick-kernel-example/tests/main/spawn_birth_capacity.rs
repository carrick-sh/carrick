//! Process-only startup must not reserve executable sibling births. The first
//! actual thread clone supplies demand and primes the same EL1 capacity path.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use carrick_abi::LinuxCloneFlags;
use carrick_hal::{NullHostSignalBridge, ThreadId};
use carrick_kernel::kernel::{
    ClonePlan, TaskKey, ThreadKey,
    thread_adoption::{ThreadBirthAdoptionFactory, ThreadBirthAdoptionReservation},
};
use carrick_kernel_example::process::{AddressSpace, AsidAllocator, ExampleProcess};

#[derive(Debug)]
struct ExecutableFactory {
    owner: TaskKey,
    reservations: AtomicUsize,
}

impl ThreadBirthAdoptionFactory for ExecutableFactory {
    fn executable_births(&self) -> bool {
        true
    }
    fn owner(&self) -> TaskKey {
        self.owner
    }
    fn reserve(&self, thread: ThreadKey) -> Option<ThreadBirthAdoptionReservation> {
        self.reservations.fetch_add(1, Ordering::Relaxed);
        Some(ThreadBirthAdoptionReservation::new(self.owner, thread, ()))
    }
}

#[test]
fn process_only_startup_reserves_no_sibling_runtime_capacity() {
    for scale in [1, 8, 32] {
        let mut total = 0;
        for _ in 0..scale {
            let (_, root) = ExampleProcess::boot_root(
                1,
                "spawn capacity contract",
                Arc::new(NullHostSignalBridge::default()),
                AddressSpace::allocate(&AsidAllocator::new()).unwrap(),
            )
            .unwrap();
            let kernel = root.kernel().clone();
            let factory = Arc::new(ExecutableFactory {
                owner: root.task().key(),
                reservations: AtomicUsize::new(0),
            });
            root.task()
                .install_thread_adoption_factory(factory.clone())
                .unwrap();
            // Runtime preparation and activation both call this entry point.
            kernel.prepare_executable_thread_births(&root);
            kernel.prepare_executable_thread_births(&root);
            total += factory.reservations.load(Ordering::Relaxed);
        }
        assert_eq!(
            total, 0,
            "{scale} process-only creations reserved unused sibling runtime cells"
        );
    }
}

#[test]
fn first_host_thread_clone_primes_executable_sibling_capacity() {
    let (_, root) = ExampleProcess::boot_root(
        1,
        "first clone capacity contract",
        Arc::new(NullHostSignalBridge::default()),
        AddressSpace::allocate(&AsidAllocator::new()).unwrap(),
    )
    .unwrap();
    let kernel = root.kernel().clone();
    let factory = Arc::new(ExecutableFactory {
        owner: root.task().key(),
        reservations: AtomicUsize::new(0),
    });
    root.task()
        .install_thread_adoption_factory(factory.clone())
        .unwrap();
    let child = kernel
        .reserve_thread_clone(
            &root,
            ClonePlan::from_flags(
                LinuxCloneFlags::THREAD
                    | LinuxCloneFlags::SIGHAND
                    | LinuxCloneFlags::VM
                    | LinuxCloneFlags::FILES
                    | LinuxCloneFlags::FS,
            )
            .unwrap(),
            None,
        )
        .unwrap()
        .prepare(ThreadId::from_guest_supplied_tid(2))
        .unwrap()
        .commit()
        .unwrap()
        .into_context()
        .unwrap();
    assert_eq!(child.task().key(), root.task().key());
    assert_eq!(factory.reservations.load(Ordering::Relaxed), 4);
    assert_eq!(
        kernel
            .standing_thread_identities(root.task().key().id)
            .len(),
        4
    );
    kernel.prepare_executable_thread_births(&root);
    assert_eq!(
        factory.reservations.load(Ordering::Relaxed),
        4,
        "already reserved executable capacity must survive rebinding"
    );
}
