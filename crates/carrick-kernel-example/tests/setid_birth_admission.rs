//! setresuid(2), setresgid(2), clone(2), nptl(7): raw credential changes
//! belong to the calling thread. A sibling's admitted birth cannot cause a
//! transient set*id errno or change the sibling's inherited credentials.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::Arc;

use carrick_abi::{LinuxCloneFlags, syscall::nr};
use carrick_hal::{NullGuestTimerBridge, NullHostSignalBridge, ThreadId};
use carrick_kernel::{
    compat::{CompatReporter, SyscallArgs},
    dispatch::{CarrierBridges, DispatchOutcome, LinearMemory, SyscallDispatcher, SyscallRequest},
    kernel::{CarrierProcess, ClonePlan},
};
use carrick_kernel_example::process::{AddressSpace, AsidAllocator, ExampleProcess};

#[test]
fn setid_during_a_claimed_sibling_birth_completes_without_wait_or_errno() {
    for scale in [1, 8, 32] {
        let host_signal = Arc::new(NullHostSignalBridge::default());
        let (process, root) = ExampleProcess::boot_root(
            1,
            "setid birth contract",
            host_signal.clone(),
            AddressSpace::allocate(&AsidAllocator::new()).unwrap(),
        )
        .unwrap();
        let kernel = root.kernel().clone();
        let sibling = kernel
            .reserve_thread_clone(
                &root,
                ClonePlan::from_flags(
                    LinuxCloneFlags::THREAD | LinuxCloneFlags::SIGHAND | LinuxCloneFlags::VM,
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
        let sibling_credentials = sibling.resources().credentials();
        let page = root.thread().control_lease().lifecycle().clone();
        let claim = page
            .claim_any()
            .expect("sibling birth owns a reserved identity");
        let identity = page.identity(claim.entry()).unwrap();
        assert_eq!(page.claimed_count(), 1);

        let mut dispatcher = SyscallDispatcher::with_bridges(CarrierBridges {
            host_signal,
            timers: Arc::new(NullGuestTimerBridge::default()),
        });
        dispatcher.bind_hvpatch_process(Arc::new(process) as Arc<dyn CarrierProcess>);
        let mut memory = LinearMemory::new(0, vec![0; 1024]);
        let reporter = CompatReporter::default();

        for iteration in 0..scale {
            for (number, real, saved) in [
                (nr::SETRESGID, 20 + iteration, 200 + iteration),
                (nr::SETRESUID, 10 + iteration, 100 + iteration),
            ] {
                let current = kernel
                    .context(root.task().key().id, root.thread().key().tid)
                    .unwrap();
                let outcome = dispatcher
                    .dispatch(
                        &current,
                        SyscallRequest::new(
                            number.raw(),
                            SyscallArgs::new([real, 0, saved, 0, 0, 0]),
                        ),
                        &mut memory,
                        &reporter,
                    )
                    .unwrap();
                // setresuid(2): these privileged transitions return 0. The
                // birth gate and its contention are not Linux errno sources.
                assert_eq!(outcome, DispatchOutcome::Returned { value: 0 });
            }
        }

        let current = kernel
            .context(root.task().key().id, root.thread().key().tid)
            .unwrap();
        let credentials = current.resources().credentials();
        assert_eq!(credentials.ruid().raw(), 10 + scale as u32 - 1);
        assert_eq!(credentials.rgid().raw(), 20 + scale as u32 - 1);
        assert_eq!(credentials.euid().raw(), 0);
        let sibling = kernel
            .context(sibling.task().key().id, sibling.thread().key().tid)
            .unwrap();
        assert!(Arc::ptr_eq(
            &sibling.resources().credentials(),
            &sibling_credentials
        ));
        // clone(2): an already claimed sibling identity and its original uid
        // credit survive; withdrawing unused credits must lose to this claim.
        assert_eq!(page.claimed_count(), 1);
        assert_eq!(page.identity(claim.entry()).unwrap(), identity);
        page.unclaim(claim).unwrap();
        // One dispatcher entry per requested transition, with no continuation,
        // polling or redispatch. This is deterministic work, not wall time.
        assert_eq!(reporter.snapshot().summary.syscall_invocations, 2 * scale);
    }
}
