//! Cross-thread vCPU "kick" for the KVM backend: force a guest thread out of
//! `KVM_RUN` so the trap loop can deliver a pending signal promptly, even when
//! the target is spinning in guest userspace (not parked in a host syscall).
//!
//! This is the Linux/KVM realisation of the "interrupt a running vCPU"
//! primitive. HVF has Apple's `hv_vcpus_exit(ids, count)`; KVM has no such
//! direct call, so we use the kernel's documented mechanism: a signal delivered
//! to the vCPU thread makes the in-progress `KVM_RUN` ioctl return `-EINTR`
//! (which `crate::kvm::KvmVcpu::run` maps to [`carrick_hal::VcpuExit::Kicked`]).
//! The signal is [`kick_signal`] (`SIGRTMIN`), and its handler does nothing —
//! its ONLY job is to interrupt `KVM_RUN`, so it must be installed WITHOUT
//! `SA_RESTART` (or the kernel would silently restart the ioctl and the kick
//! would be lost).
//!
//! Each guest thread publishes a [`KvmKickHandle`] (carrying its `pthread_t`)
//! into the shared [`KvmKicker`] when it starts running and removes it on exit.
//! A signalling thread looks the target up and `pthread_kill`s it. The in-guest
//! flag bookkeeping mirrors the HVF `crate::trap_engine`-driven path exactly:
//! the Dekker handshake with the fork / page-table coordinators is SeqCst on
//! both sides.

/// The signal carrick uses to force a vCPU out of `KVM_RUN` (dynamic `SIGRTMIN` on Linux).
#[inline]
pub fn kick_signal() -> i32 {
    carrick_hal::posix_signal_kick::resolve_kick_signal::<0>()
}

/// Install the process-wide [`kick_signal`] handler ONCE (idempotent).
pub fn install_kvm_kick_handler() {
    carrick_hal::posix_signal_kick::install_posix_kick_handler::<0>();
}

/// A `Send`/`Sync` handle to a guest thread's vCPU, usable from any thread to
/// kick it via `carrick_hal::PosixSignalKick<0>`.
pub type KvmKickHandle = carrick_hal::PosixSignalKick<0>;

/// The KVM vCPU-kick registry. The bookkeeping is the platform-neutral
/// [`carrick_hal::GenericVcpuRegistry`].
pub type KvmKicker = carrick_hal::GenericVcpuRegistry;

#[cfg(test)]
mod tests {
    use super::*;
    use carrick_hal::{
        InGuestFlag, VcpuKick, VcpuLeaseDrainPoll, VcpuRegistrationEnrollment, VcpuRegistry,
    };
    use std::sync::Arc;

    #[test]
    fn armed_run_kick_survives_signal_before_kvm_run() {
        let handle = KvmKickHandle::for_current_thread();
        let mut immediate_exit = 0_u8;
        handle.arm_run(&mut immediate_exit);
        std::thread::scope(|scope| {
            scope.spawn(|| handle.kick()).join().expect("kick thread");
        });
        assert_eq!(immediate_exit, 1, "KVM_RUN must see the pre-entry kick");
        handle.disarm_run();
        assert_eq!(
            immediate_exit, 0,
            "the next run must not inherit the prior kick"
        );
    }

    /// A pure-data stand-in for a real `KvmKickHandle`: it records nothing and
    /// kicks nothing, so the registry bookkeeping tests run on ANY host (no
    /// pthread_kill, no /dev/kvm). The `in_guest` flag the registry tracks is
    /// the load-bearing state under test, not the handle.
    #[derive(Clone)]
    struct InertHandle;
    impl VcpuKick for InertHandle {
        fn kick(&self) {}
    }

    fn t(raw: i32) -> carrick_hal::ThreadId {
        carrick_hal::ThreadId::synthetic_for_tests(raw)
    }

    fn boxed() -> Box<dyn carrick_hal::VcpuKickDyn> {
        Box::new(InertHandle)
    }

    /// register / unregister / lease-drain bookkeeping: `poll_lease_drain` reflects
    /// registered vCPUs relative to a synthetic observer, and unregister removes the
    /// whole entry (both facets).
    #[test]
    fn register_unregister_lease_drain() {
        let k = KvmKicker::new();
        let observer = t(99);
        let f10 = InGuestFlag::for_guest_thread();
        let f11 = InGuestFlag::for_guest_thread();
        assert_eq!(
            k.poll_lease_drain(observer),
            VcpuLeaseDrainPoll::Complete,
            "fresh kicker is empty"
        );

        assert!(matches!(
            k.subscribe_register(t(10), boxed(), &f10, Arc::new(|| {})),
            VcpuRegistrationEnrollment::Registered
        ));
        assert!(matches!(
            k.subscribe_register(t(11), boxed(), &f11, Arc::new(|| {})),
            VcpuRegistrationEnrollment::Registered
        ));
        assert_eq!(
            k.poll_lease_drain(observer),
            VcpuLeaseDrainPoll::Waiting(t(10)),
            "two vCPUs registered"
        );

        // Kicking an unknown tid, kick_all, kick_all_except are harmless no-ops
        // on inert handles (no pthread_kill fires).
        k.kick(t(999));
        k.kick_all();
        k.kick_all_except(t(10));

        k.unregister(t(10));
        assert_eq!(
            k.poll_lease_drain(observer),
            VcpuLeaseDrainPoll::Waiting(t(11)),
            "one vCPU after unregister"
        );
        k.unregister(t(11));
        assert_eq!(
            k.poll_lease_drain(observer),
            VcpuLeaseDrainPoll::Complete,
            "empty after unregistering both"
        );
        // Unregistering an absent tid is a no-op.
        k.unregister(t(11));
        assert_eq!(k.poll_lease_drain(observer), VcpuLeaseDrainPoll::Complete);
    }

    /// `InGuestFlag` + `any_other_in_guest` SeqCst bookkeeping (the Dekker
    /// handshake state) — pure HashMap/AtomicBool, no pthread/KVM.
    #[test]
    fn in_guest_flag_drives_any_other_in_guest() {
        let k = KvmKicker::new();
        // Two threads register their vCPUs, each with its lifetime flag.
        let f1 = InGuestFlag::for_guest_thread();
        let f2 = InGuestFlag::for_guest_thread();
        assert!(matches!(
            k.subscribe_register(t(1), boxed(), &f1, Arc::new(|| {})),
            VcpuRegistrationEnrollment::Registered
        ));
        assert!(matches!(
            k.subscribe_register(t(2), boxed(), &f2, Arc::new(|| {})),
            VcpuRegistrationEnrollment::Registered
        ));

        // Nobody in guest yet.
        assert!(!k.any_other_in_guest(t(1)), "no other thread in guest");
        assert!(!k.any_other_in_guest(t(2)));

        // Thread 2 enters the guest.
        f2.enter_guest();
        assert!(
            k.any_other_in_guest(t(1)),
            "thread 1 must observe thread 2 in guest"
        );
        // Thread 2 asking "any OTHER" excludes itself -> still false.
        assert!(
            !k.any_other_in_guest(t(2)),
            "the in-guest thread excludes itself"
        );

        // Thread 2 leaves the guest.
        f2.leave_guest();
        assert!(!k.any_other_in_guest(t(1)), "thread 2 left the guest");

        // A thread that never registered cannot make anyone in-guest.
        let stranger = InGuestFlag::for_guest_thread();
        stranger.enter_guest();
        assert!(!k.any_other_in_guest(t(1)));
    }

    /// The registry stores a CLONE of the caller's own cell, so the run loop's
    /// stores are what a coordinator reads — including across the
    /// unregister/re-register cycle every blocking wait performs. This is the
    /// aliasing the Dekker handshake relies on.
    #[test]
    fn registry_aliases_the_callers_flag_across_reregistration() {
        let k = KvmKicker::new();
        let flag = InGuestFlag::for_guest_thread();
        let observer = InGuestFlag::for_guest_thread();
        assert!(matches!(
            k.subscribe_register(t(7), boxed(), &flag, Arc::new(|| {})),
            VcpuRegistrationEnrollment::Registered
        ));
        assert!(matches!(
            k.subscribe_register(t(8), boxed(), &observer, Arc::new(|| {})),
            VcpuRegistrationEnrollment::Registered
        ));
        assert!(!k.any_other_in_guest(t(8)));

        flag.enter_guest();
        assert!(
            k.any_other_in_guest(t(8)),
            "the registry must read the caller's cell"
        );

        // Blocking-wait reclaim: unregister, then re-register the same thread.
        flag.leave_guest();
        k.unregister(t(7));
        assert!(matches!(
            k.subscribe_register(t(7), boxed(), &flag, Arc::new(|| {})),
            VcpuRegistrationEnrollment::Registered
        ));
        flag.enter_guest();
        assert!(
            k.any_other_in_guest(t(8)),
            "re-registration must restore the in-guest facet, not only the kick handle"
        );
    }
}
