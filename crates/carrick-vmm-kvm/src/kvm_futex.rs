//! KVM's `PlatformFutex`.
//!
//! A thin alias for the shared [`FutexTableFutex`]: under the unified HVPatch
//! kernel every Linux process is a thread of one carrier, so both private and
//! `MAP_SHARED` guest futexes are in-process rendezvous. The previous bare
//! `SYS_futex` shim existed for the retired one-host-process-per-guest-process
//! model, where a shared page had to survive a real host `fork`.

use std::sync::Arc;

use carrick_thread::platform_futex::FutexTableFutex;
use carrick_thread::thread::FutexTable;

/// The KVM `PlatformFutex`. Construct with [`make_kvm_futex`].
pub type KvmFutex = FutexTableFutex;

/// Wrap the process-private `FutexTable`.
pub fn make_kvm_futex(table: Arc<FutexTable>) -> KvmFutex {
    FutexTableFutex::new(table)
}

#[cfg(test)]
mod tests {
    //! Host-runnable unit tests (no `/dev/kvm`, no guest): the PRIVATE path
    //! delegates verbatim to the wrapped `FutexTable`. The shared path is the
    //! carrier-wide table, covered by `carrick-thread`'s own tests.
    use super::*;
    use carrick_hal::{FutexOutcome, PlatformFutex};
    use std::thread;
    use std::time::Duration;

    /// PRIVATE path: a `prepare_wait`→park on one thread is woken by a
    /// `private_wake` from another thread (delegated straight to `FutexTable`).
    #[test]
    fn private_wait_woken_by_other_thread() {
        let futex = Arc::new(make_kvm_futex(Arc::new(FutexTable::new())));
        const ADDR: u64 = 0x4000;
        let f2 = Arc::clone(&futex);
        let waiter = thread::spawn(move || {
            f2.private_wait(
                ADDR,
                0,
                carrick_hal::ThreadId::synthetic_for_tests(1),
                Some(Duration::from_secs(5)),
                &|| false,
            )
        });
        thread::sleep(Duration::from_millis(50));
        let woke = futex.private_wake(ADDR, 1);
        assert_eq!(woke, 1, "private_wake must report one waiter woken");
        let outcome = waiter.join().expect("waiter thread join");
        assert_eq!(
            outcome,
            FutexOutcome::Woken,
            "private_wait must report Woken after private_wake"
        );
    }

    /// PRIVATE path: with no waker, `private_wait` returns `TimedOut`.
    #[test]
    fn private_wait_times_out() {
        let futex = make_kvm_futex(Arc::new(FutexTable::new()));
        let outcome = futex.private_wait(
            0x5000,
            0,
            carrick_hal::ThreadId::synthetic_for_tests(1),
            Some(Duration::from_millis(50)),
            &never_interrupted(),
        );
        assert_eq!(
            outcome,
            FutexOutcome::TimedOut,
            "private_wait with no waker must time out"
        );
    }
}
