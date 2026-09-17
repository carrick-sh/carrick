//! Continuation fixtures shared with a sibling crate's tests.
//!
//! These are the ONLY items `carrick-kernel`'s continuation tests export
//! across the crate boundary: `carrick-runtime`'s `vcpu_loop::continuation`
//! suites boot a kernel graph (`bootstrap`), publish a task state
//! (`publish`), mint an exact continuation authority (`capture`), await one
//! wait-service event (`await_event`) and enumerate every blocking dispatch
//! family (`DISPATCH_FAMILIES`) against the carrier's own loop.
//!
//! They live here rather than in `tests.rs` for the reason
//! `carrier_process::test_support` already states: only the fixtures a
//! sibling crate consumes belong on the `test-support` feature. Compiling the
//! whole 6k-line suite through the feature dragged 77 `#[test]` bodies into
//! every sibling build and needed a blanket `allow(dead_code,
//! unused_imports)` to stay quiet, which suppressed exactly the warnings that
//! tell us a fixture has gone unused. `tests.rs` is now `cfg(test)` only.

// Test-only code that a sibling crate compiles through `test-support`, so
// `cfg(test)` is not set for it and clippy's `allow-{unwrap,expect,panic}-in-
// tests` does not apply. These are fixtures: an invariant they cannot satisfy
// is a broken fixture, not a runtime condition.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};

use carrick_hal::ThreadId;
use carrick_hal::threaded::{Aarch64TaskCpuStateV1, GuestCpuState};

use super::*;
use crate::compat::SyscallArgs;
use crate::dispatch::SyscallRequest;
use crate::kernel::objects::{ExecutionGeneration, MigratableTaskState};
use crate::kernel::{Kernel, KernelContext, RootBootstrap};

/// Drive one future to completion on the calling test thread.
///
/// This used to submit the future to the transitional runner pool, which is
/// retired. A test awaiting a single future needs no executor at all: park
/// the thread and let the waker unpark it. Parking here is a test-only host
/// wait and is outside the production source the host-blocking-authority
/// gate inspects.
pub(crate) fn block_on<F: std::future::Future>(future: F) -> F::Output {
    struct ThreadWaker(std::thread::Thread);
    impl Wake for ThreadWaker {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.unpark();
        }
    }
    let mut future = std::pin::pin!(future);
    let waker = Waker::from(Arc::new(ThreadWaker(std::thread::current())));
    let mut cx = Context::from_waker(&waker);
    loop {
        if let Poll::Ready(value) = future.as_mut().poll(&mut cx) {
            return value;
        }
        std::thread::park();
    }
}

pub fn await_event(
    service: &CarrierWaitService,
    token: ContinuationWakeToken,
) -> Result<ContinuationEvent, WaitServiceError> {
    let service = service.clone();
    block_on(async move { service.event(token).await })
}

pub fn bootstrap(pid: i32) -> (Arc<Kernel>, KernelContext) {
    let input = RootBootstrap::for_reference_model(
        pid,
        ThreadId::synthetic_for_tests(pid),
        "continuation test".to_owned(),
    )
    .expect("bootstrap input");
    Kernel::bootstrap_root(input).expect("kernel")
}

pub(crate) fn task_state(context: &KernelContext, marker: u64) -> MigratableTaskState {
    task_state_with_asid(context, marker, context.shared().mm().id().raw())
}

pub(crate) fn task_state_with_asid(
    context: &KernelContext,
    marker: u64,
    asid_generation: u64,
) -> MigratableTaskState {
    let mm = context.shared().mm().id();
    MigratableTaskState {
        cpu: GuestCpuState::from_aarch64_v1(Aarch64TaskCpuStateV1 {
            gprs: std::array::from_fn(|index| marker + index as u64),
            pc: marker + 0x1000,
            pstate: marker + 0x2000,
            trap_pc: marker + 0x2100,
            trap_pstate: marker + 0x2200,
            sp_el0: marker + 0x3000,
            elr_el1: marker + 0x3100,
            spsr_el1: marker + 0x3200,
            ttbr0: marker + 0x4000,
            ttbr1: marker + 0x5000,
            tcr: marker + 0x6000,
            sctlr_el1: marker + 0x6100,
            mair_el1: marker + 0x6200,
            vbar_el1: marker + 0x6300,
            cpacr_el1: marker + 0x6400,
            cntkctl_el1: marker + 0x6500,
            tpidr_el1: marker + 0x6600,
            actlr_el1: marker + 0x7000,
            tpidr_el0: marker + 0x8000,
            tpidrro_el0: marker + 0x9000,
            contextidr_el1: marker + 0xa000,
            vregs: std::array::from_fn(|index| marker as u128 + index as u128),
            fpsr: marker as u32,
            fpcr: marker as u32 + 1,
            pending_resume_pc: Some(marker + 0xb000),
            last_syscall_nr: Some(marker),
            last_syscall_orig_x0: marker + 2,
            last_fault_esr: marker + 3,
            last_exit_class: marker,
            is_forked_child: false,
            syscall_continuation: None,
            mm_generation: mm.raw(),
            asid_generation,
        }),
        mm,
        asid_generation,
    }
}

pub fn publish(context: &KernelContext, marker: u64) -> ExecutionGeneration {
    context
        .thread()
        .publish_initial_task_state(task_state(context, marker))
        .expect("publish task state")
}

pub(crate) fn request(number: u64) -> SyscallRequest {
    SyscallRequest::new(
        number,
        SyscallArgs([0x1100, 0x2200, 0x3300, 0x4400, 0x5500, 0x6600]),
    )
}

pub fn capture(context: &KernelContext, generation: ExecutionGeneration) -> ContinuationCapture {
    ContinuationCapture::new(
        context,
        generation,
        request(73),
        RestartClass::RestartSyscall,
    )
    .expect("capture exact continuation authority")
}

pub const DISPATCH_FAMILIES: [ContinuationFamily; 17] = [
    ContinuationFamily::FutexWait,
    ContinuationFamily::FutexWaitv,
    ContinuationFamily::SharedFutexWait,
    ContinuationFamily::SharedFutexWaitv,
    ContinuationFamily::WaitOnSharedWord,
    ContinuationFamily::WaitOnFds,
    ContinuationFamily::WaitOnFdsSelect,
    ContinuationFamily::WaitOnPollFds,
    ContinuationFamily::BlockingWrite,
    ContinuationFamily::TimerFdRead,
    ContinuationFamily::Semop,
    ContinuationFamily::Mqueue,
    ContinuationFamily::FdWait,
    ContinuationFamily::BlockingRecordLock,
    ContinuationFamily::WaitOnHvpatchChild,
    ContinuationFamily::WaitOnSignals,
    ContinuationFamily::WaitOnSleep,
];
