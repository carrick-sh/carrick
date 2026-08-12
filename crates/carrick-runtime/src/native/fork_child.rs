//! Shared native fork-child dispatcher reset (Phase-1 orchestration dedup,
//! Task 5).
//!
//! `native_darwin::native_after_fork_child` and
//! `native_freebsd::native_after_fork_child` used to hand-duplicate an
//! IDENTICAL ordered list of nine dispatcher/runtime hooks that a native
//! guest child must run right after `fork()` puts it on a fresh OS process:
//! clear buffered stdout/stderr (the child must not re-flush the parent's
//! pending bytes), reinit the event ring (`crate::event_ring`) and
//! host-signal state (`crate::host_signal` — empty pending set, no
//! inherited timers) and FIFO beacons
//! (`crate::dispatch::reset_fifo_beacons_after_fork_child`), then run each
//! dispatcher subsystem's own fork-child hook in order: network, epoll,
//! proc (timerslack/subreaper/itimers/membarrier), mem, sysv. Order matters
//! — e.g. output buffers must be cleared before anything else can write to
//! them, and `proc`/`mem`/`sysv` each assume the earlier hooks already ran —
//! so [`AFTER_FORK_CHILD_STEPS`] fixes it once here instead of twice.
//!
//! # Step 1 divergence (see Task 5 report for the full diff)
//!
//! The two bodies were compared with `git diff --no-index` on extracted
//! snippets. The nine shared steps were byte-identical, same order, on both
//! lanes. FreeBSD's body had exactly ONE extra line with no Darwin
//! equivalent at all: a `NATIVE_CHILD_EXIT_DIRTY.store(false, ..)` reset of
//! a FreeBSD-only SIGCHLD dirty-flag (Darwin uses a completely different
//! child-exit-watch mechanism — `native_poll_child_exit_watches` polling
//! `carrick_signal_core::child_watch::tracked_pids()` — that isn't part of
//! the fork-child reset at all). This is additive lane-specific residue, not
//! a semantic divergence in the shared steps, so it is kept INLINE at
//! FreeBSD's `native_after_fork_child` call site (commented as lane-only)
//! rather than folded into [`AFTER_FORK_CHILD_STEPS`] or gated behind a flag
//! parameter here.
use crate::dispatch::SyscallDispatcher;
use crate::kernel::KernelContext;

/// One named fork-child hook: its documented name (for the order test/report)
/// paired with the function pointer that runs it. The exact pre-fork context
/// remains valid in the COW child until the fresh child Kernel is published;
/// authority-dependent repair consumes it explicitly rather than consulting a
/// process-local TLS scope.
type AfterForkChildStep = (&'static str, fn(&SyscallDispatcher, &KernelContext));

fn step_clear_output_buffers(d: &SyscallDispatcher, _context: &KernelContext) {
    d.clear_output_buffers();
}

fn step_reinit_event_ring(_d: &SyscallDispatcher, _context: &KernelContext) {
    crate::event_ring::reinit_after_fork();
}

fn step_reinit_host_signal(_d: &SyscallDispatcher, _context: &KernelContext) {
    crate::host_signal::reinit_after_fork();
}

fn step_reset_fifo_beacons(_d: &SyscallDispatcher, _context: &KernelContext) {
    crate::dispatch::reset_fifo_beacons_after_fork_child();
}

fn step_network_after_fork_child(d: &SyscallDispatcher, _context: &KernelContext) {
    d.network_after_fork_child();
}

fn step_epoll_after_fork_child(d: &SyscallDispatcher, context: &KernelContext) {
    d.epoll_after_fork_child(context);
}

fn step_proc_after_fork_child(d: &SyscallDispatcher, _context: &KernelContext) {
    d.proc_after_fork_child();
}

fn step_mem_after_fork_child(d: &SyscallDispatcher, _context: &KernelContext) {
    d.mem_after_fork_child();
}

fn step_sysv_after_fork_child(d: &SyscallDispatcher, _context: &KernelContext) {
    d.sysv_after_fork_child();
}

/// The exact ordered hook list both lanes' `native_after_fork_child` used to
/// hand-duplicate. This `const` array both DRIVES
/// [`dispatcher_after_fork_child`] and gives the order test in `mod tests`
/// real structure to assert against, instead of re-parsing source text or
/// needing a full dispatcher fake.
pub(crate) const AFTER_FORK_CHILD_STEPS: &[AfterForkChildStep] = &[
    ("clear_output_buffers", step_clear_output_buffers),
    ("event_ring::reinit_after_fork", step_reinit_event_ring),
    ("host_signal::reinit_after_fork", step_reinit_host_signal),
    (
        "dispatch::reset_fifo_beacons_after_fork_child",
        step_reset_fifo_beacons,
    ),
    ("network_after_fork_child", step_network_after_fork_child),
    ("epoll_after_fork_child", step_epoll_after_fork_child),
    ("proc_after_fork_child", step_proc_after_fork_child),
    ("mem_after_fork_child", step_mem_after_fork_child),
    ("sysv_after_fork_child", step_sysv_after_fork_child),
];

/// Read-only accessor for [`AFTER_FORK_CHILD_STEPS`] — the shape the Task 5
/// brief asked for so a test can assert real structure (documented hook
/// names in documented order) rather than re-parsing source text.
pub(crate) fn after_fork_child_steps() -> &'static [AfterForkChildStep] {
    AFTER_FORK_CHILD_STEPS
}

/// Run the shared native fork-child dispatcher reset. Both
/// `native_darwin::native_after_fork_child` and
/// `native_freebsd::native_after_fork_child` reduce to a one-line call to
/// this (FreeBSD keeping its one lane-specific extra step inline at the call
/// site — see the module doc's Step 1 divergence note). Mirrors the two
/// former bodies byte-for-byte: same nine hooks, same order.
pub(crate) fn dispatcher_after_fork_child(
    dispatcher: &SyscallDispatcher,
    inherited_context: &KernelContext,
) {
    // The inherited exact generation remains authoritative until the child
    // publishes its fresh one-task Kernel. Several reset hooks still traverse
    // concrete file-backed runtime state, so install that exact scope for the
    // whole ordered reset rather than letting any hook recapture by host PID.
    dispatcher.with_kernel_credentials(inherited_context, || {
        for &(_name, step) in after_fork_child_steps() {
            step(dispatcher, inherited_context);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Step 2 unit test: the shared hook list is exactly these nine named
    /// steps, in exactly this order. Reads `after_fork_child_steps()`'s
    /// documented structure directly — no dispatcher fake needed.
    #[test]
    fn after_fork_child_steps_are_in_documented_order() {
        let names: Vec<&str> = after_fork_child_steps().iter().map(|&(n, _)| n).collect();
        assert_eq!(
            names,
            vec![
                "clear_output_buffers",
                "event_ring::reinit_after_fork",
                "host_signal::reinit_after_fork",
                "dispatch::reset_fifo_beacons_after_fork_child",
                "network_after_fork_child",
                "epoll_after_fork_child",
                "proc_after_fork_child",
                "mem_after_fork_child",
                "sysv_after_fork_child",
            ],
            "AFTER_FORK_CHILD_STEPS order regressed — this list is the single \
             source of truth both native lanes' fork-child reset drives from; \
             see the module doc for why order matters.",
        );
    }

    /// `dispatcher_after_fork_child`'s loop body walks `AFTER_FORK_CHILD_STEPS`
    /// verbatim (see its source above the const), so proving the const has
    /// the documented nine-step shape (previous test) already proves the
    /// driver's behavior by construction. This test instead pins the count
    /// so a future edit that silently adds/removes a step without updating
    /// the order-name test above still fails loudly.
    #[test]
    fn dispatcher_after_fork_child_drives_the_full_documented_list() {
        assert_eq!(
            AFTER_FORK_CHILD_STEPS.len(),
            9,
            "dispatcher_after_fork_child iterates AFTER_FORK_CHILD_STEPS in \
             full; a length drift here without updating the order test above \
             means a step was silently added or removed",
        );
    }
}
