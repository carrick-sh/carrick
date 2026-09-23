//! The per-process identity page the EL1 syscall shim reads.
//!
//! When the `syscall-shim` feature is on, a guest answers `getpid`/`gettid`
//! from this page in userspace with no vm exit, so the page is a publication
//! the kernel must stamp before the guest issues any intercepted syscall: at
//! boot, in a forked child, and after `execve`. The stamp is a pure write
//! sequence over any [`CurrentMmMemory`] (the executor's engine in
//! production, a `LinearMemory` in tests); the ordering argument for the gate
//! word lives on [`stamp_identity_values`].

use carrick_guest_mem::CurrentMmMemory;

use crate::dispatch::SyscallDispatcher;

/// Stamp the per-process identity page the EL1 syscall shim reads (no-op unless
/// the shim is enabled). Must run before the guest issues any intercepted
/// syscall: at boot, and again in a forked child / after execve, since the
/// child's pid and the new image's identity differ.
pub fn stamp_identity_page<M: CurrentMmMemory>(
    memory: &mut M,
    dispatcher: &SyscallDispatcher,
    kernel_context: &crate::kernel::KernelContext,
) -> Result<(), carrick_guest_mem::MemoryError> {
    stamp_identity_page_at(
        memory,
        dispatcher,
        kernel_context,
        crate::memory::LINUX_IDENTITY_PAGE_BASE,
    )
}

pub fn stamp_identity_page_at<M: CurrentMmMemory>(
    memory: &mut M,
    dispatcher: &SyscallDispatcher,
    kernel_context: &crate::kernel::KernelContext,
    base: u64,
) -> Result<(), carrick_guest_mem::MemoryError> {
    if !crate::syscall_shim_enabled() {
        return Ok(());
    }
    let id = dispatcher.identity_snapshot(kernel_context);
    // FAIL CLOSED on an unpublishable identity.
    //
    // `getpid()` never returns 0 on Linux, so a zero here means the identity
    // is not knowable yet rather than that it is zero — a pid-namespace
    // translation that has not been registered resolves to 0 through the
    // `unwrap_or(0)` in `identity_pid`. Opening the fast-path gate over that
    // publishes a pid no Linux process has, and the guest reads it in
    // userspace with NO vm exit, so nothing ever re-checks it. Observed as a
    // container's init reporting `getpid=0`.
    //
    // Leaving the gate SHUT costs only speed: the guest traps and the
    // dispatcher answers correctly. A later stamp re-opens it once the
    // identity is real.
    let shim_enabled = identity_gate_word(dispatcher.identity_fast_path_enabled(), id.pid);
    let clock_enabled = clock_gate_word(dispatcher, kernel_context);
    // Close both independent gates before changing any protected-page state.
    stamp_clock_gate(memory, base, 0)?;
    stamp_identity_values(memory, base, id.pid, shim_enabled)?;
    stamp_clock_gate(memory, base, clock_enabled)?;
    let _ = stamp_info_page(memory, kernel_context);
    Ok(())
}

/// Stamp the EL0-accessible info page with the live PID and TID.
///
/// Credentials and the parent pid are deliberately NOT published here: Linux
/// credentials are per-thread and change on `set*id`, and the parent changes on
/// reparenting, so a per-process EL0-readable page cannot answer them. Those
/// syscalls trap to the dispatcher (see `hvpatch::island`).
pub fn stamp_info_page<M: CurrentMmMemory>(
    memory: &mut M,
    kernel_context: &crate::kernel::KernelContext,
) -> Result<(), carrick_guest_mem::MemoryError> {
    stamp_info_page_at(memory, kernel_context, crate::memory::LINUX_INFO_PAGE_BASE)
}

pub fn stamp_info_page_at<M: CurrentMmMemory>(
    memory: &mut M,
    kernel_context: &crate::kernel::KernelContext,
    base: u64,
) -> Result<(), carrick_guest_mem::MemoryError> {
    let task_id = u32::try_from(kernel_context.task().key().id.raw()).unwrap_or(0);
    let pid = crate::namespace::pid::ns_self_pid_for(kernel_context, task_id);
    let _ = memory.write_bytes(base + crate::memory::INFO_PAGE_OFF_PID, &pid.to_le_bytes());
    if let Some(tid) = crate::namespace::pid::ns_visible_guest_tid(kernel_context) {
        let _ = memory.write_bytes(base + crate::memory::INFO_PAGE_OFF_TID, &tid.to_le_bytes());
    }
    Ok(())
}

/// The raw CLOCK_MONOTONIC path is valid only for the live system clock and
/// only when no policy, observer, interceptor, resource budget, or diagnostic
/// mode requires dispatcher visibility.
pub fn clock_gate_word(
    dispatcher: &SyscallDispatcher,
    kernel_context: &crate::kernel::KernelContext,
) -> u32 {
    clock_gate_word_for(
        crate::syscall_shim_enabled() && dispatcher.identity_fast_path_enabled(),
        kernel_context.container().clock().is_controlled(),
        kernel_context.container().budget().is_some(),
        crate::vdso_policy::raw_clock_fast_path_allowed_for_debug(),
    )
}

const fn clock_gate_word_for(
    dispatch_invisible: bool,
    controlled_clock: bool,
    has_resource_budget: bool,
    debug_allows: bool,
) -> u32 {
    if dispatch_invisible && !controlled_clock && !has_resource_budget && debug_allows {
        1
    } else {
        0
    }
}

/// Publish the separate raw-clock admission word. Callers close it before a
/// policy transition and use this helper to retain the release ordering paired
/// with the vector's acquire load.
pub fn stamp_clock_gate<M: CurrentMmMemory>(
    memory: &mut M,
    base: u64,
    enabled: u32,
) -> Result<(), carrick_guest_mem::MemoryError> {
    std::sync::atomic::fence(std::sync::atomic::Ordering::Release);
    memory.write_bytes(
        base + crate::memory::IDENTITY_OFF_CLOCK_GATE,
        &enabled.to_le_bytes(),
    )
}

/// The value to publish in the identity page's shim gate.
///
/// Non-zero opens the userspace fast path, so it must only ever be opened over
/// a pid a guest could legitimately observe. `getpid()` never returns 0 on
/// Linux: a zero here means the identity is not knowable YET — an unregistered
/// pid-namespace translation resolves to 0 through the `unwrap_or(0)` in
/// `identity_pid` — not that the pid is zero. Publishing it would let a guest
/// read a pid no process has, with no vm exit and nothing to re-check it.
///
/// Shutting the gate costs only speed: the guest traps and the dispatcher
/// answers correctly, and a later stamp opens it once the identity is real.
pub(crate) fn identity_gate_word(fast_path_enabled: bool, pid: u32) -> u32 {
    u32::from(fast_path_enabled && pid != 0)
}

pub fn stamp_identity_values<M: CurrentMmMemory>(
    memory: &mut M,
    base: u64,
    pid: u32,
    shim_enabled: u32,
) -> Result<(), carrick_guest_mem::MemoryError> {
    // Disable the fast path FIRST, then publish the identity, then re-enable.
    //
    // The shim word is the gate: while it is non-zero the guest answers
    // getpid/gettid from this page in userspace with NO vm exit, so nothing
    // re-checks the value it reads. Writing the pid before the gate is only
    // safe if the gate is known to be closed, and on a carrier VM it is not —
    // the identity page's backing is recycled between containers, so a
    // container can begin life with a predecessor's `1` still in the gate
    // while its own pid slot reads zero. The guest then reports pid 0, which
    // no Linux process ever sees. It is rare because the window is short, and
    // it widens under load, which is precisely why it must be closed rather
    // than tolerated.
    //
    // Closing the gate first costs nothing: a guest that reads it mid-stamp
    // takes the trap path and gets the correct answer from the dispatcher.
    memory.write_bytes(
        base + crate::memory::IDENTITY_OFF_SHIM_ENABLED,
        &0_u32.to_le_bytes(),
    )?;
    // Pair for the release below: the CLOSE must be observable before the
    // identity it protects starts changing, or a guest can see the old gate
    // open over a half-written pid.
    std::sync::atomic::fence(std::sync::atomic::Ordering::Release);
    memory.write_bytes(base + crate::memory::IDENTITY_OFF_PID, &pid.to_le_bytes())?;
    // A fresh stamp starts a fresh serviced-syscall ledger: a forked child
    // COWs its parent's identity page and must not inherit the parent's
    // counter (Linux children start rusage at zero), and an exec'd image
    // keeps its task ledger but not the page. (The exec re-stamp drops any
    // pre-exec counted-but-unfolded syscalls — a µs-scale undercount.)
    memory.write_bytes(
        base + crate::memory::IDENTITY_OFF_SHIM_SYSCALLS,
        &0_u64.to_le_bytes(),
    )?;
    memory.write_bytes(
        base + crate::memory::IDENTITY_OFF_SEEK_GATE,
        &0_u32.to_le_bytes(),
    )?;
    memory.write_bytes(
        base + crate::memory::IDENTITY_OFF_SEEK_FD,
        &(-1_i32).to_le_bytes(),
    )?;
    memory.write_bytes(
        base + crate::memory::IDENTITY_OFF_SEEK_OFFSET,
        &0_i64.to_le_bytes(),
    )?;
    // RELEASE the identity before opening the gate.
    //
    // Ordering the stores in program order is necessary but NOT sufficient.
    // The guest reads this page from another vCPU, and AArch64 lets plain
    // stores be observed out of order: without a barrier a guest can see the
    // gate word already non-zero while the pid store is not yet visible, and
    // report pid 0 through a fast path that never traps. That is the whole
    // failure — intermittent, wider under load, and closed by anything that
    // slows the writer down (which is why logging or a debug build hides it).
    //
    // The gate is a publication flag, so it needs release semantics: every
    // store above must be observable before the store that opens it.
    std::sync::atomic::fence(std::sync::atomic::Ordering::Release);
    memory.write_bytes(
        base + crate::memory::IDENTITY_OFF_SHIM_ENABLED,
        &shim_enabled.to_le_bytes(),
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_gate_stays_shut_over_an_unpublishable_pid() {
        // `getpid()` never returns 0 on Linux, so a zero identity means "not
        // knowable yet", not "zero" — an unregistered pid-namespace
        // translation resolves to 0 via `unwrap_or(0)` in `identity_pid`.
        // Opening the fast path over it publishes a pid no process has, and
        // the guest reads it with NO vm exit, so nothing re-checks it. Seen as
        // a container's init reporting `getpid=0`.
        //
        // Drop the `pid != 0` term and the first assertion fails.
        assert_eq!(
            identity_gate_word(true, 0),
            0,
            "an unpublishable identity must leave the fast path SHUT"
        );
        assert_eq!(
            identity_gate_word(true, 1),
            1,
            "a real pid still opens the fast path"
        );
        assert_eq!(
            identity_gate_word(false, 1),
            0,
            "a caller that disabled the fast path still wins"
        );
    }

    #[test]
    fn raw_clock_gate_requires_every_semantic_and_visibility_precondition() {
        assert_eq!(clock_gate_word_for(true, false, false, true), 1);
        for closed in [
            clock_gate_word_for(false, false, false, true),
            clock_gate_word_for(true, true, false, true),
            clock_gate_word_for(true, false, true, true),
            clock_gate_word_for(true, false, false, false),
        ] {
            assert_eq!(closed, 0);
        }
    }

    #[test]
    fn identity_stamp_closes_the_shim_gate_before_publishing_a_new_pid() {
        // The shim word gates a userspace read with NO vm exit, so the guest
        // may look at this page at any instant. Starting from a page that a
        // previous container left ENABLED with a stale pid, the stamp must
        // never leave the gate open over a pid it has not written yet —
        // otherwise the guest reads a pid that belongs to no one (observed as
        // `getpid=0` from a container's init, which no Linux process reports).
        //
        // Records the exact write order and asserts the gate is shut before the
        // pid moves and reopened only after. Under the old order (pid, then
        // gate) the first recorded write is the pid, and this fails.
        #[derive(Default)]
        struct RecordingMemory {
            base: u64,
            page: Vec<u8>,
            order: Vec<(u64, u64)>,
        }
        impl carrick_guest_mem::GuestMemory for RecordingMemory {
            fn read_bytes_raw(
                &self,
                addr: u64,
                len: usize,
            ) -> Result<Vec<u8>, carrick_guest_mem::MemoryError> {
                let off = (addr - self.base) as usize;
                Ok(self.page[off..off + len].to_vec())
            }
            fn write_bytes_raw(
                &mut self,
                addr: u64,
                bytes: &[u8],
            ) -> Result<(), carrick_guest_mem::MemoryError> {
                let off = (addr - self.base) as usize;
                self.page[off..off + bytes.len()].copy_from_slice(bytes);
                let mut word = [0u8; 8];
                let n = bytes.len().min(8);
                word[..n].copy_from_slice(&bytes[..n]);
                self.order
                    .push((addr - self.base, u64::from_le_bytes(word)));
                Ok(())
            }
        }
        impl carrick_guest_mem::CurrentMmMemory for RecordingMemory {}

        let base = crate::memory::LINUX_IDENTITY_PAGE_BASE;
        let mut memory = RecordingMemory {
            base,
            page: vec![0; 4096],
            order: Vec::new(),
        };
        // The predecessor's residue: gate open, someone else's pid.
        memory.page[crate::memory::IDENTITY_OFF_SHIM_ENABLED as usize] = 1;
        memory.page[crate::memory::IDENTITY_OFF_PID as usize] = 7;

        stamp_identity_values(&mut memory, base, 1, 1).expect("stamp");

        let gate = crate::memory::IDENTITY_OFF_SHIM_ENABLED;
        let pid_off = crate::memory::IDENTITY_OFF_PID;
        let first_gate_write = memory
            .order
            .iter()
            .position(|(off, _)| *off == gate)
            .expect("the gate must be written");
        let pid_write = memory
            .order
            .iter()
            .position(|(off, _)| *off == pid_off)
            .expect("the pid must be written");
        assert!(
            first_gate_write < pid_write,
            "the shim gate must be CLOSED before the pid moves; write order was {:?}",
            memory.order
        );
        assert_eq!(
            memory.order[first_gate_write].1, 0,
            "the first gate write must shut it, not re-open it"
        );
        assert_eq!(
            memory.order.last().map(|(off, val)| (*off, *val)),
            Some((gate, 1)),
            "the gate must be re-opened LAST, after pid and ledger are published"
        );
    }

    #[test]
    fn identity_page_stamp_surfaces_guest_memory_write_failure() {
        let base = crate::memory::LINUX_IDENTITY_PAGE_BASE;
        let mut memory = crate::dispatch::LinearMemory::new(base, vec![0; 4]);
        let error = stamp_identity_values(&mut memory, base, 123, 1)
            .expect_err("second identity word is outside the backing");
        assert!(matches!(
            error,
            carrick_guest_mem::MemoryError::OutOfBounds { .. }
        ));
    }
}
