#![allow(
    clippy::unusual_byte_groupings,
    clippy::collapsible_if,
    clippy::manual_dangling_ptr,
    clippy::items_after_test_module
)]

//! Carrick runtime — the core that runs an unmodified Linux ELF binary as a
//! native macOS process.
//!
//! # Theory of operation
//!
//! Carrick has **no guest Linux kernel**. A Linux ELF is loaded into a guest
//! address space, executed at EL0 under Apple's Hypervisor.framework (HVF), and
//! every `svc #0` (the AArch64 syscall instruction) traps back to the host. The
//! trapped syscall is then *emulated* — translated to Darwin host primitives
//! (real file descriptors, `kqueue`, `__ulock`, `posix_spawn`, `fork`) — and the
//! result is written back into the guest registers before resuming. To the
//! Linux process it is running on Linux; there is no VM image, no init, no guest
//! ring-0 code. carrick is simultaneously the VMM *and* the kernel the guest
//! thinks it is talking to.
//!
//! This crate is the union of those two roles. The split between them is
//! reflected in the module layout:
//!
//! - **The exec engine** (the leaf crate `carrick-hvf`, re-exported below under
//!   `crate::trap`, `crate::thread`, `crate::io_wait`, …): the HVF trap engine
//!   that owns the vCPUs, fork/exec address-space surgery, the SIMD/FP restore
//!   shim, cross-thread vCPU coordination (the kicker, the fork/page-table
//!   quiesce barriers), the Darwin `kqueue` wrapper, and host-signal capture.
//!   This is the "VMM half".
//! - **The kernel half** (this crate proper): [`dispatch`] — the syscall
//!   dispatcher and its subsystems — plus [`vfs`]/[`rootfs`]/[`overlay`]/
//!   [`fs_backend`] (the filesystem the guest sees), [`namespace`] (UID/GID +
//!   PID namespace emulation), [`container`] (docker-style run state), and the
//!   `/proc` and signal machinery. None of these touch HVF directly; they
//!   answer syscalls.
//! - **The lifecycle** ([`runtime`], [`execute`]): the glue that wires the two
//!   halves together. It loads the image, installs the EL0 trampoline / EL1
//!   vectors / stage-1 page tables, then drives the trap → dispatch → complete
//!   loop until the guest exits. It also owns the fork/clone model
//!   (`libc::fork` for guest processes, one host thread + one HVF vCPU per guest
//!   thread), fault-to-signal translation, the interactive pty bridge
//!   ([`pty_relay`]/[`interactive_supervisor`]), and the namespace supervisor
//!   ([`namespace::supervisor`]). Start reading at [`runtime`].
//!
//! # The leaf-crate re-exports
//!
//! Several subsystems were lifted out of this crate into leaf crates to cut the
//! build-graph fan-out (a ~40k-line monolith re-linking on every edit). They are
//! re-exported below under their *original* `crate::<module>` paths, so every
//! call site across the runtime — and every `carrick_runtime::<module>` path the
//! CLI/engine crates use — is unchanged. When you see `crate::trap::…` or
//! `crate::memory::…` in this crate, the code physically lives in `carrick-hvf`
//! / `carrick-mem` / `carrick-host` / `carrick-abi`; the boundary is a build
//! optimisation, not a semantic one.
//!
//! # Sharp edges (read before touching the lifecycle)
//!
//! - **HVF is not fork-safe.** A VM live in the parent at `libc::fork(2)` makes
//!   the child's `hv_vm_create` return `HV_BUSY`. Every fork in carrick is
//!   therefore choreographed: the namespace supervisor forks *before* any VM
//!   exists, and a guest `fork(2)` from a multithreaded guest first quiesces all
//!   sibling vCPUs, tears the VM down, forks, and rebuilds. See [`runtime`].
//! - **A forked child must `_exit`, never unwind.** It shares the parent's fd
//!   table; dropping an fd-owning value on the way out double-closes an inherited
//!   fd and trips std's IO-safety abort (`SIGABRT`). The lifecycle code branches
//!   on "am I a forked child" on every exit path for exactly this reason.
//! - **One vCPU per guest thread, one process VM.** Stage-2 mappings are shared
//!   across all vCPUs, but stage-1 page-table edits (mmap/mprotect/munmap) and
//!   forks are stop-the-world events coordinated through the quiesce barriers in
//!   `carrick-hvf::fork_quiesce`.

// carrick-runtime is an INTERNAL crate (consumed only by carrick-engine and
// carrick-cli), and its rustdoc is built with `--document-private-items` so the
// Big Theory Statements above and on each module can cross-link the internal
// run-loop / lifecycle items they describe (`run_vcpu_until_exit`,
// `maybe_fork_ns_supervisor`, `SupervisorRole`, `ThreadRuntimeState::handle_fork`,
// …). Those items are deliberately NOT public API; allow the internal doc links
// rather than widen the public surface just to satisfy rustdoc.
#![allow(rustdoc::private_intra_doc_links)]

#[cfg(target_os = "macos")]
pub mod apfs;
pub mod binfmt;
pub mod container;
pub mod cred_ipc;
#[cfg(target_os = "macos")]
pub(crate) mod darwin_fs;
pub mod deadlock_watchdog;
pub mod dispatch;
#[cfg(target_os = "macos")]
pub mod dtrace_consumer;
pub mod event_ring;
pub mod fs_backend;
pub mod host_tty;
pub(crate) mod inotify;
pub mod interactive_supervisor;
pub mod layer_cache;
pub mod namespace;
// `linux_abi` was lifted into the leaf crate `carrick-abi` (build-graph split,
// docs/archive/build-decomposition-design.md §3.A-A1). Re-exported under the original
// path so every `crate::linux_abi::…` / `carrick_runtime::linux_abi::…` site is
// unchanged.
pub use carrick_abi as linux_abi;
// elf/memory/page_table/vdso were lifted into the leaf crate `carrick-mem`
// (build-graph A3). Re-exported under their original paths so every
// `crate::memory::…` / `crate::elf::…` / `crate::page_table::…` / `crate::vdso::…`
// site (and the `carrick_runtime::*` ones) is unchanged.
pub use carrick_mem::{elf, memory, page_table, vdso};
// guest_cpu/host_facts/host_mapping/host_proc/ulock were lifted into the leaf
// crate `carrick-host` (Darwin host primitives — machine facts, __ulock, host
// shared mappings, CPU accounting, libproc introspection; no dispatch/trap/VFS
// deps). Re-exported under their original paths so every `crate::host_proc::…`
// / `crate::guest_cpu::…` / `crate::ulock::…` site is unchanged.
pub use carrick_host::{guest_cpu, host_facts, host_mapping, host_proc, ulock};
// The dispatch-free vCPU / exec-engine cluster was lifted into the leaf crate
// `carrick-hvf` (report item #1): the HVF trap engine (`trap`, incl. the
// `SyscallTrap` contract + SIMD/FP C shim), cross-thread vCPU coordination
// (`thread`/`vcpu_kick`/`io_wait`/`itimer`/`fork_quiesce`/`fork_coord`), the
// shared-aperture allocator, the Darwin `kqueue` wrapper, host-signal capture,
// the USDT probe provider (`probes`), compat-reporting (`compat`), and static
// syscall metadata (`syscall`). None depend on dispatch/VFS. Re-exported under
// their original `crate::trap::…` / `crate::thread::…` / … paths so every call
// site across the runtime is unchanged.
#[cfg(all(target_os = "macos", feature = "platform-macos"))]
pub use carrick_hvf::darwin_kqueue;
#[cfg(feature = "platform-macos")]
pub use carrick_hvf::{
    compat, fork_coord, fork_quiesce, host_signal, io_wait, itimer, posix_timer, probes,
    shared_aperture, syscall, thread, trap, vcpu_kick,
};

// Under platform-linux there is no carrick-hvf to re-export `trap` from; the
// SyscallTrap/TrapError/ForkOutcome contract lives in carrick-hal (section
// HAL). Re-export a `trap` shim so `crate::trap::{SyscallTrap, …}` resolves on
// both platforms. The concrete engine (HvfTrapEngine / KvmTrapEngine) is
// selected by the run-loop, which is itself platform-gated.
#[cfg(not(feature = "platform-macos"))]
pub mod trap {
    pub use carrick_hal::{ForkOutcome, SyscallTrap, TrapError};
    pub const HVF_PAGE_SIZE: u64 = 0x4000;
}
pub mod overlay;
pub mod pathcodec;

#[cfg(feature = "platform-macos")]
pub mod execute;
pub mod pty_relay;
pub mod rootfs;
#[cfg(feature = "platform-macos")]
pub mod runtime;
pub(crate) mod seccomp;
pub mod vfs;
#[cfg(feature = "platform-macos")]
pub use execute::Runtime;

#[cfg(not(feature = "platform-macos"))]
pub mod execute {
    pub fn guest_hostname() -> &'static str {
        "carrick"
    }
}

#[cfg(not(feature = "platform-macos"))]
pub mod runtime {
    //! Linux (KVM) run path. The full macOS run loop lives in `runtime.rs`
    //! (`cfg(platform-macos)`); on Linux we drive `carrick_linux::KvmTrapEngine`
    //! through the REAL `SyscallDispatcher` with a single-threaded loop that
    //! mirrors the macOS loop's non-blocking outcome handling
    //! (`Returned`/`Errno`/`Exit`). Blocking I/O (the epoll waiter), futex, and
    //! fork/exec/signal-injection are the full-backend spec's Phase C/D work and
    //! deliberately surface here as `RuntimeError::Unsupported` for now.
    use carrick_guest_mem::GuestMemory;
    use carrick_hal::SyscallTrap;

    use crate::compat::CompatReporter;
    use crate::dispatch::{DispatchOutcome, SyscallDispatcher, SyscallRequest};

    pub const DEFAULT_MAX_TRAPS: usize = 1_000_000;
    pub(crate) const ROSETTA_INTERPRETER: &str =
        "/Library/Apple/usr/libexec/oah/RosettaLinux/rosetta";
    pub(crate) fn rosetta_license_blob() -> Option<&'static [u8]> {
        None
    }

    /// What a finished guest run produced. The KVM backend buffers the guest's
    /// stdout/stderr in the dispatcher (fd 1/2); the driver flushes them to the
    /// host after the loop returns.
    #[derive(Debug)]
    pub struct RunResult {
        pub exit_code: i32,
        pub stdout: Vec<u8>,
        pub stderr: Vec<u8>,
        pub traps: usize,
    }

    /// Why the Linux run loop stopped short of a clean guest exit.
    #[derive(Debug)]
    pub enum RuntimeError {
        /// ELF load / address-space construction failed.
        Load(String),
        /// The trap engine (KVM bring-up, `KVM_RUN`, register I/O) failed.
        Trap(String),
        /// A syscall dispatch returned a hard error.
        Dispatch(String),
        /// The guest hit an outcome the Phase-B loop cannot service yet
        /// (blocking I/O / futex / fork / signal injection — Phase C/D).
        Unsupported(String),
        /// The guest ran past `max_traps` syscalls without exiting.
        TrapLimit,
    }

    impl std::fmt::Display for RuntimeError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                RuntimeError::Load(m) => write!(f, "load: {m}"),
                RuntimeError::Trap(m) => write!(f, "trap: {m}"),
                RuntimeError::Dispatch(m) => write!(f, "dispatch: {m}"),
                RuntimeError::Unsupported(m) => write!(f, "unsupported in linux MVP loop: {m}"),
                RuntimeError::TrapLimit => write!(f, "guest exceeded max_traps without exiting"),
            }
        }
    }
    impl std::error::Error for RuntimeError {}

    /// Single-threaded real-dispatch loop for the KVM backend. Generic over the
    /// engine, which must be BOTH the guest memory (`GuestMemory`) and the trap
    /// vehicle (`SyscallTrap`) — `KvmTrapEngine` is both, so there is no
    /// `SplitView`. `next_syscall`, `dispatch`, and `complete_syscall` are
    /// called sequentially, so the single `&mut runtime` is never aliased.
    pub fn run_combined_syscall_loop_linux<R>(
        runtime: &mut R,
        mut dispatcher: SyscallDispatcher,
        max_traps: usize,
    ) -> Result<RunResult, RuntimeError>
    where
        R: GuestMemory + SyscallTrap,
    {
        let reporter = CompatReporter::default();
        let trace_traps = std::env::var_os("CARRICK_TRACE_TRAPS").is_some();
        for traps in 1..=max_traps {
            let frame = match runtime
                .next_syscall()
                .map_err(|e| RuntimeError::Trap(e.to_string()))?
            {
                Some(f) => f,
                // A bare kick/halt with no pending syscall. Phase B has no
                // process-directed signals, so there is nothing to deliver.
                None => continue,
            };
            if trace_traps {
                eprintln!(
                    "trap#{traps}: x8={} x0={:#x} x1={:#x} x2={:#x} x3={:#x} x4={:#x} x5={:#x}",
                    frame.x8, frame.x0, frame.x1, frame.x2, frame.x3, frame.x4, frame.x5
                );
            }
            let outcome = dispatcher
                .dispatch(
                    SyscallRequest::from_aarch64_frame(frame),
                    runtime,
                    &reporter,
                )
                .map_err(|e| RuntimeError::Dispatch(e.to_string()))?;
            match outcome {
                DispatchOutcome::Returned { value } => {
                    runtime
                        .complete_syscall(value)
                        .map_err(|e| RuntimeError::Trap(e.to_string()))?;
                }
                DispatchOutcome::Errno { errno } => {
                    runtime
                        .complete_syscall(-(errno as i64))
                        .map_err(|e| RuntimeError::Trap(e.to_string()))?;
                }
                DispatchOutcome::Exit { code } => {
                    return Ok(RunResult {
                        exit_code: code,
                        stdout: dispatcher.stdout().to_vec(),
                        stderr: dispatcher.stderr().to_vec(),
                        traps,
                    });
                }
                other => {
                    // Blocking I/O / futex / fork / clone-thread / signals:
                    // Phase C/D. Surface clearly rather than silently mis-handle.
                    return Err(RuntimeError::Unsupported(format!("{other:?}")));
                }
            }
        }
        Err(RuntimeError::TrapLimit)
    }

    /// Phase B entry: boot a freestanding/static aarch64 ELF under KVM and run
    /// it through the REAL dispatcher — the `cfg(platform-linux)` sibling of the
    /// macOS `HvfTrapEngine` run path. `KvmTrapEngine` satisfies the loop's
    /// `GuestMemory + SyscallTrap` bound directly.
    #[cfg(feature = "platform-linux")]
    pub fn run_elf_real_dispatch(path: &std::path::Path) -> Result<RunResult, RuntimeError> {
        let image = crate::memory::AddressSpace::load_elf(path)
            .map_err(|e| RuntimeError::Load(e.to_string()))?;
        let mut engine = carrick_linux::KvmTrapEngine::new(&image)
            .map_err(|e| RuntimeError::Trap(e.to_string()))?;
        run_combined_syscall_loop_linux(&mut engine, SyscallDispatcher::new(), DEFAULT_MAX_TRAPS)
    }
}

/// Whether the EL1 guest-side syscall shim (the register-only identity fast
/// path: getpid/get*id/gettid) is compiled in. Gated by the `syscall-shim`
/// Cargo feature. carrick-cli enables it by default; build the binary with
/// `--no-default-features` for the legacy trap-only path.
pub(crate) const fn syscall_shim_enabled() -> bool {
    cfg!(feature = "syscall-shim")
}

#[cfg(feature = "platform-macos")]
pub use carrick_bsd::bsd_to_linux_errno as host_to_linux_errno;

#[cfg(not(feature = "platform-macos"))]
pub fn host_to_linux_errno(host: i32) -> i32 {
    host
}

// Fallbacks for the configured-out carrick-hvf re-exports when platform-macos is disabled.
#[cfg(not(feature = "platform-macos"))]
pub mod darwin_kqueue {
    pub const EVFILT_EXCEPT: i16 = -15;
    pub const NOTE_OOB: u32 = 0x0000_0002;

    pub fn trigger_user(_kq: i32, _ident: usize) -> Result<(), i32> {
        Ok(())
    }
    pub fn apply_changes(_kq: i32, _changes: &[Kevent]) -> Result<(), i32> {
        Ok(())
    }

    #[derive(Debug, Clone, Copy)]
    pub struct Kevent;
    impl Kevent {
        pub fn empty() -> Self {
            Self
        }
        pub fn read(_fd: i32, _flags: u16) -> Self {
            Self
        }
        pub fn write(_fd: i32, _flags: u16) -> Self {
            Self
        }
        pub fn oob(_fd: i32, _flags: u16) -> Self {
            Self
        }
        pub fn vnode(_fd: i32, _note: u32) -> Self {
            Self
        }
        pub fn vnode_delete(_fd: i32) -> Self {
            Self
        }
        pub fn proc_exit(_pid: i32) -> Self {
            Self
        }
        pub fn with_udata(self, _udata: i32) -> Self {
            Self
        }
        pub fn user(_ident: usize, _flags: u16) -> Self {
            Self
        }
        pub fn timer(_ident: usize, _flags: u16, _interval_ns: i64) -> Self {
            Self
        }
        pub fn udata_i32(&self) -> i32 {
            0
        }
        pub fn vnode_ident(&self) -> i32 {
            -1
        }

        pub fn is_proc_exit(&self) -> bool {
            false
        }
        pub fn is_read_for_fd(&self, _fd: i32) -> bool {
            false
        }
        pub fn filter(&self) -> i16 {
            0
        }
        pub fn flags(&self) -> u16 {
            0
        }
        pub fn fflags(&self) -> u32 {
            0
        }
        pub fn data(&self) -> i64 {
            0
        }
        pub fn ident(&self) -> usize {
            0
        }
        pub fn proc_exit_ident(&self) -> Option<i32> {
            None
        }
        pub fn proc_exit_status(&self) -> i32 {
            0
        }
    }

    #[derive(Debug)]
    pub struct Kqueue;
    impl Kqueue {
        pub fn new_internal() -> Option<Self> {
            None
        }
        pub fn apply(&self, _changes: &[Kevent]) -> Result<(), i32> {
            Ok(())
        }
        pub fn raw_fd(&self) -> i32 {
            -1
        }
        pub fn wait(
            &self,
            _changes: &[Kevent],
            _events: &mut [Kevent],
            _timeout: Option<&libc::timespec>,
        ) -> Result<usize, i32> {
            Ok(0)
        }
    }
}

#[cfg(not(feature = "platform-macos"))]
pub mod thread {
    pub type ThreadId = i32;

    #[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
    pub struct FutexWait {
        pub addr: u64,
        generation: u64,
    }

    pub struct FutexTable;
    impl FutexTable {
        pub fn new() -> Self {
            Self
        }
        pub fn wake(&self, _addr: u64, _n: u32) -> u32 {
            0
        }
        pub fn prepare_wait(&self, addr: u64) -> FutexWait {
            FutexWait {
                addr,
                generation: 0,
            }
        }
        pub fn requeue(&self, _from: u64, _to: u64, _nr_wake: u32, _nr_requeue: u32) -> (u32, u32) {
            (0, 0)
        }
    }

    pub struct ThreadRegistry;
    impl ThreadRegistry {
        pub fn live_count(&self) -> usize {
            1
        }
        pub fn is_live(&self, _tid: ThreadId) -> bool {
            true
        }
        pub fn set_clear_child_tid(&self, _tid: ThreadId, _addr: u64) {}
        pub fn set_thread_name(&self, _tid: ThreadId, _name: &[u8]) {}
        pub fn thread_name(&self, _tid: ThreadId) -> Option<[u8; 16]> {
            None
        }
        pub fn live_tids(&self) -> Vec<ThreadId> {
            Vec::new()
        }
    }

    pub fn current_thread_states() -> Vec<(ThreadId, char)> {
        Vec::new()
    }

    pub fn current_thread_name(_tid: ThreadId) -> Option<[u8; 16]> {
        None
    }

    pub fn set_current_registry(_registry: std::sync::Arc<ThreadRegistry>) {}
}

#[cfg(not(feature = "platform-macos"))]
pub mod host_signal {
    pub const NO_PENDING_SIGNAL: i32 = 0;

    pub fn relocate_internal_fd(fd: i32) -> i32 {
        fd
    }
    pub fn reset_after_supervisor_fork() {}
    pub fn has_unblocked_pending_for(_tid: i32, _mask: u64) -> bool {
        false
    }
    pub fn linux_to_host_signum(sig: i32) -> i32 {
        sig
    }
    pub fn host_to_linux_signum(sig: i32) -> i32 {
        sig
    }
    pub fn has_process_pending() -> bool {
        false
    }
    pub fn take_child_exit_parent(_child_pid: i32) -> Option<(i32, i32)> {
        None
    }
    pub fn reset_routed_handlers_after_execve(_ignored_mask: u64) {}
    pub fn xsig_has_pending() -> bool {
        false
    }
    pub fn xsig_drain_for_self() -> Vec<(i32, i32, u32, i64)> {
        Vec::new()
    }
    pub fn raise_for_self(_sig: i32) {}
    pub fn publish_pending_for(_tid: i32, _sig: i32) {}
    pub fn take_pending() -> i32 {
        0
    }
    pub fn ensure_host_handler(_sig: i32) {}
    pub fn set_host_ignore(_sig: i32) {}
    pub fn take_pending_in_for(_tid: i32, _wait_set: u64) -> i32 {
        0
    }
    pub fn xsig_enqueue(
        _target_host: i32,
        _sig: i32,
        _sender_ns: i32,
        _sender_uid: u32,
        _value: i64,
    ) -> bool {
        false
    }
    pub fn xsig_nudge(_target_host: i32) {}
    pub fn pump_kqueue() -> i32 {
        0
    }
}

#[cfg(not(feature = "platform-macos"))]
pub mod io_wait {
    use std::os::fd::RawFd;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct WaitFd {
        fd: RawFd,
        events: i16,
        anchored: bool,
    }

    impl WaitFd {
        pub fn raw(fd: RawFd, events: i16) -> Self {
            Self {
                fd,
                events,
                anchored: false,
            }
        }
        pub fn anchored(fd: RawFd, events: i16) -> Self {
            Self {
                fd,
                events,
                anchored: true,
            }
        }
        pub fn fd(&self) -> RawFd {
            self.fd
        }
        pub fn events(&self) -> i16 {
            self.events
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum WaitResult {
        Ready,
        TimedOut,
        Interrupted,
        Errno(i32),
    }

    pub struct ThreadWaiter;
}

#[cfg(not(feature = "platform-macos"))]
pub mod fork_quiesce {
    pub fn is_quiescing() -> bool {
        false
    }
}

#[cfg(not(feature = "platform-macos"))]
pub mod itimer {
    pub fn ident_for(_which: usize) -> usize {
        0
    }
    pub fn which_for_ident(_ident: usize) -> Option<usize> {
        None
    }
    pub fn signum_for(_which: usize) -> i32 {
        0
    }
    pub fn is_cpu_timer(_which: usize) -> bool {
        false
    }
    pub fn arm(_which: usize, _value_ns: u64, _interval_ns: u64, _needs_periodic: bool) -> u64 {
        0
    }
    pub fn disarm(_which: usize) {}
    pub fn is_armed(_which: usize) -> bool {
        false
    }
    pub fn interval_ns(_which: usize) -> u64 {
        0
    }
    pub fn cpu_timer_recheck_delay_ns(_remaining_cpu_ns: u64) -> u64 {
        0
    }
    pub fn spawn_fallback_timer(
        _which: usize,
        _generation: u64,
        _value: std::time::Duration,
        _interval: std::time::Duration,
    ) {
    }
}

#[cfg(not(feature = "platform-macos"))]
pub mod posix_timer {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct TimerSpec {
        pub signum: i32,
        pub value_ns: u64,
        pub interval_ns: u64,
    }

    pub fn create(_clock_id: i32, _signum: i32) -> i32 {
        0
    }
    pub fn arm(_id: i32, _value_ns: u64, _interval_ns: u64) -> Option<TimerSpec> {
        None
    }
    pub fn remaining(_id: i32) -> Option<(u64, u64)> {
        None
    }
    pub fn delete(_id: i32) -> bool {
        false
    }
    pub fn getoverrun(_id: i32) -> Option<u32> {
        None
    }
    pub fn exists(_id: i32) -> bool {
        false
    }
    pub fn clock_id(_id: i32) -> i32 {
        0
    }
    pub fn clear() {}
}

#[cfg(not(feature = "platform-macos"))]
pub mod shared_aperture {
    use crate::memory::{LINUX_SHARED_FILE_BASE, LINUX_SHARED_FILE_SIZE};
    use carrick_abi::align_up_u64;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum BackingObject {
        SharedAnon,
        SharedFile { host_fd: i32, offset: u64 },
        PrivateAnon,
    }

    #[derive(Debug, Clone, Copy)]
    pub struct SharedAlloc {
        pub guest_addr: u64,
        pub len: u64,
        pub backing: BackingObject,
        pub source: Option<u64>,
    }

    #[derive(Debug, Clone)]
    pub struct SharedAperture {
        base: u64,
        size: u64,
        next: u64,
        free: Vec<(u64, u64)>,
        live: Vec<SharedAlloc>,
    }

    const GRANULE: u64 = 0x4000;

    impl Default for SharedAperture {
        fn default() -> Self {
            Self::new()
        }
    }

    impl SharedAperture {
        pub fn new() -> Self {
            Self::with_window(LINUX_SHARED_FILE_BASE, LINUX_SHARED_FILE_SIZE)
        }

        pub fn with_window(base: u64, size: u64) -> Self {
            Self {
                base,
                size,
                next: base,
                free: Vec::new(),
                live: Vec::new(),
            }
        }

        fn window_end(&self) -> u64 {
            self.base + self.size
        }

        pub fn alloc(&mut self, len: u64, backing: BackingObject) -> Option<u64> {
            self.alloc_sourced_with_reuse(len, backing, None)
                .map(|(addr, _reused)| addr)
        }

        pub fn alloc_sourced(
            &mut self,
            len: u64,
            backing: BackingObject,
            source: Option<u64>,
        ) -> Option<u64> {
            self.alloc_sourced_with_reuse(len, backing, source)
                .map(|(addr, _reused)| addr)
        }

        pub fn alloc_sourced_with_reuse(
            &mut self,
            len: u64,
            backing: BackingObject,
            source: Option<u64>,
        ) -> Option<(u64, bool)> {
            if len == 0 {
                return None;
            }
            let len = align_up_u64(len, GRANULE)?;
            if let Some(pos) = self.free.iter().position(|&(_, l)| l >= len) {
                let (s, l) = self.free[pos];
                if l == len {
                    self.free.remove(pos);
                } else {
                    self.free[pos] = (s + len, l - len);
                }
                self.live.push(SharedAlloc {
                    guest_addr: s,
                    len,
                    backing,
                    source,
                });
                return Some((s, true));
            }
            let addr = align_up_u64(self.next, GRANULE)?;
            let end = addr.checked_add(len)?;
            if end > self.window_end() {
                return None;
            }
            self.next = end;
            self.live.push(SharedAlloc {
                guest_addr: addr,
                len,
                backing,
                source,
            });
            Some((addr, false))
        }

        pub fn find_by_source(&self, source: u64) -> Option<u64> {
            self.live
                .iter()
                .find(|a| a.source == Some(source))
                .map(|a| a.guest_addr)
        }

        pub fn free(&mut self, guest_addr: u64) -> Option<SharedAlloc> {
            let pos = self.live.iter().position(|a| a.guest_addr == guest_addr)?;
            let alloc = self.live.remove(pos);
            free_insert(&mut self.free, alloc.guest_addr, alloc.len);
            Some(alloc)
        }

        pub fn live(&self) -> &[SharedAlloc] {
            &self.live
        }
    }

    fn free_insert(regions: &mut Vec<(u64, u64)>, addr: u64, len: u64) {
        let mut start = addr;
        let mut end = addr.saturating_add(len);
        let mut out: Vec<(u64, u64)> = Vec::with_capacity(regions.len() + 1);
        let mut inserted = false;
        for &(s, l) in regions.iter() {
            let e = s.saturating_add(l);
            if e < start || s > end {
                if !inserted && s > end {
                    out.push((start, end - start));
                    inserted = true;
                }
                out.push((s, l));
            } else {
                start = start.min(s);
                end = end.max(e);
            }
        }
        if !inserted {
            out.push((start, end - start));
        }
        out.sort_by_key(|&(s, _)| s);
        *regions = out;
    }
}

#[cfg(not(feature = "platform-macos"))]
pub mod compat {
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    pub struct SyscallArgs(pub [u64; 6]);

    impl From<[u64; 6]> for SyscallArgs {
        fn from(args: [u64; 6]) -> Self {
            Self(args)
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    pub struct GuestRegs {
        pub pc: u64,
        pub sp: u64,
        pub fp: u64,
        pub lr: u64,
        pub x8: u64,
        pub x0: u64,
        pub stack_guest_base: u64,
        pub stack_host_base: u64,
        pub stack_guest_end: u64,
    }

    pub struct CompatReporter;
    impl CompatReporter {
        pub fn record(&self, _event: CompatEvent) {}
    }
    impl Default for CompatReporter {
        fn default() -> Self {
            Self
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub enum CompatEvent {
        SyscallEntry {
            number: u64,
            name: std::borrow::Cow<'static, str>,
            args: SyscallArgs,
        },
        SyscallReturn {
            number: u64,
            name: std::borrow::Cow<'static, str>,
            retval: i64,
            errno: Option<i32>,
        },
        UnhandledSyscall {
            number: u64,
            name: String,
            args: SyscallArgs,
        },
        PartialSyscall {
            number: u64,
            name: String,
            args: SyscallArgs,
            reason: String,
        },
        UnhandledIoctl {
            fd: i32,
            request: u64,
            arg: u64,
        },
        ProcReadUnimplemented {
            path: String,
        },
        SysReadUnimplemented {
            path: String,
        },
        SignalUnsupported {
            signum: i32,
            reason: String,
        },
        UnknownSyscallFlags {
            number: u64,
            name: String,
            argument: u32,
            unknown_bits: u64,
        },
    }
    impl CompatEvent {
        pub fn unhandled_syscall(number: u64, name: impl Into<String>, args: SyscallArgs) -> Self {
            Self::UnhandledSyscall {
                number,
                name: name.into(),
                args,
            }
        }
        pub fn partial_syscall(
            number: u64,
            name: impl Into<String>,
            args: SyscallArgs,
            reason: impl Into<String>,
        ) -> Self {
            Self::PartialSyscall {
                number,
                name: name.into(),
                args,
                reason: reason.into(),
            }
        }
        pub fn unhandled_ioctl(fd: i32, request: u64, arg: u64) -> Self {
            Self::UnhandledIoctl { fd, request, arg }
        }
        pub fn proc_read_unimplemented(path: impl Into<String>) -> Self {
            Self::ProcReadUnimplemented { path: path.into() }
        }
        pub fn sys_read_unimplemented(path: impl Into<String>) -> Self {
            Self::SysReadUnimplemented { path: path.into() }
        }
        pub fn unknown_syscall_flags(
            number: u64,
            name: impl Into<String>,
            argument: u32,
            unknown_bits: u64,
        ) -> Self {
            Self::UnknownSyscallFlags {
                number,
                name: name.into(),
                argument,
                unknown_bits,
            }
        }
    }
}

#[cfg(not(feature = "platform-macos"))]
pub mod syscall {
    pub struct Syscall {
        pub name: &'static str,
    }
    pub fn lookup_aarch64(_number: u64) -> Option<&'static Syscall> {
        None
    }
}

#[cfg(not(feature = "platform-macos"))]
pub mod probes {
    macro_rules! stub {
        ($name:ident($($param:ident: $ty:ty),* $(,)?)) => {
            #[allow(dead_code, unused_variables)]
            #[inline(always)]
            pub fn $name($($param: $ty),*) {}
        };
    }

    stub!(fork_pre(pc: u64, elr: u64, cpsr: u64));
    stub!(path_open(path: &str, result_size: u64, errno: i32));
    stub!(itimer_fire(signum: i32, generation: u64));
    stub!(futex_route(addr: u64, op: i32, shared: i32, host_addr: u64));
    stub!(ulock_wait(host_addr: u64, value: u32, timeout_us: u32, phase: i32, rc: i64));
    stub!(ulock_wake(host_addr: u64, iter: i32, rc: i64));
    stub!(guest_exit(code: i32));
    stub!(lifecycle(phase: u32));
    stub!(execve_argv(path: &str, argv: &[Vec<u8>]));
    stub!(fs_op(op: &str, path: &str, errno: i32));
    stub!(host_pipe_io(host_fd: i32, dir: i32, n: i64));
    stub!(epoll_ctl(epfd: i32, op: u64, fd: i32, events: u32, data: u64, errno: i32));
    stub!(epoll_interest(epfd: i32, fd: i32, requested: u32, raw_ready: u32, last_ready: u32, ready: u32));
    stub!(epoll_wait_fd(epfd: i32, fd: i32, host_fd: i32, poll_events: i32, timeout_ms: i32));
    stub!(epoll_result(epfd: i32, ready_count: i32, wait_count: i32, timeout_ms: i32, kind: i32));
    stub!(io_wait_begin(tid: i32, fd_count: i32, timeout_ms: i64, fd0: i32, events0: i32, fd1: i32));
    stub!(io_wait_end(tid: i32, result: i32, fd_count: i32, fd0: i32, fd1: i32, fd2: i32));
    stub!(fork_quiesce(phase: i32, a: i64, b: i64, tid: i32));
    stub!(fork_post(pid: i32, pc: u64, elr: u64));
    stub!(signal_inject(signum: i32, saved_pc: u64, new_sp: u64, handler: u64));
    stub!(signal_restore(saved_pc: u64, sp: u64, magic: u64));
    stub!(kick_in_kernel(pc: u64, el: u32));
    stub!(kick_stats(el1_resumed: u64, kick_inject: u64, inject_at_el1: u64));
    stub!(mem_watch(syscall_nr: u64, addr: u64, value: u64));
    stub!(sigaction_read(signum: i32, w0: u64, w1: u64, w2: u64, w3: u64));
    stub!(supervisor_fork(child_pid: i32));
    stub!(supervisor_child_ready(runtime_pid: i32));
    stub!(supervisor_foreground_pgrp(pgid: i32, errno: i32));
    stub!(supervisor_child_exit(pid: i32, status: i32));
    stub!(pt_pause_begin(tid: i32, others_in_guest: i32, count: i32));
    stub!(pt_pause_ready(tid: i32, spins: i32, wait_us: i64));
    stub!(pt_pause_timeout(tid: i32, wait_us: i64));
    stub!(pt_pause_end(tid: i32));
    stub!(pt_pool(in_use: u32, free_list: u32, capacity: u32, changed: i32));
    stub!(pt_fault_walk(far: u64, l0: u64, l1: u64, l2: u64, l3: u64));
    stub!(guest_mem_bytes(direction: u32, address: u64, bytes: &[u8]));
    stub!(vcpu_trap(regs: &crate::compat::GuestRegs));
    stub!(execve_loaded(path: &str, entry: u64, initial_sp: u64, mapping_count: u64));
    stub!(execve_sysregs(sctlr: u64, ttbr0: u64, mair: u64));
    stub!(vcpu_fault(esr: u64, elr: u64, far: u64, x30: u64, sp: u64, tid: i32));
    stub!(vcpu_fault_regs(esr: u64, elr: u64, far: u64, insn: u64, rn: u32, xrn: u64));
    stub!(pt_alias_walk(va: u64, descs: [u64; 4], flag: i32));
    stub!(hv_vm_map_alias(va: u64, ipa: u64, size: u64, rc: i32, forked: i32));
    stub!(signal_publish(target_tid: i32, signum: i32, kind: i32));
    stub!(signal_deliver(tid: i32, pending: i32));
    stub!(fire(event: &crate::compat::CompatEvent));

    #[allow(dead_code)]
    pub fn register_dtrace_probes() -> Result<(), usdt::Error> {
        Ok(())
    }
}
