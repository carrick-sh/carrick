// The kernel half was extracted wholesale from carrick-runtime, which allows
// these crate-wide for the same reasons the runtime did: the byte-groupings in
// the ABI constant tables, a guarded lock upgrade or nested `if let` that reads
// better as written, deliberate libc sentinel pointers, and the
// items-after-test-module artifact of the file layout the move preserved.
#![allow(
    clippy::unusual_byte_groupings,
    clippy::collapsible_if,
    clippy::manual_dangling_ptr,
    clippy::items_after_test_module
)]
// Several cross-platform casts (e.g. `mode_t`, fd ints) target a libc type that
// is ALREADY the destination width on non-macOS targets, so clippy flags them as
// `unnecessary_cast` only there. On macOS the source type differs (the cast is
// load-bearing), so we keep the lint STRICT on the macOS build and only relax it
// off-macOS where the casts are genuinely redundant.
#![cfg_attr(not(target_os = "macos"), allow(clippy::unnecessary_cast))]

//! carrick-kernel: the Carrick kernel. The kernel object graph, the syscall
//! dispatcher and every in-zone subsystem the guest talks to — process and
//! thread identity, memory authority, file descriptions, signals, waits,
//! futexes, namespaces, the in-zone network, the kernel-view filesystems
//! (`/proc`, `/sys`, `/dev`, `/dev/pts`) over the `carrick-vfs` filesystem
//! model, and the container/run state that frames them.
//!
//! It names no carrier and no VMM crate. Everything it needs from the
//! execution lane arrives through `carrick-hal` traits the carrier implements
//! (`SyscallTrap`, `CarrierProcess`, `Stage1MmProjection`, `HostSignalBridge`,
//! `GuestTimerBridge`); everything it needs from the host arrives through the
//! leaf crates below. That is what lets an execution backend other than
//! carrick-runtime's HVPatch carrier reuse the kernel.
//!
//! # The leaf-crate aliases
//!
//! The `pub use` lines below are aliases of LEAF crates inside this crate, not
//! shims of the crate this code came from: `crate::linux_abi::…` is
//! `carrick-abi`, `crate::memory::…` is `carrick-mem`, `crate::thread::…` is
//! `carrick-thread`, and so on. They keep the module spellings the kernel's
//! ~40k lines already use.

// carrick-kernel's rustdoc is built with `--document-private-items` so the
// module-level Big Theory Statements can cross-link the internal items they
// describe. Those items are deliberately NOT public API; allow the internal
// doc links rather than widen the public surface just to satisfy rustdoc.
#![allow(rustdoc::private_intra_doc_links)]

pub mod container;
pub(crate) mod container_policy;
pub mod core_dump;
pub mod cred_ipc;
pub mod deadlock_watchdog;
pub mod dispatch;
pub mod event_mux;
pub mod event_ring;
pub(crate) mod eventfd_shm;
pub mod exec_helpers;
pub mod exec_stamps;
pub mod fanotify;
pub(crate) mod file_authority;
// The kernel's file authority is internal, but one binding type crosses the
// crate boundary: the carrier activates the authority on the root file table
// (`SyscallDispatcher::activate_file_authority`) and names what comes back.
// Re-exported here so exactly those two types are publicly reachable and the
// rest of the authority's command/outcome vocabulary stays crate-internal.
pub use file_authority::{AuthorityFatal, FileAuthorityBinding};
pub mod host_tty;
pub(crate) mod inotify;
/// Typed object identities and reservation contracts for the backend-neutral
/// kernel model.
pub mod kernel;
// The Linux kernel keyring subsystem behind `add_key`/`request_key`/`keyctl`.
// The key objects are VM-wide (one service on `kernel::Kernel`); the
// per-thread, per-process and per-uid keyring POINTERS live in the kernel
// graph, never in a host-process global. Rendered docs live in the module
// itself so its intra-doc links resolve in its own scope.
pub(crate) mod keyring;
pub mod namespace;
pub mod network;
pub mod observe;
pub mod page_profile;
pub mod pty_relay;
// Cross-platform run-loop result/error + kernel-half state. Single home for
// `RunResult` / `RuntimeError` / `KernelState` / `Kernel` / `VcpuLoopOutcome`.
pub mod run_result;
pub mod run_state;
pub(crate) mod seccomp;
pub mod syslog;
pub mod vdso_policy;
pub mod vfs;

// `linux_abi` is the leaf crate `carrick-abi`, aliased under the module
// spelling the kernel's call sites use.
pub use carrick_abi as linux_abi;
// AArch64 syscall metadata is platform-neutral ABI data in carrick-abi.
pub use carrick_abi::syscall;
// The guest-virtual address domain the census records are keyed on.
pub use carrick_guest_mem::{GuestVa, GuestVaRange};
// guest_cpu/host_facts/host_mapping/host_proc/ulock are the host primitives in
// the leaf crate `carrick-host` (machine facts, __ulock, host shared mappings,
// CPU accounting, libproc introspection).
pub use carrick_host::{guest_cpu, host_facts, host_mapping, host_proc, ulock};
// elf/memory/page_table/vdso and the shared-aperture sub-allocator live in the
// leaf crate `carrick-mem`.
pub use carrick_mem::{elf, memory, page_table, shared_aperture, vdso};
// The syscall-compat reporter, the USDT probe provider and the VM lifecycle
// probes are platform-neutral and live in carrick-observability.
pub use carrick_observability::{compat, probes, vm_lifecycle};
// thread (ThreadRegistry/FutexTable) + fork_quiesce barriers are
// hypervisor-agnostic; both live in carrick-thread.
pub use carrick_thread::{fork_quiesce, thread};

/// Whether the EL1 guest-side syscall shim (the register-only identity fast
/// path: getpid/get*id/gettid) is compiled in. Gated by the `syscall-shim`
/// Cargo feature, which carrick-cli enables by default and forwards through
/// carrick-runtime; build the binary with `--no-default-features` for the
/// legacy trap-only path.
pub const fn syscall_shim_enabled() -> bool {
    cfg!(feature = "syscall-shim")
}

/// Live `(tid, state_char)` for every thread of the container — the data behind
/// `/proc/<pid>/task/` and `/proc/<tid>/stat`. On macOS the state char is read
/// from the kernel via `thread_info` on each thread's recorded Mach port
/// (`'S'` = WAITING, `'R'` = RUNNING, …); a thread whose port isn't recorded
/// yet reports `'R'`.
#[cfg(target_os = "macos")]
pub fn container_thread_states(
    container: carrick_hal::ContainerId,
) -> Vec<(thread::ThreadId, char)> {
    carrick_thread::thread::container_thread_ports(container)
        .into_iter()
        .map(|(tid, port)| {
            let state = if port != 0 {
                host_proc::thread_run_state_char(port)
            } else {
                'R'
            };
            (tid, state)
        })
        .collect()
}

/// Live `(tid, state_char)` for every thread of the container. Off macOS there
/// are no Mach ports to ask, so the state char is the one the thread registry
/// itself records.
#[cfg(not(target_os = "macos"))]
pub fn container_thread_states(
    container: carrick_hal::ContainerId,
) -> Vec<(thread::ThreadId, char)> {
    thread::container_thread_state_chars(container)
}

// The host→Linux errno translation the whole kernel speaks. On
// macOS/FreeBSD/NetBSD that is carrick-host-bsd's table; on Linux the host
// errno space already IS the Linux one, so the identity translation just
// enters the typed domain.
#[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "netbsd"))]
pub use carrick_host_bsd::bsd_to_linux_errno as host_to_linux_errno;

#[cfg(target_os = "linux")]
pub fn host_to_linux_errno(host: i32) -> carrick_abi::LinuxErrno {
    carrick_abi::LinuxErrno::new(host)
}
