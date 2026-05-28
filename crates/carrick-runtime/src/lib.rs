//! Carrick runtime crate.
//!
//! This crate hosts the Linux ABI translation layer, guest address-space
//! management, syscall dispatcher, rootfs/VFS support, signal/thread handling,
//! and HVF trap engine used by the CLI and engine crates.

#[cfg(target_os = "macos")]
pub mod apfs;
#[cfg(target_os = "macos")]
pub(crate) mod darwin_fs;
pub mod dispatch;
#[cfg(target_os = "macos")]
pub mod dtrace_consumer;
pub mod fs_backend;
pub mod host_tty;
pub(crate) mod inotify;
pub mod interactive_supervisor;
pub mod layer_cache;
// `linux_abi` was lifted into the leaf crate `carrick-abi` (build-graph split,
// docs/build-decomposition-design.md §3.A-A1). Re-exported under the original
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
#[cfg(target_os = "macos")]
pub use carrick_hvf::darwin_kqueue;
pub use carrick_hvf::{
    compat, fork_coord, fork_quiesce, host_signal, io_wait, itimer, probes, shared_aperture,
    syscall, thread, trap, vcpu_kick,
};
pub mod overlay;

pub mod execute;
pub mod pty_relay;
pub mod rootfs;
pub mod runtime;
pub(crate) mod seccomp;
pub mod vfs;
pub use execute::Runtime;
