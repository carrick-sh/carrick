//! HVF vCPU / exec-engine leaf crate for the carrick runtime.
//!
//! This crate holds the dispatch-free vCPU cluster: the Hypervisor.framework
//! trap engine (`trap`, with its `SyscallTrap` contract, `TrapError`,
//! `HvfTrapEngine`, fork/exec address-space management and the SIMD/FP C shim),
//! cross-thread vCPU coordination (`thread`, `vcpu_kick`, `io_wait`, `itimer`,
//! `fork_quiesce`, `fork_coord`), the shared-aperture allocator, the Darwin
//! `kqueue` wrapper, host-signal capture, the USDT probe provider (`probes`),
//! the compat-reporting primitives (`compat`), and static syscall metadata
//! (`syscall`).
//!
//! None of these modules depend on the runtime's dispatcher/VFS layers, so they
//! live in their own crate to keep edits to the vCPU/exec engine from
//! recompiling the ~40k-line runtime (and vice versa). `carrick-runtime`
//! re-exports every module here under its original `crate::<module>` path so
//! all call sites are unchanged.
//!
//! The modules reference the other leaf crates through the same re-export
//! aliases the runtime uses (`crate::linux_abi`, `crate::memory`,
//! `crate::host_mapping`, …); those aliases are re-declared below so the moved
//! code resolves identically inside this crate.

// Leaf-crate re-exports mirroring carrick-runtime's lib.rs, so the moved
// modules' `crate::linux_abi::…` / `crate::memory::…` / `crate::host_mapping::…`
// paths resolve unchanged inside carrick-hvf.
pub use carrick_abi as linux_abi;
pub use carrick_host::{guest_cpu, host_facts, host_mapping, host_proc, ulock};
pub use carrick_mem::{elf, memory, page_table, vdso};

pub mod compat;
#[cfg(target_os = "macos")]
pub mod darwin_kqueue;
pub mod fork_coord;
pub mod fork_quiesce;
pub mod host_signal;
pub mod io_wait;
pub mod itimer;
pub mod posix_timer;
pub mod probes;
pub mod shared_aperture;
pub mod syscall;
pub mod thread;
pub mod trap;
pub mod vcpu_kick;
