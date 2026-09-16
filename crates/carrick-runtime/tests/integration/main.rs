//! Consolidated integration-test binary for carrick-runtime.
//!
//! These were previously separate `tests/*.rs` files, i.e. one test binary
//! each, all statically linking the carrick-runtime rlib. Any change to the
//! runtime's public API forced all of them to recompile and relink, which
//! dominated `cargo test` wall time. Compiling them as `mod`s of a single
//! binary collapses that to one recompile + one link.
//!
//! Only tests safe to run as parallel threads in one process live here: pure
//! dispatcher/ELF-load/rootfs/io tests that touch no process-global state.
//!
//! What is left here after the kernel moved to `carrick-kernel` is exactly the
//! set that names the CARRIER or the image store: `syscall_signal`
//! (`carrick_runtime::platform_bridges`), `io_wait` and `syscall_net_epoll`
//! (`carrick_vmm_hvf::io_wait::ThreadWaiter`), `syscall_thread`
//! (`carrick_vmm_hvf::host_signal::reset_after_supervisor_fork`) and
//! `oci_layout` (`carrick_image`). Every other module tested kernel/dispatch
//! behaviour only and now lives in `carrick-kernel/tests/integration/`.
//!
//! Tests that need their own process stay as top-level `tests/*.rs` binaries:
//! - `trap_hvf`, `runtime_loop` — create the process-global HVF VM
//!   (`hv_vm_create` is once-per-process).
//! - `interactive_supervisor`, `interactive_tty` — real host fork + PTY
//!   raw-mode (process-global terminal state).
//! - `syscall_process` — dispatches host `waitid`/`wait`, which observes ALL
//!   the process's children; a sibling test's child breaks its ECHILD asserts.
//! - `thread_stress_harness` — shells out to a script via a CWD-relative path,
//!   sensitive to any sibling test that changes the process CWD.

// The three modules below that need the shared syscall helper include it from
// the kernel suite that owns it (`#[path = "../../../carrick-kernel/tests/
// integration/common/syscall_support.rs"]`). There is exactly ONE copy of that
// file in the tree — duplicating it is the transitional second path this split
// exists to avoid — and the reach follows the crate dependency, carrier →
// kernel. It loads once per submodule in this single binary.
#![allow(clippy::duplicate_mod)]

mod io_wait;
mod oci_layout;
mod syscall_net_epoll;
mod syscall_signal;
mod syscall_thread;
