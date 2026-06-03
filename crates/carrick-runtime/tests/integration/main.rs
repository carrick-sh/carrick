//! Consolidated integration-test binary for carrick-runtime.
//!
//! These were previously separate `tests/*.rs` files, i.e. one test binary
//! each, all statically linking the ~41k-line carrick-runtime rlib. Any change
//! to the runtime's public API forced all of them to recompile and relink,
//! which dominated `cargo test` wall time. Compiling them as `mod`s of a single
//! binary collapses that to one recompile + one link.
//!
//! Only tests safe to run as parallel threads in one process live here: pure
//! dispatcher/ELF-load/rootfs/io tests that touch no process-global state.
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

// Each integration submodule includes the shared `support` helper via
// `#[path = "common/syscall_support.rs"] mod support;` so it stays self-
// contained; that loads the same file once per submodule in this single binary.
#![allow(clippy::duplicate_mod)]

mod address_space;
mod compat_report;
mod concurrency_contracts;
mod elf_inspector;
mod io_blocking_guard;
mod io_wait;
mod oci_layout;
mod rootfs_overlay;
mod rootfs_streaming;
mod syscall_creds;
mod syscall_fs;
mod syscall_mem;
mod syscall_net;
mod syscall_signal;
mod syscall_table;
mod syscall_thread;
mod syscall_time;
