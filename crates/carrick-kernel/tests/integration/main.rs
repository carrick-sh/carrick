//! Consolidated integration-test binary for carrick-kernel.
//!
//! These cases test kernel and dispatch behaviour only — the syscall
//! dispatcher, the VFS view the kernel presents, the address space, the
//! ELF loader's view, the compat reporter — so they live with the code they
//! exercise. They were carrick-runtime's `tests/integration/*` modules until
//! the kernel moved out of that crate; nothing in them names the carrier.
//!
//! They stay ONE binary for the reason the carrier suite does: one test
//! binary per file meant every file statically re-linked the kernel rlib, and
//! any change to its public API recompiled and relinked all of them, which
//! dominated `cargo test` wall time. Compiling them as `mod`s of a single
//! binary collapses that to one recompile + one link.
//!
//! Cases that need the carrier (`carrick_runtime::platform_bridges`,
//! `carrick_vmm_hvf::io_wait`, `carrick_vmm_hvf::host_signal`) or the image
//! store stay in `carrick-runtime/tests/integration/`.

// Each integration submodule includes the shared `support` helper via
// `#[path = "common/syscall_support.rs"] mod support;` so it stays self-
// contained; that loads the same file once per submodule in this single binary.
#![allow(clippy::duplicate_mod)]

mod address_space;
mod compat_report;
mod concurrency_contracts;
mod elf_inspector;
mod public_backend_surface;
mod rootfs_overlay;
mod rootfs_streaming;
mod syscall_creds;
mod syscall_fs_dir;
mod syscall_fs_meta;
mod syscall_fs_open;
mod syscall_fs_pty;
mod syscall_fs_rw;
mod syscall_fs_stat;
mod syscall_mem;
mod syscall_net_tcp;
mod syscall_net_unix;
mod syscall_table;
mod syscall_time;
