//! Cross-platform run-loop result + error types.
//!
//! `RunResult` / `RuntimeError` were duplicated — once in the macOS `runtime`
//! module and once in the Linux (KVM) `runtime` shim. They live here now,
//! unconditionally, so both the HVF threaded/single-threaded loops and the KVM
//! single-threaded loop return the same `Result<RunResult, RuntimeError>`.

use serde::Serialize;
use thiserror::Error;

use crate::compat::CompatReport;
use crate::dispatch::DispatchError;
use crate::memory::AddressSpaceError;
use crate::trap::TrapError;

/// Why a guest run stopped short of (or completed with) a clean exit. Shared by
/// the HVF loops and the KVM single-threaded loop.
#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("failed to load ELF image: {0}")]
    AddressSpace(#[from] AddressSpaceError),
    // Reading a rootfs-backed ELF (main binary / PT_INTERP) lives at the runtime
    // layer now that AddressSpace loading is rootfs-agnostic (closure reader) —
    // this is what decoupled `memory` from `rootfs` (build-graph A2.5).
    #[error("failed to read rootfs-backed ELF: {0}")]
    RootFs(#[from] crate::rootfs::RootFsError),
    #[error("trap engine failed: {0}")]
    Trap(#[from] TrapError),
    #[error("syscall dispatch failed: {0}")]
    Dispatch(#[from] DispatchError),
    #[error("filesystem backend error: {0}")]
    FsBackend(anyhow::Error),
    #[error("guest did not exit after {max_traps} traps")]
    TrapLimitExceeded { max_traps: usize },
    /// A guest outcome the current backend cannot service yet (the Linux KVM
    /// MVP loop surfaces blocking I/O / futex / fork / signal injection here).
    /// The HVF loops never construct this.
    #[error("unsupported in this backend: {0}")]
    Unsupported(String),
}

/// What a finished guest run produced. The dispatcher buffers the guest's
/// stdout/stderr (fd 1/2); the driver flushes them to the host after the loop
/// returns. `report` / `trap_limit_hit` are the macOS compat-reporting fields;
/// the KVM loop fills `report` from its (stub) reporter and leaves
/// `trap_limit_hit` false (it surfaces the limit as `RuntimeError` instead).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RunResult {
    pub exit_code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub traps: usize,
    pub report: CompatReport,
    #[serde(default)]
    pub trap_limit_hit: bool,
}
