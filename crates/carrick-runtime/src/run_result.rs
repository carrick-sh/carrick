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
    #[error("frame inventory reservation failed: {0}")]
    FrameInventoryReserve(#[from] crate::kernel::FrameInventoryReserveError),
    #[error("filesystem backend error: {0}")]
    FsBackend(anyhow::Error),
    #[error("guest did not exit after {max_traps} traps")]
    TrapLimitExceeded { max_traps: usize },
    /// A guest outcome the current backend cannot service yet (the Linux KVM
    /// MVP loop surfaces blocking I/O / futex / fork / signal injection here).
    /// The HVF loops never construct this.
    #[error("unsupported in this backend: {0}")]
    Unsupported(String),
    /// A run refused at configuration time — an environment knob that no
    /// longer exists (e.g. the removed `CARRICK_DSR_LIVE_ARENA`), before any
    /// guest work starts. Deliberately passed through UNWRAPPED by the
    /// backend arms in `execute.rs`: surfacing it as "filesystem backend
    /// error: failed to run ELF from dispatcher: …" mislabels an env-policy
    /// refusal as an execution failure, and the label is the message.
    #[error("configuration refused: {0}")]
    Configuration(String),
}

/// The runtime-side edge of the native memory error seam: the native
/// mapping machinery (mapped_memory.rs, migrating into `carrick-dsr`)
/// produces `NativeMemoryError`, and only its public boundary functions
/// surface `RuntimeError` — through this conversion. It preserves the
/// historical messages exactly: `Unsupported` maps variant-to-variant, and
/// `Io` reproduces the `"{context}: {os error}"` string the old inline
/// `last_io_error` built for `RuntimeError::FsBackend`.
impl From<carrick_dsr::native_error::NativeMemoryError> for RuntimeError {
    fn from(error: carrick_dsr::native_error::NativeMemoryError) -> Self {
        match error {
            carrick_dsr::native_error::NativeMemoryError::Unsupported(message) => {
                RuntimeError::Unsupported(message)
            }
            carrick_dsr::native_error::NativeMemoryError::Io { operation, source } => {
                RuntimeError::FsBackend(anyhow::anyhow!("{operation}: {source}"))
            }
        }
    }
}

/// What a finished guest run produced. The dispatcher buffers the guest's
/// stdout/stderr (fd 1/2); the driver flushes them to the host after the loop
/// returns. `report` / `trap_limit_hit` are the macOS compat-reporting fields;
/// the KVM loop fills `report` from its (stub) reporter and leaves
/// `trap_limit_hit` false (it surfaces the limit as `RuntimeError` instead).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RunResult {
    pub exit_code: i32,
    /// The signal that KILLED this process, if one did.
    ///
    /// `exit_code` alone cannot carry this. A process killed by SIGSEGV gets
    /// the shell's `128 + signum` convention, which is byte-identical to a
    /// program that legitimately called `exit(139)` — two domains sharing one
    /// integer, the exact bug shape this tree bans from semantic boundaries.
    ///
    /// It was harmless while every Linux process was its own HOST process:
    /// `forked_child_die_by_signal` made the host child genuinely die of the
    /// signal, so the host `waitpid` reported `WIFSIGNALED` and the guest
    /// parent's `wait4` translated it. Under the kernel (`hvpatch`) lane there
    /// is no host child to die — a Linux process is a thread — so the exit is
    /// published from this value alone, and the distinction has to be IN the
    /// value. Without it a guest crash was reported as a normal exit with
    /// status 139: `WIFSIGNALED` false, `WTERMSIG` never consulted, every
    /// shell and test harness misreading the crash
    /// (`conformance-probes/src/bin/coredumpfile.rs`).
    ///
    /// `None` means the process exited of its own accord.
    #[serde(default)]
    pub terminating_signal: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub traps: usize,
    pub report: CompatReport,
    #[serde(default)]
    pub trap_limit_hit: bool,
}

impl RunResult {
    /// The Linux `wait(2)` status word for this outcome — the one place the
    /// two domains are encoded, so a caller cannot pick the wrong form.
    ///
    /// Signal death is `signum & 0x7f`, with `0x80` set when a core was
    /// produced; a normal exit is `(code & 0xff) << 8`. Encoding a signal
    /// death in the exit form is what made `WIFSIGNALED` false for a guest
    /// SIGSEGV.
    #[must_use]
    pub fn wait_status_encoding(&self, core_dumped: bool) -> i32 {
        match self.terminating_signal {
            Some(signum) => (signum & 0x7f) | if core_dumped { 0x80 } else { 0 },
            None => (self.exit_code & 0xff) << 8,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn result(exit_code: i32, terminating_signal: Option<i32>) -> RunResult {
        RunResult {
            exit_code,
            terminating_signal,
            stdout: Vec::new(),
            stderr: Vec::new(),
            traps: 0,
            report: Default::default(),
            trap_limit_hit: false,
        }
    }

    /// An `execve` that fails past its point of no return must be
    /// distinguishable, by the parent, from a program that exited 127.
    ///
    /// Carrick used to report an internal exec failure as exit code 127. That
    /// is `WIFEXITED`, so `wait(2)` said the child exited normally — and 127
    /// is exactly what a shell reports for "command not found", so an internal
    /// carrick failure was indistinguishable both from a missing binary and
    /// from a program that deliberately exited 127. Linux kills the caller
    /// with SIGSEGV there, which is `WIFSIGNALED` and unambiguous.
    #[test]
    fn a_signalled_exec_failure_is_distinguishable_from_exit_127() {
        let signalled = result(128 + 11, Some(11)).wait_status_encoding(false);
        let exited_127 = result(127, None).wait_status_encoding(false);

        // WIFSIGNALED: the low 7 bits carry the signal and are nonzero.
        assert_eq!(signalled & 0x7f, 11, "SIGSEGV in the signal field");
        // WIFEXITED: the low 7 bits are zero and the code is in bits 8..16.
        assert_eq!(exited_127 & 0x7f, 0, "a normal exit has no signal");
        assert_eq!((exited_127 >> 8) & 0xff, 127);

        // The whole point: the two are not the same status word, so a parent
        // can tell them apart.
        assert_ne!(signalled, exited_127);

        // And the signalled form must not be mistakable for ANY normal exit —
        // its exit-code field must not be read as a meaningful code.
        assert_eq!(
            signalled & 0x7f,
            11,
            "a signalled death never encodes into the exit-code field"
        );
    }

    /// The exit-code field is masked to 8 bits, so `128 + signum` stored
    /// alongside the signal cannot leak into the status word.
    #[test]
    fn the_signal_form_ignores_the_companion_exit_code() {
        let with_code = result(139, Some(11)).wait_status_encoding(false);
        let without_code = result(0, Some(11)).wait_status_encoding(false);
        assert_eq!(with_code, without_code);
    }
}
