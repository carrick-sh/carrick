//! What a finished embedded run produced.

use std::io::Write;
use std::sync::{Arc, Mutex, PoisonError};

use carrick_runtime::compat::CompatReport;
use carrick_runtime::runtime::RunResult;

use crate::{EmbedError, Signal};

/// A `Box<dyn Write + Send>` the runtime's `Piped` sink writes into, whose
/// bytes the embed side reads back after the run. Cloning shares the buffer.
#[derive(Clone, Debug, Default)]
pub(crate) struct CaptureBuffer(Arc<Mutex<Vec<u8>>>);

impl CaptureBuffer {
    pub(crate) fn take(&self) -> Vec<u8> {
        std::mem::take(&mut *self.0.lock().unwrap_or_else(PoisonError::into_inner))
    }
}

impl Write for CaptureBuffer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Which streams the embed side captured itself (mixed per-stream stdio
/// configurations lower to `StdioSink::Piped` with these as the writers).
/// `None` means the runtime's own `RunResult` buffer is authoritative.
#[derive(Debug, Default)]
pub(crate) struct CapturedStreams {
    pub(crate) stdout: Option<CaptureBuffer>,
    pub(crate) stderr: Option<CaptureBuffer>,
}

/// The outcome of one embedded run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerResult {
    /// The guest init process's exit code (`128 + signum` when it died of a
    /// signal, the shell convention; `signal` is the typed source of truth).
    pub exit_code: i32,
    /// The signal that killed the guest init, if one did.
    pub signal: Option<Signal>,
    /// Captured guest stdout (empty under `StdioConfig::Inherit`).
    pub stdout: Vec<u8>,
    /// Captured guest stderr (empty under `StdioConfig::Inherit`).
    pub stderr: Vec<u8>,
    /// The run stopped at `max_traps` without the guest exiting.
    pub trap_limit_hit: bool,
    /// Syscall traps serviced during the run.
    pub traps: usize,
    /// The runtime's compat summary (unhandled/deferred/partial syscalls).
    pub compat: CompatReport,
}

impl ContainerResult {
    pub(crate) fn from_run_result(result: RunResult, captured: CapturedStreams) -> Self {
        let RunResult {
            exit_code,
            terminating_signal,
            stdout,
            stderr,
            traps,
            report,
            trap_limit_hit,
        } = result;
        Self {
            exit_code,
            signal: terminating_signal.map(Signal),
            stdout: captured.stdout.map_or(stdout, |buffer| buffer.take()),
            stderr: captured.stderr.map_or(stderr, |buffer| buffer.take()),
            trap_limit_hit,
            traps,
            compat: report,
        }
    }

    /// Lossy UTF-8 view of `stdout`.
    pub fn stdout_utf8(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }

    /// Lossy UTF-8 view of `stderr`.
    pub fn stderr_utf8(&self) -> String {
        String::from_utf8_lossy(&self.stderr).into_owned()
    }

    /// Exit code 0, no terminating signal, and the trap limit was not hit.
    pub fn success(&self) -> bool {
        self.exit_code == 0 && self.signal.is_none() && !self.trap_limit_hit
    }

    /// Turn an unsuccessful run into the typed error a `?`-style caller wants.
    pub fn ensure_success(self) -> Result<Self, EmbedError> {
        if self.trap_limit_hit {
            return Err(EmbedError::TrapLimit);
        }
        if self.success() {
            Ok(self)
        } else {
            Err(EmbedError::Guest {
                exit_code: self.exit_code,
                signal: self.signal,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn run_result(exit_code: i32, terminating_signal: Option<i32>) -> RunResult {
        RunResult {
            exit_code,
            terminating_signal,
            stdout: b"out".to_vec(),
            stderr: b"err".to_vec(),
            traps: 3,
            report: CompatReport::default(),
            trap_limit_hit: false,
        }
    }

    #[test]
    fn a_clean_exit_is_success_and_keeps_runtime_buffers() {
        let result =
            ContainerResult::from_run_result(run_result(0, None), CapturedStreams::default());
        assert!(result.success());
        assert_eq!(result.stdout_utf8(), "out");
        assert_eq!(result.stderr_utf8(), "err");
        assert_eq!(result.traps, 3);
        assert!(result.ensure_success().is_ok());
    }

    #[test]
    fn signal_death_is_typed_and_unsuccessful() {
        let result =
            ContainerResult::from_run_result(run_result(139, Some(11)), CapturedStreams::default());
        assert_eq!(result.signal, Some(Signal(11)));
        assert!(!result.success());
        assert!(matches!(
            result.ensure_success(),
            Err(EmbedError::Guest {
                exit_code: 139,
                signal: Some(Signal(11))
            })
        ));
    }

    #[test]
    fn a_nonzero_exit_is_a_guest_error_only_through_ensure_success() {
        let result =
            ContainerResult::from_run_result(run_result(7, None), CapturedStreams::default());
        assert!(!result.success());
        assert!(matches!(
            result.ensure_success(),
            Err(EmbedError::Guest {
                exit_code: 7,
                signal: None
            })
        ));
    }

    #[test]
    fn trap_limit_is_never_success() {
        let mut raw = run_result(0, None);
        raw.trap_limit_hit = true;
        let result = ContainerResult::from_run_result(raw, CapturedStreams::default());
        assert!(!result.success());
        assert!(matches!(
            result.ensure_success(),
            Err(EmbedError::TrapLimit)
        ));
    }

    #[test]
    fn embed_side_capture_buffers_override_runtime_buffers_per_stream() {
        let stdout = CaptureBuffer::default();
        stdout.clone().write_all(b"captured-by-embed").unwrap();
        let captured = CapturedStreams {
            stdout: Some(stdout),
            stderr: None,
        };
        let result = ContainerResult::from_run_result(run_result(0, None), captured);
        assert_eq!(result.stdout, b"captured-by-embed");
        assert_eq!(
            result.stderr, b"err",
            "an uncaptured stream keeps the runtime's bytes"
        );
    }

    #[test]
    fn utf8_accessors_are_lossy_not_fallible() {
        let mut raw = run_result(0, None);
        raw.stdout = vec![0xff, b'o', b'k'];
        let result = ContainerResult::from_run_result(raw, CapturedStreams::default());
        assert!(result.stdout_utf8().ends_with("ok"));
    }
}
