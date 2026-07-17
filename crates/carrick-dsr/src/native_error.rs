//! Error vocabulary for the native guest-memory machinery.
//!
//! `mapped_memory.rs` (still in `carrick-runtime` while the extraction is in
//! flight) produces exactly two failure shapes: a typed "unsupported" message
//! and a captured host `errno` from a failed mapping/protection syscall.
//! `NativeMemoryError` names them without referencing the runtime's
//! `RuntimeError`; the runtime owns the inverse edge
//! (`impl From<NativeMemoryError> for RuntimeError` in `run_result.rs`),
//! which preserves the historical messages exactly:
//!
//!  * `Unsupported(message)` -> `RuntimeError::Unsupported(message)`
//!  * `Io { operation, source }` ->
//!    `RuntimeError::FsBackend(anyhow!("{operation}: {source}"))` — the same
//!    string `last_io_error` used to build inline.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum NativeMemoryError {
    #[error("{0}")]
    Unsupported(String),
    #[error("{operation}: {source}")]
    Io {
        operation: String,
        source: std::io::Error,
    },
}

/// Capture `errno` for a failed host syscall as a typed I/O error. Must be
/// called before anything else can clobber `errno`.
pub fn last_io_error(context: &str) -> NativeMemoryError {
    NativeMemoryError::Io {
        operation: context.to_string(),
        source: std::io::Error::last_os_error(),
    }
}

pub fn checked_add_u64(a: u64, b: u64, context: &str) -> Result<u64, NativeMemoryError> {
    a.checked_add(b).ok_or_else(|| {
        NativeMemoryError::Unsupported(format!("native Darwin {context} overflow: 0x{a:x}+0x{b:x}"))
    })
}

pub fn align_up_u64(value: u64, align: u64, context: &str) -> Result<u64, NativeMemoryError> {
    if align == 0 || !align.is_power_of_two() {
        return Err(NativeMemoryError::Unsupported(format!(
            "native Darwin {context} invalid alignment: {align}"
        )));
    }
    value
        .checked_add(align - 1)
        .map(|v| v & !(align - 1))
        .ok_or_else(|| {
            NativeMemoryError::Unsupported(format!(
                "native Darwin {context} overflow: 0x{value:x} align 0x{align:x}"
            ))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checked_add_reports_overflow_operands() {
        let error = checked_add_u64(u64::MAX, 2, "heap end").expect_err("overflow");
        assert_eq!(
            error.to_string(),
            format!("native Darwin heap end overflow: 0x{:x}+0x2", u64::MAX)
        );
        assert_eq!(checked_add_u64(40, 2, "heap end").expect("sum"), 42);
    }

    #[test]
    fn align_up_rejects_non_power_of_two_and_rounds_up() {
        assert!(matches!(
            align_up_u64(1, 3, "alias length"),
            Err(NativeMemoryError::Unsupported(message))
                if message == "native Darwin alias length invalid alignment: 3"
        ));
        assert_eq!(
            align_up_u64(16_385, 16_384, "alias length").expect("aligned"),
            32_768
        );
        assert!(align_up_u64(u64::MAX, 16_384, "alias length").is_err());
    }

    #[test]
    fn io_error_display_matches_legacy_last_io_error_format() {
        let error = NativeMemoryError::Io {
            operation: "mmap native Darwin alias".to_string(),
            source: std::io::Error::from_raw_os_error(libc::ENOMEM),
        };
        let rendered = error.to_string();
        assert!(rendered.starts_with("mmap native Darwin alias: "));
    }
}
