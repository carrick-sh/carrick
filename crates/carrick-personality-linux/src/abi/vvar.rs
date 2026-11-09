//! Layout of the Linux vDSO data (vvar) page carrick maps into a guest.
//!
//! The vDSO code and its data page are carrick's own ABI. The ring reads the
//! same words the guest's vDSO reads, so its clock view and the guest's agree.

/// Guest VA of the vvar (timekeeping) data page. The embedded vDSO code loads
/// this with a single `movz x9, #0x2E, lsl #32`, so it MUST match the asm.
pub const LINUX_VVAR_BASE: u64 = 0x2E_0000_0000;
/// Byte offset of the realtime word: `CLOCK_REALTIME` nanoseconds minus
/// `CLOCK_MONOTONIC` nanoseconds, added with u64 wrapping arithmetic.
pub const REALTIME_OFF_NS: u64 = 16;
