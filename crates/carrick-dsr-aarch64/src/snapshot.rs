//! The AArch64 guest register file captured at every gateway/signal
//! boundary. Moved verbatim from `carrick-runtime/src/native_darwin.rs` as
//! part of the staged native-backend extraction.
//!
//! LAYOUT IS ABI: the struct is `repr(C)` and mirrored field-for-field by
//! the runtime's C trap shim (`csrc/native_darwin.c`, whose
//! `carrick_native_dsr_signal_context` `_Static_assert`s pin the snapshot's
//! 832-byte size and the gateway context offsets built on top of it) and by
//! `gateway_aarch64.S`. `gateway::DsrContext`'s `const` asserts check the
//! same offsets from the Rust side; do not reorder or resize fields.

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct NativeUcontextSnapshot {
    pub x: [u64; 31],
    pub sp: u64,
    pub pc: u64,
    pub pstate: u64,
    pub v: [[u8; 16]; 32],
    pub fpsr: u32,
    pub fpcr: u32,
    pub event_kind: i32,
    pub signal: libc::c_int,
    pub signal_code: libc::c_int,
    pub fault_address: u64,
    pub esr: u64,
    pub far: u64,
}
