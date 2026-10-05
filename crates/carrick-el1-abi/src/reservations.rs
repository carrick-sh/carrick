//! Anonymous reservation transaction ABI (T1 policy / T2 descriptors).
//!
//! A request is a proposal, never permission to replay a Linux syscall. T2
//! authenticates its MM, generation and sequence against the pending proposal,
//! completes the descriptor transaction and backing grant/return, then returns
//! a completion for that exact request. Only T1 commits reservation metadata.
//! Refusal leaves the old reservation visible; a failed descriptor rollback
//! must fail stopped, never manufacture a refusal/completion.

/// Shared reservation bootstrap region, before T2's descriptor transaction slots.
pub const EL1_RESERVATIONS_OFFSET: u64 = crate::EL1_COUNTERS_OFFSET + 0x1_8000;
pub const EL1_RESERVATIONS_END: u64 = crate::EL1_COUNTERS_OFFSET + 0x8_0000;
/// Protocol revision of the request/flag vocabulary below. Folded into
/// [`crate::EL1_ABI_LAYOUT_HASH`]: an image that decodes `Move`, node flags or
/// the request's `source` differently must not attach to this host.
pub const RESERVATION_PROTOCOL_VERSION: u64 = 3;
