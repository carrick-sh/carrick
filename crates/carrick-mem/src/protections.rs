//! Moved to `carrick-guest-mem` (the leaf crate the `GuestMemory` trait lives in)
//! so the trait's default `read_bytes`/`write_bytes` gate can reference the type
//! without a dependency cycle. Re-exported here for back-compat; prefer
//! `carrick_guest_mem::protections::MemoryProtections` in new code.

pub use carrick_guest_mem::protections::MemoryProtections;
