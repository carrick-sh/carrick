//! Guest address-space construction: ELF loading, the guest VA layout +
//! `AddressSpace`, stage-1 page tables, and the in-userspace vDSO. Lifted out of
//! carrick-runtime as a cache/parallelism boundary (build-graph A3); depends only
//! on the leaf crates carrick-abi (constants) and carrick-guest-mem (the
//! `GuestMemory`/`MemoryError` hub types). The `memory ↔ dispatch` cycle and the
//! `memory → rootfs` edge were removed first (A2/A2.5).

// Moved files use `crate::linux_abi::…`; alias the leaf crate so they're unchanged.
pub use carrick_abi as linux_abi;

pub mod elf;
pub mod memory;
pub mod page_table;
pub mod vdso;
mod vdso_getrandom_chacha;
