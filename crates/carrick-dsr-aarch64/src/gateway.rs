#![allow(dead_code)] // Additional typed exits consume the same context in later tasks.

//! The DSR gateway: the typed Rust surface over `gateway_aarch64.S`.
//!
//! `DsrContext`, its offset asserts, and `IndirectTargetCache` are pure data
//! and compile on every host (the emitter needs the offsets everywhere). The
//! assembled half -- the `extern "C"` symbols and everything that enters
//! translated execution -- sits behind ONE
//! `#[cfg(all(target_os = "macos", target_arch = "aarch64"))]` module
//! boundary below (mirroring build.rs), with a fail-closed complement off
//! that lane. The runtime's component microbenchmarks for the gateway
//! closure/wrapper stayed in the runtime shim (they measure the C trap
//! shim's ABI helpers, which live in csrc/native_darwin.c).

use super::types::{CacheVa, CodeGeneration, DsrError, NativeDsrExit};
use crate::snapshot::NativeUcontextSnapshot;

use std::sync::atomic::{AtomicU64, Ordering};

pub const INDIRECT_CACHE_ENTRIES: usize = 8192;
pub const INDIRECT_CACHE_MASK: u64 = (INDIRECT_CACHE_ENTRIES - 1) as u64;
pub const INDIRECT_CACHE_INDEX_BITS: u32 = 13;
pub const INDIRECT_CACHE_ENTRY_SHIFT: u32 = 5;
pub const CTX_INDIRECT_CACHE: u32 = 1136;
pub const CTX_GENERATION: u32 = 1144;

#[repr(C, align(32))]
pub struct IndirectTargetCacheEntry {
    guest: AtomicU64,
    generation: AtomicU64,
    cache: AtomicU64,
    pad: u64,
}

#[inline(always)]
fn indirect_cache_index(guest: carrick_guest_mem::GuestVa) -> usize {
    let raw = guest.raw();
    let mixed = raw ^ (raw >> 12);
    ((mixed >> 2) & INDIRECT_CACHE_MASK) as usize
}

pub struct IndirectTargetCache {
    entries: Box<[IndirectTargetCacheEntry; INDIRECT_CACHE_ENTRIES]>,
}

impl IndirectTargetCache {
    pub fn new() -> Self {
        Self {
            entries: Box::new(std::array::from_fn(|_| IndirectTargetCacheEntry {
                guest: AtomicU64::new(0),
                generation: AtomicU64::new(0),
                cache: AtomicU64::new(0),
                pad: 0,
            })),
        }
    }

    pub fn publish(
        &self,
        guest: carrick_guest_mem::GuestVa,
        generation: CodeGeneration,
        cache: CacheVa,
    ) {
        let entry = &self.entries[indirect_cache_index(guest)];
        entry
            .cache
            .store(cache.host().raw() as u64, Ordering::Relaxed);
        entry.generation.store(generation.get(), Ordering::Relaxed);
        entry.guest.store(guest.raw(), Ordering::Release);
    }

    pub fn clear(&self) {
        for entry in self.entries.iter() {
            // Make the entry unreachable before clearing its payload.
            entry.guest.store(0, Ordering::Release);
            entry.generation.store(0, Ordering::Relaxed);
            entry.cache.store(0, Ordering::Relaxed);
        }
    }

    pub fn as_ptr(&self) -> *const IndirectTargetCacheEntry {
        self.entries.as_ptr()
    }
}

impl Default for IndirectTargetCache {
    fn default() -> Self {
        Self::new()
    }
}

#[repr(C, align(16))]
pub struct DsrContext {
    pub snapshot: NativeUcontextSnapshot,
    pub host_sp: u64,
    pub host_x19_x30: [u64; 12],
    pub generation_pstate_scratch: u64,
    pub host_v8_v15: [[u8; 16]; 8],
    pub entry: u64,
    pub exit_target: u64,
    pub exit_source: u64,
    pub exit_status: u32,
    pub exit_pad: u32,
    pub exit_link: u64,
    pub exit_has_link: u32,
    pub exit_link_pad: u32,
    pub rewrite_scratch: u64,
    pub rewrite_context_scratch: u64,
    pub indirect_cache: *const IndirectTargetCacheEntry,
    pub generation: u64,
    /// Gateway phase: 1 entering, 0 translated code, 2 leaving after capture.
    pub entry_in_progress: u32,
    pub entry_pad: u32,
    pub indirect_x15_scratch: u64,
    pub indirect_x30_scratch: u64,
    pub cache_start: u64,
    pub cache_end: u64,
    pub host_bias: u64,
    pub biased_guest_fault_address: u64,
    pub biased_fault_pad: u64,
}

impl DsrContext {
    #[allow(
        clippy::too_many_arguments,
        reason = "the C gateway context is initialized from one explicit execution record"
    )]
    pub fn new(
        snapshot: NativeUcontextSnapshot,
        entry: CacheVa,
        exit: NativeDsrExit,
        indirect_cache: *const IndirectTargetCacheEntry,
        generation: CodeGeneration,
        cache_start: usize,
        cache_end: usize,
        address_mode: carrick_dsr::address::NativeAddressMode,
    ) -> Self {
        let (exit_target, exit_source, _exit_status, exit_link, exit_has_link) = match exit {
            NativeDsrExit::Syscall { resume } => (resume.raw(), 0, 1, 0, 0),
            NativeDsrExit::ResolveDirect { source, target } => {
                (target.raw(), source.raw(), 2, 0, 0)
            }
            NativeDsrExit::ResolveIndirect {
                source,
                target,
                link,
            } => (
                target.raw(),
                source.raw(),
                3,
                link.map_or(0, carrick_guest_mem::GuestVa::raw),
                u32::from(link.is_some()),
            ),
            NativeDsrExit::Sensitive {
                guest_pc, resume, ..
            } => (resume.raw(), guest_pc.raw(), 6, 0, 0),
            NativeDsrExit::Unsupported { guest_pc, .. } => {
                (guest_pc.raw(), guest_pc.raw(), 7, 0, 0)
            }
            NativeDsrExit::Fault { guest_pc, .. } => (guest_pc.raw(), guest_pc.raw(), 4, 0, 0),
            NativeDsrExit::Kick { resume, .. } => (resume.raw(), 0, 5, 0, 0),
            _ => (0, 0, 0, 0, 0),
        };
        Self {
            rewrite_scratch: snapshot.x[16],
            rewrite_context_scratch: snapshot.x[17],
            generation_pstate_scratch: snapshot.pstate,
            snapshot,
            host_sp: 0,
            host_x19_x30: [0; 12],
            host_v8_v15: [[0; 16]; 8],
            entry: entry.host().raw() as u64,
            exit_target,
            exit_source,
            // Zero means no gateway or signal exit has been captured yet.
            // Emitted exits always publish their status before branching.
            exit_status: 0,
            exit_pad: 0,
            exit_link,
            exit_has_link,
            exit_link_pad: 0,
            indirect_cache,
            generation: generation.get(),
            entry_in_progress: 1,
            entry_pad: 0,
            indirect_x15_scratch: snapshot.x[15],
            indirect_x30_scratch: snapshot.x[30],
            cache_start: cache_start as u64,
            cache_end: cache_end as u64,
            host_bias: address_mode.bias(),
            biased_guest_fault_address: 0,
            biased_fault_pad: 0,
        }
    }
}

const _: () = assert!(std::mem::size_of::<NativeUcontextSnapshot>() == 832);
const _: () = assert!(std::mem::offset_of!(DsrContext, snapshot) == 0);
const _: () = assert!(std::mem::offset_of!(DsrContext, host_sp) == 832);
const _: () = assert!(std::mem::offset_of!(DsrContext, host_x19_x30) == 840);
const _: () = assert!(std::mem::offset_of!(DsrContext, generation_pstate_scratch) == 936);
const _: () = assert!(std::mem::offset_of!(DsrContext, host_v8_v15) == 944);
const _: () = assert!(std::mem::offset_of!(DsrContext, entry) == 1072);
const _: () = assert!(std::mem::offset_of!(DsrContext, exit_target) == 1080);
const _: () = assert!(std::mem::offset_of!(DsrContext, exit_source) == 1088);
const _: () = assert!(std::mem::offset_of!(DsrContext, exit_status) == 1096);
const _: () = assert!(std::mem::offset_of!(DsrContext, exit_link) == 1104);
const _: () = assert!(std::mem::offset_of!(DsrContext, exit_has_link) == 1112);
const _: () = assert!(std::mem::offset_of!(DsrContext, rewrite_scratch) == 1120);
const _: () = assert!(std::mem::offset_of!(DsrContext, rewrite_context_scratch) == 1128);
const _: () = assert!(std::mem::offset_of!(DsrContext, indirect_cache) == 1136);
const _: () = assert!(std::mem::offset_of!(DsrContext, generation) == 1144);
const _: () = assert!(std::mem::offset_of!(DsrContext, entry_in_progress) == 1152);
const _: () = assert!(std::mem::offset_of!(DsrContext, indirect_x15_scratch) == 1160);
const _: () = assert!(std::mem::offset_of!(DsrContext, indirect_x30_scratch) == 1168);
const _: () = assert!(std::mem::offset_of!(DsrContext, cache_start) == 1176);
const _: () = assert!(std::mem::offset_of!(DsrContext, cache_end) == 1184);
const _: () = assert!(std::mem::offset_of!(DsrContext, host_bias) == 1192);
const _: () = assert!(std::mem::offset_of!(DsrContext, biased_guest_fault_address) == 1200);
const _: () = assert!(std::mem::size_of::<DsrContext>() == 1216);
const _: () = assert!(std::mem::size_of::<IndirectTargetCacheEntry>() == 32);
const _: () = assert!(std::mem::offset_of!(IndirectTargetCacheEntry, guest) == 0);
const _: () = assert!(std::mem::offset_of!(IndirectTargetCacheEntry, generation) == 8);
const _: () = assert!(std::mem::offset_of!(IndirectTargetCacheEntry, cache) == 16);

// ---------------------------------------------------------------------------
// The assembled gateway. This module is the ONE target boundary in this
// crate: everything that references the `gateway_aarch64.S` symbols or
// enters translated execution lives here, compiled only where build.rs
// assembles the gateway.
// ---------------------------------------------------------------------------
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod native_gateway {
    use super::*;

    unsafe extern "C" {
        fn carrick_dsr_enter_raw(context: *mut DsrContext) -> libc::c_int;
        fn carrick_dsr_exit_syscall();
        fn carrick_dsr_exit_direct();
        fn carrick_dsr_exit_indirect();
        fn carrick_dsr_exit_sensitive();
        fn carrick_dsr_exit_unsupported();
        fn carrick_dsr_exit_signal();
    }

    pub fn syscall_exit_address() -> u64 {
        carrick_dsr_exit_syscall as *const () as usize as u64
    }

    pub fn direct_exit_address() -> u64 {
        carrick_dsr_exit_direct as *const () as usize as u64
    }

    pub fn indirect_exit_address() -> u64 {
        carrick_dsr_exit_indirect as *const () as usize as u64
    }

    pub fn sensitive_exit_address() -> u64 {
        carrick_dsr_exit_sensitive as *const () as usize as u64
    }

    pub fn unsupported_exit_address() -> u64 {
        carrick_dsr_exit_unsupported as *const () as usize as u64
    }

    pub fn signal_exit_address() -> u64 {
        carrick_dsr_exit_signal as *const () as usize as u64
    }

    pub fn enter_translated(
        entry: CacheVa,
        snapshot: &mut NativeUcontextSnapshot,
        exit: &mut NativeDsrExit,
    ) -> Result<(), DsrError> {
        enter_translated_raw(
            entry,
            snapshot,
            exit,
            std::ptr::null(),
            CodeGeneration::INITIAL,
            0,
            usize::MAX,
            carrick_dsr::address::NativeAddressMode::Direct,
        )
    }

    pub fn enter_translated_in_mode(
        entry: CacheVa,
        snapshot: &mut NativeUcontextSnapshot,
        exit: &mut NativeDsrExit,
        address_mode: carrick_dsr::address::NativeAddressMode,
    ) -> Result<(), DsrError> {
        enter_translated_raw(
            entry,
            snapshot,
            exit,
            std::ptr::null(),
            CodeGeneration::INITIAL,
            0,
            usize::MAX,
            address_mode,
        )
    }

    pub fn enter_translated_with_cache(
        entry: CacheVa,
        snapshot: &mut NativeUcontextSnapshot,
        exit: &mut NativeDsrExit,
        indirect_cache: &IndirectTargetCache,
    ) -> Result<(), DsrError> {
        enter_translated_raw(
            entry,
            snapshot,
            exit,
            indirect_cache.as_ptr(),
            CodeGeneration::INITIAL,
            0,
            usize::MAX,
            carrick_dsr::address::NativeAddressMode::Direct,
        )
    }

    pub fn enter_translated_with_cache_range(
        entry: CacheVa,
        snapshot: &mut NativeUcontextSnapshot,
        exit: &mut NativeDsrExit,
        indirect_cache: &IndirectTargetCache,
        cache_start: usize,
        cache_end: usize,
        address_mode: carrick_dsr::address::NativeAddressMode,
    ) -> Result<(), DsrError> {
        enter_translated_raw(
            entry,
            snapshot,
            exit,
            indirect_cache.as_ptr(),
            CodeGeneration::INITIAL,
            cache_start,
            cache_end,
            address_mode,
        )
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "raw gateway entry pins cache, generation, and address-mode authority together"
    )]
    fn enter_translated_raw(
        entry: CacheVa,
        snapshot: &mut NativeUcontextSnapshot,
        exit: &mut NativeDsrExit,
        indirect_cache: *const IndirectTargetCacheEntry,
        generation: CodeGeneration,
        cache_start: usize,
        cache_end: usize,
        address_mode: carrick_dsr::address::NativeAddressMode,
    ) -> Result<(), DsrError> {
        if !matches!(
            *exit,
            NativeDsrExit::Syscall { .. }
                | NativeDsrExit::ResolveDirect { .. }
                | NativeDsrExit::ResolveIndirect { .. }
                | NativeDsrExit::Sensitive { .. }
                | NativeDsrExit::Unsupported { .. }
                | NativeDsrExit::Fault { .. }
                | NativeDsrExit::Kick { .. }
        ) {
            return Err(DsrError::Gateway(
                "DSR gateway only accepts syscall or control-flow exits".to_string(),
            ));
        }
        let mut context = DsrContext::new(
            *snapshot,
            entry,
            *exit,
            indirect_cache,
            generation,
            cache_start,
            cache_end,
            address_mode,
        );
        let rc = unsafe { carrick_dsr_enter_raw(&mut context) };
        if !matches!(rc, 1..=8) {
            return Err(DsrError::Gateway(format!(
                "translated entry returned invalid gateway status {rc}"
            )));
        }
        *snapshot = context.snapshot;
        *exit = match rc {
            1 => NativeDsrExit::Syscall {
                resume: carrick_guest_mem::GuestVa(context.exit_target),
            },
            2 => NativeDsrExit::ResolveDirect {
                source: carrick_guest_mem::GuestVa(context.exit_source),
                target: carrick_guest_mem::GuestVa(context.exit_target),
            },
            3 => NativeDsrExit::ResolveIndirect {
                source: carrick_guest_mem::GuestVa(context.exit_source),
                target: carrick_guest_mem::GuestVa(context.exit_target),
                link: (context.exit_has_link != 0)
                    .then_some(carrick_guest_mem::GuestVa(context.exit_link)),
            },
            4 => NativeDsrExit::Fault {
                guest_pc: carrick_guest_mem::GuestVa(context.exit_target),
                signal: context.snapshot.signal,
                code: context.snapshot.signal_code,
                address: carrick_guest_mem::HostVa(
                    usize::try_from(context.snapshot.fault_address).map_err(|_| {
                        DsrError::Gateway(format!(
                            "host fault address does not fit HostVa: 0x{:x}",
                            context.snapshot.fault_address
                        ))
                    })?,
                ),
                rewrite_scratch: context.rewrite_scratch,
                rewrite_context_scratch: context.rewrite_context_scratch,
                generation_pstate_scratch: context.generation_pstate_scratch,
                indirect_x15_scratch: context.indirect_x15_scratch,
                indirect_x30_scratch: context.indirect_x30_scratch,
                physical_x18: context.exit_link,
                gateway_phase: context.exit_has_link,
                biased_guest_fault_address: context.biased_guest_fault_address,
            },
            5 => NativeDsrExit::Kick {
                resume: carrick_guest_mem::GuestVa(context.exit_target),
                rewrite_scratch: context.rewrite_scratch,
                rewrite_context_scratch: context.rewrite_context_scratch,
                generation_pstate_scratch: context.generation_pstate_scratch,
                indirect_x15_scratch: context.indirect_x15_scratch,
                indirect_x30_scratch: context.indirect_x30_scratch,
            },
            6 => NativeDsrExit::Sensitive {
                guest_pc: carrick_guest_mem::GuestVa(context.exit_source),
                resume: carrick_guest_mem::GuestVa(context.exit_target),
                generation: CodeGeneration::claimed(context.generation),
            },
            7 => NativeDsrExit::Unsupported {
                guest_pc: carrick_guest_mem::GuestVa(context.exit_source),
                word: 0,
                op: bad64::Op::UDF,
            },
            8 => NativeDsrExit::KickAtEntry {
                resume: carrick_guest_mem::GuestVa(context.exit_target),
            },
            _ => {
                return Err(DsrError::Gateway(format!(
                    "translated entry returned invalid gateway status {rc}"
                )));
            }
        };
        Ok(())
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub use native_gateway::*;

// Fail-closed complement for every other (host OS, arch) pair: entering
// translated execution reports a typed `DsrError::Gateway` (mirroring how
// csrc/native_darwin.c self-stubs with -1 off-target), and the exit-address
// constants -- pure emission data that translated code would branch to --
// degrade to 0. Emission remains exercisable off-lane (block shapes, word
// streams); nothing can execute the emitted code without the gateway, and
// every execution entry point above fails closed before reaching it.
#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
mod native_gateway {
    use super::*;

    const GATEWAY_UNAVAILABLE: &str = "native gateway is not built for this target";

    pub fn syscall_exit_address() -> u64 {
        0
    }

    pub fn direct_exit_address() -> u64 {
        0
    }

    pub fn indirect_exit_address() -> u64 {
        0
    }

    pub fn sensitive_exit_address() -> u64 {
        0
    }

    pub fn unsupported_exit_address() -> u64 {
        0
    }

    pub fn signal_exit_address() -> u64 {
        0
    }

    pub fn enter_translated(
        _entry: CacheVa,
        _snapshot: &mut NativeUcontextSnapshot,
        _exit: &mut NativeDsrExit,
    ) -> Result<(), DsrError> {
        Err(DsrError::Gateway(GATEWAY_UNAVAILABLE.to_string()))
    }

    pub fn enter_translated_in_mode(
        _entry: CacheVa,
        _snapshot: &mut NativeUcontextSnapshot,
        _exit: &mut NativeDsrExit,
        _address_mode: carrick_dsr::address::NativeAddressMode,
    ) -> Result<(), DsrError> {
        Err(DsrError::Gateway(GATEWAY_UNAVAILABLE.to_string()))
    }

    pub fn enter_translated_with_cache(
        _entry: CacheVa,
        _snapshot: &mut NativeUcontextSnapshot,
        _exit: &mut NativeDsrExit,
        _indirect_cache: &IndirectTargetCache,
    ) -> Result<(), DsrError> {
        Err(DsrError::Gateway(GATEWAY_UNAVAILABLE.to_string()))
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "matches the live gateway entry signature"
    )]
    pub fn enter_translated_with_cache_range(
        _entry: CacheVa,
        _snapshot: &mut NativeUcontextSnapshot,
        _exit: &mut NativeDsrExit,
        _indirect_cache: &IndirectTargetCache,
        _cache_start: usize,
        _cache_end: usize,
        _address_mode: carrick_dsr::address::NativeAddressMode,
    ) -> Result<(), DsrError> {
        Err(DsrError::Gateway(GATEWAY_UNAVAILABLE.to_string()))
    }
}

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
pub use native_gateway::*;

#[cfg(test)]
mod indirect_cache_tests {
    use super::*;

    #[test]
    fn indirect_cache_uses_approved_256kib_layout() {
        assert_eq!(INDIRECT_CACHE_ENTRIES, 8192);
        assert_eq!(std::mem::size_of::<IndirectTargetCacheEntry>(), 32);
        assert_eq!(
            INDIRECT_CACHE_ENTRIES * std::mem::size_of::<IndirectTargetCacheEntry>(),
            256 * 1024,
        );
    }

    #[test]
    fn mixed_index_separates_old_page_offset_aliases() {
        let first = carrick_guest_mem::GuestVa(0x42_000);
        let second = carrick_guest_mem::GuestVa(0x48_000);
        assert_ne!(indirect_cache_index(first), indirect_cache_index(second));
    }

    #[test]
    fn dsr_context_appends_host_bias_without_shifting_gateway_fields() {
        assert_eq!(std::mem::offset_of!(DsrContext, cache_end), 1184);
        assert_eq!(std::mem::offset_of!(DsrContext, host_bias), 1192);
        assert_eq!(
            std::mem::offset_of!(DsrContext, biased_guest_fault_address),
            1200
        );
        assert_eq!(std::mem::size_of::<DsrContext>(), 1216);
    }
}
