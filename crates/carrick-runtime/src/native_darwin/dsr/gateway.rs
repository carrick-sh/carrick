#![allow(dead_code)] // Additional typed exits consume the same context in later tasks.

use super::super::NativeUcontextSnapshot;
use super::types::{CacheVa, CodeGeneration, DsrError, NativeDsrExit};

use std::sync::atomic::{AtomicU64, Ordering};

pub(super) const INDIRECT_CACHE_ENTRIES: usize = 8192;
pub(super) const INDIRECT_CACHE_MASK: u64 = (INDIRECT_CACHE_ENTRIES - 1) as u64;
pub(super) const INDIRECT_CACHE_INDEX_BITS: u32 = 13;
pub(super) const INDIRECT_CACHE_ENTRY_SHIFT: u32 = 5;
pub(super) const CTX_INDIRECT_CACHE: u32 = 1136;
pub(super) const CTX_GENERATION: u32 = 1144;

#[repr(C, align(32))]
struct IndirectTargetCacheEntry {
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

pub(super) struct IndirectTargetCache {
    entries: Box<[IndirectTargetCacheEntry; INDIRECT_CACHE_ENTRIES]>,
}

impl IndirectTargetCache {
    pub(super) fn new() -> Self {
        Self {
            entries: Box::new(std::array::from_fn(|_| IndirectTargetCacheEntry {
                guest: AtomicU64::new(0),
                generation: AtomicU64::new(0),
                cache: AtomicU64::new(0),
                pad: 0,
            })),
        }
    }

    pub(super) fn publish(
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

    pub(super) fn clear(&self) {
        for entry in self.entries.iter() {
            // Make the entry unreachable before clearing its payload.
            entry.guest.store(0, Ordering::Release);
            entry.generation.store(0, Ordering::Relaxed);
            entry.cache.store(0, Ordering::Relaxed);
        }
    }

    fn as_ptr(&self) -> *const IndirectTargetCacheEntry {
        self.entries.as_ptr()
    }
}

impl Default for IndirectTargetCache {
    fn default() -> Self {
        Self::new()
    }
}

#[repr(C, align(16))]
struct DsrContext {
    snapshot: NativeUcontextSnapshot,
    host_sp: u64,
    host_x19_x30: [u64; 12],
    generation_pstate_scratch: u64,
    host_v8_v15: [[u8; 16]; 8],
    entry: u64,
    exit_target: u64,
    exit_source: u64,
    exit_status: u32,
    exit_pad: u32,
    exit_link: u64,
    exit_has_link: u32,
    exit_link_pad: u32,
    rewrite_scratch: u64,
    rewrite_context_scratch: u64,
    indirect_cache: *const IndirectTargetCacheEntry,
    generation: u64,
    /// Gateway phase: 1 entering, 0 translated code, 2 leaving after capture.
    entry_in_progress: u32,
    entry_pad: u32,
    indirect_x15_scratch: u64,
    indirect_x30_scratch: u64,
    cache_start: u64,
    cache_end: u64,
    host_bias: u64,
}

impl DsrContext {
    #[allow(
        clippy::too_many_arguments,
        reason = "the C gateway context is initialized from one explicit execution record"
    )]
    fn new(
        snapshot: NativeUcontextSnapshot,
        entry: CacheVa,
        exit: NativeDsrExit,
        indirect_cache: *const IndirectTargetCacheEntry,
        generation: CodeGeneration,
        cache_start: usize,
        cache_end: usize,
        address_mode: super::super::address::NativeAddressMode,
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
const _: () = assert!(std::mem::size_of::<DsrContext>() == 1200);
const _: () = assert!(std::mem::size_of::<IndirectTargetCacheEntry>() == 32);
const _: () = assert!(std::mem::offset_of!(IndirectTargetCacheEntry, guest) == 0);
const _: () = assert!(std::mem::offset_of!(IndirectTargetCacheEntry, generation) == 8);
const _: () = assert!(std::mem::offset_of!(IndirectTargetCacheEntry, cache) == 16);

unsafe extern "C" {
    fn carrick_dsr_enter_raw(context: *mut DsrContext) -> libc::c_int;
    fn carrick_dsr_exit_syscall();
    fn carrick_dsr_exit_direct();
    fn carrick_dsr_exit_indirect();
    fn carrick_dsr_exit_sensitive();
    fn carrick_dsr_exit_unsupported();
    fn carrick_dsr_exit_signal();
}

pub(super) fn syscall_exit_address() -> u64 {
    carrick_dsr_exit_syscall as *const () as usize as u64
}

pub(super) fn direct_exit_address() -> u64 {
    carrick_dsr_exit_direct as *const () as usize as u64
}

pub(super) fn indirect_exit_address() -> u64 {
    carrick_dsr_exit_indirect as *const () as usize as u64
}

pub(super) fn sensitive_exit_address() -> u64 {
    carrick_dsr_exit_sensitive as *const () as usize as u64
}

pub(super) fn unsupported_exit_address() -> u64 {
    carrick_dsr_exit_unsupported as *const () as usize as u64
}

pub(super) fn signal_exit_address() -> u64 {
    carrick_dsr_exit_signal as *const () as usize as u64
}

pub(super) fn enter_translated(
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
        super::super::address::NativeAddressMode::Direct,
    )
}

pub(super) fn enter_translated_in_mode(
    entry: CacheVa,
    snapshot: &mut NativeUcontextSnapshot,
    exit: &mut NativeDsrExit,
    address_mode: super::super::address::NativeAddressMode,
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

pub(super) fn enter_translated_with_cache(
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
        super::super::address::NativeAddressMode::Direct,
    )
}

pub(super) fn enter_translated_with_cache_range(
    entry: CacheVa,
    snapshot: &mut NativeUcontextSnapshot,
    exit: &mut NativeDsrExit,
    indirect_cache: &IndirectTargetCache,
    cache_start: usize,
    cache_end: usize,
    address_mode: super::super::address::NativeAddressMode,
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
        assert_eq!(std::mem::size_of::<DsrContext>(), 1200);
    }
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
    address_mode: super::super::address::NativeAddressMode,
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

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq)]
struct GatewayComponentSummary {
    p50_us: f64,
    p95_us: f64,
    min_us: f64,
}

#[cfg(test)]
fn summarize_component_ticks(
    mut samples: Vec<u64>,
    counter_frequency: u64,
    batch: usize,
) -> GatewayComponentSummary {
    assert!(counter_frequency > 0, "counter frequency must be nonzero");
    assert!(batch > 0, "batch size must be nonzero");
    assert!(!samples.is_empty(), "component samples must be nonempty");
    samples.sort_unstable();
    let denominator = counter_frequency as f64 * batch as f64;
    let ticks_to_us = |ticks: u64| ticks as f64 * 1_000_000.0 / denominator;
    let percentile = |fraction: f64| {
        let index = (((samples.len() as f64) * fraction).ceil() as usize)
            .saturating_sub(1)
            .min(samples.len() - 1);
        ticks_to_us(samples[index])
    };
    GatewayComponentSummary {
        p50_us: percentile(0.50),
        p95_us: percentile(0.95),
        min_us: ticks_to_us(samples[0]),
    }
}

#[cfg(test)]
fn format_component_summary(name: &str, summary: GatewayComponentSummary) -> String {
    format!(
        "{name}_p50_us={:.3}\n{name}_p95_us={:.3}\n{name}_min_us={:.3}",
        summary.p50_us, summary.p95_us, summary.min_us
    )
}

#[cfg(all(test, target_arch = "aarch64"))]
#[inline(always)]
fn component_read_counter() -> u64 {
    let value: u64;
    unsafe {
        core::arch::asm!(
            "mrs {value}, cntvct_el0",
            value = out(reg) value,
            options(nomem, nostack, preserves_flags)
        );
    }
    value
}

#[cfg(all(test, target_arch = "aarch64"))]
fn component_counter_frequency() -> u64 {
    let value: u64;
    unsafe {
        core::arch::asm!(
            "mrs {value}, cntfrq_el0",
            value = out(reg) value,
            options(nomem, nostack, preserves_flags)
        );
    }
    value
}

#[cfg(all(test, target_arch = "aarch64"))]
fn measure_component(mut operation: impl FnMut()) -> GatewayComponentSummary {
    const ITERS: usize = 20_000;
    const WARMUP: usize = 2_000;
    const BATCH: usize = 16;

    for _ in 0..WARMUP {
        operation();
    }
    let mut samples = Vec::with_capacity(ITERS);
    for _ in 0..ITERS {
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
        let started = component_read_counter();
        for _ in 0..BATCH {
            operation();
        }
        let elapsed = component_read_counter().wrapping_sub(started);
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
        samples.push(elapsed);
    }
    summarize_component_ticks(samples, component_counter_frequency(), BATCH)
}

#[cfg(all(test, target_arch = "aarch64"))]
fn measure_gateway_components() -> (GatewayComponentSummary, GatewayComponentSummary) {
    let result = std::thread::spawn(|| {
        let mut kick: libc::sigset_t = unsafe { std::mem::zeroed() };
        let mut original: libc::sigset_t = unsafe { std::mem::zeroed() };
        unsafe {
            libc::sigemptyset(&mut kick);
            libc::sigaddset(&mut kick, libc::SIGPIPE);
        }
        assert_eq!(
            unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &kick, &mut original) },
            0
        );

        let mut snapshot = NativeUcontextSnapshot::default();
        for (index, register) in snapshot.x.iter_mut().enumerate() {
            *register = 0x1100_0000_0000_0000 | index as u64;
        }
        for (index, vector) in snapshot.v.iter_mut().enumerate() {
            *vector =
                (0x2200_0000_0000_0000_0000_0000_0000_0000_u128 | index as u128).to_le_bytes();
        }
        let entry = CacheVa::published(carrick_guest_mem::HostVa(1));
        let exit = NativeDsrExit::Syscall {
            resume: carrick_guest_mem::GuestVa(4),
        };

        let measure_closure = || {
            measure_component(|| {
                let guest = unsafe {
                    super::super::carrick_native_dsr_enter_guest_abi(std::ptr::null_mut())
                };
                std::hint::black_box(guest);
                unsafe { super::super::carrick_native_dsr_enter_host_abi() };
            })
        };
        let measure_wrapper = || {
            measure_component(|| {
                let context = DsrContext::new(
                    std::hint::black_box(snapshot),
                    entry,
                    exit,
                    std::ptr::null(),
                    CodeGeneration::INITIAL,
                    0,
                    usize::MAX,
                    super::super::address::NativeAddressMode::Direct,
                );
                let published = std::hint::black_box(context).snapshot;
                std::hint::black_box(published);
            })
        };

        let (closure, wrapper) = if unsafe { libc::getpid() } & 1 == 0 {
            (measure_closure(), measure_wrapper())
        } else {
            let wrapper = measure_wrapper();
            (measure_closure(), wrapper)
        };

        let mut current: libc::sigset_t = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, std::ptr::null(), &mut current) },
            0
        );
        assert_eq!(unsafe { libc::sigismember(&current, libc::SIGPIPE) }, 1);
        assert_eq!(
            unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &original, std::ptr::null_mut()) },
            0
        );
        (closure, wrapper)
    })
    .join();
    match result {
        Ok(summaries) => summaries,
        Err(payload) => std::panic::resume_unwind(payload),
    }
}

#[cfg(all(test, target_arch = "aarch64"))]
fn measure_closure_subcomponents() -> (
    GatewayComponentSummary,
    GatewayComponentSummary,
    GatewayComponentSummary,
) {
    let result = std::thread::spawn(|| {
        let mut kick: libc::sigset_t = unsafe { std::mem::zeroed() };
        let mut original: libc::sigset_t = unsafe { std::mem::zeroed() };
        unsafe {
            libc::sigemptyset(&mut kick);
            libc::sigaddset(&mut kick, libc::SIGPIPE);
        }
        assert_eq!(
            unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &kick, &mut original) },
            0
        );

        assert_eq!(
            unsafe { super::super::carrick_native_dsr_benchmark_custom_x18_pair() },
            0
        );
        let measure_signal_mask = || {
            measure_component(|| {
                let result =
                    unsafe { super::super::carrick_native_dsr_benchmark_signal_mask_pair() };
                std::hint::black_box(result);
            })
        };
        let measure_custom_x18 = || {
            measure_component(|| {
                let result =
                    unsafe { super::super::carrick_native_dsr_benchmark_custom_x18_pair() };
                std::hint::black_box(result);
            })
        };
        let measure_signal_mask_prebuilt = || {
            measure_component(|| {
                let unblock = unsafe {
                    libc::pthread_sigmask(libc::SIG_UNBLOCK, &kick, std::ptr::null_mut())
                };
                let block =
                    unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &kick, std::ptr::null_mut()) };
                std::hint::black_box((unblock, block));
            })
        };
        let (signal_mask, signal_mask_prebuilt, custom_x18) = if unsafe { libc::getpid() } & 1 == 0
        {
            (
                measure_signal_mask(),
                measure_signal_mask_prebuilt(),
                measure_custom_x18(),
            )
        } else {
            let custom_x18 = measure_custom_x18();
            (
                measure_signal_mask(),
                measure_signal_mask_prebuilt(),
                custom_x18,
            )
        };

        let mut current: libc::sigset_t = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, std::ptr::null(), &mut current) },
            0
        );
        assert_eq!(unsafe { libc::sigismember(&current, libc::SIGPIPE) }, 1);
        assert_eq!(
            unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &original, std::ptr::null_mut()) },
            0
        );
        (signal_mask, signal_mask_prebuilt, custom_x18)
    })
    .join();
    match result {
        Ok(summaries) => summaries,
        Err(payload) => std::panic::resume_unwind(payload),
    }
}

#[cfg(all(test, not(target_arch = "aarch64")))]
fn measure_closure_subcomponents() -> (
    GatewayComponentSummary,
    GatewayComponentSummary,
    GatewayComponentSummary,
) {
    panic!("native DSR closure component benchmark requires AArch64")
}

#[cfg(all(test, not(target_arch = "aarch64")))]
fn measure_gateway_components() -> (GatewayComponentSummary, GatewayComponentSummary) {
    panic!("native DSR gateway component benchmark requires AArch64")
}

#[cfg(test)]
mod component_benchmark_tests {
    use super::*;

    #[test]
    fn component_summary_reports_per_operation_latency() {
        let summary = summarize_component_ticks(vec![160_u64; 10], 1_000_000, 16);
        assert_eq!(summary.p50_us, 10.0);
        assert_eq!(summary.p95_us, 10.0);
        assert_eq!(summary.min_us, 10.0);
    }

    #[test]
    fn component_output_has_stable_machine_keys() {
        let summary = GatewayComponentSummary {
            p50_us: 0.101,
            p95_us: 0.202,
            min_us: 0.050,
        };
        let output = format_component_summary("closure", summary);
        assert_eq!(
            output,
            "closure_p50_us=0.101\nclosure_p95_us=0.202\nclosure_min_us=0.050"
        );
    }

    #[test]
    #[ignore = "explicit opt-in native DSR component microbenchmark"]
    fn dsr_gateway_component_benchmark() {
        let (closure, wrapper) = measure_gateway_components();
        for summary in [closure, wrapper] {
            assert!(summary.p50_us.is_finite() && summary.p50_us > 0.0);
            assert!(summary.p95_us.is_finite() && summary.p95_us > 0.0);
            assert!(summary.min_us.is_finite() && summary.min_us > 0.0);
        }
        println!("{}", format_component_summary("closure", closure));
        println!("{}", format_component_summary("wrapper", wrapper));
        println!("component_iters=20000");
        println!("component_batch=16");
    }

    #[test]
    #[ignore = "explicit opt-in native DSR closure decomposition"]
    fn dsr_gateway_closure_component_benchmark() {
        let (signal_mask, signal_mask_prebuilt, custom_x18) = measure_closure_subcomponents();
        for summary in [signal_mask, signal_mask_prebuilt, custom_x18] {
            assert!(summary.p50_us.is_finite() && summary.p50_us > 0.0);
            assert!(summary.p95_us.is_finite() && summary.p95_us > 0.0);
            assert!(summary.min_us.is_finite() && summary.min_us > 0.0);
        }
        println!(
            "{}",
            format_component_summary("closure_signal_mask", signal_mask)
        );
        println!(
            "{}",
            format_component_summary("closure_signal_mask_prebuilt", signal_mask_prebuilt)
        );
        println!(
            "{}",
            format_component_summary("closure_custom_x18", custom_x18)
        );
        println!("component_iters=20000");
        println!("component_batch=16");
    }
}
