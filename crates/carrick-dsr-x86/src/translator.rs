//! x86 DSR translate/cache/chain engine: the guest-VA block index
//! (`CachedBlock`/`VaHasher`), the chain-edge bookkeeping (`PendingChainEdge`/
//! `GuardedChainPatch`), the fault-recovery index entry
//! (`PublishedFaultEntry`), the target-first chain-edge patch protocol
//! (`patch_slot`/`publish_guarded_chain_edge`), and the padded JIT-bytes
//! publish helper (`publish_x86_translated_bytes`).
//!
//! Moved verbatim from `run_x86_thread` in
//! `carrick-runtime/src/native_freebsd.rs` (Phase 3 Task 2 of
//! `docs/superpowers/plans/2026-07-23-native-lane-seam-phase3.md`, the
//! REDIRECTED scope — see
//! `docs/superpowers/specs/2026-07-24-loop-merge-precision-map.md` for why:
//! aarch64's translate/cache/JIT orchestration already lived in a shared
//! crate, `carrick_dsr_aarch64::translator`; x86's equivalent was still
//! inline in the runtime crate).
//!
//! Deliberately NOT here (stays in `native_freebsd.rs`'s `run_x86_thread`
//! loop, per that task's explicit boundary): the xstate residency policy
//! (`NativeX86XstatePolicy`) and its edge-barrier decisions, xstate tracing
//! (`native_x86_trace_xstate`), the block-plan/emit call sites themselves
//! (already delegate to `carrick_dsr_x86::block`/`emit`, unchanged by this
//! move), `SharedRun`/`ExecutableEpoch` admission, and fault/signal
//! delivery. The per-thread `cache`/`cflow_plans`/`pending`/`fault_entries`
//! collections also stay loop-owned local state — only the VALUE TYPES they
//! hold move here; the collections remain per-thread-private (no `Arc`, no
//! lock), architecturally unlike aarch64's shared `ProcessState::blocks`
//! behind a process-wide `RwLock` (see Phase-2 Task-3's KEEP-LANE cache
//! boundary, `docs/native-lane-seam-phase2-evidence.md` §4). Unifying that
//! would be a cross-ISA cache merge, which is explicitly out of scope here.
//!
//! One seam change (the only one this move makes): [`patch_slot`] and
//! [`publish_guarded_chain_edge`] took a concrete `&FreebsdHostJit` in
//! `native_freebsd.rs`; here they take `&dyn NativeHostJit`, the SAME trait
//! `carrick_dsr::host` already defines and `FreebsdHostJit` already
//! implements — a thin re-front over existing capability, not a new one.
//! The `native_freebsd.rs` call sites are unchanged (`&jit` unsize-coerces
//! to `&dyn NativeHostJit` automatically).

use carrick_dsr::cache::{CacheError, TranslationCache};
use carrick_dsr::host::{JitRegion, NativeHostJit};
use carrick_guest_mem::GuestVa;

use crate::emit::ScratchRestore;

/// A minimal multiply-based hasher for the guest-VA block cache. The default
/// `HashMap` uses SipHash (DoS-resistant but slow), and an lldb backtrace of a
/// hot guest loop showed SipHash dominating — the cache is looked up once per
/// block per iteration, millions of times. The keys are our OWN guest VAs (no
/// adversarial input), so a single FxHash-style multiply is both correct and
/// far cheaper. Only `write_u64` is exercised (u64 keys); other inputs fold in
/// byte-wise so the impl is still a valid `Hasher`.
#[derive(Default)]
pub struct VaHasher(u64);

impl std::hash::Hasher for VaHasher {
    fn finish(&self) -> u64 {
        self.0
    }
    fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.write_u64(u64::from(b));
        }
    }
    fn write_u64(&mut self, value: u64) {
        // FxHash's rotate-xor-multiply step (rustc's `rustc-hash`).
        const K: u64 = 0x51_7c_c1_b7_27_22_0a_95;
        self.0 = (self.0.rotate_left(5) ^ value).wrapping_mul(K);
    }
}

pub type VaBuildHasher = std::hash::BuildHasherDefault<VaHasher>;

/// Reserve, write, and publish `bytes` into the calling thread's private JIT
/// slice through the shared bump-allocator
/// (`carrick_dsr::cache::TranslationCache`, adopted here per the Phase-2
/// cache-adoption precision map: the block index and the chain-edge patch
/// protocol below stay lane-local, but the raw byte-cache allocation now
/// routes through the same typed capacity/publish machinery the aarch64 lane
/// uses). `TranslationCache::begin_write`/`CacheWriter::write_words` are
/// ISA-neutral in principle but were authored against aarch64's fixed 4-byte
/// instructions -- `begin_write` rejects any length that is not a `u32`
/// multiple. x86 translated blocks are an arbitrary byte length, so pad up
/// to the next `u32` boundary with `0xCC` (`int3`) filler before handing the
/// bytes over. The filler is never reached: every emitted block ends in an
/// unconditional jump (to its chain guard, cold stub, or a gateway-exit
/// trampoline), so control flow never falls through into the padding.
/// Reassembling the padded buffer into `u32` words via `from_ne_bytes`
/// (rather than a pointer cast) keeps this alignment-safe regardless of the
/// `Vec<u8>` allocator's actual alignment.
pub fn publish_x86_translated_bytes(
    cache: &mut TranslationCache,
    bytes: &[u8],
) -> Result<carrick_dsr::cache::PublishedCode, CacheError> {
    let padded_len = bytes
        .len()
        .checked_add(3)
        .map(|rounded| rounded & !3)
        .ok_or_else(|| CacheError::Policy("translated block length overflow".to_string()))?;
    let mut padded = Vec::with_capacity(padded_len);
    padded.extend_from_slice(bytes);
    padded.resize(padded_len, 0xCC);
    let words: Vec<u32> = padded
        .chunks_exact(4)
        .map(|word| u32::from_ne_bytes([word[0], word[1], word[2], word[3]]))
        .collect();
    let mut writer = cache.begin_write(padded_len)?;
    writer.write_words(&words)?;
    writer.publish()
}

/// Patch a chainable branch's 5-byte `jmp` slot to jump straight to a
/// translated successor block. `patch_abs` is the exec-alias address of the
/// slot's 4-byte `rel32` field; `next_abs` is the address just after it (the
/// jmp's own next-instruction address the rel32 is relative to); `target_exec`
/// is the successor's exec VA. Both endpoints live in the <4 MiB JIT cache, so
/// the displacement always fits `i32`. The write goes through the region's RW
/// alias (the exec alias is not writable).
pub fn patch_slot(
    region: &JitRegion,
    jit: &dyn NativeHostJit,
    patch_abs: u64,
    next_abs: u64,
    target_exec: u64,
) -> bool {
    let rel = (target_exec as i64 - next_abs as i64) as i32;
    let Some(w) = region.write_ptr_for(patch_abs as *mut u8) else {
        return false;
    };
    // SAFETY: `w` is the RW alias of the 4-byte rel32 field inside the JIT.
    unsafe { std::ptr::copy_nonoverlapping(rel.to_le_bytes().as_ptr(), w, 4) };
    jit.flush_icache(patch_abs as *mut u8, 4);
    true
}

#[derive(Clone, Copy, Debug)]
pub struct GuardedChainPatch {
    pub entry_patch_abs: u64,
    pub entry_next_abs: u64,
    pub guard_exec: u64,
    pub guard_target_patch_abs: u64,
    pub guard_target_next_abs: u64,
}

/// Publish one hot direct edge target-first. Until the final entry displacement
/// is written, the original branch still reaches its cold Rust-exit stub. Once
/// the entry points at the guard, its separately-published target is complete.
pub fn publish_guarded_chain_edge(
    region: &JitRegion,
    jit: &dyn NativeHostJit,
    patch: GuardedChainPatch,
    target_exec: u64,
) {
    if !patch_slot(
        region,
        jit,
        patch.guard_target_patch_abs,
        patch.guard_target_next_abs,
        target_exec,
    ) {
        return;
    }
    std::sync::atomic::fence(std::sync::atomic::Ordering::Release);
    let _ = patch_slot(
        region,
        jit,
        patch.entry_patch_abs,
        patch.entry_next_abs,
        patch.guard_exec,
    );
}

/// One published block's fault-recovery metadata: the host `[host_start,
/// host_end)` interval of an emitted instruction that can fault, the guest VA
/// to resume translation at, and (for the copied-x87 case) which host GPRs
/// to restore from the fault shim's scratch slots before resuming. Fields
/// are `pub`: `native_freebsd.rs`'s run loop constructs and reads these
/// directly as loop-owned `Vec<PublishedFaultEntry>` state — no
/// encapsulation boundary crosses the move.
#[derive(Clone, Debug)]
pub struct PublishedFaultEntry {
    pub host_start: u64,
    pub host_end: u64,
    pub guest_va: u64,
    pub is_copied_x87: bool,
    pub restores: Vec<ScratchRestore>,
}

/// One generation-scoped translated block and the complete guest instruction
/// span that produced it. The span is reclassified atomically on every reuse so
/// an RX prefix with mutable W+X or shared backing can never reuse or receive a
/// stale edge.
#[derive(Clone, Copy, Debug)]
pub struct CachedBlock {
    pub exec: u64,
    pub has_edges: bool,
    pub uses_fpu: bool,
    pub has_indirect_cache: bool,
    pub guest_len: usize,
}

/// A chain edge whose target guest VA has not been translated yet. The run
/// loop indexes these by `target_va` (`HashMap<u64, Vec<PendingChainEdge>,
/// VaBuildHasher>`) and drains/publishes them via
/// [`publish_guarded_chain_edge`] once that VA is finally cached.
#[derive(Clone, Copy, Debug)]
pub struct PendingChainEdge {
    pub entry_patch_abs: u64,
    pub entry_next_abs: u64,
    pub guard_exec: u64,
    pub guard_target_patch_abs: u64,
    pub guard_target_next_abs: u64,
    pub source: GuestVa,
    pub source_uses_fpu: bool,
    pub source_requires_guest_pkru: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr::NonNull;

    /// A `NativeHostJit` that does nothing: these tests only prove
    /// `patch_slot`/`publish_guarded_chain_edge`'s pointer arithmetic and
    /// target-first ordering, never real code execution or icache
    /// coherence.
    struct NoopHostJit;

    impl NativeHostJit for NoopHostJit {
        fn supported(&self) -> Result<(), &'static str> {
            Ok(())
        }
        fn map_code_cache(&self, _capacity: usize) -> std::io::Result<JitRegion> {
            Err(std::io::Error::other(
                "not exercised by these pointer-arithmetic tests",
            ))
        }
        unsafe fn unmap(&self, _region: &JitRegion) {}
        fn begin_thread_write(&self) {}
        fn end_thread_write(&self) {}
        fn flush_icache(&self, _exec_ptr: *const u8, _len: usize) {}
        fn remap_for_fork_child(
            &self,
            _prior: &JitRegion,
        ) -> std::io::Result<carrick_dsr::host::ForkChildJit> {
            Ok(carrick_dsr::host::ForkChildJit::Inherited)
        }
    }

    static NOOP_HOST_JIT: NoopHostJit = NoopHostJit;

    /// A same-address exec/write region (like Darwin's collapsed dual
    /// alias) backed by a real heap buffer, purely so `patch_slot`'s
    /// `copy_nonoverlapping` has real, valid memory to write into. Never
    /// executed as code.
    fn buffer_region(buf: &mut [u8]) -> JitRegion {
        let base = NonNull::new(buf.as_mut_ptr()).expect("nonzero base");
        JitRegion {
            exec_base: base,
            write_base: base,
            capacity: buf.len(),
        }
    }

    #[test]
    fn va_build_hasher_is_deterministic_and_usable_in_a_hashmap() {
        let mut a = VaHasher::default();
        let mut b = VaHasher::default();
        std::hash::Hasher::write_u64(&mut a, 0xDEAD_BEEF_u64);
        std::hash::Hasher::write_u64(&mut b, 0xDEAD_BEEF_u64);
        assert_eq!(std::hash::Hasher::finish(&a), std::hash::Hasher::finish(&b));

        let mut cache: std::collections::HashMap<u64, CachedBlock, VaBuildHasher> =
            std::collections::HashMap::default();
        cache.insert(
            0x4000,
            CachedBlock {
                exec: 0x8000,
                has_edges: false,
                uses_fpu: false,
                has_indirect_cache: false,
                guest_len: 4,
            },
        );
        assert_eq!(cache.get(&0x4000).map(|b| b.exec), Some(0x8000));
        assert!(!cache.contains_key(&0x4001));
    }

    #[test]
    fn patch_slot_writes_the_rel32_displacement_relative_to_next_abs() {
        let mut buf = vec![0u8; 64];
        let region = buffer_region(&mut buf);
        let base = region.exec_base.as_ptr() as u64;
        // A 4-byte rel32 slot at offset 16; the jmp's "next instruction"
        // address (what the displacement is relative to) is offset 20.
        let patch_abs = base + 16;
        let next_abs = base + 20;
        let target_exec = base + 40;

        assert!(patch_slot(
            &region,
            &NOOP_HOST_JIT,
            patch_abs,
            next_abs,
            target_exec
        ));
        let written = i32::from_le_bytes(buf[16..20].try_into().unwrap());
        assert_eq!(written, 20); // (base+40) - (base+20)
    }

    #[test]
    fn patch_slot_rejects_a_patch_address_outside_the_region() {
        let mut buf = vec![0u8; 16];
        let region = buffer_region(&mut buf);
        let outside = region.exec_base.as_ptr() as u64 + 1000;
        assert!(!patch_slot(
            &region,
            &NOOP_HOST_JIT,
            outside,
            outside + 4,
            0
        ));
    }

    #[test]
    fn publish_guarded_chain_edge_is_target_first() {
        let mut buf = vec![0u8; 64];
        let region = buffer_region(&mut buf);
        let base = region.exec_base.as_ptr() as u64;
        let patch = GuardedChainPatch {
            entry_patch_abs: base,
            entry_next_abs: base + 4,
            guard_exec: base + 32,
            guard_target_patch_abs: base + 8,
            guard_target_next_abs: base + 12,
        };
        let target_exec = base + 48;

        publish_guarded_chain_edge(&region, &NOOP_HOST_JIT, patch, target_exec);

        let guard_target_rel = i32::from_le_bytes(buf[8..12].try_into().unwrap());
        assert_eq!(
            guard_target_rel,
            (target_exec - patch.guard_target_next_abs) as i32
        );
        let entry_rel = i32::from_le_bytes(buf[0..4].try_into().unwrap());
        assert_eq!(entry_rel, (patch.guard_exec - patch.entry_next_abs) as i32);
    }

    #[test]
    fn publish_guarded_chain_edge_never_touches_entry_when_guard_target_patch_fails() {
        let mut buf = vec![0xAAu8; 16];
        let region = buffer_region(&mut buf);
        let base = region.exec_base.as_ptr() as u64;
        let patch = GuardedChainPatch {
            entry_patch_abs: base,
            entry_next_abs: base + 4,
            guard_exec: base + 8,
            // Deliberately outside the 16-byte region: the target-first
            // write fails, so the entry slot must be left untouched.
            guard_target_patch_abs: base + 1000,
            guard_target_next_abs: base + 1004,
        };

        publish_guarded_chain_edge(&region, &NOOP_HOST_JIT, patch, base + 64);

        assert_eq!(&buf[0..4], &[0xAA, 0xAA, 0xAA, 0xAA]);
    }
}
