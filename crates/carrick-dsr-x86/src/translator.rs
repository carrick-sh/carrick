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
use carrick_dsr::identity_memory::IdentityCheckedReadError;
use carrick_guest_mem::GuestVa;
use carrick_guest_mem::protections::MemoryProtections;

use crate::block::{X86BlockPlanError, X86Exit, plan_block_with_reader};
use crate::emit::{ChainEdge, ScratchRestore, emit_block_linked};

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

/// The bounded outcome of [`X86ThreadTranslator::translate`]. x86's
/// fetch/translate fault path is RETRYABLE (`SynchronousFaultDelivery::RetryAt`
/// / `Fatal`), unlike aarch64's hard abort, so the engine returns this outcome
/// instead of aborting inside a `translate` that owns the loop's control flow.
/// The run loop matches it at the SINGLE translate call site and, on the fault
/// arm, still calls the loop-resident `deliver_x86_instruction_fetch_error`
/// itself — that helper plus the xstate/edge-registration and gateway
/// admission/entry machinery deliberately stay in the loop (they are
/// xstate-entangled). This return enum, consumed at one call site, is the sized
/// shape for that seam; no callback trait is introduced.
pub enum X86TranslateOutcome {
    /// The block was translated (or recycled-then-translated) and its cache /
    /// cflow-plan / return-cache / fault-index entries are published. The loop
    /// then runs the still-resident xstate edge registration for this block.
    Translated(X86TranslatedBlock),
    /// A guest instruction fetch or executable read faulted. The loop delivers
    /// the synchronous signal via
    /// `deliver_x86_instruction_fetch_error(report_va, error)` and retries or
    /// terminates exactly as before. `report_va` is the failing VA the planner
    /// surfaced (a `plan_block_with_reader` read miss) or the block entry VA (a
    /// whole-block executable read miss), matching the two pre-extraction call
    /// sites.
    InstructionFetchFault {
        report_va: u64,
        error: IdentityCheckedReadError,
    },
    /// An unrecoverable translation error. The loop records it as `fault_detail`
    /// and breaks, byte-for-byte as the pre-extraction `break` arms did.
    Fatal(String),
}

/// The published block plus the loop-owned decisions the still-resident xstate
/// edge-registration logic consumes. `edges` is this block's outgoing chain
/// edges, moved out of the (now consumed) `LinkedBlock`; the run loop iterates
/// them under `xstate_policy`. The three `ephemeral_*` fields carry exactly the
/// loop-locals the pre-extraction translate-miss branch used to set inline
/// (`ephemeral_return_adjust`, `ephemeral_cflow_plan`,
/// `current_ephemeral_fault_range`), so the loop's later resolve/normalization
/// paths are unchanged.
pub struct X86TranslatedBlock {
    pub entry: CachedBlock,
    pub edges: Vec<ChainEdge>,
    pub source_translation_ephemeral: bool,
    pub ephemeral_return_adjust: Option<u64>,
    pub ephemeral_cflow_plan: Option<(u64, crate::cflow::ControlFlowPlan)>,
    pub current_ephemeral_fault_range: Option<(u64, u64)>,
}

/// One guest OS thread's private DSR translate/cache/chain engine: the owned
/// translation state the run loop used to hold as loop-locals — the
/// guest-VA block index (`cache`), the predecoded indirect-exit plans
/// (`cflow_plans`), the monomorphic return-site table (`indirect_cache_entries`),
/// the not-yet-resolved chain edges (`pending`), the published fault-recovery
/// index (`fault_entries`), and the bump-allocator handle they all write
/// through (`translation_cache`).
///
/// Mirrors aarch64's `ProcessTranslator` owning its cache + publication index,
/// but stays PER-THREAD-PRIVATE (no `Arc`, no lock) per the KEEP-LANE cache
/// boundary the module header documents: x86 identity-maps guest memory so the
/// translated bytes for a VA are the same across threads, yet each thread owns a
/// non-overlapping JIT slice and its own block index. Unifying that into a
/// shared, locked process cache is an out-of-scope cross-ISA merge.
pub struct X86ThreadTranslator {
    /// This thread's private slice of the shared JIT code cache, wrapped in the
    /// shared bump-allocator. Borrows nothing — `TranslationCache::from_region`
    /// copies the region's raw pointers — so this engine needs no lifetime.
    pub translation_cache: TranslationCache,
    /// Generation-scoped translations keyed by guest VA. Each `CachedBlock`
    /// retains its full planned guest span so reuse, incoming edges, and return
    /// targets atomically re-check mixed immutable/mutable executable spans.
    pub cache: std::collections::HashMap<u64, CachedBlock, VaBuildHasher>,
    /// Predecoded plans for genuine indirect exits, keyed by the exit VA.
    pub cflow_plans: std::collections::HashMap<u64, crate::cflow::ControlFlowPlan, VaBuildHasher>,
    /// One thread-local, generation-scoped monomorphic entry per emitted return
    /// site. Emitted code publishes a one-based index into this vector.
    pub indirect_cache_entries: Vec<crate::X86IndirectCacheEntry>,
    /// Chain edges awaiting their target's translation, indexed by target VA.
    pub pending: std::collections::HashMap<u64, Vec<PendingChainEdge>, VaBuildHasher>,
    /// Fault-recovery metadata for the currently live translated blocks.
    pub fault_entries: Vec<PublishedFaultEntry>,
}

impl X86ThreadTranslator {
    /// Adopt a freshly borrowed JIT slice (`TranslationCache::from_region`) and
    /// start with empty translation maps.
    pub fn new(translation_cache: TranslationCache) -> Self {
        Self {
            translation_cache,
            cache: std::collections::HashMap::default(),
            cflow_plans: std::collections::HashMap::default(),
            indirect_cache_entries: Vec::new(),
            pending: std::collections::HashMap::default(),
            fault_entries: Vec::new(),
        }
    }

    /// Drop every generation-scoped translation map: the block index, the
    /// predecoded cflow plans, the return-site table, the pending chain edges,
    /// and the fault-recovery index. The bump-allocator (`translation_cache`)
    /// is reset or rebuilt by the caller because its reset shape differs by site
    /// (in-place `reset_after_fork_for_exec` recycle vs a fresh fork-child
    /// slice). Verbatim of the five `.clear()` calls the run loop repeated at
    /// each cache-refresh boundary (capacity recycle, admission refresh, fork
    /// child, in-place exec).
    pub fn clear_translation_state(&mut self) {
        self.cache.clear();
        self.cflow_plans.clear();
        self.indirect_cache_entries.clear();
        self.pending.clear();
        self.fault_entries.clear();
    }

    /// Translate the block at `next` on a cache miss: plan → classify
    /// ephemeral → read the guest bytes → decode any control-flow plan → emit &
    /// link → assign a return-cache site → publish the padded bytes (recycling
    /// the whole slice on capacity exhaustion) → record the fault-recovery
    /// index → construct the `CachedBlock` → insert it (and any cflow plan) into
    /// the owned maps. Returns the block plus the loop-owned decisions the
    /// still-resident xstate edge-registration logic needs.
    ///
    /// Moved verbatim from `run_x86_thread`'s translate-miss branch (Phase-3
    /// Task 2b); the only necessary adaptations are: control flow that was
    /// `continue 'run`/`break 'run`/inline-`deliver` becomes a returned
    /// [`X86TranslateOutcome`] variant; the runtime-side guest readers arrive as
    /// the `fetch`/`read_exact` closures (`plan_block_with_reader` already took a
    /// reader closure); the one-line runtime helper
    /// `native_x86_translation_is_ephemeral` is inlined to its
    /// `MemoryProtections::range_translation_requires_ephemeral` body; and the
    /// no-progress breadcrumb reads the `segments`/`history` slices the loop
    /// passes rather than closing over `image`/`history` directly.
    #[allow(
        clippy::too_many_arguments,
        reason = "the miss orchestration consumes the guest readers, protections, and diagnostic context the loop owned inline"
    )]
    pub fn translate(
        &mut self,
        next: u64,
        slice_len: usize,
        page: u64,
        protections: &MemoryProtections,
        segments: &[(u64, u64)],
        history: &[u64],
        mut fetch: impl FnMut(u64) -> Result<Vec<u8>, IdentityCheckedReadError>,
        mut read_exact: impl FnMut(GuestVa, &mut [u8]) -> Result<(), IdentityCheckedReadError>,
    ) -> X86TranslateOutcome {
        let mut ephemeral_return_adjust: Option<u64> = None;
        let mut ephemeral_cflow_plan: Option<(u64, crate::cflow::ControlFlowPlan)> = None;
        let mut current_ephemeral_fault_range: Option<(u64, u64)> = None;

        // Plan bounded to the 4 KiB guest page so a block stays within one
        // mapped PT_LOAD segment (a larger span could read across an unmapped
        // gap between them). `plan_block` always includes its first instruction
        // even if it spans the page boundary, so it never returns an empty
        // `Continue{target: start}` — which the chainer would turn into an
        // infinite self-jump.
        let block = match plan_block_with_reader(next, 256, page, &mut fetch) {
            Ok(block) => block,
            Err(X86BlockPlanError::Read { va, error }) => {
                return X86TranslateOutcome::InstructionFetchFault {
                    report_va: va,
                    error,
                };
            }
            Err(X86BlockPlanError::Block(error)) => {
                return X86TranslateOutcome::Fatal(format!("plan_block at 0x{next:x}: {error}"));
            }
        };
        // Defensive: a block that plans zero instructions AND only CONTINUES at
        // its own start makes no progress (a page-spanning instruction that
        // could not be planned, or the guest ran off mapped code). A block whose
        // first instruction is a TERMINATOR also has zero copy-instructions and
        // `exit.va() == start` — normal — so match only the `Continue` shape.
        let empty_self_continue = block.instructions.is_empty()
            && matches!(block.exit, X86Exit::Continue { target, .. } if target == next);
        if empty_self_continue {
            let bytes = fetch(next)
                .map(|bytes| format!("{bytes:02x?}"))
                .unwrap_or_else(|error| format!("fetch-error={error:?}"));
            let in_seg = segments.iter().any(|&(s, e)| next >= s && next < e);
            let recent: Vec<String> = history
                .iter()
                .rev()
                .take(8)
                .map(|v| format!("0x{v:x}"))
                .collect();
            return X86TranslateOutcome::Fatal(format!(
                "no-progress block at 0x{next:x}: exit={:?} in_segment={in_seg} \
                 bytes={bytes} segments={segments:x?} recent_blocks={recent:?}",
                block.exit,
            ));
        }
        let guest_len = match block
            .end
            .checked_sub(block.start)
            .and_then(|len| usize::try_from(len).ok())
        {
            Some(len) if len != 0 => len,
            _ => {
                return X86TranslateOutcome::Fatal(format!(
                    "invalid native x86 guest block span 0x{:x}..0x{:x}",
                    block.start, block.end
                ));
            }
        };
        // Classify the complete planned instruction span before publishing cache
        // metadata, edges, or a return-cache site — the planner may include its
        // first instruction across a page boundary.
        let source_translation_ephemeral =
            protections.range_translation_requires_ephemeral(block.start, guest_len);
        let mut body = vec![0u8; guest_len];
        if let Err(error) = read_exact(GuestVa(block.start), &mut body) {
            return X86TranslateOutcome::InstructionFetchFault {
                report_va: next,
                error,
            };
        }
        let control_flow_plan = match block.exit {
            X86Exit::ControlFlow { va, .. } => {
                let offset = va
                    .checked_sub(block.start)
                    .and_then(|offset| usize::try_from(offset).ok());
                let Some(bytes) = offset.and_then(|offset| body.get(offset..)) else {
                    return X86TranslateOutcome::Fatal(format!(
                        "cflow plan at 0x{va:x} is outside block 0x{:x}..0x{:x}",
                        block.start, block.end
                    ));
                };
                match crate::cflow::ControlFlowPlan::decode(bytes, va) {
                    Ok(plan) => Some((va, plan)),
                    Err(error) => {
                        return X86TranslateOutcome::Fatal(format!(
                            "cflow plan at 0x{va:x}: {error}"
                        ));
                    }
                }
            }
            _ => None,
        };
        let mut linked = match emit_block_linked(&body, &block) {
            Ok(t) => t,
            Err(e) => {
                // Loud: include the already checked terminator bytes so an
                // unsupported instruction is identifiable without another
                // uncontained guest-memory read.
                let at = block.exit.va();
                let terminator_bytes = at
                    .checked_sub(block.start)
                    .and_then(|offset| usize::try_from(offset).ok())
                    .and_then(|offset| body.get(offset..))
                    .unwrap_or(&[]);
                return X86TranslateOutcome::Fatal(format!(
                    "emit_block at 0x{next:x} ({:?}): {e} — insn bytes at 0x{at:x} = {terminator_bytes:02x?}",
                    block.exit,
                ));
            }
        };
        if linked.bytes.len() > slice_len {
            return X86TranslateOutcome::Fatal(format!(
                "single translated block exceeds the {slice_len}-byte JIT slice at 0x{next:x}"
            ));
        }
        if let Some(site) = linked.indirect_cache {
            if source_translation_ephemeral {
                // Site id zero keeps the gateway cache cold, while the emitted
                // probe still captures `[rsp]` exactly once for the Rust
                // resolver. No persistent cache entry is created.
                ephemeral_return_adjust = Some(site.stack_adjust);
            } else {
                let Some(site_id) = self
                    .indirect_cache_entries
                    .len()
                    .checked_add(1)
                    .and_then(|id| u32::try_from(id).ok())
                else {
                    return X86TranslateOutcome::Fatal(
                        "native x86 indirect-cache site id overflow".into(),
                    );
                };
                linked.bytes[site.site_id_imm_off..site.site_id_imm_off + 4]
                    .copy_from_slice(&site_id.to_le_bytes());
                self.indirect_cache_entries
                    .push(crate::X86IndirectCacheEntry::return_site(site.stack_adjust));
            }
        }
        let published = match publish_x86_translated_bytes(
            &mut self.translation_cache,
            &linked.bytes,
        ) {
            Ok(published) => published,
            Err(CacheError::Capacity { .. }) => {
                // The guest is back at a gateway boundary, so no code in this
                // thread's private slice is executing. Recycle the whole slice
                // instead of imposing a lifetime translation-volume limit: large
                // static Go programs execute far more than 4 MiB of distinct
                // emitted code during startup. Guest return addresses remain
                // guest VAs, so dropping every block/edge map and re-translating
                // `next` at the slice base is safe.
                self.translation_cache.reset_after_fork_for_exec();
                self.clear_translation_state();
                match publish_x86_translated_bytes(&mut self.translation_cache, &linked.bytes) {
                    Ok(published) => published,
                    Err(error) => {
                        return X86TranslateOutcome::Fatal(format!(
                            "native x86 JIT publish at 0x{next:x} failed just after slice recycle: {error}"
                        ));
                    }
                }
            }
            Err(error) => {
                return X86TranslateOutcome::Fatal(format!(
                    "native x86 JIT publish at 0x{next:x} failed: {error}"
                ));
            }
        };
        let exec_u64 = published.entry().host().raw() as u64;
        self.fault_entries
            .extend(linked.fault_map.iter().map(|entry| PublishedFaultEntry {
                host_start: exec_u64 + entry.emitted_start as u64,
                host_end: exec_u64 + entry.emitted_end as u64,
                guest_va: entry.guest_va,
                is_copied_x87: entry.is_copied_x87,
                restores: entry.restores.clone(),
            }));
        let entry = if source_translation_ephemeral {
            current_ephemeral_fault_range = Some((exec_u64, exec_u64 + linked.bytes.len() as u64));
            CachedBlock {
                exec: exec_u64,
                has_edges: false,
                uses_fpu: block.uses_fpu,
                has_indirect_cache: false,
                guest_len,
            }
        } else {
            CachedBlock {
                exec: exec_u64,
                has_edges: !linked.edges.is_empty() || linked.indirect_cache.is_some(),
                uses_fpu: block.uses_fpu,
                has_indirect_cache: linked.indirect_cache.is_some(),
                guest_len,
            }
        };
        if !source_translation_ephemeral {
            self.cache.insert(next, entry);
        }
        if let Some((va, plan)) = control_flow_plan {
            if source_translation_ephemeral {
                ephemeral_cflow_plan = Some((va, plan));
            } else {
                self.cflow_plans.insert(va, plan);
            }
        }
        X86TranslateOutcome::Translated(X86TranslatedBlock {
            entry,
            edges: linked.edges,
            source_translation_ephemeral,
            ephemeral_return_adjust,
            ephemeral_cflow_plan,
            current_ephemeral_fault_range,
        })
    }
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
