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
use crate::direct_binding::{
    DirectBindingCellVa, DirectBindingExitMetadata, DirectBindingMiss, DirectBindingOrdinal,
};
use crate::snapshot::NativeUcontextSnapshot;

use std::sync::atomic::{AtomicPtr, AtomicU64, Ordering};

pub const INDIRECT_CACHE_ENTRIES: usize = 32_768;
pub const INDIRECT_CACHE_MASK: u64 = (INDIRECT_CACHE_ENTRIES - 1) as u64;
pub const INDIRECT_CACHE_INDEX_BITS: u32 = 15;
pub const INDIRECT_CACHE_ENTRY_SHIFT: u32 = 6;
/// The GPR carrick reserves for the biased-address computation, chosen by the
/// sample-weighted guest-register census in
/// `docs/perf-results/native-dsr-shape-census.jsonl` (record
/// `guest-register-census`): x19 carried zero sampled weight in translated
/// guest code, tied with x21-x25, and x18/x28 are already host-owned.
///
/// Inside translated code the physical register belongs to carrick, exactly
/// like physical x18 (Darwin's platform register) and physical x28 (the
/// context pointer). The guest's architectural value therefore lives in the
/// snapshot slot below for the lifetime of translated execution, and every
/// guest instruction naming the register is virtualized through it.
///
/// Changing this constant is NOT a one-line edit: `gateway_aarch64.S` and
/// `csrc/native_darwin.c` both name the skipped register numerically (the
/// assembler and the C signal handler cannot read a Rust const), so the
/// assertion below fails the build until they are updated together.
pub const RESERVED_SCRATCH: u32 = 19;
const _: () = assert!(RESERVED_SCRATCH == 19);

/// Context byte offset of the reserved scratch's guest value.
///
/// This is `snapshot.x[RESERVED_SCRATCH]` -- the same slot the gateway would
/// otherwise use for the register -- so the guest register file stays
/// architecturally correct for every consumer (fault recovery, emulation,
/// fork, signal delivery) with no separate round-trip, exactly like guest x18
/// (slot 144) and guest x28 (slot 224).
pub const CTX_GUEST_RESERVED_SCRATCH: u32 = 152;

/// Byte offset of the gateway phase, `DsrContext::entry_in_progress`.
///
/// Not a boolean: 1 means the gateway is handing control to translated code,
/// 0 means translated code is executing, and 2 means the gateway's exit path has
/// captured guest state and is transitioning host signal masks.
/// `carrick_native_dsr_signal_handler` branches on all three, and does NOT trust
/// phase 0 alone -- it also requires the interrupted PC to be inside the code
/// cache or the executable-range catalog.
///
/// `gateway_aarch64.S` names this offset numerically as `CTX_GATEWAY_PHASE` and
/// `csrc/native_darwin.c` static-asserts it, because neither an assembler nor a C
/// compiler can read a Rust const. The `offset_of!` assertion below is what keeps
/// the three in step.
pub const CTX_GATEWAY_PHASE: u32 = 1152;

// 1272, not its historical 1136: the indirect-cache pointer is the hottest
// READ in translated code (the dispatch sequence loads it per indirect
// branch), and 1136's 64-byte line (1088..1151) also carries the most-written
// slots in the context - the template spill pair (1120/1128) and the
// generation publish (1144). It now lives on the read-mostly exit-address
// line (1216..1279), whose only stores are cross-authority transitions.
pub const CTX_INDIRECT_CACHE: u32 = 1272;
pub const CTX_GENERATION: u32 = 1144;
pub const CTX_ENFORCE_CACHE_AUTHORITY: u32 = 1156;
pub const CTX_CACHE_START: u32 = 1176;
pub const CTX_CACHE_END: u32 = 1184;
pub const CTX_GENERATION_BINDINGS: u32 = 1264;
pub const CTX_DIRECT_BINDING_CELL: u32 = 1280;
pub const CTX_DIRECT_BINDING_ORDINAL: u32 = 1288;
pub const CTX_DIRECT_BINDING_PRESENT: u32 = 1292;
pub const CTX_DIRECT_BINDING_TARGET: u32 = 1296;

#[repr(C)]
pub struct ExecutableRangeCatalogHeader {
    head: AtomicPtr<ExecutableRangeCatalogNode>,
}

#[repr(C)]
pub struct ExecutableRangeCatalogNode {
    start: u64,
    end: u64,
    next: *const ExecutableRangeCatalogNode,
}

// SAFETY: nodes are pinned before publication and immutable afterward.
unsafe impl Send for ExecutableRangeCatalogNode {}
// SAFETY: see `Send`; readers only traverse immutable nodes.
unsafe impl Sync for ExecutableRangeCatalogNode {}

pub(crate) struct PreparedExecutableRange {
    node: Box<ExecutableRangeCatalogNode>,
}

pub struct ExecutableRangeCatalog {
    header: Box<ExecutableRangeCatalogHeader>,
    private: Box<ExecutableRangeCatalogNode>,
    // Each node's address is published into the lock-free `next`/head chain
    // before insertion, so nodes must never move; `Vec<Node>` would relocate
    // them on growth and dangle every published pointer.
    #[allow(clippy::vec_box)]
    shared: Vec<Box<ExecutableRangeCatalogNode>>,
}

impl ExecutableRangeCatalog {
    pub fn new(private_start: usize, private_end: usize) -> Result<Self, DsrError> {
        if private_start >= private_end {
            return Err(DsrError::CachePolicy(
                "private executable range is empty or inverted".to_string(),
            ));
        }
        let mut private = Box::new(ExecutableRangeCatalogNode {
            start: private_start as u64,
            end: private_end as u64,
            next: std::ptr::null(),
        });
        let header = Box::new(ExecutableRangeCatalogHeader {
            head: AtomicPtr::new(std::ptr::from_mut(private.as_mut())),
        });
        Ok(Self {
            header,
            private,
            shared: Vec::new(),
        })
    }

    pub fn prepend(&mut self, start: usize, end: usize) -> Result<(), DsrError> {
        let prepared = self.prepare_prepend(start, end)?;
        self.commit_prepend(prepared);
        Ok(())
    }

    pub(crate) fn prepare_prepend(
        &mut self,
        start: usize,
        end: usize,
    ) -> Result<PreparedExecutableRange, DsrError> {
        if start >= end {
            return Err(DsrError::CachePolicy(
                "shared executable range is empty or inverted".to_string(),
            ));
        }
        self.shared.try_reserve(1).map_err(|error| {
            DsrError::CachePolicy(format!(
                "shared executable range retention reservation failed: {error}"
            ))
        })?;
        Ok(PreparedExecutableRange {
            node: Box::new(ExecutableRangeCatalogNode {
                start: start as u64,
                end: end as u64,
                next: std::ptr::null(),
            }),
        })
    }

    pub(crate) fn commit_prepend(&mut self, mut prepared: PreparedExecutableRange) {
        prepared.node.next = self.header.head.load(Ordering::Acquire);
        let published = std::ptr::from_mut(prepared.node.as_mut());
        self.shared.push(prepared.node);
        self.header.head.store(published, Ordering::Release);
    }

    #[cfg(any(test, feature = "test-hooks"))]
    pub(crate) fn prepare_prepend_with_reserver(
        &mut self,
        start: usize,
        end: usize,
        reserve: impl FnOnce(&mut Vec<Box<ExecutableRangeCatalogNode>>) -> Result<(), DsrError>,
    ) -> Result<PreparedExecutableRange, DsrError> {
        if start >= end {
            return Err(DsrError::CachePolicy(
                "shared executable range is empty or inverted".to_string(),
            ));
        }
        reserve(&mut self.shared)?;
        Ok(PreparedExecutableRange {
            node: Box::new(ExecutableRangeCatalogNode {
                start: start as u64,
                end: end as u64,
                next: std::ptr::null(),
            }),
        })
    }

    pub fn header_ptr(&self) -> *const ExecutableRangeCatalogHeader {
        self.header.as_ref()
    }

    pub fn head_ptr(&self) -> *mut ExecutableRangeCatalogNode {
        self.header.head.load(Ordering::Acquire)
    }

    pub fn contains(&self, pc: usize) -> bool {
        // SAFETY: the catalog owns its stable header and all linked nodes.
        unsafe { executable_range_catalog_contains(self.header_ptr(), pc) }
    }

    pub fn reset_head_to_private(&mut self) {
        self.header
            .head
            .store(std::ptr::from_mut(self.private.as_mut()), Ordering::Release);
    }

    pub fn drop_shared_nodes(&mut self) {
        self.shared.clear();
    }

    pub fn shared_node_count(&self) -> usize {
        self.shared.len()
    }
}

/// Traverse one stable process catalog using the signal handler's acquire
/// ordering.
///
/// # Safety
///
/// `header` and every node reachable from its head must remain alive for the
/// traversal.
pub unsafe fn executable_range_catalog_contains(
    header: *const ExecutableRangeCatalogHeader,
    pc: usize,
) -> bool {
    let Some(header) = (unsafe { header.as_ref() }) else {
        return false;
    };
    let mut node = header.head.load(Ordering::Acquire);
    while let Some(current) = unsafe { node.as_ref() } {
        if (current.start..current.end).contains(&(pc as u64)) {
            return true;
        }
        node = current.next.cast_mut();
    }
    false
}

/// Process-local data referenced by an immutable translated block.
///
/// The block embeds only this table's stable index. The current-generation
/// pointer and expected value are installed for the process entering it.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct GenerationBinding {
    current: *const AtomicU64,
    expected: u64,
}

// SAFETY: `current` can only be constructed from a shared `AtomicU64`; users
// retaining a binding table also retain the mapped-memory generation table.
// Translated code only performs an acquire load through the pointer.
unsafe impl Send for GenerationBinding {}
// SAFETY: see `Send`; the pointee is atomic and the expected value immutable.
unsafe impl Sync for GenerationBinding {}

impl GenerationBinding {
    pub fn new(current: &AtomicU64, expected: CodeGeneration) -> Self {
        Self {
            current,
            expected: expected.get(),
        }
    }
}

/// One way of the emitted-probe target cache. Two FLAVORS share the layout,
/// discriminated by bit 0 of `reserved` (old-flavor entries always publish
/// `reserved == 0`):
///
/// - **Flavor 0** (`reserved == 0`): `cache` is the target block's GUARDED
///   entry and `authority` points at a [`TargetCacheAuthority`] record the
///   emitted slow path validates and installs before branching.
/// - **Flavor 1** (`reserved == (expected_generation << 1) | 1`): private
///   trusted-entry targets only. `cache` is the TARGET'S TRUSTED ENTRY
///   address (block entry + trusted offset, past the generation guard) and
///   `authority` holds the ADDRESS of the target page's generation
///   `AtomicU64` — the same cell the target's own guard would `ldar` — so
///   the emitted hot path validates the generation inline and skips the
///   authority switch entirely (a private→private hop never changes the
///   installed cache authority).
#[repr(C, align(16))]
pub struct IndirectTargetCacheEntry {
    guest: u64,
    cache: u64,
    authority: u64,
    reserved: u64,
}

/// Executable ownership installed when a target-cache hit crosses from one
/// immutable translation unit (or the private JIT) into another.
#[repr(C)]
pub struct TargetCacheAuthority {
    cache_start: u64,
    cache_end: u64,
    generation_bindings: u64,
}

impl TargetCacheAuthority {
    pub fn new(
        cache_start: usize,
        cache_end: usize,
        generation_bindings: *const GenerationBinding,
    ) -> Self {
        Self {
            cache_start: cache_start as u64,
            cache_end: cache_end as u64,
            generation_bindings: generation_bindings as usize as u64,
        }
    }

    pub fn owns(&self, entry: CacheVa) -> bool {
        let address = entry.host().raw() as u64;
        (self.cache_start..self.cache_end).contains(&address)
    }
}

#[repr(C, align(64))]
struct IndirectTargetCacheSet {
    ways: [IndirectTargetCacheEntry; 2],
}

#[inline(always)]
fn indirect_cache_index(guest: carrick_guest_mem::GuestVa) -> usize {
    let raw = guest.raw();
    let mixed = raw ^ (raw >> 12);
    ((mixed >> 2) & INDIRECT_CACHE_MASK) as usize
}

pub struct IndirectTargetCache {
    entries: Box<[IndirectTargetCacheSet; INDIRECT_CACHE_ENTRIES]>,
}

impl IndirectTargetCache {
    pub fn new() -> Self {
        let entries = (0..INDIRECT_CACHE_ENTRIES)
            .map(|_| IndirectTargetCacheSet {
                ways: std::array::from_fn(|_| IndirectTargetCacheEntry {
                    guest: 0,
                    cache: 0,
                    authority: 0,
                    reserved: 0,
                }),
            })
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let entries = match entries.try_into() {
            Ok(entries) => entries,
            Err(_) => unreachable!("indirect target cache length is fixed"),
        };
        Self { entries }
    }

    pub fn publish(
        &mut self,
        guest: carrick_guest_mem::GuestVa,
        _generation: CodeGeneration,
        cache: CacheVa,
        authority: *const TargetCacheAuthority,
    ) {
        let set = &mut self.entries[indirect_cache_index(guest)];
        let way = set
            .ways
            .iter()
            .position(|entry| entry.guest == guest.raw() || entry.guest == 0)
            .unwrap_or_else(|| {
                usize::from(((guest.raw() >> (2 + INDIRECT_CACHE_INDEX_BITS)) & 1) != 0)
            });
        let entry = &mut set.ways[way];
        // A thread translator owns its table. Rust publishes only while the
        // translated reader is not running, so plain stores are sufficient.
        entry.guest = 0;
        entry.cache = cache.host().raw() as u64;
        entry.authority = authority as usize as u64;
        entry.reserved = 0;
        entry.guest = guest.raw();
    }

    /// Publish the private trusted-entry FLAVOR (flavor 1, see
    /// [`IndirectTargetCacheEntry`]): `trusted_code` is the target's trusted
    /// entry address (block entry + trusted offset), `generation_atomic` the
    /// address of the target page's generation `AtomicU64`, and `expected`
    /// the generation the trusted entry was translated against. The emitted
    /// hot path `ldar`s the atomic, compares against `reserved >> 1`, and
    /// branches straight to `trusted_code` on a match.
    pub fn publish_private_trusted(
        &mut self,
        guest: carrick_guest_mem::GuestVa,
        trusted_code: u64,
        generation_atomic: u64,
        expected: CodeGeneration,
    ) {
        let set = &mut self.entries[indirect_cache_index(guest)];
        let way = set
            .ways
            .iter()
            .position(|entry| entry.guest == guest.raw() || entry.guest == 0)
            .unwrap_or_else(|| {
                usize::from(((guest.raw() >> (2 + INDIRECT_CACHE_INDEX_BITS)) & 1) != 0)
            });
        let entry = &mut set.ways[way];
        // Same publication discipline as `publish`: unreachable while the
        // payload is written, `guest` (the probe tag) last. Flavor-1 field
        // roles follow the emitted `ldp x17, x19, [x15, #8]`: the tagged
        // expected generation sits at offset 8 (odd — the flavor bit; a
        // flavor-0 entry's offset-8 code address is even), the generation
        // atomic at 16, and the TRUSTED-entry code address at 24 where its
        // load overlaps the generation `ldar`.
        entry.guest = 0;
        entry.cache = (expected.get() << 1) | 1;
        entry.authority = generation_atomic;
        entry.reserved = trusted_code;
        entry.guest = guest.raw();
    }

    pub fn clear(&mut self) {
        for set in self.entries.iter_mut() {
            for entry in &mut set.ways {
                // Make the entry unreachable before clearing its payload.
                entry.guest = 0;
                entry.cache = 0;
                entry.authority = 0;
                entry.reserved = 0;
            }
        }
    }

    pub fn as_ptr(&self) -> *const IndirectTargetCacheEntry {
        self.entries.as_ptr().cast()
    }

    /// Test/diagnostic view of the way tagged `guest`:
    /// `(cache, authority, reserved)`.
    #[doc(hidden)]
    pub fn entry_snapshot(&self, guest: carrick_guest_mem::GuestVa) -> Option<(u64, u64, u64)> {
        self.entries[indirect_cache_index(guest)]
            .ways
            .iter()
            .find(|entry| entry.guest == guest.raw())
            .map(|entry| (entry.cache, entry.authority, entry.reserved))
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
    /// Former `indirect_cache` slot, retired to the pad role when the
    /// pointer moved to the read-mostly line (see `CTX_INDIRECT_CACHE`).
    pub retired_indirect_cache_pad: u64,
    pub generation: u64,
    /// Gateway phase: 1 entering, 0 translated code, 2 leaving after capture.
    pub entry_in_progress: u32,
    pub enforce_cache_authority: u32,
    pub indirect_x15_scratch: u64,
    pub indirect_x30_scratch: u64,
    pub cache_start: u64,
    pub cache_end: u64,
    pub host_bias: u64,
    pub biased_guest_fault_address: u64,
    /// Interrupted physical x19 (`RESERVED_SCRATCH`), stashed by the signal
    /// handler for the reserved-resident commit recovery. Occupies the former
    /// `biased_fault_pad`, so every later offset is unchanged.
    pub physical_reserved: u64,
    /// The six gateway exit entry points, so emitted code can REACH them
    /// without EMBEDDING them. Guest processes self-reexec with different ASLR
    /// slides, so a gateway address baked into a block pins that block to the
    /// process that emitted it; a context load does not. Same mechanism as
    /// `host_bias` above.
    pub exit_syscall_addr: u64,
    pub exit_direct_addr: u64,
    pub exit_indirect_addr: u64,
    pub exit_sensitive_addr: u64,
    pub exit_unsupported_addr: u64,
    pub exit_signal_addr: u64,
    pub generation_bindings: *const GenerationBinding,
    /// Occupies the former ABI tail pad, preserving the 1280-byte boundary.
    pub indirect_cache: *const IndirectTargetCacheEntry,
    pub direct_binding_cell: u64,
    pub direct_binding_ordinal: u32,
    pub direct_binding_present: u32,
    pub direct_binding_target: u64,
    pub executable_range_catalog: *const ExecutableRangeCatalogHeader,
}

/// Context byte offset of the gateway exit entry point for `kind`.
pub const fn exit_address_offset(kind: crate::artifact_spike::GatewayKind) -> u32 {
    match kind {
        crate::artifact_spike::GatewayKind::Syscall => 1216,
        crate::artifact_spike::GatewayKind::Direct => 1224,
        crate::artifact_spike::GatewayKind::Indirect => 1232,
        crate::artifact_spike::GatewayKind::Sensitive => 1240,
        crate::artifact_spike::GatewayKind::Unsupported => 1248,
        crate::artifact_spike::GatewayKind::Signal => 1256,
    }
}

fn gateway_exit_addresses() -> [u64; 6] {
    // Each getter is itself a `cfg(test)` placeholder in a crate test build
    // (see the `exit_address!` note in `native_gateway`), so this stays [0; 6]
    // there and carries the real addresses in a runtime build.
    [
        syscall_exit_address(),
        direct_exit_address(),
        indirect_exit_address(),
        sensitive_exit_address(),
        unsupported_exit_address(),
        signal_exit_address(),
    ]
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
        let [
            exit_syscall_addr,
            exit_direct_addr,
            exit_indirect_addr,
            exit_sensitive_addr,
            exit_unsupported_addr,
            exit_signal_addr,
        ] = gateway_exit_addresses();
        let (exit_target, exit_source, _exit_status, exit_link, exit_has_link) = match exit {
            NativeDsrExit::Syscall { resume } => (resume.raw(), 0, 1, 0, 0),
            NativeDsrExit::ResolveDirect { source, target, .. } => {
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
            enforce_cache_authority: 1,
            indirect_x15_scratch: snapshot.x[15],
            indirect_x30_scratch: snapshot.x[30],
            cache_start: cache_start as u64,
            cache_end: cache_end as u64,
            host_bias: address_mode.bias(),
            biased_guest_fault_address: 0,
            physical_reserved: 0,
            exit_syscall_addr,
            exit_direct_addr,
            exit_indirect_addr,
            exit_sensitive_addr,
            exit_unsupported_addr,
            exit_signal_addr,
            generation_bindings: std::ptr::null(),
            retired_indirect_cache_pad: 0,
            direct_binding_cell: 0,
            direct_binding_ordinal: 0,
            direct_binding_present: 0,
            direct_binding_target: 0,
            executable_range_catalog: std::ptr::null(),
        }
    }
}

fn decode_direct_exit(context: &DsrContext) -> NativeDsrExit {
    // `exit_source` is written by the stub that actually returned to Rust.
    // It is therefore exit-time evidence after any preceding cache/direct
    // hit, unlike the `PreparedEntry` that began this translated run. The
    // cold registry classifier combines this exact `(source,target)` with the
    // miss cell/ordinal below and rejects ambiguous loaded-manifest matches.
    let binding = if context.direct_binding_present != 1 {
        DirectBindingExitMetadata::Absent
    } else if let Some(cell) = usize::try_from(context.direct_binding_cell)
        .ok()
        .and_then(DirectBindingCellVa::mapped)
    {
        DirectBindingExitMetadata::Mapped(DirectBindingMiss {
            cell,
            ordinal: DirectBindingOrdinal::claimed(context.direct_binding_ordinal),
        })
    } else {
        DirectBindingExitMetadata::MappedCellFailure {
            raw_cell: context.direct_binding_cell,
            ordinal: DirectBindingOrdinal::claimed(context.direct_binding_ordinal),
        }
    };
    NativeDsrExit::ResolveDirect {
        source: carrick_guest_mem::GuestVa(context.exit_source),
        target: carrick_guest_mem::GuestVa(context.exit_target),
        binding,
    }
}

const _: () = assert!(std::mem::size_of::<NativeUcontextSnapshot>() == 832);
const _: () = assert!(std::mem::offset_of!(DsrContext, snapshot) == 0);
// The reserved scratch's guest value is the snapshot slot the gateway would
// otherwise hold in the physical register; pin the two together so the
// emitter's context offset can never drift from the register it virtualizes.
const _: () = assert!(
    std::mem::offset_of!(DsrContext, snapshot) + (RESERVED_SCRATCH as usize) * 8
        == CTX_GUEST_RESERVED_SCRATCH as usize
);
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
const _: () = assert!(std::mem::offset_of!(DsrContext, retired_indirect_cache_pad) == 1136);
const _: () =
    assert!(std::mem::offset_of!(DsrContext, indirect_cache) == CTX_INDIRECT_CACHE as usize);
const _: () = assert!(std::mem::offset_of!(DsrContext, generation) == 1144);
const _: () = assert!(std::mem::offset_of!(DsrContext, entry_in_progress) == 1152);
const _: () =
    assert!(std::mem::offset_of!(DsrContext, entry_in_progress) == CTX_GATEWAY_PHASE as usize);
const _: () = assert!(std::mem::offset_of!(DsrContext, enforce_cache_authority) == 1156);
const _: () = assert!(std::mem::offset_of!(DsrContext, indirect_x15_scratch) == 1160);
const _: () = assert!(std::mem::offset_of!(DsrContext, indirect_x30_scratch) == 1168);
const _: () = assert!(std::mem::offset_of!(DsrContext, cache_start) == 1176);
const _: () = assert!(std::mem::offset_of!(DsrContext, cache_end) == 1184);
const _: () = assert!(std::mem::offset_of!(DsrContext, host_bias) == 1192);
const _: () = assert!(std::mem::offset_of!(DsrContext, biased_guest_fault_address) == 1200);
const _: () = assert!(std::mem::offset_of!(DsrContext, physical_reserved) == 1208);
const _: () = assert!(std::mem::offset_of!(DsrContext, exit_syscall_addr) == 1216);
const _: () = assert!(std::mem::offset_of!(DsrContext, exit_direct_addr) == 1224);
const _: () = assert!(std::mem::offset_of!(DsrContext, exit_indirect_addr) == 1232);
const _: () = assert!(std::mem::offset_of!(DsrContext, exit_sensitive_addr) == 1240);
const _: () = assert!(std::mem::offset_of!(DsrContext, exit_unsupported_addr) == 1248);
const _: () = assert!(std::mem::offset_of!(DsrContext, exit_signal_addr) == 1256);
const _: () = assert!(std::mem::offset_of!(DsrContext, generation_bindings) == 1264);

const _: () = assert!(std::mem::offset_of!(DsrContext, direct_binding_cell) == 1280);
const _: () = assert!(std::mem::offset_of!(DsrContext, direct_binding_ordinal) == 1288);
const _: () = assert!(std::mem::offset_of!(DsrContext, direct_binding_present) == 1292);
const _: () = assert!(std::mem::offset_of!(DsrContext, direct_binding_target) == 1296);
const _: () = assert!(std::mem::offset_of!(DsrContext, executable_range_catalog) == 1304);
const _: () = assert!(std::mem::size_of::<DsrContext>() == 1312);
const _: () = assert!(std::mem::align_of::<DsrContext>() == 16);
const _: () = assert!(std::mem::size_of::<ExecutableRangeCatalogHeader>() == 8);
const _: () = assert!(std::mem::align_of::<ExecutableRangeCatalogHeader>() == 8);
const _: () = assert!(std::mem::offset_of!(ExecutableRangeCatalogHeader, head) == 0);
const _: () = assert!(std::mem::size_of::<ExecutableRangeCatalogNode>() == 24);
const _: () = assert!(std::mem::align_of::<ExecutableRangeCatalogNode>() == 8);
const _: () = assert!(std::mem::offset_of!(ExecutableRangeCatalogNode, start) == 0);
const _: () = assert!(std::mem::offset_of!(ExecutableRangeCatalogNode, end) == 8);
const _: () = assert!(std::mem::offset_of!(ExecutableRangeCatalogNode, next) == 16);
const _: () = assert!(std::mem::size_of::<GenerationBinding>() == 16);
const _: () = assert!(std::mem::offset_of!(GenerationBinding, current) == 0);
const _: () = assert!(std::mem::offset_of!(GenerationBinding, expected) == 8);
const _: () = assert!(std::mem::size_of::<IndirectTargetCacheEntry>() == 32);
const _: () = assert!(std::mem::size_of::<IndirectTargetCacheSet>() == 64);
const _: () = assert!(std::mem::offset_of!(IndirectTargetCacheEntry, guest) == 0);
const _: () = assert!(std::mem::offset_of!(IndirectTargetCacheEntry, cache) == 8);
const _: () = assert!(std::mem::offset_of!(IndirectTargetCacheEntry, authority) == 16);

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

    // The six exit labels are assembled into the SAME object as
    // `carrick_dsr_enter_raw`, which calls the runtime's C ABI helpers
    // (`carrick_native_dsr_enter_{guest,host}_abi`). Standalone crate tests do
    // not link those helpers, so taking any one of these addresses drags the
    // gateway object -- and its unresolvable calls -- into this crate's test
    // binary. Placeholders under `cfg(test)` keep every caller reachable from a
    // crate test linkable; runtime builds install the real addresses. This is
    // the same substitution `gateway_exit_addresses` used to make on its own,
    // now made once at the leaves so a test may call the getters directly.
    macro_rules! exit_address {
        ($name:ident, $symbol:ident) => {
            #[cfg(not(test))]
            pub fn $name() -> u64 {
                $symbol as *const () as usize as u64
            }

            #[cfg(test)]
            pub fn $name() -> u64 {
                0
            }
        };
    }

    exit_address!(syscall_exit_address, carrick_dsr_exit_syscall);
    exit_address!(direct_exit_address, carrick_dsr_exit_direct);
    exit_address!(indirect_exit_address, carrick_dsr_exit_indirect);
    exit_address!(sensitive_exit_address, carrick_dsr_exit_sensitive);
    exit_address!(unsupported_exit_address, carrick_dsr_exit_unsupported);
    exit_address!(signal_exit_address, carrick_dsr_exit_signal);

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
            std::ptr::null(),
            std::ptr::null(),
            true,
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
            std::ptr::null(),
            std::ptr::null(),
            true,
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
            std::ptr::null(),
            std::ptr::null(),
            true,
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
            std::ptr::null(),
            std::ptr::null(),
            true,
        )
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "process entry carries its stable executable catalog authority"
    )]
    pub fn enter_translated_with_cache_range_and_catalog(
        entry: CacheVa,
        snapshot: &mut NativeUcontextSnapshot,
        exit: &mut NativeDsrExit,
        indirect_cache: &IndirectTargetCache,
        cache_start: usize,
        cache_end: usize,
        address_mode: carrick_dsr::address::NativeAddressMode,
        executable_range_catalog: *const ExecutableRangeCatalogHeader,
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
            std::ptr::null(),
            executable_range_catalog,
            true,
        )
    }

    pub fn enter_translated_with_trusted_private_cache(
        entry: CacheVa,
        snapshot: &mut NativeUcontextSnapshot,
        exit: &mut NativeDsrExit,
        indirect_cache: &IndirectTargetCache,
        address_mode: carrick_dsr::address::NativeAddressMode,
    ) -> Result<(), DsrError> {
        enter_translated_raw(
            entry,
            snapshot,
            exit,
            indirect_cache.as_ptr(),
            CodeGeneration::INITIAL,
            0,
            usize::MAX,
            address_mode,
            std::ptr::null(),
            std::ptr::null(),
            false,
        )
    }

    pub fn enter_translated_with_generation_bindings(
        entry: CacheVa,
        snapshot: &mut NativeUcontextSnapshot,
        exit: &mut NativeDsrExit,
        generation_bindings: &[GenerationBinding],
    ) -> Result<(), DsrError> {
        if generation_bindings.is_empty() {
            return Err(DsrError::Gateway(
                "binding-index block entered without generation bindings".to_string(),
            ));
        }
        enter_translated_raw(
            entry,
            snapshot,
            exit,
            std::ptr::null(),
            CodeGeneration::INITIAL,
            0,
            usize::MAX,
            carrick_dsr::address::NativeAddressMode::Direct,
            generation_bindings.as_ptr(),
            std::ptr::null(),
            true,
        )
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "shared entry pins its cache and generation-table authorities"
    )]
    pub fn enter_translated_with_cache_range_and_generation_bindings(
        entry: CacheVa,
        snapshot: &mut NativeUcontextSnapshot,
        exit: &mut NativeDsrExit,
        indirect_cache: &IndirectTargetCache,
        cache_start: usize,
        cache_end: usize,
        address_mode: carrick_dsr::address::NativeAddressMode,
        generation_bindings: &[GenerationBinding],
    ) -> Result<(), DsrError> {
        if generation_bindings.is_empty() {
            return Err(DsrError::Gateway(
                "shared block entered without generation bindings".to_string(),
            ));
        }
        enter_translated_raw(
            entry,
            snapshot,
            exit,
            indirect_cache.as_ptr(),
            CodeGeneration::INITIAL,
            cache_start,
            cache_end,
            address_mode,
            generation_bindings.as_ptr(),
            std::ptr::null(),
            true,
        )
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "shared process entry pins cache, generation, and catalog authorities"
    )]
    pub fn enter_translated_with_cache_range_and_generation_bindings_and_catalog(
        entry: CacheVa,
        snapshot: &mut NativeUcontextSnapshot,
        exit: &mut NativeDsrExit,
        indirect_cache: &IndirectTargetCache,
        cache_start: usize,
        cache_end: usize,
        address_mode: carrick_dsr::address::NativeAddressMode,
        generation_bindings: &[GenerationBinding],
        executable_range_catalog: *const ExecutableRangeCatalogHeader,
    ) -> Result<(), DsrError> {
        if generation_bindings.is_empty() {
            return Err(DsrError::Gateway(
                "shared block entered without generation bindings".to_string(),
            ));
        }
        enter_translated_raw(
            entry,
            snapshot,
            exit,
            indirect_cache.as_ptr(),
            CodeGeneration::INITIAL,
            cache_start,
            cache_end,
            address_mode,
            generation_bindings.as_ptr(),
            executable_range_catalog,
            true,
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
        generation_bindings: *const GenerationBinding,
        executable_range_catalog: *const ExecutableRangeCatalogHeader,
        enforce_cache_authority: bool,
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
        context.generation_bindings = generation_bindings;
        context.executable_range_catalog = executable_range_catalog;
        context.enforce_cache_authority = u32::from(enforce_cache_authority);
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
            2 => decode_direct_exit(&context),
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
                physical_reserved: context.physical_reserved,
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
                physical_reserved: context.physical_reserved,
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

    #[allow(
        clippy::too_many_arguments,
        reason = "matches the live process gateway entry signature"
    )]
    pub fn enter_translated_with_cache_range_and_catalog(
        _entry: CacheVa,
        _snapshot: &mut NativeUcontextSnapshot,
        _exit: &mut NativeDsrExit,
        _indirect_cache: &IndirectTargetCache,
        _cache_start: usize,
        _cache_end: usize,
        _address_mode: carrick_dsr::address::NativeAddressMode,
        _executable_range_catalog: *const ExecutableRangeCatalogHeader,
    ) -> Result<(), DsrError> {
        Err(DsrError::Gateway(GATEWAY_UNAVAILABLE.to_string()))
    }

    pub fn enter_translated_with_trusted_private_cache(
        _entry: CacheVa,
        _snapshot: &mut NativeUcontextSnapshot,
        _exit: &mut NativeDsrExit,
        _indirect_cache: &IndirectTargetCache,
        _address_mode: carrick_dsr::address::NativeAddressMode,
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

    pub fn enter_translated_with_generation_bindings(
        _entry: CacheVa,
        _snapshot: &mut NativeUcontextSnapshot,
        _exit: &mut NativeDsrExit,
        _generation_bindings: &[GenerationBinding],
    ) -> Result<(), DsrError> {
        Err(DsrError::Gateway(GATEWAY_UNAVAILABLE.to_string()))
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "matches the live shared gateway entry signature"
    )]
    pub fn enter_translated_with_cache_range_and_generation_bindings(
        _entry: CacheVa,
        _snapshot: &mut NativeUcontextSnapshot,
        _exit: &mut NativeDsrExit,
        _indirect_cache: &IndirectTargetCache,
        _cache_start: usize,
        _cache_end: usize,
        _address_mode: carrick_dsr::address::NativeAddressMode,
        _generation_bindings: &[GenerationBinding],
    ) -> Result<(), DsrError> {
        Err(DsrError::Gateway(GATEWAY_UNAVAILABLE.to_string()))
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "matches the live shared process gateway entry signature"
    )]
    pub fn enter_translated_with_cache_range_and_generation_bindings_and_catalog(
        _entry: CacheVa,
        _snapshot: &mut NativeUcontextSnapshot,
        _exit: &mut NativeDsrExit,
        _indirect_cache: &IndirectTargetCache,
        _cache_start: usize,
        _cache_end: usize,
        _address_mode: carrick_dsr::address::NativeAddressMode,
        _generation_bindings: &[GenerationBinding],
        _executable_range_catalog: *const ExecutableRangeCatalogHeader,
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
    fn indirect_cache_uses_compact_two_way_2mib_layout() {
        assert_eq!(INDIRECT_CACHE_ENTRIES, 32_768);
        assert_eq!(std::mem::size_of::<IndirectTargetCacheEntry>(), 32);
        assert_eq!(
            INDIRECT_CACHE_ENTRIES * 2 * std::mem::size_of::<IndirectTargetCacheEntry>(),
            2 * 1024 * 1024,
        );
    }

    #[test]
    fn two_colliding_guests_remain_reachable_in_cache_ways() {
        let first = carrick_guest_mem::GuestVa(0x40_000);
        let mut guests = vec![first];
        guests.extend(
            (0x40_004..)
                .step_by(4)
                .map(carrick_guest_mem::GuestVa)
                .filter(|guest| indirect_cache_index(*guest) == indirect_cache_index(first))
                .take(1),
        );
        assert_eq!(guests.len(), 2);
        let mut cache = IndirectTargetCache::new();
        let authority = TargetCacheAuthority::new(0x10_000, 0x20_000, std::ptr::null());
        for (index, guest) in guests.iter().copied().enumerate() {
            cache.publish(
                guest,
                CodeGeneration::INITIAL,
                CacheVa::published(carrick_guest_mem::HostVa(0x10_000 + index * 0x1000)),
                &authority,
            );
        }

        let set = &cache.entries[indirect_cache_index(first)];
        for (way, guest) in guests.into_iter().enumerate() {
            assert_eq!(set.ways[way].guest, guest.raw());
        }
    }

    #[test]
    fn mixed_index_separates_old_page_offset_aliases() {
        let first = carrick_guest_mem::GuestVa(0x42_000);
        let second = carrick_guest_mem::GuestVa(0x48_000);
        assert_ne!(indirect_cache_index(first), indirect_cache_index(second));
    }

    #[test]
    fn direct_binding_fields_append_without_moving_the_existing_gateway_abi() {
        assert_eq!(std::mem::offset_of!(DsrContext, cache_end), 1184);
        assert_eq!(std::mem::offset_of!(DsrContext, host_bias), 1192);
        assert_eq!(
            std::mem::offset_of!(DsrContext, biased_guest_fault_address),
            1200
        );
        assert_eq!(std::mem::offset_of!(DsrContext, generation_bindings), 1264);
        assert_eq!(std::mem::offset_of!(DsrContext, indirect_cache), 1272);
        assert_eq!(std::mem::offset_of!(DsrContext, direct_binding_cell), 1280);
        assert_eq!(
            std::mem::offset_of!(DsrContext, direct_binding_ordinal),
            1288
        );
        assert_eq!(
            std::mem::offset_of!(DsrContext, direct_binding_present),
            1292
        );
        assert_eq!(
            std::mem::offset_of!(DsrContext, direct_binding_target),
            1296
        );
        assert_eq!(
            std::mem::offset_of!(DsrContext, executable_range_catalog),
            1304
        );
        assert_eq!(std::mem::size_of::<DsrContext>(), 1312);
    }

    #[test]
    fn executable_range_catalog_layout_matches_the_signal_bridge_abi() {
        assert_eq!(std::mem::size_of::<ExecutableRangeCatalogHeader>(), 8);
        assert_eq!(std::mem::align_of::<ExecutableRangeCatalogHeader>(), 8);
        assert_eq!(std::mem::offset_of!(ExecutableRangeCatalogHeader, head), 0);
        assert_eq!(std::mem::size_of::<ExecutableRangeCatalogNode>(), 24);
        assert_eq!(std::mem::align_of::<ExecutableRangeCatalogNode>(), 8);
        assert_eq!(std::mem::offset_of!(ExecutableRangeCatalogNode, start), 0);
        assert_eq!(std::mem::offset_of!(ExecutableRangeCatalogNode, end), 8);
        assert_eq!(std::mem::offset_of!(ExecutableRangeCatalogNode, next), 16);
    }

    #[test]
    fn gateway_executable_range_prepare_keeps_head_unpublished_until_commit() {
        let mut catalog =
            ExecutableRangeCatalog::new(0x10_000, 0x20_000).expect("private cache range");
        let private_head = catalog.head_ptr();
        let private_nodes = catalog.shared_node_count();
        let mut context = DsrContext::new(
            NativeUcontextSnapshot::default(),
            CacheVa::published(carrick_guest_mem::HostVa(0x10_000)),
            NativeDsrExit::Syscall {
                resume: carrick_guest_mem::GuestVa(0x4000),
            },
            std::ptr::null(),
            CodeGeneration::INITIAL,
            0x10_000,
            0x20_000,
            carrick_dsr::address::NativeAddressMode::Direct,
        );
        context.executable_range_catalog = catalog.header_ptr();
        let header = context.executable_range_catalog as usize;
        let prepared = catalog
            .prepare_prepend(0x30_000, 0x40_000)
            .expect("prepare shared cache range");

        assert_eq!(catalog.head_ptr(), private_head);
        assert_eq!(catalog.shared_node_count(), private_nodes);
        assert!(!catalog.contains(0x38_000));

        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    catalog.commit_prepend(prepared);
                })
                .join()
                .expect("join catalog publisher");
        });

        // SAFETY: `catalog` owns the stable header and every immutable node
        // through this traversal.
        assert!(unsafe {
            executable_range_catalog_contains(
                header as *const ExecutableRangeCatalogHeader,
                0x38_000,
            )
        });
    }

    #[test]
    fn direct_exit_decodes_an_exact_typed_binding_miss() {
        let mut context = DsrContext::new(
            NativeUcontextSnapshot::default(),
            CacheVa::published(carrick_guest_mem::HostVa(0x10_000)),
            NativeDsrExit::ResolveDirect {
                source: carrick_guest_mem::GuestVa(0x4000),
                target: carrick_guest_mem::GuestVa(0x5000),
                binding: DirectBindingExitMetadata::Absent,
            },
            std::ptr::null(),
            CodeGeneration::INITIAL,
            0x10_000,
            0x20_000,
            carrick_dsr::address::NativeAddressMode::Direct,
        );
        context.direct_binding_cell = 0x20_000;
        context.direct_binding_ordinal = 7;
        context.direct_binding_present = 1;

        assert_eq!(
            decode_direct_exit(&context),
            NativeDsrExit::ResolveDirect {
                source: carrick_guest_mem::GuestVa(0x4000),
                target: carrick_guest_mem::GuestVa(0x5000),
                binding: crate::direct_binding::DirectBindingExitMetadata::Mapped(
                    crate::direct_binding::DirectBindingMiss {
                        cell: crate::direct_binding::DirectBindingCellVa::mapped(0x20_000)
                            .expect("aligned cell"),
                        ordinal: crate::direct_binding::DirectBindingOrdinal::claimed(7),
                    },
                ),
            }
        );

        for (present, cell) in [(0, 0x20_000), (2, 0x20_000)] {
            context.direct_binding_present = present;
            context.direct_binding_cell = cell;
            assert_eq!(
                decode_direct_exit(&context),
                NativeDsrExit::ResolveDirect {
                    source: carrick_guest_mem::GuestVa(0x4000),
                    target: carrick_guest_mem::GuestVa(0x5000),
                    binding: crate::direct_binding::DirectBindingExitMetadata::Absent,
                }
            );
        }
        for cell in [0, 0x20_001] {
            context.direct_binding_present = 1;
            context.direct_binding_cell = cell;
            assert_eq!(
                decode_direct_exit(&context),
                NativeDsrExit::ResolveDirect {
                    source: carrick_guest_mem::GuestVa(0x4000),
                    target: carrick_guest_mem::GuestVa(0x5000),
                    binding: crate::direct_binding::DirectBindingExitMetadata::MappedCellFailure {
                        raw_cell: cell,
                        ordinal: crate::direct_binding::DirectBindingOrdinal::claimed(7),
                    },
                }
            );
        }
    }

    #[test]
    fn new_context_clears_stale_binding_authority_for_every_exit_kind() {
        let guest = carrick_guest_mem::GuestVa(0x4000);
        let exits = [
            NativeDsrExit::Syscall { resume: guest },
            NativeDsrExit::ResolveDirect {
                source: guest,
                target: guest,
                binding: DirectBindingExitMetadata::Absent,
            },
            NativeDsrExit::ResolveIndirect {
                source: guest,
                target: guest,
                link: Some(guest),
            },
            NativeDsrExit::Sensitive {
                guest_pc: guest,
                resume: guest,
                generation: CodeGeneration::INITIAL,
            },
            NativeDsrExit::Fault {
                guest_pc: guest,
                signal: libc::SIGSEGV,
                code: 0,
                address: carrick_guest_mem::HostVa(0x20_000),
                rewrite_scratch: 0,
                rewrite_context_scratch: 0,
                generation_pstate_scratch: 0,
                indirect_x15_scratch: 0,
                indirect_x30_scratch: 0,
                physical_x18: 0,
                physical_reserved: 0,
                gateway_phase: 0,
                biased_guest_fault_address: 0,
            },
            NativeDsrExit::Kick {
                resume: guest,
                rewrite_scratch: 0,
                rewrite_context_scratch: 0,
                generation_pstate_scratch: 0,
                indirect_x15_scratch: 0,
                indirect_x30_scratch: 0,
                physical_reserved: 0,
            },
            NativeDsrExit::KickAtEntry { resume: guest },
            NativeDsrExit::StaleGeneration {
                guest_pc: guest,
                observed: CodeGeneration::INITIAL,
            },
            NativeDsrExit::Unsupported {
                guest_pc: guest,
                word: 0,
                op: bad64::Op::UDF,
            },
        ];

        for exit in exits {
            let context = DsrContext::new(
                NativeUcontextSnapshot::default(),
                CacheVa::published(carrick_guest_mem::HostVa(0x10_000)),
                exit,
                std::ptr::null(),
                CodeGeneration::INITIAL,
                0x10_000,
                0x20_000,
                carrick_dsr::address::NativeAddressMode::Direct,
            );
            assert_eq!(context.direct_binding_cell, 0, "exit={exit:?}");
            assert_eq!(context.direct_binding_ordinal, 0, "exit={exit:?}");
            assert_eq!(context.direct_binding_present, 0, "exit={exit:?}");
            assert_eq!(context.direct_binding_target, 0, "exit={exit:?}");
            assert!(context.executable_range_catalog.is_null(), "exit={exit:?}");
        }
    }
}
