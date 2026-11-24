//! Linux reservation ownership, VMA interpretation and charges.
pub mod madvise;
mod reservation;
use carrick_core_abi::*;

pub const LINUX_HEAP_BASE: u64 = 0x40_0000_0000;
pub const LINUX_HEAP_SIZE: u64 = 128 * 1024 * 1024;
pub const LINUX_MMAP_BASE: u64 = 0x60_0000_0000;
pub const LINUX_MMAP_SIZE: u64 = 32 * 1024 * 1024 * 1024;
pub const LINUX_MMAP_SIZE_MAX: u64 = LINUX_PIE_DEFAULT_BASE - LINUX_MMAP_BASE;

/// Default load base for ET_DYN (PIE) main executables. Linux places an
/// ET_DYN image high (`ELF_ET_DYN_BASE = 2/3 * TASK_SIZE`), leaving the low
/// gigabytes FREE for the program's own fixed mappings. The old 4 GiB base
/// violated that: a glibc binary that `MAP_FIXED`s at 0x1_0000_0000 (the
/// `aliassize` probe pins this) clobbered its own image and SIGSEGV'd where
/// Linux succeeds. The Linux-proportional 2/3 point of the 1 TiB guest task
/// size (~683 GiB) is unavailable — it falls inside the HVPatch global-frame
/// IPA arena (620..1016 GiB) — so the base sits in the free identity window
/// below the interpreter image (`LINUX_INTERPRETER_BASE`, 560 GiB) and the
/// shared aperture (`LINUX_SHARED_FILE_BASE`, 576 GiB), 2 MiB-aligned for
/// stage-1 block mappings. The exact value is guest-observable only through
/// /proc/*/maps; the freed low region is what conformance measures.
pub const LINUX_PIE_DEFAULT_BASE: u64 = 0x88_0000_0000;

// Stable shared aperture for guest MAP_SHARED mmaps. The whole window is
// hv_vm_map'd ONCE at boot (host MAP_ANON|MAP_SHARED|MAP_NORESERVE; see
// `linux_runtime_regions`), then guest MAP_SHARED|MAP_ANON and MAP_SHARED file
// mmaps sub-allocate sub-ranges via `shared_aperture::SharedAperture` — no
// post-vCPU hv_vm_map. Kept disjoint from the private anonymous mmap arena.
pub const LINUX_SHARED_FILE_BASE: u64 = 0x90_0000_0000; // 576 GiB
pub const LINUX_SHARED_FILE_SIZE: u64 = 2 * 1024 * 1024 * 1024; // 2 GiB

pub const LINUX_STACK_TOP: u64 = 0xff_ffff_0000; // just under 1 TiB
pub const LINUX_STACK_SIZE: u64 = 8 * 1024 * 1024; // 8 MiB (Linux default RLIMIT_STACK)

// ── Rosetta 2 high-VA alias ──────────────────────────────────────────────────
// Apple's Rosetta Linux interpreter is a non-relocatable ET_EXEC fixed-linked at
// 2^47. M-series HVF caps the guest IPA at 40 bits, so we cannot hv_vm_map at
// that address. Instead — exactly as Apple's Virtualization.framework does via
// the guest kernel's own page tables — we alias the Rosetta VA window down to a
// low IPA: the guest's stage-1 tables translate VA 2^47.. to this low IPA, which
// is what actually gets hv_vm_map'd (well within 40 bits). This is the ONLY
// region whose VA differs from its IPA; everything else stays identity-mapped.
pub const LINUX_ROSETTA_VA_BASE: u64 = 0x8000_0000_0000; // 2^47, Rosetta's link base
pub const LINUX_ROSETTA_WINDOW_SIZE: u64 = 0x20_0000; // 2 MiB (one L2 block; Rosetta ~1.7 MiB)

/// Guest VAs at or above this are aliased to a low IPA rather than mapped
/// identity. Above every identity region (stack top is just under 1 TiB).
pub const LINUX_HIGH_VA_THRESHOLD: u64 = 0x100_0000_0000; // 1 TiB (2^40)

/// Whether `[start, end)` lies in one of the layout's alias windows:
/// outside the anonymous arena `[arena_start, arena_end)`, below the ISA's
/// `user_end`, and either at or above [`LINUX_HIGH_VA_THRESHOLD`] or between
/// the shared aperture and the stack.
pub fn uses_alias_window(
    start: u64,
    end: u64,
    arena_start: u64,
    arena_end: u64,
    user_end: u64,
) -> bool {
    if end > user_end || (arena_start <= start && end <= arena_end) {
        return false;
    }
    if start >= LINUX_HIGH_VA_THRESHOLD {
        return true;
    }
    let alias_low_base = LINUX_SHARED_FILE_BASE + LINUX_SHARED_FILE_SIZE;
    let stack_base = LINUX_STACK_TOP - LINUX_STACK_SIZE;
    alias_low_base <= start && end <= stack_base
}

/// Whether a private anonymous hint outside the allocation layout lies in
/// an aperture no carrier mapping occupies, for `venue`. Both venues refuse
/// the arena and everything below its end, the Rosetta window, and anything
/// past the ISA's user VA end.
///
/// - **Ring** (a ring-only MM editing its own stage-1 tables): only at or
///   above [`LINUX_HIGH_VA_THRESHOLD`]. Below 1 TiB live every carrier
///   window (the EL1 region, vDSO, clock stub, GIC, the private overlay,
///   the AArch64 stage-1 table pool) and, on AArch64 HVPatch, invalidated
///   block descriptors the stage-1 editor refuses; and on x86 CPL0 an
///   `ET_EXEC` image's arena sits low, under those windows. Nothing but
///   Rosetta is mapped above 1 TiB on either ISA (`carrick-mem`'s asserts).
/// - **Host**: also the low alias window and the gap between the arena and
///   the PIE image base; the host venue checks its own VMA rows and carrier
///   windows (`carrick-kernel`) before it offers one.
fn external_anonymous_aperture(
    layout: Layout,
    range: ReservationRange,
    user_end: u64,
    venue: AnonymousHintVenue,
) -> bool {
    let arena = layout.arena;
    let rosetta_end = LINUX_ROSETTA_VA_BASE + LINUX_ROSETTA_WINDOW_SIZE;
    let outside = range.end() <= user_end
        && range.start() >= arena.end()
        && !(range.start() < rosetta_end && LINUX_ROSETTA_VA_BASE < range.end());
    outside
        && match venue {
            AnonymousHintVenue::Ring => range.start() >= LINUX_HIGH_VA_THRESHOLD,
            AnonymousHintVenue::Host => {
                uses_alias_window(
                    range.start(),
                    range.end(),
                    arena.start(),
                    arena.end(),
                    user_end,
                ) || range.end() <= LINUX_PIE_DEFAULT_BASE
            }
        }
}

/// Linux edit authority and rlimit charging for the neutral flag record.
pub trait NodeFlagsPolicy {
    fn root_editable(self) -> bool;
    fn charges_data(self, protection: ReservationProtection) -> bool;
    fn protection_ceiling(self, protection: ReservationProtection) -> ReservationProtection;
}
impl NodeFlagsPolicy for ReservationNodeFlags {
    /// EL1 may edit private anonymous or retained private file nodes,
    /// preserving their carried attributes. File nodes additionally require
    /// a retained source in the production reservation node.
    fn root_editable(self) -> bool {
        let kind = self.bits() & !Self::CARRIED.bits();
        kind == Self::ANONYMOUS_PRIVATE.bits() || kind == (Self::PRIVATE.bits() | Self::FILE.bits())
    }
    /// `RLIMIT_DATA` covers private writable non-stack mappings (getrlimit(2),
    /// mmap(2)); shared, stack and read-only nodes are not charged.
    fn charges_data(self, protection: ReservationProtection) -> bool {
        self.contains(Self::PRIVATE)
            && !self.contains(Self::GROWSDOWN)
            && protection.bits() & 2 != 0
    }
    /// A private mapping may take any protection (mprotect(2)). A shared
    /// mapping of a description not open for writing may never become
    /// writable (mprotect(2), EACCES). Other shared mappings conservatively
    /// cap at their committed `protection`.
    fn protection_ceiling(self, protection: ReservationProtection) -> ReservationProtection {
        if self.contains(Self::SHARED_READ_ONLY) {
            ReservationProtection::READ_EXECUTE
        } else if self.contains(Self::PRIVATE) {
            ReservationProtection::READ_WRITE_EXECUTE
        } else {
            protection
        }
    }
}
/// Linux-owned state projected through the neutral root's opaque wire payload.
#[derive(::core::clone::Clone, ::core::marker::Copy, ::core::fmt::Debug)]
#[repr(C)]
pub struct LinuxReservationState {
    pub brk: u64,
    pub address_limit: u64,
    pub data_limit: u64,
    pub external_address_bytes: u64,
    pub external_data_bytes: u64,
}
impl From<ReservationPolicyPayload> for LinuxReservationState {
    fn from(payload: ReservationPolicyPayload) -> Self {
        let [
            brk,
            address_limit,
            data_limit,
            external_address_bytes,
            external_data_bytes,
        ] = payload.words();
        Self {
            brk,
            address_limit,
            data_limit,
            external_address_bytes,
            external_data_bytes,
        }
    }
}
impl From<LinuxReservationState> for ReservationPolicyPayload {
    fn from(state: LinuxReservationState) -> Self {
        Self::new([
            state.brk,
            state.address_limit,
            state.data_limit,
            state.external_address_bytes,
            state.external_data_bytes,
        ])
    }
}
/// Linux admission record. This is an input projection, never a second store.
#[derive(::core::clone::Clone, ::core::marker::Copy, ::core::fmt::Debug)]
#[repr(C)]
pub struct LinuxReservationLayout {
    pub heap: ReservationRange,
    pub arena: ReservationRange,
    pub brk: u64,
    pub address_limit: u64,
    pub data_limit: u64,
    pub external_address_bytes: u64,
    pub external_data_bytes: u64,
}
impl From<LinuxReservationLayout> for Layout {
    fn from(l: LinuxReservationLayout) -> Self {
        Self {
            heap: l.heap,
            arena: l.arena,
            policy: LinuxReservationState {
                brk: l.brk,
                address_limit: l.address_limit,
                data_limit: l.data_limit,
                external_address_bytes: l.external_address_bytes,
                external_data_bytes: l.external_data_bytes,
            }
            .into(),
        }
    }
}
impl From<Layout> for LinuxReservationLayout {
    fn from(l: Layout) -> Self {
        let state = LinuxReservationState::from(l.policy);
        Self {
            heap: l.heap,
            arena: l.arena,
            brk: state.brk,
            address_limit: state.address_limit,
            data_limit: state.data_limit,
            external_address_bytes: state.external_address_bytes,
            external_data_bytes: state.external_data_bytes,
        }
    }
}

/// Linux interpretation of the one neutral root store.
pub struct LinuxReservationPolicy;
impl carrick_core_abi::ReservationPolicy for LinuxReservationPolicy {
    fn validates_layout(layout: Layout) -> bool {
        let brk = LinuxReservationState::from(layout.policy).brk;
        layout.heap.contains(brk) || brk == layout.heap.end()
    }
    fn external_anonymous_aperture(
        layout: Layout,
        range: ReservationRange,
        user_end: u64,
        venue: AnonymousHintVenue,
    ) -> bool {
        external_anonymous_aperture(layout, range, user_end, venue)
    }
    fn active_value(policy: ReservationPolicyPayload) -> u64 {
        LinuxReservationState::from(policy).brk
    }
    fn apply_value(policy: &mut ReservationPolicyPayload, value: u64) {
        let mut state = LinuxReservationState::from(*policy);
        state.brk = value;
        *policy = state.into();
    }
    fn admits_charges(
        policy: ReservationPolicyPayload,
        total: Charges,
        removed: Charges,
        added: Charges,
    ) -> Result<(), Refusal> {
        let layout = LinuxReservationState::from(policy);
        reservation::admits_charges(layout, total, removed, added)
    }
    fn update_limits(policy: &mut ReservationPolicyPayload, address: u64, data: u64) {
        let mut state = LinuxReservationState::from(*policy);
        state.address_limit = address;
        state.data_limit = data;
        *policy = state.into();
    }
    fn update_external_charges(policy: &mut ReservationPolicyPayload, address: u64, data: u64) {
        let mut state = LinuxReservationState::from(*policy);
        state.external_address_bytes = address;
        state.external_data_bytes = data;
        *policy = state.into();
    }
    fn authenticates_maintenance(
        layout: Layout,
        request: ReservationRequest,
        pending_value: u64,
    ) -> bool {
        let old = LinuxReservationState::from(layout.policy).brk;
        request.operation == ReservationOperation::Retire
            && request.protection == ReservationProtection::NONE
            && request.source.is_none()
            && pending_value < old
            && pending_value.checked_add(4095).map(|end| end & !4095) == Some(request.range.start())
            && old.checked_add(4095).map(|end| end & !4095) == Some(request.range.end())
    }
    fn validates_attributes(node: &ReservationNodeData, set: ReservationNodeFlags) -> bool {
        !set.contains(ReservationNodeFlags::WIPEONFORK)
            || Self::flags(node).contains(ReservationNodeFlags::ANONYMOUS_PRIVATE)
    }
    fn inherits(node: &ReservationNodeData) -> bool {
        !Self::flags(node).contains(ReservationNodeFlags::DONTFORK)
    }

    fn place<M: carrick_core_abi::ReservationPolicyAccess>(
        root: &mut M,
        placement: Placement,
        len: GuestLen,
    ) -> Result<ReservationRange, Refusal> {
        reservation::place(root, placement, len)
    }
    fn mmap<M: carrick_core_abi::ReservationPolicyAccess>(
        root: &mut M,
        placement: Placement,
        len: GuestLen,
        protection: ReservationProtection,
    ) -> Result<Decision, Refusal> {
        reservation::mmap(root, placement, len, protection)
    }
    fn mmap_private_file<M: carrick_core_abi::ReservationPolicyAccess>(
        root: &mut M,
        placement: Placement,
        len: GuestLen,
        protection: ReservationProtection,
        backing: HostBackingIdentity,
        sharing: FileMapSharing,
    ) -> Result<Decision, Refusal> {
        reservation::mmap_private_file(root, placement, len, protection, backing, sharing)
    }
    fn mremap<M: carrick_core_abi::ReservationPolicyAccess>(
        root: &mut M,
        source: ReservationRange,
        new_len: GuestLen,
        target: MoveTarget,
    ) -> Result<Decision, Refusal> {
        reservation::mremap(root, source, new_len, target)
    }
    fn brk<M: carrick_core_abi::ReservationPolicyAccess>(
        root: &mut M,
        requested: UserVa,
    ) -> Result<Decision, Refusal> {
        reservation::brk(root, requested)
    }
    fn root_editable(node: &ReservationNodeData) -> bool {
        Self::flags(node).root_editable()
            && (!Self::flags(node).contains(ReservationNodeFlags::FILE)
                || node.host_backing.is_some())
    }
    fn flags(node: &ReservationNodeData) -> ReservationNodeFlags {
        // Nodes are only written from validated flags.
        ReservationNodeFlags::from_bits(u32::from(node.flags))
            .unwrap_or(ReservationNodeFlags::EMPTY)
    }
    fn protection(node: &ReservationNodeData) -> ReservationProtection {
        ReservationProtection::from_bits(u64::from(node.prot))
            .unwrap_or(ReservationProtection::NONE)
    }
    fn protection_ceiling(node: &ReservationNodeData) -> ReservationProtection {
        Self::flags(node).protection_ceiling(Self::protection(node))
    }
    fn charged_data(node: &ReservationNodeData) -> u64 {
        if Self::charges_data(Self::flags(node), Self::protection(node)) {
            node.end - node.start
        } else {
            0
        }
    }
    fn charged_locked(node: &ReservationNodeData) -> u64 {
        if Self::flags(node).contains(ReservationNodeFlags::ANONYMOUS)
            && Self::flags(node).contains(ReservationNodeFlags::LOCKED)
        {
            node.end - node.start
        } else {
            0
        }
    }
    /// Charges of the part of this one node inside `[start, end)`.
    fn charges_within(node: &ReservationNodeData, start: u64, end: u64) -> Charges {
        let bytes = node.end.min(end).saturating_sub(node.start.max(start));
        Charges {
            bytes,
            data: if Self::charged_data(node) != 0 {
                bytes
            } else {
                0
            },
            locked: if Self::charged_locked(node) != 0 {
                bytes
            } else {
                0
            },
        }
    }
    fn mapping(
        node: &ReservationNodeData,
        generation: ReservationGeneration,
    ) -> Result<Mapping, Refusal> {
        // Nodes are only constructed from validated ABI ranges/protections.
        Ok(Mapping {
            range: ReservationRange::new(node.start, node.end).ok_or(Refusal::Invalid)?,
            protection: Self::protection(node),
            anonymous: Self::flags(node).contains(ReservationNodeFlags::ANONYMOUS),
            flags: Self::flags(node),
            generation,
            host_backing: node.host_backing,
        })
    }
    /// Whether an adjacent node is the same Linux mapping (a VMA boundary
    /// the tree keeps only to separate incarnations).
    fn same_mapping(node: &ReservationNodeData, other: &ReservationNodeData) -> bool {
        node.prot == other.prot
            && node.flags == other.flags
            && match (node.host_backing, other.host_backing) {
                (None, None) => true,
                (Some(a), Some(b)) if node.start <= other.start => {
                    a.advance(other.start - node.start) == Some(b)
                }
                (Some(a), Some(b)) => b.advance(node.start - other.start) == Some(a),
                _ => false,
            }
    }
    fn charges_data(flags: ReservationNodeFlags, protection: ReservationProtection) -> bool {
        flags.charges_data(protection)
    }
}

use carrick_core::mm::transaction::MmError;
/// Linux wire encoding of the neutral owner's typed refusal.
pub trait MmErrorLinux {
    fn errno(self) -> u32;
}
impl MmErrorLinux for MmError {
    fn errno(self) -> u32 {
        match self {
            Self::Fault => 14,
            Self::UnsupportedExecutableCow => 95,
            Self::Stale => 3,
            Self::Busy | Self::ParentChanged => 16,
            Self::NoMemory => 12,
            Self::MetadataRequired | Self::Wait(_) => 11,
            Self::Invalid => 22,
            Self::Core | Self::Reservation(_) | Self::Table(_) => 5,
        }
    }
}

pub const fn cancelled_copy_errno() -> u32 {
    125
}

#[cfg(test)]
mod aperture_tests {
    use super::*;
    use carrick_guest_arch::{AARCH64_USER_VA_END, X86_64_USER_VA_END};

    fn r(start: u64, end: u64) -> ReservationRange {
        ReservationRange::new(start, end).expect("aligned fixture range")
    }
    fn layout() -> Layout {
        LinuxReservationLayout {
            heap: r(LINUX_HEAP_BASE, LINUX_HEAP_BASE + LINUX_HEAP_SIZE),
            arena: r(LINUX_MMAP_BASE, LINUX_MMAP_BASE + LINUX_MMAP_SIZE),
            brk: LINUX_HEAP_BASE,
            address_limit: u64::MAX,
            data_limit: u64::MAX,
            external_address_bytes: 0,
            external_data_bytes: 0,
        }
        .into()
    }
    fn free_for(venue: AnonymousHintVenue, start: u64, len: u64, end: u64) -> bool {
        external_anonymous_aperture(layout(), r(start, start + len), end, venue)
    }
    fn ring(start: u64, len: u64, end: u64) -> bool {
        free_for(AnonymousHintVenue::Ring, start, len, end)
    }
    fn host(start: u64, len: u64, end: u64) -> bool {
        free_for(AnonymousHintVenue::Host, start, len, end)
    }

    /// V8's cage hint (#2706) is free to both venues on both ISAs. Below
    /// 1 TiB only the host venue, which checks its own VMA rows and carrier
    /// windows, is offered Go's arena hint and the gap above the arena
    /// (#2950 review: HVPatch's invalidated blocks and the carrier windows
    /// live there). The arena, the image, the shared aperture, the stack,
    /// Rosetta and anything past the ISA's user VA end are free to neither.
    #[test]
    fn external_anonymous_apertures_follow_the_venue_layout_and_isa_end() {
        let arena_end = LINUX_MMAP_BASE + LINUX_MMAP_SIZE;
        for end in [AARCH64_USER_VA_END, X86_64_USER_VA_END] {
            for free in [ring, host] {
                assert!(free(0x2517_7424_0000, 0x7f000, end), "V8 cage hint");
                assert!(free(LINUX_HIGH_VA_THRESHOLD, 0x1000, end), "1 TiB");
                assert!(!free(LINUX_MMAP_BASE, 0x1000, end), "inside the arena");
                assert!(!free(0x1000_0000, 0x1000, end), "below the arena");
                assert!(!free(LINUX_PIE_DEFAULT_BASE, 0x1000, end), "PIE image");
                assert!(!free(LINUX_SHARED_FILE_BASE, 0x1000, end), "shared");
                assert!(!free(LINUX_STACK_TOP - 0x1000, 0x1000, end), "stack");
                assert!(
                    !free(LINUX_PIE_DEFAULT_BASE - 0x1000, 0x2000, end),
                    "straddles PIE"
                );
            }
            assert!(host(0xc0_0000_0000, 0x400_0000, end), "Go arena hint");
            assert!(host(arena_end, 0x1000, end), "gap above the arena");
            assert!(!ring(0xc0_0000_0000, 0x400_0000, end), "Go arena hint");
            assert!(!ring(arena_end, 0x1000, end), "gap above the arena");
            assert!(!ring(0x9a_0000_0000, 0x1000, end), "stage-1 table pool");
            assert!(!ring(0x98_0000_0000, 0x1000, end), "private overlay");
            assert!(
                !ring(LINUX_HIGH_VA_THRESHOLD - 0x1000, 0x2000, end),
                "straddles 1 TiB"
            );
        }
        for free in [ring, host] {
            // The x86 end is the last lower-half page; AArch64 reaches 2^48.
            assert!(!free(X86_64_USER_VA_END, 0x1000, X86_64_USER_VA_END));
            assert!(free(
                X86_64_USER_VA_END - 0x1000,
                0x1000,
                X86_64_USER_VA_END
            ));
            assert!(!free(1 << 47, 0x1000, X86_64_USER_VA_END));
            assert!(free(
                (1 << 47) + LINUX_ROSETTA_WINDOW_SIZE,
                0x1000,
                AARCH64_USER_VA_END
            ));
            assert!(
                !free(LINUX_ROSETTA_VA_BASE, 0x1000, AARCH64_USER_VA_END),
                "Rosetta window"
            );
            assert!(!free(
                AARCH64_USER_VA_END - 0x1000,
                0x2000,
                AARCH64_USER_VA_END
            ));
        }
    }

    /// An x86 `ET_EXEC` image's arena sits low (`[1 GiB, 33 GiB)`), under
    /// the EL1 region, vDSO and trampoline windows: the ring venue still
    /// offers nothing below 1 TiB there.
    #[test]
    fn a_low_arena_never_opens_the_carrier_windows_to_the_ring() {
        let low = LinuxReservationLayout {
            heap: r(0x40_0000, 0x4000_0000),
            arena: r(0x4000_0000, 0x8_4000_0000),
            brk: 0x40_0000,
            address_limit: u64::MAX,
            data_limit: u64::MAX,
            external_address_bytes: 0,
            external_data_bytes: 0,
        }
        .into();
        for hint in [
            0x2d_0400_0000,
            0x2e_0000_0000,
            0x30_0000_0000,
            0xc0_0000_0000,
        ] {
            assert!(!external_anonymous_aperture(
                low,
                r(hint, hint + 0x1000),
                X86_64_USER_VA_END,
                AnonymousHintVenue::Ring
            ));
        }
    }
}

#[cfg(test)]
mod flag_tests {
    use super::*;
    #[test]
    fn reservation_node_flags_classify_data_and_root_ownership() {
        let rw = ReservationProtection::READ_WRITE;
        let anon = ReservationNodeFlags::ANONYMOUS_PRIVATE;
        assert!(anon.root_editable());
        assert!(anon.charges_data(rw));
        assert!(!anon.charges_data(ReservationProtection::NONE));
        // Shared writable: not RLIMIT_DATA.
        assert!(!ReservationNodeFlags::ANONYMOUS.charges_data(rw));
        assert!(!ReservationNodeFlags::ANONYMOUS.root_editable());
        // Stack: not RLIMIT_DATA, host-owned.
        let stack = anon.union(ReservationNodeFlags::GROWSDOWN);
        assert!(!stack.charges_data(rw));
        assert!(!stack.root_editable());
        // Private writable opaque (file) mapping is charged.
        assert!(ReservationNodeFlags::PRIVATE.charges_data(rw));
        for flag in [
            ReservationNodeFlags::LOCKED,
            ReservationNodeFlags::DONTFORK,
            ReservationNodeFlags::WIPEONFORK,
            ReservationNodeFlags::DONTDUMP,
        ] {
            assert!(anon.union(flag).root_editable());
            assert!(ReservationNodeFlags::CARRIED.contains(flag));
            assert!(ReservationNodeFlags::ATTRIBUTES.contains(flag));
            assert!(!ReservationNodeFlags::PRIVATE.union(flag).root_editable());
        }
        // The import-only image mark rides edits but is no host attribute.
        let image = ReservationNodeFlags::IMAGE;
        assert!(ReservationNodeFlags::CARRIED.contains(image));
        assert!(!ReservationNodeFlags::ATTRIBUTES.contains(image));
        assert!(anon.union(image).root_editable());
        assert_eq!(
            anon.protection_ceiling(ReservationProtection::NONE),
            ReservationProtection::READ_WRITE_EXECUTE
        );
        assert_eq!(
            ReservationNodeFlags::PRIVATE
                .union(ReservationNodeFlags::FILE)
                .protection_ceiling(ReservationProtection::READ),
            ReservationProtection::READ_WRITE_EXECUTE
        );
        assert_eq!(
            ReservationNodeFlags::ANONYMOUS.protection_ceiling(ReservationProtection::READ),
            ReservationProtection::READ
        );
        // A read-only shared file mapping: private byte-source custody the
        // ring edits, carried by every edit, never writable, never charged.
        let shared = ReservationNodeFlags::PRIVATE
            .union(ReservationNodeFlags::FILE)
            .union(ReservationNodeFlags::SHARED_READ_ONLY);
        assert!(shared.root_editable());
        assert!(ReservationNodeFlags::CARRIED.contains(ReservationNodeFlags::SHARED_READ_ONLY));
        assert!(!ReservationNodeFlags::ATTRIBUTES.contains(ReservationNodeFlags::SHARED_READ_ONLY));
        assert_eq!(
            shared.protection_ceiling(ReservationProtection::READ),
            ReservationProtection::READ_EXECUTE
        );
        assert_eq!(ReservationNodeFlags::from_bits(1 << 12), None);
    }
}
