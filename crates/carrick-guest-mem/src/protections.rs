//! Process-wide guest-VMA protection bookkeeping, shared by every backend.
//!
//! When the guest `mprotect(PROT_NONE)`s (or `munmap`s) a range, a later
//! syscall whose buffer overlaps that range must fault with `EFAULT` exactly as
//! Linux would — even though the host backing is still physically accessible
//! (the host-side check; making the GUEST's own EL0 access fault needs stage-1
//! edits + signal injection, which the page-table managers handle separately).
//!
//! These sets are the single source of truth for that host-side check and keep
//! mapped `PROT_NONE` distinct from post-`munmap` holes for Linux `si_code`.
//! They are
//! **process-wide**: sibling vCPU threads (a `clone(CLONE_VM)` thread group run
//! on one VM) MUST share ONE instance — wrapped in [`std::sync::Arc`] — so a
//! `mprotect` made by any guest thread is observed by every other thread's
//! syscall-path access checks. A thread-local copy silently diverges: one
//! thread reserves a region `PROT_NONE`, another commits it `PROT_READ|WRITE`,
//! and the first thread then wrongly faults a perfectly valid buffer there (the
//! Go-runtime-on-KVM `futexwakeup … EFAULT` / `netpollBreak write failed`
//! crashes were exactly this divergence before the set was shared).
//!
//! This type lives in `carrick-guest-mem` (the leaf crate the [`GuestMemory`]
//! trait lives in) so the trait's default `read_bytes`/`write_bytes` can run the
//! gate directly — one shared host-side EFAULT check every backend inherits.
//! `carrick-mem::protections` re-exports it for back-compat.
//!
//! One interior [`parking_lot::RwLock`] covers all VMA-classification sets, so
//! transitions are coherent and the shared `Arc` needs no outer lock. The HVF
//! and KVM backends both hold an `Arc<MemoryProtections>` and clone it into each
//! sibling; a `fork(2)` child gets an INDEPENDENT copy (the Linux COW of the
//! whole process duplicates the underlying `Vec`, or `MemoryProtections::snapshot`
//! plus `MemoryProtections::from_snapshot`); `execve` starts fresh
//! (`MemoryProtections::default`). Mutable `MAP_SHARED` backing is VMA-local
//! metadata, not a process-local write epoch: a second view, `pwrite(2)`, or a
//! forked/external writer can change an RX view without entering this process's
//! mutation hooks. Native translation backends therefore keep every executable
//! shared span permanently ephemeral in each process.
//!
//! [`GuestMemory`]: crate::GuestMemory

use crate::MappingSharing;

/// Sorted, merged, non-overlapping `[start, end)` guest-address ranges with an
/// O(log n) overlap query. The shared building block for the PROT_NONE,
/// unmapped, and read-only sets in [`MemoryProtections`].
#[derive(Default)]
struct RangeSet {
    ranges: Vec<(u64, u64)>,
}

impl RangeSet {
    fn from_ranges(ranges: Vec<(u64, u64)>) -> Self {
        Self { ranges }
    }

    fn snapshot(&self) -> Vec<(u64, u64)> {
        self.ranges.clone()
    }

    /// True if `[address, address+length)` overlaps any range in the set.
    fn contains(&self, address: u64, length: usize) -> bool {
        let end = address.saturating_add(length as u64);
        if end <= address {
            return false;
        }
        let idx = self.ranges.partition_point(|&(_, e)| e <= address);
        self.ranges
            .get(idx)
            .is_some_and(|&(s, e)| address < e && s < end)
    }

    /// Address of the first byte in this set intersecting the query.
    fn first_intersection(&self, address: u64, length: usize) -> Option<u64> {
        let end = address.saturating_add(length as u64);
        if end <= address {
            return None;
        }
        let index = self.ranges.partition_point(|&(_, e)| e <= address);
        self.ranges.get(index).and_then(|&(start, range_end)| {
            let first = start.max(address);
            (first < range_end.min(end)).then_some(first)
        })
    }

    /// Return the exact intersections between `[address,address+length)` and
    /// this set. Native identity backends use this snapshot to restore only
    /// tracked holes without MAP_FIXED-replacing adjacent live bytes.
    fn intersections(&self, address: u64, length: usize) -> Vec<(u64, u64)> {
        let end = address.saturating_add(length as u64);
        if end <= address {
            return Vec::new();
        }
        let mut intersections = Vec::new();
        let mut index = self
            .ranges
            .partition_point(|&(_, range_end)| range_end <= address);
        while let Some(&(start, range_end)) = self.ranges.get(index) {
            if start >= end {
                break;
            }
            let intersection_start = start.max(address);
            let intersection_end = range_end.min(end);
            if intersection_start < intersection_end {
                intersections.push((intersection_start, intersection_end));
            }
            index += 1;
        }
        intersections
    }

    /// True if one merged interval fully covers `[address,address+length)`.
    fn covers(&self, address: u64, length: usize) -> bool {
        let end = address.saturating_add(length as u64);
        if end <= address {
            return false;
        }
        let idx = self.ranges.partition_point(|&(_, e)| e <= address);
        self.ranges
            .get(idx)
            .is_some_and(|&(s, e)| s <= address && e >= end)
    }

    /// True when this set and `other` both contain at least one byte inside the
    /// queried span. Both sets are sorted, so a two-cursor walk is linear only
    /// in the intersecting range count (normally one VMA).
    fn intersects_set(&self, other: &Self, address: u64, length: usize) -> bool {
        let end = address.saturating_add(length as u64);
        if end <= address {
            return false;
        }
        let mut left = self.ranges.partition_point(|&(_, e)| e <= address);
        let mut right = other.ranges.partition_point(|&(_, e)| e <= address);
        while let (Some(&(left_start, left_end)), Some(&(right_start, right_end))) =
            (self.ranges.get(left), other.ranges.get(right))
        {
            if left_start >= end || right_start >= end {
                return false;
            }
            if left_start.max(right_start) < left_end.min(right_end).min(end) {
                return true;
            }
            if left_end <= right_end {
                left += 1;
            } else {
                right += 1;
            }
        }
        false
    }

    /// Add (`present=true`, merging adjacent/overlapping) or remove
    /// (`present=false`, splitting a partially-cleared range into the surviving
    /// ends) the range `[address, address+len)`, keeping the set sorted + merged.
    fn set(&mut self, address: u64, len: usize, present: bool) {
        let end = address.saturating_add(len as u64);
        if end <= address {
            return;
        }
        if present {
            let mut start = address;
            let mut merged_end = end;
            let idx = self
                .ranges
                .partition_point(|&(_, range_end)| range_end < start);
            let mut remove_end = idx;
            while let Some(&(range_start, range_end)) = self.ranges.get(remove_end) {
                if range_start > merged_end {
                    break;
                }
                start = start.min(range_start);
                merged_end = merged_end.max(range_end);
                remove_end += 1;
            }
            self.ranges.splice(idx..remove_end, [(start, merged_end)]);
            return;
        }

        let idx = self
            .ranges
            .partition_point(|&(_, range_end)| range_end <= address);
        let mut remove_end = idx;
        let mut replacement = Vec::new();
        while let Some(&(s, e)) = self.ranges.get(remove_end) {
            if s >= end {
                break;
            }
            if s < address {
                replacement.push((s, address));
            }
            if end < e {
                replacement.push((end, e));
            }
            remove_end += 1;
        }
        if idx != remove_end {
            self.ranges.splice(idx..remove_end, replacement);
        }
    }
}

#[derive(Default)]
struct ProtectionState {
    no_access: RangeSet,
    unmapped: RangeSet,
    no_write: RangeSet,
    executable: RangeSet,
    /// Page-rounded mapped-file tails that Linux reports as `SIGBUS/BUS_ADRERR`.
    /// These bytes are also in `no_access`; the separate classification lets a
    /// backend distinguish them from an ordinary live `PROT_NONE` VMA.
    bus_fault: RangeSet,
    /// Live VMAs whose bytes may change through another `MAP_SHARED` view,
    /// positional I/O, or another process. This classification intentionally
    /// survives `mprotect`: sharing is a backing fact, not a permission bit.
    mutable_shared_backing: RangeSet,
}

/// Direction of one guest-memory access sampled against VMA protections.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuestMemoryAccess {
    Read,
    Write,
}

/// Linux-visible reason one guest-memory access cannot reach its first denied
/// byte. Backends translate this neutral classification to their guest ABI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuestMemoryFaultKind {
    Unmapped,
    AccessDenied,
}

/// Immutable fault descriptor captured under the protection registry lock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GuestMemoryFault {
    pub address: crate::GuestVa,
    pub kind: GuestMemoryFaultKind,
}

/// The process-wide host-side protection sets a backend enforces on the syscall
/// path: live PROT_NONE, unmapped holes, and read-only mappings. See the module
/// docs for the sharing contract.
#[derive(Default)]
pub struct MemoryProtections {
    /// One lock covers every VMA classification so readers see coherent state
    /// and the hot path pays one lock acquisition, not one per range set.
    state: parking_lot::RwLock<ProtectionState>,
}

/// Exact, range-local protection/sharing image used by a fallible host mapping
/// transaction. Restoring it clears and rebuilds only the captured span, never a
/// whole-process snapshot that could erase unrelated sibling changes.
pub struct MappingProtectionSnapshot {
    address: u64,
    len: usize,
    no_access: Vec<(u64, u64)>,
    unmapped: Vec<(u64, u64)>,
    no_write: Vec<(u64, u64)>,
    executable: Vec<(u64, u64)>,
    bus_fault: Vec<(u64, u64)>,
    mutable_shared_backing: Vec<(u64, u64)>,
}

/// Opaque exclusive lease over a [`MemoryProtections`] instance.
///
/// Native backends acquire this after their executable epoch and host-mapping
/// lock and hold it across `fork(2)`. The child can then drop the inherited
/// lease before touching guest memory, proving that no vanished sibling owned
/// the internal protection lock at the fork boundary without exposing
/// [`ProtectionState`] outside this module.
pub struct MemoryProtectionsExclusiveGuard<'a> {
    _state: parking_lot::RwLockWriteGuard<'a, ProtectionState>,
}

impl MemoryProtections {
    /// Capture every classification intersecting one exact mapping range.
    pub fn snapshot_mapping_range(&self, address: u64, len: usize) -> MappingProtectionSnapshot {
        let state = self.state.read();
        MappingProtectionSnapshot {
            address,
            len,
            no_access: state.no_access.intersections(address, len),
            unmapped: state.unmapped.intersections(address, len),
            no_write: state.no_write.intersections(address, len),
            executable: state.executable.intersections(address, len),
            bus_fault: state.bus_fault.intersections(address, len),
            mutable_shared_backing: state.mutable_shared_backing.intersections(address, len),
        }
    }

    /// Restore a range-local mapping snapshot atomically. Changes outside the
    /// captured span survive, so rollback cannot erase a sibling's disjoint VMA.
    pub fn restore_mapping_range(&self, snapshot: MappingProtectionSnapshot) {
        fn restore(
            set: &mut RangeSet,
            snapshot: &MappingProtectionSnapshot,
            ranges: &[(u64, u64)],
        ) {
            set.set(snapshot.address, snapshot.len, false);
            for &(start, end) in ranges {
                if let Ok(len) = usize::try_from(end - start) {
                    set.set(start, len, true);
                }
            }
        }

        let mut state = self.state.write();
        restore(&mut state.no_access, &snapshot, &snapshot.no_access);
        restore(&mut state.unmapped, &snapshot, &snapshot.unmapped);
        restore(&mut state.no_write, &snapshot, &snapshot.no_write);
        restore(&mut state.executable, &snapshot, &snapshot.executable);
        restore(&mut state.bus_fault, &snapshot, &snapshot.bus_fault);
        restore(
            &mut state.mutable_shared_backing,
            &snapshot,
            &snapshot.mutable_shared_backing,
        );
    }

    /// Hold the complete protection registry exclusively across a host fork.
    ///
    /// Callers must acquire any executable-quiescence and host-mapping locks
    /// first. Both parent and child must explicitly drop the returned guard as
    /// soon as `fork(2)` returns.
    pub fn exclusive_for_fork(&self) -> MemoryProtectionsExclusiveGuard<'_> {
        MemoryProtectionsExclusiveGuard {
            _state: self.state.write(),
        }
    }

    /// Bounded variant for native host-fork protocols. Retry work exists only
    /// on the rare fork path; ordinary protection reads/writes are unchanged.
    pub fn exclusive_for_fork_until(
        &self,
        deadline: std::time::Instant,
    ) -> Option<MemoryProtectionsExclusiveGuard<'_>> {
        loop {
            if let Some(state) = self.state.try_write() {
                return Some(MemoryProtectionsExclusiveGuard { _state: state });
            }
            if std::time::Instant::now() >= deadline {
                return None;
            }
            std::thread::yield_now();
        }
    }

    /// Replace all protection state with one initially-unmapped address range.
    /// Native identity backends use this at process-image start so every raw
    /// syscall pointer is fail-closed until the loader or mmap path publishes a
    /// live VMA. The update is atomic to readers under the one state lock.
    pub fn reset_to_unmapped(&self, address: u64, len: usize) {
        let mut state = self.state.write();
        *state = ProtectionState::default();
        state.unmapped.set(address, len, true);
    }

    /// Seed the PROT_NONE set from an existing range list. The no-write set starts
    /// empty; use [`Self::from_snapshot`] when cloning full syscall-path protection
    /// state across fork.
    pub fn from_ranges(ranges: Vec<(u64, u64)>) -> Self {
        Self {
            state: parking_lot::RwLock::new(ProtectionState {
                no_access: RangeSet::from_ranges(ranges),
                ..ProtectionState::default()
            }),
        }
    }

    /// A point-in-time copy of the PROT_NONE ranges.
    pub fn snapshot(&self) -> Vec<(u64, u64)> {
        self.state.read().no_access.snapshot()
    }

    /// A point-in-time copy of both syscall-path protection sets.
    pub fn snapshot_all(&self) -> ProtectionSnapshot {
        let state = self.state.read();
        ProtectionSnapshot {
            no_access: state.no_access.snapshot(),
            unmapped: state.unmapped.snapshot(),
            no_write: state.no_write.snapshot(),
            executable: state.executable.snapshot(),
            bus_fault: state.bus_fault.snapshot(),
            mutable_shared_backing: state.mutable_shared_backing.snapshot(),
        }
    }

    /// Seed both syscall-path protection sets from a fork-time snapshot.
    pub fn from_snapshot(snapshot: ProtectionSnapshot) -> Self {
        Self {
            state: parking_lot::RwLock::new(ProtectionState {
                no_access: RangeSet::from_ranges(snapshot.no_access),
                unmapped: RangeSet::from_ranges(snapshot.unmapped),
                no_write: RangeSet::from_ranges(snapshot.no_write),
                executable: RangeSet::from_ranges(snapshot.executable),
                bus_fault: RangeSet::from_ranges(snapshot.bus_fault),
                mutable_shared_backing: RangeSet::from_ranges(snapshot.mutable_shared_backing),
            }),
        }
    }

    /// True if `[address, address+length)` overlaps any PROT_NONE range — a syscall
    /// buffer there must fault `EFAULT` (read OR write).
    pub fn range_no_access(&self, address: u64, length: usize) -> bool {
        let state = self.state.read();
        state.no_access.contains(address, length) || state.unmapped.contains(address, length)
    }

    /// True only for a live `PROT_NONE` mapping. Unlike
    /// [`Self::range_no_access`], this excludes post-`munmap` holes so fault
    /// delivery can distinguish Linux `SEGV_ACCERR` from `SEGV_MAPERR`.
    pub fn range_prot_none(&self, address: u64, length: usize) -> bool {
        self.state.read().no_access.contains(address, length)
    }

    /// True when the range was removed from the guest VMA set.
    pub fn range_unmapped(&self, address: u64, length: usize) -> bool {
        self.state.read().unmapped.contains(address, length)
    }

    /// Snapshot the exact tracked-hole intervals intersecting a query range.
    /// The returned ranges are sorted, disjoint, and clipped to the query.
    pub fn unmapped_intersections(&self, address: u64, length: usize) -> Vec<(u64, u64)> {
        self.state.read().unmapped.intersections(address, length)
    }

    /// Capture the first inaccessible byte and its stable reason under one
    /// registry read. Read-only spans deny writes but never reads; an unmapped
    /// byte wins ties because it is not part of a live VMA.
    pub fn first_access_fault(
        &self,
        address: crate::GuestVa,
        length: usize,
        access: GuestMemoryAccess,
    ) -> Option<GuestMemoryFault> {
        let state = self.state.read();
        let address = address.raw();
        let unmapped = state.unmapped.first_intersection(address, length);
        let denied = match access {
            GuestMemoryAccess::Read => state.no_access.first_intersection(address, length),
            GuestMemoryAccess::Write => {
                let no_access = state.no_access.first_intersection(address, length);
                let no_write = state.no_write.first_intersection(address, length);
                match (no_access, no_write) {
                    (Some(left), Some(right)) => Some(left.min(right)),
                    (left, right) => left.or(right),
                }
            }
        };
        match (unmapped, denied) {
            (Some(unmapped), Some(denied)) if denied < unmapped => Some(GuestMemoryFault {
                address: crate::GuestVa(denied),
                kind: GuestMemoryFaultKind::AccessDenied,
            }),
            (Some(unmapped), _) => Some(GuestMemoryFault {
                address: crate::GuestVa(unmapped),
                kind: GuestMemoryFaultKind::Unmapped,
            }),
            (None, Some(denied)) => Some(GuestMemoryFault {
                address: crate::GuestVa(denied),
                kind: GuestMemoryFaultKind::AccessDenied,
            }),
            (None, None) => None,
        }
    }

    /// True when a syscall write must fail: PROT_NONE, post-unmap, or a live
    /// read-only mapping. All three sets are sampled under one read lock.
    pub fn range_write_denied(&self, address: u64, length: usize) -> bool {
        let state = self.state.read();
        state.no_access.contains(address, length)
            || state.unmapped.contains(address, length)
            || state.no_write.contains(address, length)
    }

    /// True when a hardware `MAPERR` must be upgraded to Linux `ACCERR`: the
    /// VMA is live but denies the access. Post-unmap holes are excluded.
    pub fn range_fault_is_access_error(&self, address: u64, length: usize) -> bool {
        let state = self.state.read();
        state.no_access.contains(address, length) || state.no_write.contains(address, length)
    }

    /// True when an inaccessible byte belongs to the page-rounded mapped-file
    /// EOF tail that Linux reports as `SIGBUS/BUS_ADRERR`, rather than to an
    /// ordinary `PROT_NONE` mapping (`SIGSEGV/SEGV_ACCERR`).
    pub fn range_bus_fault(&self, address: u64, length: usize) -> bool {
        self.state.read().bus_fault.contains(address, length)
    }

    /// Snapshot the exact page-rounded EOF-tail intervals intersecting a query.
    /// Native identity mprotect uses this to change ordinary pages without ever
    /// reopening a materialized file hole between permission and metadata steps.
    pub fn bus_fault_intersections(&self, address: u64, length: usize) -> Vec<(u64, u64)> {
        self.state.read().bus_fault.intersections(address, length)
    }

    /// Publish or clear an exact mapped-file EOF tail. The caller owns the
    /// corresponding physical `PROT_NONE` transition and dispatcher VMA record;
    /// this registry bit only preserves the guest-visible fault reason for
    /// checked native memory paths.
    pub fn set_bus_fault(&self, address: u64, len: usize, bus_fault: bool) {
        self.state.write().bus_fault.set(address, len, bus_fault);
    }

    /// Record (`no_access=true`) or clear (`false`) a live PROT_NONE range.
    /// Any protection update establishes a live mapping, so it also clears
    /// stale post-unmap state for the same range.
    pub fn set_no_access(&self, address: u64, len: usize, no_access: bool) {
        let mut state = self.state.write();
        state.unmapped.set(address, len, false);
        state.no_access.set(address, len, no_access);
    }

    /// Record or clear a post-unmap hole. Removing a VMA also clears its prior
    /// PROT_NONE/read-only attributes so a later reuse cannot inherit them.
    pub fn set_unmapped(&self, address: u64, len: usize, unmapped: bool) {
        let mut state = self.state.write();
        if unmapped {
            state.no_access.set(address, len, false);
            state.no_write.set(address, len, false);
            state.executable.set(address, len, false);
            state.bus_fault.set(address, len, false);
            state.mutable_shared_backing.set(address, len, false);
        }
        state.unmapped.set(address, len, unmapped);
    }

    /// True if `[address, address+length)` overlaps any READ-ONLY range — a syscall
    /// WRITE there must fault `EFAULT` (a READ is allowed).
    pub fn range_no_write(&self, address: u64, length: usize) -> bool {
        self.state.read().no_write.contains(address, length)
    }

    /// Record (`no_write=true`, a `PROT_READ`-only range) or clear (`false`, the
    /// range became writable / unmapped) a read-only range.
    pub fn set_no_write(&self, address: u64, len: usize, no_write: bool) {
        let mut state = self.state.write();
        if no_write {
            state.unmapped.set(address, len, false);
        }
        state.no_write.set(address, len, no_write);
    }

    /// True when the complete range is executable. Executability is kept
    /// separate from read/write denial because Linux permits execute-only VMAs
    /// and DSR reads their bytes through a host-readable translation view.
    pub fn range_executable(&self, address: u64, length: usize) -> bool {
        if length == 0 {
            return false;
        }
        let state = self.state.read();
        state.executable.covers(address, length)
            && !state.unmapped.contains(address, length)
            && !state.no_access.contains(address, length)
    }

    /// True when any executable interval overlaps the queried range.
    pub fn range_has_executable(&self, address: u64, length: usize) -> bool {
        if length == 0 {
            return false;
        }
        self.state.read().executable.contains(address, length)
    }

    /// True when the complete live range is both writable and executable.
    ///
    /// All protection dimensions are sampled under the same state lock. Native
    /// DSR backends use this at translation boundaries: separately querying
    /// execute and write permission could otherwise classify a transitioning
    /// page as ordinary immutable text and retain a stale translation.
    pub fn range_writable_executable(&self, address: u64, length: usize) -> bool {
        if length == 0 {
            return false;
        }
        let state = self.state.read();
        state.executable.covers(address, length)
            && !state.no_access.contains(address, length)
            && !state.unmapped.contains(address, length)
            && !state.no_write.contains(address, length)
    }

    /// Conservatively report whether any byte in the range may be both writable
    /// and executable.
    ///
    /// The complete classification is sampled under one read lock. Returning a
    /// false positive only makes a native DSR block ephemeral; returning a false
    /// negative could retain stale translated code. We therefore prove a range
    /// safe only when one denial set covers the whole query. This deliberately
    /// treats mixed RX/W+X spans, and ambiguous mixtures of disjoint denial
    /// sets, as possibly W+X.
    pub fn range_may_have_writable_executable(&self, address: u64, length: usize) -> bool {
        if length == 0 {
            return false;
        }
        let state = self.state.read();
        state.executable.contains(address, length)
            && !state.no_access.covers(address, length)
            && !state.unmapped.covers(address, length)
            && !state.no_write.covers(address, length)
    }

    /// True when any byte in the range belongs to a mutable `MAP_SHARED`
    /// backing. This is intentionally independent of current R/W/X permission.
    pub fn range_mutable_shared_backing(&self, address: u64, length: usize) -> bool {
        self.state
            .read()
            .mutable_shared_backing
            .contains(address, length)
    }

    /// Conservatively classify a complete planned translation span.
    ///
    /// A span is ephemeral when any byte may be W+X, or when executable bytes
    /// overlap mutable shared backing. The latter remains true for read-only RX
    /// views because writers need not use this VMA or even this process. All
    /// dimensions are sampled under one lock so a mapping transition cannot be
    /// misclassified from independently observed states.
    pub fn range_translation_requires_ephemeral(&self, address: u64, length: usize) -> bool {
        if length == 0 {
            return false;
        }
        let state = self.state.read();
        let may_be_writable_executable = state.executable.contains(address, length)
            && !state.no_access.covers(address, length)
            && !state.unmapped.covers(address, length)
            && !state.no_write.covers(address, length);
        let mutable_shared_executable =
            state
                .executable
                .intersects_set(&state.mutable_shared_backing, address, length);
        may_be_writable_executable || mutable_shared_executable
    }

    /// Publish or revoke executable permission for a live VMA.
    pub fn set_executable(&self, address: u64, len: usize, executable: bool) {
        let mut state = self.state.write();
        if executable {
            state.unmapped.set(address, len, false);
        }
        state.executable.set(address, len, executable);
    }

    /// Publish or clear the backing-sharing classification without changing
    /// protection. `mprotect` uses this property: R/W/X changes must not turn a
    /// shared VMA private. New mapping publication should prefer
    /// [`Self::set_mapping_protection_and_sharing`] so replacement is atomic.
    pub fn set_mapping_sharing(&self, address: u64, len: usize, sharing: MappingSharing) {
        let mut state = self.state.write();
        state
            .mutable_shared_backing
            .set(address, len, matches!(sharing, MappingSharing::Shared));
    }

    /// Publish the complete protection state of a live mapping atomically.
    /// This prevents sibling vCPUs from observing a transient accessible gap
    /// while an unmapped range becomes PROT_NONE/read-only or vice versa.
    /// Mapped-file EOF tails remain inaccessible across `mprotect`: changing
    /// VMA permissions cannot turn a Linux `BUS_ADRERR` page into zero backing.
    pub fn set_mapping_protection(
        &self,
        address: u64,
        len: usize,
        no_access: bool,
        no_write: bool,
    ) {
        let mut state = self.state.write();
        let bus_faults = state.bus_fault.intersections(address, len);
        state.unmapped.set(address, len, false);
        state.no_access.set(address, len, no_access);
        for (bus_start, bus_end) in bus_faults {
            if let Ok(bus_len) = usize::try_from(bus_end - bus_start) {
                state.no_access.set(bus_start, bus_len, true);
            }
        }
        state.no_write.set(address, len, no_write);
    }

    /// Publish a replacement mapping's protection and backing-sharing state in
    /// one transition. Replacement revokes stale execute metadata; the caller
    /// publishes the new executable permission only after the backing and host
    /// protection succeed. This makes the transition temporarily restrictive,
    /// never permissive, and clears a prior shared classification for a private
    /// `MAP_FIXED` replacement.
    pub fn set_mapping_protection_and_sharing(
        &self,
        address: u64,
        len: usize,
        no_access: bool,
        no_write: bool,
        sharing: MappingSharing,
    ) {
        let mut state = self.state.write();
        state.unmapped.set(address, len, false);
        state.no_access.set(address, len, no_access);
        state.no_write.set(address, len, no_write);
        state.executable.set(address, len, false);
        state.bus_fault.set(address, len, false);
        state
            .mutable_shared_backing
            .set(address, len, matches!(sharing, MappingSharing::Shared));
    }
}

/// Fork-time copy of syscall-path protection state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectionSnapshot {
    pub no_access: Vec<(u64, u64)>,
    pub unmapped: Vec<(u64, u64)>,
    pub no_write: Vec<(u64, u64)>,
    pub executable: Vec<(u64, u64)>,
    pub bus_fault: Vec<(u64, u64)>,
    pub mutable_shared_backing: Vec<(u64, u64)>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_merge_split_and_query() {
        let p = MemoryProtections::default();
        assert!(!p.range_no_access(0x1000, 0x1000));
        // Two adjacent sets merge.
        p.set_no_access(0x1000, 0x1000, true);
        p.set_no_access(0x2000, 0x1000, true);
        assert_eq!(p.snapshot(), vec![(0x1000, 0x3000)]);
        assert!(p.range_no_access(0x1500, 0x100));
        assert!(p.range_no_access(0x2fff, 0x1)); // last byte protected
        assert!(!p.range_no_access(0x3000, 0x1)); // one past the end is clear
        // Clearing the middle splits into two ends.
        p.set_no_access(0x1800, 0x1000, false);
        assert_eq!(p.snapshot(), vec![(0x1000, 0x1800), (0x2800, 0x3000)]);
        assert!(!p.range_no_access(0x1800, 0x1000));
        assert!(p.range_no_access(0x1700, 0x100));
    }

    #[test]
    fn unmapped_intersections_are_clipped_and_preserve_live_gaps() {
        let p = MemoryProtections::default();
        p.set_unmapped(0x2000, 0x1000, true);
        p.set_unmapped(0x5000, 0x2000, true);

        assert_eq!(
            p.unmapped_intersections(0x2800, 0x3800),
            vec![(0x2800, 0x3000), (0x5000, 0x6000)]
        );
        assert!(p.unmapped_intersections(0x3000, 0x2000).is_empty());
    }

    #[test]
    fn executable_ranges_require_full_live_coverage() {
        let p = MemoryProtections::default();
        p.set_executable(0x1000, 0x2000, true);
        assert!(p.range_executable(0x1000, 0x2000));
        assert!(p.range_executable(0x1800, 1));
        assert!(!p.range_executable(0x0800, 0x1000));
        assert!(!p.range_executable(0x2000, 0x2000));
        assert!(p.range_has_executable(0x0800, 0x1000));
        assert!(!p.range_has_executable(0x4000, 0x1000));
        assert!(p.range_writable_executable(0x1000, 0x1000));
        p.set_no_write(0x1000, 0x1000, true);
        assert!(!p.range_writable_executable(0x1000, 0x1000));
        p.set_no_write(0x1000, 0x1000, false);
        p.set_unmapped(0x2000, 0x1000, true);
        assert!(!p.range_executable(0x1000, 0x2000));
        assert!(p.range_executable(0x1000, 0x1000));
        assert!(!p.range_writable_executable(0x1800, 0x1000));
    }

    #[test]
    fn possible_writable_executable_query_catches_mixed_span() {
        let p = MemoryProtections::default();
        p.set_executable(0x1fff, 2, true);
        p.set_no_write(0x1fff, 1, true);

        assert!(!p.range_may_have_writable_executable(0x1fff, 1));
        assert!(
            p.range_may_have_writable_executable(0x1fff, 2),
            "the writable executable suffix makes the complete span ephemeral"
        );
    }

    #[test]
    fn exclusive_fork_guard_blocks_protection_updates() {
        let p = std::sync::Arc::new(MemoryProtections::default());
        let guard = p.exclusive_for_fork();
        let sibling = std::sync::Arc::clone(&p);
        let (done_tx, done_rx) = std::sync::mpsc::sync_channel(1);
        let updater = std::thread::spawn(move || {
            sibling.set_executable(0x4000, 0x1000, true);
            done_tx.send(()).expect("report protection update");
        });

        assert!(
            done_rx
                .recv_timeout(std::time::Duration::from_millis(20))
                .is_err(),
            "exclusive guard allowed a concurrent protection update"
        );
        drop(guard);
        done_rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .expect("protection update resumed after exclusive guard");
        updater.join().expect("join protection updater");
    }

    #[test]
    fn zero_length_and_overflow_are_noops() {
        let p = MemoryProtections::from_ranges(vec![(0x1000, 0x2000)]);
        p.set_no_access(0x4000, 0, true); // zero length: no-op
        assert_eq!(p.snapshot(), vec![(0x1000, 0x2000)]);
        assert!(!p.range_no_access(0x4000, 0)); // zero length never faults
        assert!(!p.range_no_access(u64::MAX, 16)); // saturating end: no overlap
    }

    /// The no_write (read-only) set is INDEPENDENT of no_access and shares the same
    /// merge/split RangeSet logic. A PROT_READ range is no_write but NOT no_access
    /// (reads are fine, writes EFAULT); clearing (became writable) removes it.
    #[test]
    fn no_write_set_is_independent_of_no_access() {
        let p = MemoryProtections::default();
        p.set_no_write(0x5000, 0x1000, true);
        assert!(p.range_no_write(0x5500, 0x10), "read-only range recorded");
        assert!(
            !p.range_no_access(0x5500, 0x10),
            "no_write != no_access (reads ok)"
        );
        // Independent sets: marking no_access elsewhere doesn't touch no_write.
        p.set_no_access(0x8000, 0x1000, true);
        assert!(p.range_no_write(0x5500, 0x10));
        assert!(p.range_no_access(0x8000, 0x10));
        assert!(!p.range_no_write(0x8000, 0x10));
        // Became writable: cleared.
        p.set_no_write(0x5000, 0x1000, false);
        assert!(
            !p.range_no_write(0x5500, 0x10),
            "writable again clears no_write"
        );
    }

    #[test]
    fn first_access_fault_is_directional_and_byte_exact() {
        let p = MemoryProtections::default();
        p.set_no_write(0x2000, 0x1000, true);
        p.set_unmapped(0x3000, 0x1000, true);
        p.set_no_access(0x5000, 0x1000, true);

        assert_eq!(
            p.first_access_fault(crate::GuestVa(0x2ffc), 8, GuestMemoryAccess::Read),
            Some(GuestMemoryFault {
                address: crate::GuestVa(0x3000),
                kind: GuestMemoryFaultKind::Unmapped,
            }),
            "read-only bytes must not turn a later read hole into ACCERR"
        );
        assert_eq!(
            p.first_access_fault(crate::GuestVa(0x2ffc), 8, GuestMemoryAccess::Write),
            Some(GuestMemoryFault {
                address: crate::GuestVa(0x2ffc),
                kind: GuestMemoryFaultKind::AccessDenied,
            })
        );
        assert_eq!(
            p.first_access_fault(crate::GuestVa(0x4ffc), 8, GuestMemoryAccess::Read),
            Some(GuestMemoryFault {
                address: crate::GuestVa(0x5000),
                kind: GuestMemoryFaultKind::AccessDenied,
            })
        );
        assert_eq!(
            p.first_access_fault(crate::GuestVa(0x1000), 8, GuestMemoryAccess::Write),
            None
        );
    }

    #[test]
    fn bus_fault_classification_is_exact_forked_and_cleared_by_replacement() {
        let p = MemoryProtections::default();
        p.set_no_access(0x1000, 0x1000, true);
        p.set_no_access(0x4000, 0x1000, true);
        p.set_bus_fault(0x4000, 0x1000, true);

        assert!(
            !p.range_bus_fault(0x1000, 1),
            "ordinary PROT_NONE is ACCERR"
        );
        assert!(p.range_bus_fault(0x4000, 1));
        assert_eq!(
            p.bus_fault_intersections(0x3000, 0x3000),
            vec![(0x4000, 0x5000)]
        );

        let forked = MemoryProtections::from_snapshot(p.snapshot_all());
        assert!(forked.range_bus_fault(0x4fff, 1));
        forked.set_mapping_protection(0x3000, 0x3000, false, false);
        assert!(
            forked.range_no_access(0x4000, 1),
            "mprotect cannot reopen a mapped-file EOF tail"
        );
        assert!(!forked.range_no_access(0x3000, 1));
        assert!(!forked.range_no_access(0x5000, 1));
        forked.set_mapping_protection_and_sharing(
            0x4000,
            0x1000,
            false,
            false,
            MappingSharing::Private,
        );
        assert!(!forked.range_bus_fault(0x4000, 1));
        assert!(
            p.range_bus_fault(0x4000, 1),
            "fork snapshots are independent"
        );
    }

    #[test]
    fn full_snapshot_preserves_no_write() {
        let p = MemoryProtections::default();
        p.set_no_access(0x1000, 0x1000, true);
        p.set_no_write(0x4000, 0x1000, true);
        p.set_unmapped(0x8000, 0x1000, true);

        let cloned = MemoryProtections::from_snapshot(p.snapshot_all());

        assert!(cloned.range_no_access(0x1800, 0x10));
        assert!(cloned.range_prot_none(0x1800, 0x10));
        assert!(cloned.range_no_write(0x4800, 0x10));
        assert!(!cloned.range_no_access(0x4800, 0x10));
        assert!(cloned.range_no_access(0x8800, 0x10));
        assert!(cloned.range_unmapped(0x8800, 0x10));
        assert!(!cloned.range_prot_none(0x8800, 0x10));
    }

    #[test]
    fn reset_to_unmapped_replaces_prior_state_and_allows_live_subranges() {
        let p = MemoryProtections::default();
        p.set_no_access(0x1000, 0x1000, true);
        p.set_no_write(0x3000, 0x1000, true);

        p.reset_to_unmapped(0x1_0000, 0x10_0000);
        assert!(!p.range_no_access(0x1000, 1));
        assert!(!p.range_no_write(0x3000, 1));
        assert!(p.range_unmapped(0x1_0000, 1));

        p.set_mapping_protection(0x2_0000, 0x1000, false, false);
        assert!(!p.range_no_access(0x2_0000, 0x1000));
        assert!(p.range_unmapped(0x2_1000, 1));
    }

    #[test]
    fn mapped_prot_none_is_distinct_from_unmapped_and_reuse_clears_hole() {
        let p = MemoryProtections::default();
        p.set_no_access(0x1000, 0x1000, true);
        assert!(p.range_no_access(0x1800, 1));
        assert!(p.range_prot_none(0x1800, 1));
        assert!(!p.range_unmapped(0x1800, 1));

        p.set_unmapped(0x1000, 0x1000, true);
        assert!(p.range_no_access(0x1800, 1));
        assert!(!p.range_prot_none(0x1800, 1));
        assert!(p.range_unmapped(0x1800, 1));

        p.set_mapping_protection(0x1000, 0x1000, true, false);
        assert!(p.range_prot_none(0x1800, 1));
        assert!(!p.range_unmapped(0x1800, 1));

        p.set_mapping_protection(0x1000, 0x1000, false, true);
        assert!(!p.range_no_access(0x1800, 1));
        assert!(p.range_no_write(0x1800, 1));
        assert!(!p.range_unmapped(0x1800, 1));
    }

    #[test]
    fn mapping_range_restore_is_exact_and_preserves_disjoint_sibling_changes() {
        let protections = MemoryProtections::default();
        protections.set_mapping_protection_and_sharing(
            0x1000,
            0x1000,
            false,
            true,
            MappingSharing::Shared,
        );
        protections.set_executable(0x1000, 0x1000, true);
        let snapshot = protections.snapshot_mapping_range(0x1000, 0x1000);

        protections.set_mapping_protection_and_sharing(
            0x1000,
            0x1000,
            true,
            false,
            MappingSharing::Private,
        );
        protections.set_mapping_protection_and_sharing(
            0x4000,
            0x1000,
            false,
            false,
            MappingSharing::Private,
        );
        protections.restore_mapping_range(snapshot);

        assert!(!protections.range_no_access(0x1000, 0x1000));
        assert!(protections.range_no_write(0x1000, 0x1000));
        assert!(protections.range_executable(0x1000, 0x1000));
        assert!(protections.range_mutable_shared_backing(0x1000, 0x1000));
        assert!(!protections.range_no_write(0x4000, 0x1000));
        assert!(!protections.range_mutable_shared_backing(0x4000, 0x1000));
    }

    #[test]
    fn shared_rx_is_ephemeral_while_private_rx_is_cacheable() {
        let shared = MemoryProtections::default();
        shared.set_mapping_protection_and_sharing(
            0x1000,
            0x1000,
            false,
            true,
            MappingSharing::Shared,
        );
        shared.set_executable(0x1000, 0x1000, true);
        assert!(shared.range_mutable_shared_backing(0x1000, 1));
        assert!(shared.range_translation_requires_ephemeral(0x1000, 0x1000));

        // mprotect changes only permission. A shared RX view cannot become
        // persistently cacheable merely because it toggles through RW then RX.
        shared.set_mapping_protection(0x1000, 0x1000, false, false);
        shared.set_mapping_protection(0x1000, 0x1000, false, true);
        assert!(shared.range_translation_requires_ephemeral(0x1000, 0x1000));

        let private = MemoryProtections::default();
        private.set_mapping_protection_and_sharing(
            0x1000,
            0x1000,
            false,
            true,
            MappingSharing::Private,
        );
        private.set_executable(0x1000, 0x1000, true);
        assert!(!private.range_mutable_shared_backing(0x1000, 1));
        assert!(!private.range_translation_requires_ephemeral(0x1000, 0x1000));
    }

    #[test]
    fn unmap_and_private_replacement_clear_shared_backing() {
        let p = MemoryProtections::default();
        p.set_mapping_protection_and_sharing(0x2000, 0x1000, false, true, MappingSharing::Shared);
        p.set_executable(0x2000, 0x1000, true);
        p.set_unmapped(0x2000, 0x1000, true);
        assert!(!p.range_mutable_shared_backing(0x2000, 1));
        assert!(!p.range_translation_requires_ephemeral(0x2000, 1));

        p.set_mapping_protection_and_sharing(0x2000, 0x1000, false, true, MappingSharing::Shared);
        p.set_executable(0x2000, 0x1000, true);
        p.set_mapping_protection_and_sharing(0x2000, 0x1000, false, true, MappingSharing::Private);
        assert!(
            !p.range_executable(0x2000, 1),
            "replacement revokes stale X"
        );
        assert!(!p.range_mutable_shared_backing(0x2000, 1));
        p.set_executable(0x2000, 0x1000, true);
        assert!(!p.range_translation_requires_ephemeral(0x2000, 0x1000));
    }

    #[test]
    fn fork_snapshot_preserves_mutable_shared_backing() {
        let p = MemoryProtections::default();
        p.set_mapping_protection_and_sharing(0x3000, 0x1000, false, true, MappingSharing::Shared);
        p.set_executable(0x3000, 0x1000, true);

        let child = MemoryProtections::from_snapshot(p.snapshot_all());
        assert!(child.range_mutable_shared_backing(0x3000, 0x1000));
        assert!(child.range_translation_requires_ephemeral(0x3000, 0x1000));

        child.set_unmapped(0x3000, 0x1000, true);
        assert!(p.range_mutable_shared_backing(0x3000, 0x1000));
        assert!(!child.range_mutable_shared_backing(0x3000, 0x1000));
    }

    #[test]
    fn mixed_private_and_shared_rx_span_is_ephemeral() {
        let p = MemoryProtections::default();
        p.set_mapping_protection_and_sharing(0x4fff, 1, false, true, MappingSharing::Private);
        p.set_mapping_protection_and_sharing(0x5000, 1, false, true, MappingSharing::Shared);
        p.set_executable(0x4fff, 2, true);

        assert!(!p.range_translation_requires_ephemeral(0x4fff, 1));
        assert!(p.range_translation_requires_ephemeral(0x4fff, 2));
    }
}
