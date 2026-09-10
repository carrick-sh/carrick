//! # vCPU and Virtual Machine Creation Admission
//!
//! Hypervisor.framework bounds concurrent VM allocations per process and across
//! the system. This module manages soft pre-throttles, global permit allocation,
//! atomic permit tables in shared memory, backpressure retry on `HV_NO_RESOURCES`,
//! and admission registration/release across thread lifecycle boundaries.

#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

use super::*;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum VmCreateAdmission {
    Initial,
    ExecveRebuild,
    SharedWaitResume,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl VmCreateAdmission {
    pub(super) fn probe_code(self) -> i32 {
        match self {
            Self::Initial => 0,
            Self::ExecveRebuild => 3,
            Self::SharedWaitResume => 4,
        }
    }

    /// Soft pre-throttle on concurrently-CREATING HVF VMs across a fork tree.
    /// This bounds VM/vCPU *creation* only (the pre-block window of a fork storm),
    /// NOT guest *execution* — execution is already bounded by the per-process M:N
    /// scheduler gate and the Darwin kernel time-slicing cores across processes.
    ///
    /// Measured via `hvf_fork_probe concurrent-ceiling` (E4,
    /// `docs/2026-07-08-hvf-residency-e4-evidence.md`): the ceiling is a **per-VM
    /// slot budget**, not a system-wide vCPU budget. Exactly **127** VMs
    /// materialize across separate processes before `hv_vm_create`/
    /// `hv_vcpu_create` returns `HV_NO_RESOURCES`, and that 127 held flat in five
    /// quiet-host configurations while `total_vcpus` scaled 127 → 254 → 508
    /// (`vcpus_per_vm` 1/2/4) and mapped memory scaled 0 → 16 → 64 MiB — i.e. 508
    /// concurrent vCPUs ran fine at 127 VMs, so a materialized vCPU is not what
    /// the ceiling counts. It is also NOT `hv_vm_get_max_vcpu_count()` (64), which
    /// is the per-VM max vCPU count, not a system total. The old cap (12, clamped
    /// from `hvf_cap_budget()` = 64 − reserve) was ~10× too low: it was sourced
    /// from the wrong number and starved suites that need dozens of
    /// simultaneously-alive processes (e.g. `ltp-fcntl36` needs ~36). An earlier
    /// "~126" reading is superseded by the five exact-127 runs; why it read one
    /// lower is undetermined (plausibly a 128-slot machine-wide table with one
    /// slot consumed elsewhere, or stray live VMs on that host).
    ///
    /// The true hard limit is discovered at runtime by `HV_NO_RESOURCES` and
    /// handled with park+retry backpressure (`create_with_no_resources_backpressure`);
    /// 120 is a soft pre-throttle margin a little under the measured 127 to leave
    /// headroom for other system VM consumers.
    const GLOBAL_VCPU_CEILING: usize = 120;

    pub(super) fn global_permit_budget(self) -> Option<usize> {
        match self {
            Self::Initial | Self::SharedWaitResume => Some(Self::GLOBAL_VCPU_CEILING),
            Self::ExecveRebuild => None,
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(super) struct GlobalVcpuPermit {
    slot: usize,
    fd: libc::c_int,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(super) struct GlobalVcpuPermitBackoff {
    next_ms: u64,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl Default for GlobalVcpuPermitBackoff {
    fn default() -> Self {
        Self { next_ms: 1 }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl GlobalVcpuPermitBackoff {
    const MAX_MS: u64 = 50;

    fn next_delay(&mut self) -> std::time::Duration {
        let delay = self.next_ms;
        self.next_ms = self.next_ms.saturating_mul(2).min(Self::MAX_MS);
        std::time::Duration::from_millis(delay)
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Default)]
pub(crate) struct GlobalVcpuPermitState {
    live: HashMap<u64, GlobalVcpuPermit>,
    pending: Vec<usize>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(super) fn close_global_vcpu_permit(permit: GlobalVcpuPermit) {
    unsafe {
        let _ = libc::close(permit.fd);
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(super) fn ensure_global_vcpu_slot_dir() {
    let dir = c"/tmp/carrick-hvf-vcpu-slots";
    unsafe {
        let _ = libc::mkdir(dir.as_ptr(), 0o700);
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(super) fn open_global_vcpu_slot(slot: usize) -> Option<libc::c_int> {
    let Ok(path) = std::ffi::CString::new(format!("/tmp/carrick-hvf-vcpu-slots/slot-{slot}"))
    else {
        return None;
    };
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_CREAT, 0o600) };
    if fd < 0 {
        return None;
    }
    let rc = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
    if rc == 0 {
        Some(fd)
    } else {
        unsafe {
            let _ = libc::close(fd);
        }
        None
    }
}

/// Total time an admission-permit acquire may park before declaring the host
/// exhausted and returning [`TrapError::HostResourceExhausted`] — the bound
/// that turns the historical SILENT UNBOUNDED permit stall (the sigwait-shaped
/// procladder_mt red: 160 blocked children, zero output, zero trace lines)
/// into a loud, typed error the fork path degrades to guest `EAGAIN`.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(super) const ADMISSION_PERMIT_MAX_WAIT: std::time::Duration =
    std::time::Duration::from_secs(60);

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(super) fn acquire_global_vcpu_permit(budget: usize) -> Result<GlobalVcpuPermit, TrapError> {
    // `hv_vm_get_max_vcpu_count` is a per-VM ceiling. A fork storm creates many
    // one-vCPU VMs, and HVF can exhaust host resources well below that per-VM count.
    // Admission classes choose the budget: plain fork needs the physical-core M:N
    // budget so forked waiters can reach their blocking syscall, while shared-wait
    // resume drains already-parked processes through a smaller gate.
    let budget = budget.max(1);
    ensure_global_vcpu_slot_dir();
    let mut backoff = GlobalVcpuPermitBackoff::default();
    let start = std::time::Instant::now();
    let mut parks: u32 = 0;
    loop {
        let mut state = global_vcpu_permits()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        for slot in 0..budget {
            if state.pending.contains(&slot) || state.live.values().any(|p| p.slot == slot) {
                continue;
            }
            let Some(fd) = open_global_vcpu_slot(slot) else {
                continue;
            };
            state.pending.push(slot);
            return Ok(GlobalVcpuPermit { slot, fd });
        }
        drop(state);
        if start.elapsed() >= ADMISSION_PERMIT_MAX_WAIT {
            return Err(vcpu_gate::permit_exhausted(
                "vcpu permit (flock)",
                budget,
                parks,
                start.elapsed(),
            ));
        }
        parks += 1;
        vcpu_gate::trace_permit_park("vcpu permit (flock)", budget, parks, start.elapsed());
        std::thread::sleep(backoff.next_delay());
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(super) fn forget_pending_global_vcpu_permit(state: &mut GlobalVcpuPermitState, slot: usize) {
    if let Some(pos) = state.pending.iter().position(|&s| s == slot) {
        state.pending.swap_remove(pos);
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(super) fn register_global_vcpu_permit(vcpu_id: u64, permit: GlobalVcpuPermit) {
    let mut state = global_vcpu_permits()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    forget_pending_global_vcpu_permit(&mut state, permit.slot);
    if let Some(old) = state.live.insert(vcpu_id, permit) {
        close_global_vcpu_permit(old);
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(super) fn release_unregistered_global_vcpu_permit(permit: GlobalVcpuPermit) {
    let mut state = global_vcpu_permits()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    forget_pending_global_vcpu_permit(&mut state, permit.slot);
    drop(state);
    close_global_vcpu_permit(permit);
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(super) fn release_global_vcpu_permit(vcpu_id: u64) {
    let permit = global_vcpu_permits()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .live
        .remove(&vcpu_id);
    if let Some(permit) = permit {
        close_global_vcpu_permit(permit);
    }
}

// ===========================================================================
// Atomic vCPU admission permit (Option 3, Task 1) — the DEFAULT admission path.
// The flock permit above remains as a fallback, selectable with
// `CARRICK_HVF_ATOMIC_PERMIT=0` (`false`/`no` also accepted).
//
// The flock permit above gets its cross-process death-reclaim for free from the
// kernel (a slot lock releases when the holder's last fd closes on exit). A bare
// shared counter does NOT — that was the 3b leak (`cur=4 live_len=0`). So here
// OWNERSHIP is the source of truth: every admitted count IS a generation-stamped
// slot in a fork-shared table, published owner-first, so a crash between acquire
// and vcpu_create leaves a reclaimable owner record (reaped by Tasks 2/3). There
// is NO separate live counter; `occupied()` is DERIVED from non-free slots.
// ===========================================================================

/// Packed-slot bit layout for one `AtomicU64` entry in the shared table:
///
/// ```text
///   bits 63..62  state       (2 bits: 0=free, 1=acquiring, 2=registered)
///   bits 61..32  generation  (30 bits, from the shared monotonic counter)
///   bits 31..0   owner_pid    (32 bits)
/// ```
///
/// A `MAP_ANON` zero-filled word is therefore `state=free, gen=0, pid=0` — a
/// valid empty slot — and no live slot is ever all-zero (state is never free).
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(super) mod atomic_permit_slot {
    // Sized to cover `GLOBAL_VCPU_CEILING` (120) with headroom so the DEFAULT
    // atomic admission path honors the full measured system-wide vCPU budget;
    // at 64 the soft pre-throttle would silently clamp to 64 concurrent creators
    // (well below the real ~126 ceiling). Auto-sizes the shared table's mmap
    // (`size_of::<SharedPermitTable>()`) and every slot scan.
    pub(super) const MAX_SLOTS: usize = 128;

    pub(super) const STATE_SHIFT: u32 = 62;
    pub(super) const STATE_MASK: u64 = 0b11 << STATE_SHIFT;
    pub(super) const GEN_SHIFT: u32 = 32;
    pub(super) const GEN_BITS: u32 = 30;
    pub(super) const GEN_MASK: u64 = ((1u64 << GEN_BITS) - 1) << GEN_SHIFT;
    pub(super) const GEN_VALUE_MASK: u32 = (1u32 << GEN_BITS) - 1;
    pub(super) const PID_MASK: u64 = 0xFFFF_FFFF;

    pub(super) const STATE_FREE: u64 = 0;
    pub(super) const STATE_ACQUIRING: u64 = 1;
    pub(super) const STATE_REGISTERED: u64 = 2;

    /// A fully-free slot word (all zero).
    pub(super) const FREE_WORD: u64 = 0;

    pub(super) fn pack(state: u64, pid: u32, generation: u32) -> u64 {
        (state << STATE_SHIFT)
            | ((u64::from(generation) & ((1u64 << GEN_BITS) - 1)) << GEN_SHIFT)
            | u64::from(pid)
    }

    pub(super) fn state_of(word: u64) -> super::SlotState {
        match (word & STATE_MASK) >> STATE_SHIFT {
            STATE_FREE => super::SlotState::Free,
            STATE_ACQUIRING => super::SlotState::Acquiring,
            STATE_REGISTERED => super::SlotState::Registered,
            _ => super::SlotState::Free, // unused 0b11 encoding
        }
    }

    pub(super) fn pid_of(word: u64) -> u32 {
        (word & PID_MASK) as u32
    }

    pub(super) fn gen_of(word: u64) -> u32 {
        ((word & GEN_MASK) >> GEN_SHIFT) as u32
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SlotState {
    Free,
    Acquiring,
    Registered,
}

/// A held atomic permit: proof that exactly one generation-stamped slot is owned
/// by `owner_pid`. `Copy` so events/tokens can be compared without consuming.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Debug, Clone, Copy)]
pub(super) struct PermitToken {
    slot: u16,
    generation: u32,
    owner_pid: u32,
}

/// The carrier-local slot table itself, laid out in a kernel-arena page.
/// `next_generation` hands out a monotonic (30-bit-wrapping) generation per
/// acquire so a freed-then-reused slot never collides with a stale token/event.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[repr(C)]
pub(super) struct SharedPermitTable {
    magic: std::sync::atomic::AtomicU32,
    version: std::sync::atomic::AtomicU32,
    next_generation: std::sync::atomic::AtomicU32,
    // `#[repr(C)]` inserts 4 bytes of padding here to 8-align `slots`.
    slots: [std::sync::atomic::AtomicU64; atomic_permit_slot::MAX_SLOTS],
}

/// Process-local handle onto the carrier's [`SharedPermitTable`].
///
/// `local` is the carrier-private `vcpu_id -> PermitToken` authority for
/// token-guarded release: only a `vcpu_id` that registered a token can free the
/// slot it named.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) struct PermitRegion {
    table: usize,
    local: std::sync::Mutex<HashMap<u64, PermitToken>>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl PermitRegion {
    /// mmap a fresh zero-filled shared table and publish its header. Used only
    /// for injectable test regions; the process-global table lives in the
    /// carrick-kernel arena.
    #[cfg(test)]
    fn map_private_table_for_tests() -> usize {
        use std::sync::atomic::Ordering;
        let size = std::mem::size_of::<SharedPermitTable>();
        // SAFETY: MAP_ANON pages are zero-filled, so the region is a valid
        // `SharedPermitTable` with every slot `FREE_WORD`. MAP_SHARED matches the
        // kernel-arena representation used by production.
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANON | libc::MAP_SHARED,
                -1,
                0,
            )
        };
        assert!(
            ptr != libc::MAP_FAILED,
            "mmap(MAP_ANON|MAP_SHARED) for the vCPU permit table failed"
        );
        // SAFETY: `ptr` is a live, page-aligned, zero-filled mapping of exactly
        // `size_of::<SharedPermitTable>()` bytes, kept for the process lifetime.
        let table = unsafe { &*(ptr as *const SharedPermitTable) };
        // Generations start at 1 so 0 is reserved for "no owner".
        table.next_generation.store(1, Ordering::Relaxed);
        table
            .version
            .store(carrick_kernel::arena::PERMIT_VERSION, Ordering::Relaxed);
        // Publish the magic last (Release) so a reader that sees it also sees the
        // initialized header.
        table
            .magic
            .store(carrick_kernel::arena::PERMIT_MAGIC, Ordering::Release);
        ptr as usize
    }

    pub(super) fn new_shared_global() -> PermitRegion {
        let arena = carrick_kernel::arena::KernelArena::global();
        PermitRegion {
            table: &arena.layout().permits as *const _ as usize,
            local: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Same as [`Self::new_shared_global`] but over the arena's resident-VM
    /// slot section. One slot per live HVF VM, claimed/freed at the actual
    /// `hv_vm_create`/`hv_vm_destroy` transitions; occupancy is DERIVED from
    /// the slots (no separate counter to drift), and the death reaper
    /// reclaims a dead owner's slot exactly like a permit slot.
    pub(super) fn new_shared_global_vm() -> PermitRegion {
        let arena = carrick_kernel::arena::KernelArena::global();
        PermitRegion {
            table: &arena.layout().vm_slots as *const _ as usize,
            local: std::sync::Mutex::new(HashMap::new()),
        }
    }

    fn table(&self) -> &SharedPermitTable {
        // SAFETY: `self.table` is either the arena permit section or a test-only
        // private mapping. Both are live mappings for the process lifetime; fork
        // children inherit the same VA.
        unsafe { &*(self.table as *const SharedPermitTable) }
    }

    /// DERIVED occupancy: the count of non-free slots across the whole fork tree.
    /// There is deliberately no separate `live` counter to drift from this.
    ///
    /// These per-slot loads are `SeqCst`, not `Acquire`, to forbid a
    /// store-buffering (SB) over-admit: two acquirers racing on DIFFERENT
    /// slots i != j each publish their own claim with a store, then read the
    /// other's slot to check the budget. With only `AcqRel`/`Acquire` (no
    /// total store order) each can observe the other's slot as still-free —
    /// both claims land, both pass the budget check, and occupancy transiently
    /// exceeds `budget`. `SeqCst` here plus `SeqCst` on the claim CAS's success
    /// case (below) puts both operations in one global total order, so at
    /// least one racer's occupancy scan is guaranteed to see the other's
    /// already-published claim and back out.
    fn occupied(&self) -> usize {
        use std::sync::atomic::Ordering;
        self.table()
            .slots
            .iter()
            .filter(|s| atomic_permit_slot::state_of(s.load(Ordering::SeqCst)) != SlotState::Free)
            .count()
    }

    /// Single acquire attempt. Publishes an OWNED slot FIRST (a crash after this
    /// is reclaimable), THEN counts occupancy: if the claim pushed occupancy over
    /// `budget`, it CASes that exact `(slot, gen)` back to free and returns `None`
    /// so the caller backs off. Returns `None` (no leak) on a full table too.
    ///
    /// The claim CAS's success ordering is `SeqCst` (paired with the `SeqCst`
    /// loads in `occupied()`) specifically to forbid the store-buffering
    /// over-admit race: with plain `AcqRel`/`Acquire`, two threads claiming
    /// slots i != j can each fail to observe the other's just-published claim
    /// when scanning for occupancy, so both slip past the `budget` check.
    /// `SeqCst` on both sides puts every claim-store and occupancy-load into
    /// one total order, so at least one of the two racers is guaranteed to
    /// see the other's slot occupied and back out.
    fn acquire(&self, budget: usize, pid: u32) -> Option<PermitToken> {
        use std::sync::atomic::Ordering;
        let budget = budget.max(1);
        let table = self.table();
        for (idx, slot) in table.slots.iter().enumerate() {
            let cur = slot.load(Ordering::Acquire);
            if atomic_permit_slot::state_of(cur) != SlotState::Free {
                continue;
            }
            let generation = table.next_generation.fetch_add(1, Ordering::AcqRel)
                & atomic_permit_slot::GEN_VALUE_MASK;
            let claimed =
                atomic_permit_slot::pack(atomic_permit_slot::STATE_ACQUIRING, pid, generation);
            if slot
                .compare_exchange(cur, claimed, Ordering::SeqCst, Ordering::Acquire)
                .is_err()
            {
                // Lost this slot to a concurrent acquirer; try the next free one.
                continue;
            }
            // An owned slot now exists; count occupancy (which includes it).
            if self.occupied() > budget {
                // Over budget: undo THIS exact claim and let the caller back off.
                let _ = slot.compare_exchange(
                    claimed,
                    atomic_permit_slot::FREE_WORD,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                );
                return None;
            }
            return Some(PermitToken {
                slot: idx as u16,
                generation,
                owner_pid: pid,
            });
        }
        None
    }

    /// Transition `acquiring -> registered` for the same `(pid, gen)` and record
    /// `vcpu_id -> token` locally. The local entry is the release authority; the
    /// shared transition is best-effort (an acquiring slot already counts as
    /// occupied, so a lost race here cannot drop the count).
    fn register(&self, vcpu_id: u64, token: PermitToken) {
        use std::sync::atomic::Ordering;
        let slot = &self.table().slots[token.slot as usize];
        let acquiring = atomic_permit_slot::pack(
            atomic_permit_slot::STATE_ACQUIRING,
            token.owner_pid,
            token.generation,
        );
        let registered = atomic_permit_slot::pack(
            atomic_permit_slot::STATE_REGISTERED,
            token.owner_pid,
            token.generation,
        );
        let _ = slot.compare_exchange(acquiring, registered, Ordering::AcqRel, Ordering::Acquire);
        self.local
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(vcpu_id, token);
    }

    /// Token-guarded release: only frees the shared slot if THIS `vcpu_id` holds
    /// a locally-recorded token. An unregistered sibling teardown is a no-op on
    /// the shared table (mirrors the flock `live`-set guard).
    fn release_token(&self, vcpu_id: u64) {
        let token = self
            .local
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&vcpu_id);
        if let Some(token) = token {
            self.free_exact(token);
        }
    }

    /// Free a slot iff it still holds this exact `(owner_pid, generation)` — the
    /// generation guard: a stale token or a late death event for a reused slot
    /// (now owned by a newer generation) will not match and cannot free it.
    fn free_exact(&self, token: PermitToken) -> bool {
        use std::sync::atomic::Ordering;
        let slot = &self.table().slots[token.slot as usize];
        loop {
            let cur = slot.load(Ordering::Acquire);
            if atomic_permit_slot::state_of(cur) == SlotState::Free
                || atomic_permit_slot::pid_of(cur) != token.owner_pid
                || atomic_permit_slot::gen_of(cur)
                    != (token.generation & atomic_permit_slot::GEN_VALUE_MASK)
            {
                return false;
            }
            match slot.compare_exchange_weak(
                cur,
                atomic_permit_slot::FREE_WORD,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(_) => continue,
            }
        }
    }

    /// Release a token that was acquired but never registered against a `vcpu_id`
    /// (VM- or vcpu-create failed after acquire). Frees the exact acquiring slot.
    fn release_unregistered(&self, token: PermitToken) {
        self.free_exact(token);
    }

    /// Cooperatively release this carrier's locally registered atomic permits.
    ///
    /// Precise + idempotent: it DRAINS the process-local token map and frees each
    /// named slot with the generation-guarded [`Self::free_exact`], so
    /// - a slot a normal `vcpu_destroyed` already freed is gone from the map (no
    ///   entry → nothing to free);
    /// - a slot already freed or reused under an advanced generation fails the
    ///   guard in `free_exact` → no double-free;
    /// - a second call finds an empty map → frees nothing.
    ///
    /// It can only free slots this carrier registered. Returns the number of
    /// slots actually freed (for tests/diagnostics).
    fn cooperative_release_local(&self) -> usize {
        let tokens: Vec<PermitToken> = {
            let mut map = self.local.lock().unwrap_or_else(|e| e.into_inner());
            map.drain().map(|(_, token)| token).collect()
        };
        tokens.iter().filter(|t| self.free_exact(**t)).count()
    }

    /// Diagnostic slot-state read (used by tests and the Task 2 supervisor).
    #[allow(dead_code)]
    fn slot_state(&self, slot: u16) -> SlotState {
        use std::sync::atomic::Ordering;
        atomic_permit_slot::state_of(self.table().slots[slot as usize].load(Ordering::Acquire))
    }

    #[cfg(test)]
    fn new_anon_for_test() -> PermitRegion {
        PermitRegion {
            table: Self::map_private_table_for_tests(),
            local: std::sync::Mutex::new(HashMap::new()),
        }
    }

    #[cfg(test)]
    fn local_token(&self, vcpu_id: u64) -> Option<PermitToken> {
        self.local
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&vcpu_id)
            .copied()
    }

    #[cfg(test)]
    fn try_free_exact_for_test(&self, token: PermitToken) -> bool {
        self.free_exact(token)
    }

    #[cfg(test)]
    fn table_addr_for_test(&self) -> usize {
        self.table
    }
}

/// The process-global permit region. Initialized lazily on first use, but the
/// FIRST use is the `Initial` admission acquire during initial-VM creation, which
/// runs before the guest can execute any `fork` — so the region always exists,
/// `MAP_SHARED`, before any guest fork inherits it.
/// The process-global resident-VM region. Same fork-inheritance property as
/// `permit_region`: first touched during initial-VM creation, before any
/// guest fork.
/// The process-local registration key for THE resident VM (one VM per
/// process). `u64::MAX` cannot collide with an HVF vcpu_id in the shared
/// local map.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(super) const VM_RESIDENCY_LOCAL_KEY: u64 = u64::MAX;

/// Record "this process now holds a live HVF VM". Called from the single
/// create funnel (`create_vm_with_admission` Ok arm). Recording is
/// UNCONDITIONAL (budget = MAX_SLOTS): the VM already exists; the budget is
/// enforced only by the fork-admission PROBE. A full table (impossible in
/// practice: 128 slots > the ~127-VM hard ceiling) logs and under-counts by
/// one rather than failing the create.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(super) fn record_vm_resident() {
    if !atomic_permit_enabled() {
        return; // flock fallback: no residency table; the gate skips the VM probe too
    }
    let region = vm_residency_region();
    // A stale prior registration (should not happen: one VM per process,
    // destroy paths release first) would leak a slot until death-reclaim;
    // release defensively so the table can never double-count one process.
    region.release_token(VM_RESIDENCY_LOCAL_KEY);
    match region.acquire(atomic_permit_slot::MAX_SLOTS, std::process::id()) {
        Some(token) => region.register(VM_RESIDENCY_LOCAL_KEY, token),
        None => eprintln!(
            "[hvf-admission pid={}] resident-VM table full; VM unrecorded (fork gate will under-count by one)",
            unsafe { libc::getpid() }
        ),
    }
}

/// Record "this process's HVF VM is gone". Called after each SUCCESSFUL
/// `hv_vm_destroy`. Idempotent (token-guarded).
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(super) fn record_vm_released() {
    crate::probes::vm_lifecycle(3, -1);
    CARRIER_VM_LIVE.store(false, std::sync::atomic::Ordering::Release);
    // The eager mmap arena belonged to the VM that just died. A VM rebuilt
    // after this point gets a fresh eager mapping and must retire it once of
    // its own accord, so the carrier's once-flag is released with the VM.
    carrier_initial_arena_retired().store(false, std::sync::atomic::Ordering::Release);
    if !atomic_permit_enabled() {
        return;
    }
    vm_residency_region().release_token(VM_RESIDENCY_LOCAL_KEY);
}

/// Retire the one persistent HVPatch VM when the CARRIER exits — never at a
/// container's run terminal. Containers boot, run and retire inside this VM;
/// the VM wrapper is `ManuallyDrop`, so relying on host process death would
/// leave no authoritative destroy-success boundary for the lifecycle ledger.
///
/// Idempotent and honest about "nothing to do": a carrier that never created
/// a VM (image resolution failed, an entrypoint resolved to 127, or the second
/// call after a successful destroy) records no lifecycle event at all.
pub(super) fn atomic_permit_enabled_from_env(val: Option<&str>) -> bool {
    match val {
        Some(v) => !matches!(v.trim().to_ascii_lowercase().as_str(), "0" | "false" | "no"),
        None => true,
    }
}

/// Blocking acquire against the atomic slot table: retry the single-attempt
/// [`PermitRegion::acquire`] with the same exponential backoff as the flock path
/// until a slot is admitted, bounded at [`ADMISSION_PERMIT_MAX_WAIT`] like the
/// flock analogue [`acquire_global_vcpu_permit`].
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(super) fn acquire_atomic_vcpu_permit(budget: usize) -> Result<PermitToken, TrapError> {
    let region = permit_region();
    let pid = std::process::id();
    let mut backoff = GlobalVcpuPermitBackoff::default();
    let start = std::time::Instant::now();
    let mut parks: u32 = 0;
    loop {
        if let Some(token) = region.acquire(budget, pid) {
            return Ok(token);
        }
        if start.elapsed() >= ADMISSION_PERMIT_MAX_WAIT {
            return Err(vcpu_gate::permit_exhausted(
                "vcpu permit (atomic)",
                budget,
                parks,
                start.elapsed(),
            ));
        }
        parks += 1;
        vcpu_gate::trace_permit_park("vcpu permit (atomic)", budget, parks, start.elapsed());
        std::thread::sleep(backoff.next_delay());
    }
}

/// A held admission permit, either flock (default) or atomic (flag-gated). It
/// flows from `create_vm_with_admission` through `create_vcpu_with_permit` where
/// it is registered against the created `vcpu_id` (or released on failure).
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(super) enum HeldPermit {
    Flock(GlobalVcpuPermit),
    Atomic(PermitToken),
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(super) struct HeldPermitGuard {
    permit: Option<HeldPermit>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl HeldPermitGuard {
    pub(super) fn new(permit: HeldPermit) -> Self {
        Self {
            permit: Some(permit),
        }
    }

    pub(super) fn into_inner(mut self) -> HeldPermit {
        self.permit
            .take()
            .unwrap_or_else(|| unreachable!("held permit guard already consumed"))
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl Drop for HeldPermitGuard {
    fn drop(&mut self) {
        if let Some(permit) = self.permit.take() {
            release_unregistered_admission_permit(permit);
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(super) fn acquire_admission_permit(budget: usize) -> Result<HeldPermit, TrapError> {
    if atomic_permit_enabled() {
        Ok(HeldPermit::Atomic(acquire_atomic_vcpu_permit(budget)?))
    } else {
        Ok(HeldPermit::Flock(acquire_global_vcpu_permit(budget)?))
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(super) fn register_admission_permit(vcpu_id: u64, permit: HeldPermit) {
    match permit {
        HeldPermit::Flock(permit) => register_global_vcpu_permit(vcpu_id, permit),
        HeldPermit::Atomic(token) => permit_region().register(vcpu_id, token),
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(super) fn release_unregistered_admission_permit(permit: HeldPermit) {
    match permit {
        HeldPermit::Flock(permit) => release_unregistered_global_vcpu_permit(permit),
        HeldPermit::Atomic(token) => permit_region().release_unregistered(token),
    }
}

/// Dispatch a normal `vcpu_destroyed` release to whichever permit path is active.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(super) fn release_admission_permit_for_vcpu(vcpu_id: u64) {
    if atomic_permit_enabled() {
        permit_region().release_token(vcpu_id);
    } else {
        release_global_vcpu_permit(vcpu_id);
    }
}

/// Cooperatively release this carrier's atomic permit slots before process
/// termination. No-op unless the atomic permit path is active; token-guarded
/// release keeps this idempotent with normal `vcpu_destroyed` teardown.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub fn cooperative_release_atomic_permit() -> usize {
    if !atomic_permit_enabled() {
        return 0;
    }
    permit_region().cooperative_release_local() + vm_residency_region().cooperative_release_local()
}

/// True when park+retry admission tracing is requested (`CARRICK_HVF_ADMISSION_TRACE`).
/// Cached once; park+retry is rare, so this stays off the hot path.
/// A fresh VM config (max-IPA-sized), rebuilt per creation attempt so
/// `HV_NO_RESOURCES` park+retry can re-run `hv_vm_create` (config is consumed on
/// each `with_config`, so a retry needs a new one).
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(super) fn fresh_vm_config() -> applevisor::error::Result<applevisor::vm::VirtualMachineConfig> {
    use applevisor::prelude::*;
    let max_ipa = VirtualMachineConfig::get_max_ipa_size()?;
    let mut config = VirtualMachineConfig::new();
    config.set_ipa_size(max_ipa)?;
    Ok(config)
}

/// Run a VM/vCPU creation, absorbing the TRUE hard limit (`HV_NO_RESOURCES`,
/// reachable if other system VMs consumed budget or a multithreaded guest pushed
/// total vCPUs past the measured ~126 even under the 120 soft budget) by PARKING
/// on the vcpu gate and RETRYING, rather than propagating a fatal error.
///
/// A sibling vCPU's `vcpu_destroyed` calls `vcpu_gate::notify()`, which wakes an
/// in-process waiter fast; the bounded per-park timeout also drives cross-process
/// recovery (a slot freed by a DIFFERENT process's teardown is picked up on the
/// next retry, since that process's notify can't reach this process's condvar).
/// Bounded by a total-wait deadline so a genuinely-full system propagates the
/// error instead of hanging forever. Any non-`NoResources` error is propagated
/// immediately. Gated logging makes the park+retry observable.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(super) fn create_with_no_resources_backpressure<T>(
    what: &str,
    attempt: impl FnMut() -> applevisor::error::Result<T>,
) -> Result<T, TrapError> {
    /// One park between retries; also the cross-process retry cadence.
    const PARK: std::time::Duration = std::time::Duration::from_millis(25);
    /// Total time to keep parking+retrying before declaring the host genuinely full.
    const MAX_WAIT: std::time::Duration = std::time::Duration::from_secs(10);
    create_with_no_resources_backpressure_bounded(what, PARK, MAX_WAIT, attempt)
}

/// The bounded park+retry loop, split out with explicit `park`/`max_wait` so it
/// is unit-testable in milliseconds instead of the production 10s ceiling. See
/// [`create_with_no_resources_backpressure`] for the semantics.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(super) fn create_with_no_resources_backpressure_bounded<T>(
    what: &str,
    park: std::time::Duration,
    max_wait: std::time::Duration,
    mut attempt: impl FnMut() -> applevisor::error::Result<T>,
) -> Result<T, TrapError> {
    use applevisor::error::HypervisorError;

    let start = std::time::Instant::now();
    let mut parks: u32 = 0;
    loop {
        match attempt() {
            Ok(v) => {
                if parks > 0 && admission_trace_enabled() {
                    eprintln!(
                        "[hvf-admission pid={}] {what} recovered from HV_NO_RESOURCES after {parks} park(s) / {:?}",
                        unsafe { libc::getpid() },
                        start.elapsed(),
                    );
                }
                return Ok(v);
            }
            Err(e) if e == HypervisorError::NoResources && start.elapsed() < max_wait => {
                parks += 1;
                if admission_trace_enabled() {
                    eprintln!(
                        "[hvf-admission pid={}] {what} HV_NO_RESOURCES; park+retry #{parks} (waited {:?})",
                        unsafe { libc::getpid() },
                        start.elapsed(),
                    );
                }
                vcpu_gate::park_for_slot(park);
            }
            Err(e) => {
                if e == HypervisorError::NoResources && admission_trace_enabled() {
                    eprintln!(
                        "[hvf-admission pid={}] {what} HV_NO_RESOURCES persisted {:?} after {parks} park(s); host full, propagating",
                        unsafe { libc::getpid() },
                        start.elapsed(),
                    );
                }
                // Name the operation. This loop already carries `what` for
                // its trace output and then dropped it on the error path, so a
                // real failure surfaced as a bare "owning resource is busy
                // (error 0xfae94002)" with nothing saying WHICH call — the
                // concurrent container-gate failure had to be chased from a
                // 7.5 GiB core to find out.
                return Err(TrapError::Hypervisor(format!("{what}: {e}")));
            }
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(super) fn create_vcpu_with_permit(
    vm: &applevisor::vm::VirtualMachineInstance<applevisor::vm::GicDisabled>,
    permit: Option<HeldPermitGuard>,
) -> Result<applevisor::vcpu::Vcpu, TrapError> {
    // The permit (this process's admitted soft-budget slot) is held across all
    // retries; only the terminal outcome registers or releases it.
    match create_with_no_resources_backpressure("hv_vcpu_create", || vm.vcpu_create()) {
        Ok(vcpu) => {
            if let Some(permit) = permit {
                register_admission_permit(vcpu.id(), permit.into_inner());
            }
            vcpu_created();
            Ok(vcpu)
        }
        Err(e) => {
            drop(permit);
            Err(e)
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(super) fn create_vcpu(
    vm: &applevisor::vm::VirtualMachineInstance<applevisor::vm::GicDisabled>,
) -> Result<applevisor::vcpu::Vcpu, TrapError> {
    // Existing-VM vCPUs (thread siblings and reclaim/rebind) are admitted by the
    // in-process scheduler. Applying the VM-creation permit here would duplicate
    // that scheduler's bounded vCPU accounting.
    match vm.vcpu_create() {
        Ok(vcpu) => {
            vcpu_created();
            Ok(vcpu)
        }
        Err(e) => Err(TrapError::Hypervisor(format!(
            "hv_vcpu_create (existing carrier VM): {e}"
        ))),
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[cfg(test)]
mod vm_create_admission_tests {
    use super::*;

    #[test]
    fn resource_growing_vm_creation_uses_global_permit() {
        assert!(VmCreateAdmission::Initial.global_permit_budget().is_some());
        assert!(
            VmCreateAdmission::ExecveRebuild
                .global_permit_budget()
                .is_none()
        );
        assert!(
            VmCreateAdmission::SharedWaitResume
                .global_permit_budget()
                .is_some()
        );
    }

    #[test]
    fn global_permit_budget_depends_on_admission_kind() {
        // Every gated class is now bounded by the measured system-wide vCPU
        // ceiling (GLOBAL_VCPU_CEILING), NOT the per-VM hv_vm_get_max_vcpu_count
        // the old cap of 12 was clamped from. The true hard limit is discovered
        // at runtime via HV_NO_RESOURCES park+retry, not this soft pre-throttle.
        let ceiling = Some(VmCreateAdmission::GLOBAL_VCPU_CEILING);
        assert_eq!(VmCreateAdmission::Initial.global_permit_budget(), ceiling);
        assert_eq!(
            VmCreateAdmission::SharedWaitResume.global_permit_budget(),
            ceiling,
            "shared-wait resume drains parked processes through the creation ceiling"
        );
        // Execve rebuilds must make progress and therefore bypass the global
        // creation permit.
        assert_eq!(
            VmCreateAdmission::ExecveRebuild.global_permit_budget(),
            None
        );
        // The ceiling is the measured margin under the ~126 real host limit, well
        // above the old cap of 12 that starved dozens-of-processes suites.
        assert_eq!(VmCreateAdmission::GLOBAL_VCPU_CEILING, 120);
    }

    #[test]
    fn permit_table_is_the_arena_permit_section() {
        assert_eq!(
            std::mem::size_of::<SharedPermitTable>(),
            std::mem::size_of::<carrick_kernel::arena::PermitSection>()
        );
        assert_eq!(
            std::mem::offset_of!(SharedPermitTable, slots),
            std::mem::offset_of!(carrick_kernel::arena::PermitSection, slots)
        );

        let arena = carrick_kernel::arena::KernelArena::global();
        let section = &arena.layout().permits as *const _ as usize;
        assert_eq!(permit_region().table_addr_for_test(), section);
    }

    #[test]
    fn vm_residency_region_is_the_arena_vm_slots_section() {
        let arena = carrick_kernel::arena::KernelArena::global();
        assert_eq!(
            vm_residency_region().table_addr_for_test(),
            &arena.layout().vm_slots as *const _ as usize,
        );
        // Independent of the permit table.
        assert_ne!(
            vm_residency_region().table_addr_for_test(),
            permit_region().table_addr_for_test(),
        );
    }

    #[test]
    fn vm_residency_record_release_roundtrip_on_test_region() {
        let region = PermitRegion::new_anon_for_test();
        let pid = std::process::id();
        let token = region
            .acquire(atomic_permit_slot::MAX_SLOTS, pid)
            .expect("record acquires unconditionally under MAX_SLOTS");
        region.register(VM_RESIDENCY_LOCAL_KEY, token);
        assert_eq!(region.occupied(), 1);
        region.release_token(VM_RESIDENCY_LOCAL_KEY);
        assert_eq!(region.occupied(), 0);
        // Idempotent: a second release is a no-op.
        region.release_token(VM_RESIDENCY_LOCAL_KEY);
        assert_eq!(region.occupied(), 0);
    }

    // ---- Part B: HV_NO_RESOURCES park+retry backpressure ----
    // The live fork-storm never reaches the ~126 hard ceiling under the 120 soft
    // budget, so these drive the bounded retry loop directly (millisecond timings)
    // to prove: transient HV_NO_RESOURCES recovers, a genuinely-full host bounds
    // out and propagates, and a non-NoResources error is never parked on.
    use applevisor::error::HypervisorError;
    use std::cell::Cell;
    use std::time::Duration;

    #[test]
    fn no_resources_backpressure_recovers_after_transient() {
        // NoResources for the first two attempts, then success — the loop must
        // park+retry through them and return Ok, not propagate.
        let calls = Cell::new(0u32);
        let out: Result<u64, TrapError> = create_with_no_resources_backpressure_bounded(
            "test",
            Duration::from_millis(1),
            Duration::from_secs(5),
            || {
                let n = calls.get();
                calls.set(n + 1);
                if n < 2 {
                    Err(HypervisorError::NoResources)
                } else {
                    Ok(42)
                }
            },
        );
        assert_eq!(out.ok(), Some(42), "transient NoResources must recover");
        assert_eq!(calls.get(), 3, "expected two retries then success");
    }

    #[test]
    fn no_resources_backpressure_bounds_out_when_host_is_full() {
        // Always NoResources: the loop must give up after ~max_wait and propagate
        // the error (never hang forever). A tiny max_wait keeps the test fast.
        let calls = Cell::new(0u32);
        let start = std::time::Instant::now();
        let out: Result<u64, TrapError> = create_with_no_resources_backpressure_bounded(
            "test",
            Duration::from_millis(1),
            Duration::from_millis(20),
            || {
                calls.set(calls.get() + 1);
                Err(HypervisorError::NoResources)
            },
        );
        assert!(
            out.is_err(),
            "a genuinely-full host must propagate the error"
        );
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "bounded wait must not hang"
        );
        assert!(
            calls.get() >= 2,
            "expected at least one park+retry before giving up"
        );
    }

    #[test]
    fn no_resources_backpressure_never_parks_on_other_errors() {
        // A non-NoResources error is propagated immediately, with no retry.
        let calls = Cell::new(0u32);
        let out: Result<u64, TrapError> = create_with_no_resources_backpressure_bounded(
            "test",
            Duration::from_secs(30),
            Duration::from_secs(30),
            || {
                calls.set(calls.get() + 1);
                Err(HypervisorError::Busy)
            },
        );
        assert!(out.is_err());
        assert_eq!(
            calls.get(),
            1,
            "a non-NoResources error must not be retried"
        );
    }

    #[test]
    fn global_permit_retries_back_off_to_cap() {
        let mut backoff = GlobalVcpuPermitBackoff::default();
        let delays: Vec<_> = (0..8).map(|_| backoff.next_delay()).collect();

        assert_eq!(
            delays,
            [
                std::time::Duration::from_millis(1),
                std::time::Duration::from_millis(2),
                std::time::Duration::from_millis(4),
                std::time::Duration::from_millis(8),
                std::time::Duration::from_millis(16),
                std::time::Duration::from_millis(32),
                std::time::Duration::from_millis(50),
                std::time::Duration::from_millis(50),
            ]
        );
    }

    #[test]
    fn mn_budget_uses_physical_cores_but_never_exceeds_hvf_cap() {
        // The hypervisor ceiling is the budget; the host's core count is not a
        // correctness bound on how many guest threads may be admitted.
        assert_eq!(vcpu_gate::budget_from_limits(60, 10), 60);
        assert_eq!(vcpu_gate::budget_from_limits(6, 10), 6);
        assert_eq!(vcpu_gate::budget_from_limits(60, 0), 60);
        assert_eq!(vcpu_gate::budget_from_limits(0, 10), 1);
    }

    // ---- Atomic permit slot-table state machine (Option 3, Task 1) ----------
    //
    // These prove the load-bearing invariant the 3b bare-counter attempt lost:
    // ownership is the source of truth, so a crash between acquire and
    // vcpu_create is reclaimable and no sibling teardown or stale event can
    // free a live owner's slot.

    #[test]
    fn acquire_cannot_leave_an_unowned_count() {
        let r = PermitRegion::new_anon_for_test();
        let t = r.acquire(4, std::process::id()).unwrap(); // slot published owned BEFORE any count-only state
        assert_eq!(r.occupied(), 1);
        assert_eq!(r.slot_state(t.slot), SlotState::Acquiring); // owner+gen visible even pre-register
        assert!(r.try_free_exact_for_test(t));
        assert_eq!(r.occupied(), 0);
    }

    #[test]
    fn vcpu_destroyed_of_unregistered_vcpu_does_not_release_a_permit() {
        let r = PermitRegion::new_anon_for_test();
        let t = r.acquire(4, std::process::id()).unwrap();
        r.register(100, t); // vcpu 100 holds the permit
        r.release_token(999); // an UNPERMITTED sibling vcpu teardown
        assert_eq!(r.occupied(), 1); // must NOT free vcpu 100's permit
        r.release_token(100);
        assert_eq!(r.occupied(), 0);
    }

    #[test]
    fn release_is_generation_checked() {
        let r = PermitRegion::new_anon_for_test();
        let t = r.acquire(4, std::process::id()).unwrap();
        r.register(1, t);
        let stale = PermitToken {
            generation: t.generation.wrapping_sub(1),
            ..t
        };
        assert!(!r.try_free_exact_for_test(stale)); // a stale token/event cannot free a newer owner
        assert_eq!(r.occupied(), 1);
    }

    // ---- Cooperative carrier-exit release -----------------------------------

    #[test]
    fn cooperative_release_frees_owned_slots_and_is_idempotent() {
        let r = PermitRegion::new_anon_for_test();
        let pid = std::process::id();
        let t1 = r.acquire(4, pid).unwrap();
        r.register(1, t1);
        let t2 = r.acquire(4, pid).unwrap();
        r.register(2, t2);
        assert_eq!(r.occupied(), 2);

        // The carrier-exit fast path frees both registered slots at once.
        assert_eq!(r.cooperative_release_local(), 2);
        assert_eq!(r.occupied(), 0);
        assert!(r.local_token(1).is_none());
        assert!(r.local_token(2).is_none());

        // Idempotent: a second call frees nothing.
        assert_eq!(r.cooperative_release_local(), 0);
        assert_eq!(r.occupied(), 0);
    }

    #[test]
    fn cooperative_release_is_idempotent_with_vcpu_destroyed() {
        let r = PermitRegion::new_anon_for_test();
        let pid = std::process::id();
        let t1 = r.acquire(4, pid).unwrap();
        r.register(10, t1);
        let t2 = r.acquire(4, pid).unwrap();
        r.register(20, t2);
        // A normal `vcpu_destroyed` already released one token (removed it from
        // the local map AND freed its slot) before the process exits.
        r.release_token(10);
        assert_eq!(r.occupied(), 1);
        // Cooperative exit frees only the STILL-owned remaining slot; no double-free.
        assert_eq!(r.cooperative_release_local(), 1);
        assert_eq!(r.occupied(), 0);
    }

    #[test]
    fn atomic_permit_enabled_from_env_defaults_to_atomic() {
        // The flip: atomic admission is the DEFAULT admission path.
        // Unset → enabled.
        assert!(atomic_permit_enabled_from_env(None));
        // `=1` → enabled (the historical explicit-on still works).
        assert!(atomic_permit_enabled_from_env(Some("1")));
        // Explicit falsey tokens → disabled = the flock fallback.
        assert!(!atomic_permit_enabled_from_env(Some("0")));
        assert!(!atomic_permit_enabled_from_env(Some("false")));
        assert!(!atomic_permit_enabled_from_env(Some("no")));
        // Case-insensitive, tolerant of surrounding whitespace.
        assert!(!atomic_permit_enabled_from_env(Some("FALSE")));
        assert!(!atomic_permit_enabled_from_env(Some(" 0 ")));
        // Any other value falls through to the default (enabled).
        assert!(atomic_permit_enabled_from_env(Some("yes")));
        assert!(atomic_permit_enabled_from_env(Some("")));
    }

    #[test]
    fn cooperative_release_atomic_permit_is_noop_on_flock_path() {
        // `CARRICK_HVF_ATOMIC_PERMIT=0` selects the legacy flock fallback...
        assert!(!atomic_permit_enabled_from_env(Some("0")));
        // ...on which `cooperative_release_atomic_permit` early-returns 0 without
        // touching the region (the permit is fd-lifetime-bound). Mirror that
        // "frees nothing" result against a fresh region: with no owned local
        // slots the cooperative release frees zero and leaves the table empty.
        // (Testing the parse gate here rather than the process-global
        // `atomic_permit_enabled()` cache, which is now DEFAULT-on and cannot be
        // toggled per-test without the edition-2024-unsafe `set_var`.)
        let r = PermitRegion::new_anon_for_test();
        assert_eq!(r.cooperative_release_local(), 0);
        assert_eq!(r.occupied(), 0);
    }

    // ---- Task 4: execve rebuild releases the pre-exec token, no double-free -
    //
    // `execve_rebuild` destroys the inherited pre-exec vCPU with a raw
    // `hv_vcpu_destroy` and calls `vcpu_destroyed(inherited_vcpu_id)` BEFORE
    // creating the replacement VM/vCPU under `VmCreateAdmission::ExecveRebuild`
    // (`global_permit_budget_depends_on_admission_kind` above proves that
    // admission class's budget is `None`, so the replacement acquires no
    // permit at all). After Task 1's tokenization this is ALREADY correct: the
    // pre-exec `vcpu_id` was registered when its process/thread was admitted
    // (`Initial`/`SharedWaitResume` have `Some` budgets), so `vcpu_destroyed`'s
    // `release_token(vcpu_id)` finds it in the
    // local map and frees exactly that slot — no leak, and nothing left for an
    // extra explicit release to double-free. These tests drive that exact
    // sequence against a private `PermitRegion` (they never call
    // `atomic_permit_enabled()` or the real dispatch functions, so they are
    // insulated from the process-global gate — now DEFAULT-on) to PROVE the
    // premise instead of merely asserting it.

    #[test]
    fn execve_rebuild_releases_pre_exec_permit_and_acquires_nothing_new() {
        let r = PermitRegion::new_anon_for_test();
        let pid = std::process::id();

        // Pre-exec admission (e.g. `VmCreateAdmission::Initial`, budget
        // `Some(_)`): `create_vcpu_with_permit` registers the token against
        // the vCPU it just created.
        let pre_exec_vcpu_id = 42u64;
        let budget = VmCreateAdmission::Initial
            .global_permit_budget()
            .expect("Initial admission is budgeted");
        let t = r.acquire(budget, pid).unwrap();
        r.register(pre_exec_vcpu_id, t);
        assert_eq!(r.occupied(), 1);

        // execve_rebuild: hv_vcpu_destroy(inherited_vcpu_id) succeeds, so
        // vcpu_destroyed(inherited_vcpu_id) runs, which dispatches to
        // release_token(pre_exec_vcpu_id) on the atomic path.
        r.release_token(pre_exec_vcpu_id);
        assert_eq!(
            r.occupied(),
            0,
            "the pre-exec permit must already be released by the ordinary \
             vcpu_destroyed path, before the ungated replacement is created"
        );

        // create_vm_with_admission(ExecveRebuild) acquires NOTHING (budget
        // None), so create_vcpu_with_permit registers no token for the
        // replacement vCPU — even if HVF hands back the same numeric id.
        assert_eq!(
            VmCreateAdmission::ExecveRebuild.global_permit_budget(),
            None
        );
        let post_exec_vcpu_id = pre_exec_vcpu_id;
        assert!(r.local_token(post_exec_vcpu_id).is_none());
        assert_eq!(
            r.occupied(),
            0,
            "exec must not leave the table over baseline"
        );

        // A later vcpu_destroyed on the post-exec vCPU (e.g. eventual process
        // exit) must be a safe no-op: it never registered a token.
        r.release_token(post_exec_vcpu_id);
        assert_eq!(r.occupied(), 0);
    }

    #[test]
    fn execve_rebuild_extra_release_would_be_a_harmless_but_pointless_noop() {
        // Guards the "do NOT add an explicit release" half of the premise: an
        // EXTRA release bolted onto execve_rebuild alongside the existing
        // vcpu_destroyed call would target a slot vcpu_destroyed already
        // freed. release_token is token-guarded (the local map entry is gone
        // after the first call), so a redundant second call on the SAME
        // vcpu_id is a no-op, not a double-free — but it also proves such an
        // addition does nothing useful, i.e. it is dead weight at best. This
        // locks in that no-op behavior so nobody "fixes" the proof-passing
        // case with an unnecessary release.
        let r = PermitRegion::new_anon_for_test();
        let pid = std::process::id();
        let t = r.acquire(4, pid).unwrap();
        r.register(7, t);

        r.release_token(7); // the real vcpu_destroyed(inherited_vcpu_id) release
        assert_eq!(r.occupied(), 0);

        r.release_token(7); // a hypothetical redundant "exec path" release
        assert_eq!(
            r.occupied(),
            0,
            "a redundant release on an already-released vcpu_id must stay a no-op"
        );
    }

    #[test]
    fn region_address_is_inherited_across_fork() {
        let _fork_serial = crate::fork_test_lock();
        // The MAP_ANON|MAP_SHARED region must live at the same address in a fork
        // child AND expose the same physical slot table, so a child's acquire is
        // visible to the parent. This is the property flock got from the kernel.
        let r = PermitRegion::new_anon_for_test();
        let parent_addr = r.table_addr_for_test();
        assert_eq!(r.occupied(), 0);
        // SAFETY: the child does only async-signal-safe atomic work on the shared
        // region (no allocation, no locks) before `_exit`, so the multithreaded
        // test harness fork is safe here.
        match unsafe { libc::fork() } {
            -1 => panic!("fork failed"),
            0 => {
                let addr_ok = r.table_addr_for_test() == parent_addr;
                let acquired = r.acquire(4, std::process::id()).is_some();
                unsafe { libc::_exit(if addr_ok && acquired { 0 } else { 1 }) };
            }
            pid => {
                let mut status: libc::c_int = 0;
                let rc = unsafe { libc::waitpid(pid, &mut status, 0) };
                assert_eq!(rc, pid);
                assert!(
                    libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
                    "child saw a different region address or could not acquire"
                );
                // The child's acquire on the SHARED table is visible in the parent.
                assert_eq!(r.occupied(), 1);
            }
        }
    }

    /// Regression smoke test for the store-buffering over-admit race: with
    /// `AcqRel`/`Acquire` (no total store order), two threads claiming
    /// DIFFERENT slots could each fail to see the other's just-published claim
    /// when checking `occupied()` against `budget`, so both would keep their
    /// claim and the number of SIMULTANEOUSLY-held permits could exceed
    /// `budget` (e.g. 5 outstanding vs a cap of 4). `SeqCst` on the claim CAS
    /// and the `occupied()` loads forbids that outcome.
    ///
    /// NOTE: a memory-ordering bug is not guaranteed to reproduce
    /// deterministically (it depends on the host's actual store-buffering
    /// behavior and scheduling), so this test's value is as a regression
    /// tripwire, not a proof the ordering is correct.
    #[test]
    fn concurrent_acquire_never_over_admits_past_budget() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let region = Arc::new(PermitRegion::new_anon_for_test());
        let budget = 4usize;
        let held = Arc::new(AtomicUsize::new(0));
        let max_held = Arc::new(AtomicUsize::new(0));
        let iterations = 5_000;

        let handles: Vec<_> = (0..8)
            .map(|_| {
                let region = Arc::clone(&region);
                let held = Arc::clone(&held);
                let max_held = Arc::clone(&max_held);
                std::thread::spawn(move || {
                    let pid = std::process::id();
                    for _ in 0..iterations {
                        if let Some(token) = region.acquire(budget, pid) {
                            let now = held.fetch_add(1, Ordering::SeqCst) + 1;
                            max_held.fetch_max(now, Ordering::SeqCst);
                            // Widen the race window before releasing.
                            std::thread::yield_now();
                            held.fetch_sub(1, Ordering::SeqCst);
                            region.release_unregistered(token);
                        }
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }

        let observed = max_held.load(Ordering::SeqCst);
        assert!(
            observed <= budget,
            "observed {observed} concurrently-held permits with budget {budget} \
             — over-admission past the budget cap (store-buffering regression)"
        );
    }
}
