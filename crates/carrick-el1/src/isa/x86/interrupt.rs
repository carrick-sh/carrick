//! CPL0 APIC and interrupt-mask projection.

use super::{ArchError, X86Backend, interrupts};
use carrick_guest_arch::{
    AddressContext, ContextGeneration, CounterFrequency, CounterTick, CpuId, CpuTarget, Deadline,
    InterruptAck, InterruptBackend, InterruptReason, MmGeneration, RootGpa, WakeToken,
};
use core::num::NonZeroU64;
use core::sync::atomic::{Ordering, fence};

fn shootdown_table(
    binding: &super::context::native::CpuBinding,
) -> Result<&'static super::context::native::ShootdownTable, ArchError> {
    if binding.shootdown_table_address == 0 {
        return Err(ArchError::Unbound);
    }
    // SAFETY: stopped KVM bootstrap initialized the supervisor-only table
    // before either vCPU ran and retains it until both vCPUs retire.
    Ok(unsafe {
        &*(binding.shootdown_table_address as *const super::context::native::ShootdownTable)
    })
}

pub(crate) fn current_address_owner(
    binding: &super::context::native::CpuBinding,
) -> Result<AddressContext<RootGpa>, ArchError> {
    let root = super::mmu::hardware_live_root()?;
    if binding.task_address == 0 {
        return Err(ArchError::Unbound);
    }
    // SAFETY: the admitted binding retains its exact task record until the
    // host stops this vCPU; the MM key is atomically published before entry.
    let task = unsafe { &*(binding.task_address as *const carrick_el1_abi::CurrentTask) };
    let mm = NonZeroU64::new(task.mm.key.load(Ordering::Acquire)).ok_or(ArchError::Unbound)?;
    let generation = NonZeroU64::new(binding.mm_owner_generation.load(Ordering::Acquire))
        .ok_or(ArchError::Unbound)?;
    Ok(AddressContext {
        root,
        mm: MmGeneration::new(mm),
        generation: ContextGeneration::new(generation),
    })
}

/// Install a new x86 address owner and publish its exact member identity as
/// one transition. Senders treat an odd revision as potentially matching.
pub(crate) fn install_address_context(context: AddressContext<RootGpa>) -> Result<(), ArchError> {
    super::mmu::hardware_live_root()?;
    let binding = super::context::current_cpu_binding().ok_or(ArchError::Unbound)?;
    let table = shootdown_table(binding)?;
    let member = table
        .members
        .get(binding.cpu_slot as usize)
        .ok_or(ArchError::Unbound)?;
    if binding.task_address == 0 {
        return Err(ArchError::Unbound);
    }
    // SAFETY: this CPU's stopped-host binding retains the current task.
    // Update the task's active MM identity to match the installed context.
    let task = unsafe { &*(binding.task_address as *const carrick_el1_abi::CurrentTask) };
    task.mm.key.store(context.mm.raw().get(), Ordering::Release);
    member.revision.fetch_add(1, Ordering::AcqRel);
    // SAFETY: the authenticated context owns a retained supervisor mapping;
    // PCID/PGE were rejected above, so MOV CR3 flushes local translations.
    unsafe {
        core::arch::asm!(
            "mov cr3, {}",
            in(reg) context.root.address().raw(),
            options(nostack, preserves_flags)
        )
    };
    binding
        .mm_owner_generation
        .store(context.generation.raw().get(), Ordering::Release);
    let mut current_gen = 0;
    for request in &table.requests {
        if request.root.load(Ordering::Acquire) == context.root.address().raw()
            && request.mm_key.load(Ordering::Acquire) == context.mm.raw().get()
            && request.owner_generation.load(Ordering::Acquire) == context.generation.raw().get()
        {
            current_gen = current_gen.max(request.generation.load(Ordering::Acquire));
        }
    }
    binding
        .last_seen_generation
        .store(current_gen, Ordering::Release);
    member
        .root
        .store(context.root.address().raw(), Ordering::Relaxed);
    member
        .mm_key
        .store(context.mm.raw().get(), Ordering::Relaxed);
    member
        .owner_generation
        .store(context.generation.raw().get(), Ordering::Relaxed);
    member.revision.fetch_add(1, Ordering::Release);
    Ok(())
}

/// A root page through its retained supervisor alias (direct window or
/// initial-extent alias), bounds-checked by the shared table-alias rule.
fn direct_root(root: RootGpa) -> Result<&'static [u64; 512], ArchError> {
    let alias = carrick_el1_abi::x86_cpl0_table_alias(root.address()).ok_or(ArchError::Unbound)?;
    // SAFETY: boot retains this alias over the aligned page; root pages are
    // only read here, and shared supervisor entries never move.
    Ok(unsafe { &*(alias.raw() as *const [u64; 512]) })
}

/// Leave every process root for the carrier's maintenance root, which holds
/// only the shared supervisor branches. The caller then releases the slot's
/// installed space: from that point this CPU caches and walks no table of
/// any MM, so a retired MM's tables may be cleared and reissued.
pub fn install_maintenance_root(maintenance: RootGpa) -> Result<(), ArchError> {
    let live = super::mmu::hardware_live_root()?;
    // The maintenance root is a copy of the shared supervisor entries taken
    // when fork stock was installed; refuse it if they changed since.
    if !carrick_mmu_core::x86::owner_mmu::maintenance_root_matches(
        direct_root(live)?,
        direct_root(maintenance)?,
    ) {
        return Err(ArchError::Unbound);
    }
    let binding = super::context::current_cpu_binding().ok_or(ArchError::Unbound)?;
    let table = shootdown_table(binding)?;
    let member = table
        .members
        .get(binding.cpu_slot as usize)
        .ok_or(ArchError::Unbound)?;
    member.revision.fetch_add(1, Ordering::AcqRel);
    // SAFETY: the carrier retains the maintenance root's shared supervisor
    // branches for the VM lifetime; PCID/PGE were rejected above, so MOV CR3
    // drains every local translation of the previous root.
    unsafe {
        core::arch::asm!(
            "mov cr3, {}",
            in(reg) maintenance.address().raw(),
            options(nostack, preserves_flags)
        )
    };
    // No MM is installed: no shootdown sender waits for this CPU.
    member.root.store(0, Ordering::Relaxed);
    member.mm_key.store(0, Ordering::Relaxed);
    member.owner_generation.store(0, Ordering::Relaxed);
    member.revision.fetch_add(1, Ordering::Release);
    Ok(())
}

fn publish_root_request(
    context: AddressContext<RootGpa>,
    table: &super::context::native::ShootdownTable,
    slot: usize,
) -> Result<u64, ArchError> {
    let request = table.requests.get(slot).ok_or(ArchError::Unbound)?;
    let generation = table
        .next_generation
        .fetch_add(1, Ordering::AcqRel)
        .checked_add(1)
        .filter(|generation| *generation != 0)
        .ok_or(ArchError::Unbound)?;
    request
        .root
        .store(context.root.address().raw(), Ordering::Relaxed);
    request
        .mm_key
        .store(context.mm.raw().get(), Ordering::Relaxed);
    request
        .owner_generation
        .store(context.generation.raw().get(), Ordering::Relaxed);
    request.generation.store(generation, Ordering::Release);
    Ok(generation)
}

/// Service all published sender generations on this CPU. This is also called
/// from a sender's wait loop, so two CPUs invalidating each other cannot deadlock
/// with IF masked. A context install always MOV CR3, closing a switch race.
pub fn service_shootdowns() -> Result<(), ArchError> {
    let binding = super::context::current_cpu_binding().ok_or(ArchError::Unbound)?;
    let slot = binding.cpu_slot as usize;
    let table = shootdown_table(binding)?;
    if slot >= table.requests.len() {
        return Err(ArchError::Unbound);
    }
    for request in &table.requests {
        let generation = request.generation.load(Ordering::Acquire);
        if generation == 0 || request.served[slot].load(Ordering::Acquire) >= generation {
            continue;
        }
        let root = request.root.load(Ordering::Relaxed);
        let mm_key = request.mm_key.load(Ordering::Relaxed);
        let owner_generation = request.owner_generation.load(Ordering::Relaxed);
        if root == 0 || mm_key == 0 || owner_generation == 0 {
            return Err(ArchError::Unbound);
        }
        let live = current_address_owner(binding)?;
        if live.root.address().raw() == root
            && live.mm.raw().get() == mm_key
            && live.generation.raw().get() == owner_generation
        {
            // SAFETY: PCID/PGE are rejected by hardware_live_root. Reloading
            // the same CR3 drains every local non-global translation before
            // the release acknowledgement becomes visible to the editor.
            unsafe {
                core::arch::asm!("mov cr3, {}", in(reg) root, options(nostack, preserves_flags))
            }
            binding
                .last_seen_generation
                .fetch_max(generation, Ordering::Release);
        }
        request.served[slot].store(generation, Ordering::Release);
        request.ack[slot].store(generation, Ordering::Release);
    }
    Ok(())
}

/// Settle outstanding shootdown debt before touching user memory in CPL0.
/// Any active debt for this root reloads CR3 and records acknowledgement.
pub fn sync_user_memory_generation() -> Result<(), ArchError> {
    service_shootdowns()
}

/// Completed x86 shootdown drain receipt. A producer passes this to the MM
/// publication layer to settle global drain debt with `acknowledge_global_drain`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShootdownReceipt {
    pub context: AddressContext<RootGpa>,
    pub generation: u64,
}

impl ShootdownReceipt {
    pub const fn new(context: AddressContext<RootGpa>, generation: u64) -> Self {
        Self {
            context,
            generation,
        }
    }

    pub const fn mm_key(&self) -> NonZeroU64 {
        self.context.mm.raw()
    }

    pub const fn owner_generation(&self) -> NonZeroU64 {
        self.context.generation.raw()
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }
}

#[cold]
#[inline(never)]
pub fn fatal_unacknowledged_shootdown(cpu: u32, root: u64, generation: u64) -> ! {
    #[cfg(target_os = "none")]
    unsafe {
        core::arch::asm!(
            "out dx, al",
            "2: hlt",
            "jmp 2b",
            in("dx") super::context::native::FATAL_PORT,
            in("rax") carrick_el1_abi::PANIC_SENTINEL,
            in("rsi") (u64::from(cpu) << 32) | (generation & 0xffff_ffff),
            in("rdi") root,
            options(noreturn)
        );
    }
    #[cfg(not(target_os = "none"))]
    panic!("fatal: shootdown ack never arrived for cpu {cpu}, root {root:#x}, gen {generation}");
}

#[cfg(target_os = "none")]
unsafe extern "Rust" {
    fn carrick_fixture_hold_check(
        table: &super::context::native::ShootdownTable,
        target_mode: u32,
    ) -> Result<(), ArchError>;
}

/// Publish the exact edited root/MM generation and wait only for matching
/// CPUs that were running when the request became visible. A stopped CPU
/// settles its retained generation through KICK before its next user access.
pub fn rendezvous_context(context: AddressContext<RootGpa>) -> Result<ShootdownReceipt, ArchError> {
    let binding = super::context::current_cpu_binding().ok_or(ArchError::Unbound)?;
    let slot = binding.cpu_slot as usize;
    let table = shootdown_table(binding)?;
    if current_address_owner(binding)? != context {
        return Err(ArchError::Unbound);
    }
    // Check if any peer currently has this root active (or changing).
    let mut any_peer_active = false;
    for peer in 0..table.requests.len() {
        if peer == slot {
            continue;
        }
        let member = &table.members[peer];
        if member.matches_or_changing(
            context.root.address().raw(),
            context.mm.raw().get(),
            context.generation.raw().get(),
        ) {
            any_peer_active = true;
            break;
        }
    }
    if !any_peer_active {
        // No other CPU has this root active: local INVLPG (executed during the
        // descriptor edit transaction) is sufficient.
        let seen_gen = binding.last_seen_generation.load(Ordering::Acquire);
        return Ok(ShootdownReceipt::new(context, seen_gen));
    }
    #[cfg(target_os = "none")]
    unsafe {
        carrick_fixture_hold_check(table, super::context::native::FIXTURE_HOLD_PUBLISH)?;
    }
    let generation = publish_root_request(context, table, slot)?;
    let request = table.requests.get(slot).ok_or(ArchError::Unbound)?;
    binding
        .last_seen_generation
        .fetch_max(generation, Ordering::Release);
    service_shootdowns()?;
    fence(Ordering::SeqCst);
    let mut awaited = [false; super::context::native::CPL0_CPU_COUNT];
    for (peer, awaited_peer) in awaited.iter_mut().enumerate().take(table.requests.len()) {
        if peer == slot {
            continue;
        }
        let member = &table.members[peer];
        if member.running.load(Ordering::Acquire) == 0
            || !member.matches_or_changing(
                context.root.address().raw(),
                context.mm.raw().get(),
                context.generation.raw().get(),
            )
        {
            continue;
        }
        *awaited_peer = true;
        let apic = bound_apic_id(CpuId::new(peer as u32))?;
        #[cfg(target_os = "none")]
        unsafe {
            carrick_fixture_hold_check(table, super::context::native::FIXTURE_HOLD_IPI)?;
        }
        // SAFETY: the retained request is published before this native IPI.
        unsafe { interrupts::hardware::send_shootdown(apic) }.map_err(|_| ArchError::Busy)?;
    }
    let tsc_hz = tsc_frequency().ok_or(ArchError::Unbound)?.get();
    let limit = tsc_hz.checked_mul(5).ok_or(ArchError::Unbound)?;
    let start = read_tsc();
    for (peer, &awaited_peer) in awaited.iter().enumerate().take(table.requests.len()) {
        if !awaited_peer {
            continue;
        }
        while request.ack[peer].load(Ordering::Acquire) < generation {
            let member = &table.members[peer];
            if member.running.load(Ordering::Acquire) == 0 {
                break;
            }
            service_shootdowns()?;
            if read_tsc().wrapping_sub(start) > limit {
                fatal_unacknowledged_shootdown(
                    peer as u32,
                    context.root.address().raw(),
                    generation,
                );
            }
            core::hint::spin_loop();
        }
    }
    Ok(ShootdownReceipt::new(context, generation))
}

/// Validate this CPU's invalidation generation before returning to user mode.
/// A CPU whose seen generation is behind does a full CR3 reload.
pub fn check_user_return_generation() -> Result<(), ArchError> {
    service_shootdowns()?;
    let binding = super::context::current_cpu_binding().ok_or(ArchError::Unbound)?;
    let table = shootdown_table(binding)?;
    let live = current_address_owner(binding)?;
    let mut latest_gen = binding.last_seen_generation.load(Ordering::Acquire);
    let mut behind = false;
    for request in &table.requests {
        let generation = request.generation.load(Ordering::Acquire);
        if generation > latest_gen
            && request.root.load(Ordering::Acquire) == live.root.address().raw()
            && request.mm_key.load(Ordering::Acquire) == live.mm.raw().get()
            && request.owner_generation.load(Ordering::Acquire) == live.generation.raw().get()
        {
            latest_gen = generation;
            behind = true;
        }
    }
    if behind {
        let root = live.root.address().raw();
        // SAFETY: PCID/PGE are rejected. Reloading CR3 drains stale translations before user mode.
        unsafe { core::arch::asm!("mov cr3, {}", in(reg) root, options(nostack, preserves_flags)) }
        binding
            .last_seen_generation
            .fetch_max(latest_gen, Ordering::Release);
    }
    Ok(())
}

/// Native two-sender fixture entry; normal MM edits pass the typed owner.
pub fn rendezvous_root(root: u64) -> Result<u64, ArchError> {
    let binding = super::context::current_cpu_binding().ok_or(ArchError::Unbound)?;
    let context = current_address_owner(binding)?;
    if context.root.address().raw() != root {
        return Err(ArchError::Unbound);
    }
    rendezvous_context(context).map(|receipt| receipt.generation)
}

pub fn read_tsc() -> u64 {
    let (lo, hi): (u32, u32);
    // SAFETY: RDTSC reads this admitted CPU's monotonic counter only.
    unsafe {
        core::arch::asm!(
            "rdtsc", out("eax") lo, out("edx") hi,
            options(nomem, nostack, preserves_flags)
        );
    }
    (u64::from(hi) << 32) | u64::from(lo)
}

fn witness_mutual_rendezvous() -> Result<u64, ArchError> {
    let binding = super::context::current_cpu_binding().ok_or(ArchError::Unbound)?;
    let slot = binding.cpu_slot as usize;
    let table = shootdown_table(binding)?;
    if slot >= table.requests.len() {
        return Err(ArchError::Unbound);
    }
    let limit = tsc_frequency()
        .ok_or(ArchError::Unbound)?
        .get()
        .checked_mul(5)
        .ok_or(ArchError::Unbound)?;
    let start = read_tsc();
    table.fixture_arrived.fetch_or(1 << slot, Ordering::AcqRel);
    while table.fixture_arrived.load(Ordering::Acquire) != 0b11 {
        if read_tsc().wrapping_sub(start) > limit {
            return Err(ArchError::Busy);
        }
        core::hint::spin_loop();
    }
    let root = super::mmu::hardware_live_root()?.address().raw();
    let generation = rendezvous_root(root)?;
    let peer = 1 - slot;
    // Hold this fixture CPU live until it has serviced the peer's request.
    // Without this, a completed vCPU can leave KVM_RUN before the peer sends.
    loop {
        service_shootdowns()?;
        let peer_request = &table.requests[peer];
        let peer_generation = peer_request.generation.load(Ordering::Acquire);
        if peer_generation != 0 && peer_request.ack[slot].load(Ordering::Acquire) >= peer_generation
        {
            return Ok(generation);
        }
        if read_tsc().wrapping_sub(start) > limit {
            return Err(ArchError::Busy);
        }
        core::hint::spin_loop();
    }
}

/// Native interrupt identity. These are xAPIC vectors, never ARM GIC INTIDs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeIrq {
    Timer,
    Kick,
    Resched,
    Shootdown,
}

impl NativeIrq {
    pub const fn from_vector(vector: u8) -> Option<Self> {
        match vector {
            interrupts::TIMER_VECTOR => Some(Self::Timer),
            interrupts::KICK_VECTOR => Some(Self::Kick),
            interrupts::RESCHED_VECTOR => Some(Self::Resched),
            interrupts::SHOOTDOWN_VECTOR => Some(Self::Shootdown),
            _ => None,
        }
    }

    pub const fn pending_bit(self) -> u32 {
        match self {
            Self::Timer => 1,
            Self::Kick => 2,
            Self::Resched => 4,
            Self::Shootdown => 8,
        }
    }
}

/// Retain the accepted native IRQ until the shared scheduler drains it.
/// The interrupt gate masks IF; the accepted xAPIC ISR must match its gate.
pub fn capture_irq(vector: u8) -> Result<NativeIrq, ArchError> {
    let irq = NativeIrq::from_vector(vector).ok_or(ArchError::InvalidFrame)?;
    let binding = super::context::current_cpu_binding().ok_or(ArchError::Unbound)?;
    // SAFETY: this CPL0 CPU owns the mapped xAPIC ISR and IF is masked by
    // the interrupt gate throughout publication and EOI.
    if unsafe { interrupts::hardware::highest_in_service_vector() } != Some(vector) {
        return Err(ArchError::InvalidFrame);
    }
    if matches!(irq, NativeIrq::Shootdown | NativeIrq::Kick) {
        service_shootdowns()?;
    }
    if irq == NativeIrq::Kick {
        let table = shootdown_table(binding)?;
        table
            .kick_checks
            .get(binding.cpu_slot as usize)
            .ok_or(ArchError::Unbound)?
            .fetch_add(1, Ordering::Release);
    }
    binding
        .pending_irqs
        .fetch_or(irq.pending_bit(), Ordering::Release);
    // SAFETY: the matching vector was confirmed in service above; EOI does
    // not consume the pending mailbox bit or a shootdown generation receipt.
    unsafe { interrupts::hardware::end_interrupt() };
    Ok(irq)
}

fn bound_apic_id(slot: CpuId) -> Result<interrupts::ApicId, ArchError> {
    let binding = super::context::current_cpu_binding().ok_or(ArchError::Unbound)?;
    if binding.wake_routes_address == 0 {
        return Err(ArchError::Unbound);
    }
    // SAFETY: stopped-host bootstrap mapped and initialized this exact table
    // before any vCPU ran; it remains live until every vCPU retires.
    let routes = unsafe {
        &*(binding.wake_routes_address as *const super::context::native::PublishedApicIds)
    };
    routes
        .destination(slot)
        .map(|route| interrupts::ApicId(route.0))
        .ok_or(ArchError::Unbound)
}

/// What became of a reschedule IPI [`send_resched`] was asked for.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReschedSend {
    /// The local APIC accepted the command.
    Sent,
    /// The local APIC was still sending this CPU's previous IPI (ICR
    /// delivery status busy). That is "not now": the IPI is owed in this
    /// CPU's binding ([`CpuBinding::owed_resched`]) and sent again at its
    /// next delivery point ([`deliver_owed_resched`]), at the latest before
    /// it returns to user ([`deliver_owed_resched_before_user`]). Nothing
    /// for the caller to do.
    ///
    /// [`CpuBinding::owed_resched`]: super::context::native::CpuBinding::owed_resched
    Owed,
}

/// Send a scheduler reschedule using a slot-indexed published APIC route.
///
/// A busy ICR never fails the send and is never spun on (#3083): the IPI
/// is owed by this CPU and resent once at each of its delivery points.
/// Only a broken invariant (no binding, no published route) is an error.
pub fn send_resched(slot: carrick_sched_core::SlotId) -> Result<ReschedSend, ArchError> {
    let binding = super::context::current_cpu_binding().ok_or(ArchError::Unbound)?;
    let apic = bound_apic_id(CpuId::new(u32::from(slot.raw())))?;
    // Older owed IPIs go first: this CPU's next send is a delivery point.
    let _ = deliver_owed_resched();
    core::sync::atomic::fence(Ordering::SeqCst);
    match send_resched_ipi(apic) {
        Ok(()) => Ok(ReschedSend::Sent),
        Err(interrupts::IpiBusy) => {
            owe_resched(binding, slot);
            Ok(ReschedSend::Owed)
        }
    }
}

/// Owed reschedule IPIs this CPU resent, for the KVM witness's census.
#[cfg(feature = "test-support")]
static OWED_RESCHED_RESENT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// Sends that found the ICR busy by injection, for the census.
#[cfg(feature = "test-support")]
static RESCHED_BUSY_INJECTED: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// Idle-ICR waits that observed the ICR busy, for the census.
#[cfg(feature = "test-support")]
static RESCHED_ICR_WAITS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// The [`UserReturn`] of the last resend at a return to user, for the census.
#[cfg(feature = "test-support")]
static RESCHED_RESEND_SITE: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);
/// The CPU slot (plus one) the busy injection applies to.
#[cfg(feature = "test-support")]
static RESCHED_BUSY_CPU: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
/// How many more of that CPU's IPI sends find the ICR busy (`u32::MAX`:
/// every one).
#[cfg(feature = "test-support")]
static RESCHED_SEND_BUSY_LEFT: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);
/// How many more of that CPU's idle-ICR polls read the ICR busy.
#[cfg(feature = "test-support")]
static RESCHED_POLL_BUSY_LEFT: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);

/// Make this CPU's next `sends` reschedule IPI sends (first sends and
/// resends alike; `u32::MAX`: all of them) and its next `polls` idle-ICR
/// polls find the ICR busy (#3083 witness). Another CPU's sends never
/// consume them. False when some are still armed, or this CPU has no
/// binding.
#[cfg(feature = "test-support")]
pub fn inject_resched_busy(sends: u32, polls: u32) -> bool {
    let Some(binding) = super::context::current_cpu_binding() else {
        return false;
    };
    if RESCHED_SEND_BUSY_LEFT.load(Ordering::Acquire) != 0
        || RESCHED_POLL_BUSY_LEFT.load(Ordering::Acquire) != 0
    {
        return false;
    }
    RESCHED_BUSY_CPU.store(binding.cpu_slot + 1, Ordering::Release);
    RESCHED_POLL_BUSY_LEFT.store(polls, Ordering::Release);
    RESCHED_SEND_BUSY_LEFT.store(sends, Ordering::Release);
    true
}

/// `(sends found busy by injection, owed IPIs resent, idle-ICR waits that
/// observed it busy, the last resend's UserReturn as u8)`, for the #3083
/// witness.
#[cfg(feature = "test-support")]
pub fn resched_busy_census() -> (u64, u64, u64, u8) {
    (
        RESCHED_BUSY_INJECTED.load(Ordering::Acquire),
        OWED_RESCHED_RESENT.load(Ordering::Acquire),
        RESCHED_ICR_WAITS.load(Ordering::Acquire),
        RESCHED_RESEND_SITE.load(Ordering::Acquire),
    )
}

/// Take one injected busy result from `left` for this CPU.
#[cfg(feature = "test-support")]
fn injected_busy(left: &core::sync::atomic::AtomicU32) -> bool {
    super::context::current_cpu_binding().is_some_and(|binding| {
        RESCHED_BUSY_CPU.load(Ordering::Acquire) == binding.cpu_slot + 1
            && left
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| match n {
                    0 => None,
                    u32::MAX => Some(u32::MAX),
                    n => Some(n - 1),
                })
                .is_ok()
    })
}

fn send_resched_ipi(apic: interrupts::ApicId) -> Result<(), interrupts::IpiBusy> {
    #[cfg(feature = "test-support")]
    if injected_busy(&RESCHED_SEND_BUSY_LEFT) {
        RESCHED_BUSY_INJECTED.fetch_add(1, Ordering::AcqRel);
        return Err(interrupts::IpiBusy);
    }
    // SAFETY: the scheduler published the target work before sending this
    // IPI; the stopped bootstrap retains the destination APIC until
    // retirement.
    unsafe { interrupts::hardware::send_resched(apic) }
}

/// Whether this CPU's own ICR still reads busy, for the idle-ICR wait.
fn icr_poll_busy() -> bool {
    #[cfg(feature = "test-support")]
    if injected_busy(&RESCHED_POLL_BUSY_LEFT) {
        return true;
    }
    // SAFETY: CPL0 on this CPU, with its local APIC mapped.
    unsafe { interrupts::hardware::icr_busy() }
}

fn owe_resched(binding: &super::context::native::CpuBinding, slot: carrick_sched_core::SlotId) {
    let index = usize::from(slot.raw());
    let Some(word) = binding.owed_resched.get(index / 64) else {
        // A slot the published routes named is a zone slot: always in range.
        super::fatal_entry_binding();
    };
    word.fetch_or(1 << (index % 64), Ordering::AcqRel);
}

/// Resend, once each, the reschedule IPIs this CPU owes ([`ReschedSend::Owed`]).
/// Called at every delivery point of this CPU short of a return to user:
/// its next reschedule send, each idle pass (before its reads, and before
/// HLT) and every interrupt that returns to the kernel. True when none is
/// owed any more; an IPI that finds the ICR busy again stays owed for the
/// next point, never waited on. A return to user is the last-chance point
/// ([`deliver_owed_resched_before_user`]).
#[must_use]
pub fn deliver_owed_resched() -> bool {
    resend_owed().clear
}

/// What one resend pass over this CPU's owed IPIs did.
struct Resent {
    /// None is owed any more.
    clear: bool,
    /// At least one owed IPI was sent.
    progress: bool,
}

fn resend_owed() -> Resent {
    let Some(binding) = super::context::current_cpu_binding() else {
        return Resent {
            clear: true,
            progress: false,
        };
    };
    let mut clear = true;
    let mut progress = false;
    for (word_index, word) in binding.owed_resched.iter().enumerate() {
        let mut owed = word.swap(0, Ordering::AcqRel);
        while owed != 0 {
            let bit = owed.trailing_zeros() as usize;
            let Some(slot) = u8::try_from(word_index * 64 + bit)
                .ok()
                .map(carrick_sched_core::SlotId::new)
            else {
                super::fatal_entry_binding();
            };
            let Ok(apic) = bound_apic_id(CpuId::new(u32::from(slot.raw()))) else {
                // The route was published when the IPI was owed, and routes
                // live until every vCPU retires.
                super::fatal_entry_binding();
            };
            core::sync::atomic::fence(Ordering::SeqCst);
            if send_resched_ipi(apic).is_err() {
                // Still busy: keep this and the rest owed, in order.
                word.fetch_or(owed, Ordering::AcqRel);
                clear = false;
                break;
            }
            #[cfg(feature = "test-support")]
            OWED_RESCHED_RESENT.fetch_add(1, Ordering::AcqRel);
            progress = true;
            owed &= owed - 1;
        }
        if !clear {
            break;
        }
    }
    Resent { clear, progress }
}

/// How long this CPU's own ICR may stay busy before its local APIC counts
/// as broken. The delivery-status bit is a hardware handshake that clears
/// once the APIC has handed the previous IPI to the interconnect, a few
/// bus cycles; the SDM gives no number. One millisecond is orders of
/// magnitude past it, so reaching it is a broken invariant, never
/// contention.
const ICR_IDLE_BOUND_NS: u128 = 1_000_000;

/// The last-chance delivery point (#3083): this CPU returns to user, and
/// may then run with no later kernel entry (a syscall-free loop, no timer
/// armed). Resend what it owes as [`deliver_owed_resched`] does; an IPI
/// whose ICR is still busy is not left owed past this point, but waits
/// for this CPU's own ICR to go idle (an ISA mechanic, how an x86 kernel
/// sends an IPI: no software holder to enrol on, and a timer retry would
/// be polling) and is then sent. An ICR busy past [`ICR_IDLE_BOUND_NS`] is
/// a broken local APIC: fatal.
pub fn deliver_owed_resched_before_user(site: UserReturn) {
    loop {
        let resent = resend_owed();
        #[cfg(feature = "test-support")]
        if resent.progress {
            RESCHED_RESEND_SITE.store(site as u8, Ordering::Release);
        }
        if resent.clear {
            return;
        }
        wait_icr_idle();
    }
}

/// The return to user a last-chance delivery runs at.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum UserReturn {
    /// A syscall's return (`carrier_validate_return`).
    Syscall = 1,
    /// The scheduler resuming a parked thread (`resume_parked`).
    Resume = 2,
    /// A resolved user page fault.
    PageFault = 3,
    /// An interrupt taken in user mode.
    Interrupt = 4,
}

fn wait_icr_idle() {
    let Some(hz) = tsc_frequency() else {
        super::fatal_entry_binding();
    };
    let bound = u128::from(hz.get()) * ICR_IDLE_BOUND_NS / 1_000_000_000;
    let start = read_tsc();
    while icr_poll_busy() {
        #[cfg(feature = "test-support")]
        RESCHED_ICR_WAITS.fetch_add(1, Ordering::AcqRel);
        if u128::from(read_tsc().wrapping_sub(start)) > bound {
            // A local APIC that never finishes its own send is broken.
            super::fatal_entry_binding();
        }
        core::hint::spin_loop();
    }
}

/// Query the TSC frequency from architectural CPUID or the exact KVM binding.
pub fn tsc_frequency() -> Option<NonZeroU64> {
    if let Some(hz) = super::context::current_cpu_binding()
        .and_then(|binding| NonZeroU64::new(binding.tsc_hz.load(Ordering::Acquire)))
    {
        return Some(hz);
    }
    let max_leaf: u32;
    // SAFETY: CPUID leaf 0 returns max basic leaf without side effects.
    unsafe {
        core::arch::asm!(
            "push rbx",
            "cpuid",
            "pop rbx",
            inout("eax") 0u32 => max_leaf,
            out("ecx") _,
            out("edx") _,
            options(nomem, preserves_flags),
        );
    }
    if max_leaf >= 0x15 {
        let eax: u32;
        let ebx: u32;
        let ecx: u32;
        // SAFETY: CPUID leaf 0x15 returns TSC frequency ratio and crystal clock.
        unsafe {
            core::arch::asm!(
                "push rbx",
                "cpuid",
                "mov {0:e}, ebx",
                "pop rbx",
                out(reg) ebx,
                inout("eax") 0x15u32 => eax,
                out("ecx") ecx,
                out("edx") _,
                options(nomem, preserves_flags),
            );
        }
        if eax != 0
            && ebx != 0
            && ecx != 0
            && let Some(prod) = (ecx as u64).checked_mul(ebx as u64)
            && let Some(hz) = NonZeroU64::new(prod / (eax as u64))
        {
            return Some(hz);
        }
    }
    if max_leaf >= 0x16 {
        let eax: u32;
        // SAFETY: CPUID leaf 0x16 returns processor base frequency in MHz.
        unsafe {
            core::arch::asm!(
                "push rbx",
                "cpuid",
                "pop rbx",
                inout("eax") 0x16u32 => eax,
                out("ecx") _,
                out("edx") _,
                options(nomem, preserves_flags),
            );
        }
        if eax != 0
            && let Some(hz) = (eax as u64)
                .checked_mul(1_000_000)
                .and_then(NonZeroU64::new)
        {
            return Some(hz);
        }
    }
    None
}

fn has_tsc_deadline() -> bool {
    let features: u32;
    // SAFETY: CPUID leaf 1 reports this vCPU's TSC-deadline MSR capability.
    unsafe {
        core::arch::asm!(
            "push rbx", "cpuid", "pop rbx",
            inout("eax") 1_u32 => _,
            out("ecx") features,
            out("edx") _,
            options(nomem, preserves_flags),
        );
    }
    features & (1 << 24) != 0
}

impl InterruptBackend for X86Backend {
    fn counter(&mut self) -> Result<CounterTick, Self::Error> {
        let (lo, hi): (u32, u32);
        // SAFETY: RDTSC reads the native monotonic counter without touching
        // guest memory or interrupt state.
        unsafe {
            core::arch::asm!(
                "rdtsc",
                out("eax") lo,
                out("edx") hi,
                options(nomem, nostack, preserves_flags)
            );
        }
        Ok(CounterTick::new((u64::from(hi) << 32) | u64::from(lo)))
    }
    fn frequency(&mut self) -> Result<CounterFrequency, Self::Error> {
        tsc_frequency()
            .map(CounterFrequency::new)
            .ok_or(ArchError::Unbound)
    }
    fn arm_timer(&mut self, deadline: Option<Deadline>) -> Result<(), Self::Error> {
        let binding = super::context::current_cpu_binding().ok_or(ArchError::Unbound)?;
        // SAFETY: this exact CPL0 CPU has its xAPIC mapped by bootstrap.
        unsafe { interrupts::hardware::enable() };
        if has_tsc_deadline() {
            // SAFETY: CPUID qualified IA32_TSC_DEADLINE; the argument uses
            // the same absolute TSC domain as `counter()`.
            unsafe { interrupts::hardware::arm_tsc_deadline(deadline.map(|d| d.0.raw())) };
        } else {
            let tsc_hz = self.frequency()?.raw().get();
            let mut apic_hz = binding.apic_timer_hz.load(Ordering::Acquire);
            if deadline.is_some() && apic_hz == 0 {
                // SAFETY: this CPU owns its mapped xAPIC timer while stopped
                // in CPL0. The measured rate is retained for later arms.
                apic_hz = unsafe { interrupts::hardware::measure_timer_rate(tsc_hz) }
                    .ok_or(ArchError::Unbound)?;
                binding.apic_timer_hz.store(apic_hz, Ordering::Release);
            }
            let ticks = deadline
                .map(|d| {
                    let delta = d.0.raw().saturating_sub(self.counter()?.raw()).max(1);
                    interrupts::calibrated_timer_ticks(delta, apic_hz, tsc_hz)
                        .ok_or(ArchError::Unbound)
                })
                .transpose()?;
            // SAFETY: the APIC rate was measured on this CPU; the one-shot
            // count and divider are in the same calibrated tick domain.
            unsafe { interrupts::hardware::arm_timer(ticks) };
        }
        Ok(())
    }
    fn send_wake(&mut self, target: CpuTarget, _token: WakeToken) -> Result<(), Self::Error> {
        let apic_id = bound_apic_id(target.cpu)?;
        core::sync::atomic::fence(Ordering::SeqCst);
        // SAFETY: caller published wake ownership first; target CPU is bound.
        unsafe { interrupts::hardware::send_wake(apic_id) }.map_err(|_| ArchError::Busy)?;
        Ok(())
    }
    fn ack_interrupt(
        &mut self,
    ) -> Result<Option<InterruptAck<Self::HardwareInterrupt>>, Self::Error> {
        // SAFETY: CPL0 reads the local APIC in-service register to determine the active vector.
        let vector = unsafe { interrupts::hardware::highest_in_service_vector() };
        let Some(vector) = vector else {
            return Ok(None);
        };
        if vector == interrupts::SPURIOUS_VECTOR {
            return Ok(None);
        }
        let reason = if vector == interrupts::TIMER_VECTOR {
            InterruptReason::Timer
        } else {
            InterruptReason::External
        };
        Ok(Some(InterruptAck {
            reason,
            hardware: u32::from(vector),
        }))
    }
    fn end_interrupt(
        &mut self,
        _ack: InterruptAck<Self::HardwareInterrupt>,
    ) -> Result<(), Self::Error> {
        // SAFETY: the acknowledged interrupt belongs to this CPL0 CPU.
        unsafe { interrupts::hardware::end_interrupt() };
        Ok(())
    }
    fn mask_interrupts(&mut self) -> Self::InterruptMask {
        // SAFETY: CPL0 owns IF and restores this saved mask on the same lane.
        unsafe { interrupts::hardware::mask_interrupts() }
    }
    fn restore_interrupts(&mut self, mask: Self::InterruptMask) -> Result<(), Self::Error> {
        // SAFETY: the caller has dropped all locks before restoring IF.
        unsafe { interrupts::hardware::restore_interrupts(mask) };
        Ok(())
    }
    fn park_until_interrupt(&mut self) -> Result<(), Self::Error> {
        // SAFETY: the owner has checked its queue with IF masked; STI+HLT
        // closes the lost-wake window and returns with IF masked.
        unsafe { interrupts::hardware::park_until_interrupt() };
        Ok(())
    }
    fn current_cpu(&mut self) -> CpuId {
        let Some(binding) = super::context::current_cpu_binding() else {
            super::transport::fatal_entry_binding();
        };
        CpuId::new(binding.cpu_slot)
    }
}

/// A CPL0-only fixture syscall that exercises this shared kernel interrupt module.
pub const INTERRUPT_WITNESS: u64 = 0xffff_ffff_ffff_ff40;

pub fn witness(op: u64, arg: u64) -> u64 {
    let mut backend = X86Backend;
    match op {
        0 => match backend.frequency() {
            Ok(freq) => freq.raw().get(),
            Err(_) => 0,
        },
        1 => {
            let deadline = if arg != 0 {
                Some(Deadline(CounterTick::new(arg)))
            } else {
                None
            };
            match backend.arm_timer(deadline) {
                Ok(()) => 0,
                Err(_) => u64::MAX,
            }
        }
        2 => {
            let target = CpuTarget {
                cpu: CpuId::new(arg as u32),
                generation: carrick_guest_arch::CpuGeneration::new(core::num::NonZeroU64::MIN),
            };
            let token = WakeToken {
                task: carrick_guest_arch::TaskIdentity {
                    carrier: carrick_guest_arch::CarrierGeneration::new(core::num::NonZeroU64::MIN),
                    task: carrick_guest_arch::TaskSerial::new(core::num::NonZeroU64::MIN),
                    execution: carrick_guest_arch::ExecutionGeneration::new(
                        core::num::NonZeroU64::MIN,
                    ),
                },
                operation: carrick_guest_arch::OperationSequence::new(core::num::NonZeroU64::MIN),
            };
            match backend.send_wake(target, token) {
                Ok(()) => 0,
                Err(_) => u64::MAX,
            }
        }
        3 => match backend.ack_interrupt() {
            Ok(Some(ack)) => u64::from(ack.hardware),
            Ok(None) => 0,
            Err(_) => u64::MAX,
        },
        4 => {
            // Exercise the scheduler's current reschedule path, including
            // its stored route and interrupt identity, on two real vCPUs.
            use crate::substrate::sched::ThreadCpu;
            let Ok(slot) = u8::try_from(arg) else {
                return u64::MAX;
            };
            let route = arg + 1;
            crate::substrate::sched::hw::HardwareCpu
                .send_resched(carrick_sched_core::SlotId::new(slot), route);
            0
        }
        5 => {
            use crate::substrate::sched::ThreadCpu;
            u64::from(crate::substrate::sched::hw::HardwareCpu.ack_irq())
        }
        6 => witness_mutual_rendezvous().unwrap_or(u64::MAX),
        _ => u64::MAX,
    }
}
