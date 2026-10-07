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
        if table.fixture_hold_ipi.load(Ordering::Acquire) {
            let tsc_hz = tsc_frequency().ok_or(ArchError::Unbound)?.get();
            let limit = tsc_hz.checked_mul(5).ok_or(ArchError::Unbound)?;
            let start = read_tsc();
            while table.fixture_hold_ipi.load(Ordering::Acquire) {
                if read_tsc().wrapping_sub(start) > limit {
                    return Err(ArchError::Busy);
                }
                core::hint::spin_loop();
            }
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

fn read_tsc() -> u64 {
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

/// Send a scheduler reschedule using a slot-indexed published APIC route.
pub fn send_resched(slot: carrick_sched_core::SlotId) -> Result<(), ArchError> {
    let apic = bound_apic_id(CpuId::new(u32::from(slot.raw())))?;
    core::sync::atomic::fence(Ordering::SeqCst);
    // SAFETY: scheduler published the target work before sending this IPI;
    // the stopped bootstrap retains the destination APIC until retirement.
    unsafe { interrupts::hardware::send_resched(apic) }.map_err(|_| ArchError::Busy)
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
