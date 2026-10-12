//! Supervisor direct-mapped table span and live address context authority.

use carrick_guest_arch::RootGpa;
use core::sync::atomic::{AtomicU64, Ordering};

static TABLE_START: AtomicU64 = AtomicU64::new(0);
static TABLE_END: AtomicU64 = AtomicU64::new(0);

// Boot publishes this disjoint physical license before either native actor runs.
static WORKING_TABLES: carrick_el1::lock::SpinLock<Option<carrick_core_abi::X86PrepareTableSpan>> =
    carrick_el1::lock::SpinLock::new(None);

pub fn working_tables() -> Option<carrick_core_abi::X86PrepareTableSpan> {
    *WORKING_TABLES.lock()
}

static LIVE_CONTEXTS: carrick_el1::lock::SpinLock<
    carrick_el1::isa::x86::live_context::LiveContexts,
> = carrick_el1::lock::SpinLock::new(carrick_el1::isa::x86::live_context::LiveContexts::new());

pub fn live_context(
    mm: carrick_guest_arch::MmGeneration,
    root: RootGpa,
) -> Option<carrick_guest_arch::AddressContext<RootGpa>> {
    LIVE_CONTEXTS.lock().authenticate(mm, root)
}

pub fn admit_context(context: carrick_guest_arch::AddressContext<RootGpa>) -> bool {
    LIVE_CONTEXTS.lock().admit(context)
}

pub fn retire_context(context: carrick_guest_arch::AddressContext<RootGpa>) -> bool {
    LIVE_CONTEXTS.lock().retire(context.mm, context.root)
}

pub fn live_words(mm: carrick_el1_abi::ReservationMm) -> Option<crate::entry::InitialWords> {
    let root = carrick_el1::isa::x86::hardware_live_root().ok()?;
    let mm = carrick_guest_arch::MmGeneration::new(core::num::NonZeroU64::new(mm.raw())?);
    let context = LIVE_CONTEXTS.lock().authenticate(mm, root)?;
    let end = TABLE_END.load(Ordering::Acquire);
    let start = TABLE_START.load(Ordering::Relaxed);
    let working = working_tables()?;
    if start != 0 && end > start {
        Some(crate::entry::InitialWords::live(
            start, end, context, working,
        ))
    } else {
        None
    }
}

pub fn admit_tables(
    start: u64,
    end: u64,
    context: carrick_guest_arch::AddressContext<RootGpa>,
    working: carrick_core_abi::X86PrepareTableSpan,
) {
    let mut retained = WORKING_TABLES.lock();
    if retained.is_some() {
        crate::entry::halt();
    }
    *retained = Some(working);
    drop(retained);
    if !LIVE_CONTEXTS.lock().admit(context) {
        crate::entry::halt();
    }
    TABLE_START.store(start, Ordering::Relaxed);
    TABLE_END.store(end, Ordering::Release);
}
