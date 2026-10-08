//! Bounded segregated-fit metadata allocator for Carrick EL1 kernel.
//!
//! Provides $O(1)$ allocation, deallocation, bidirectional coalescing, and
//! dynamic extent expansion/return through the shared pending-host-work mailbox.

use crate::lock::SpinLock;
use core::alloc::Layout;

pub use carrick_core::mm::capacity::*;

pub use crate::substrate::sched::hw::{IrqGuard, disable_irq_save, restore_irq};

#[cfg(all(target_os = "none", target_arch = "aarch64"))]
#[inline(always)]
fn current_el1_slot() -> Option<usize> {
    let sp = crate::substrate::sched::hw::read_current_sp();
    let offset = sp.checked_sub(carrick_el1_abi::EL1_STACKS_BASE)?;
    if offset >= carrick_el1_abi::EL1_STACK_SLOTS * carrick_el1_abi::EL1_STACK_SIZE {
        return None;
    }
    Some((offset / carrick_el1_abi::EL1_STACK_SIZE) as usize)
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
fn current_el1_slot() -> Option<usize> {
    // The CPL0 image has a retained bootstrap extent but does not yet map the
    // ARM mailbox/zone aperture used for dynamic metadata grants.
    None
}

/// Safe thread-safe wrapper around `MetadataAllocatorCore` with IRQ save/restore spinlock.
pub struct MetadataStorage {
    lock: SpinLock<MetadataAllocatorCore>,
}

#[cfg(target_os = "none")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MailboxSync {
    None,
    AllocReady,
    AllocDenied,
    ReturnFinished,
}

impl Default for MetadataStorage {
    fn default() -> Self {
        Self::new()
    }
}

fn bootstrap_metadata_base() -> u64 {
    #[cfg(all(target_os = "none", target_arch = "x86_64"))]
    {
        carrick_el1_abi::X86_CPL0_BOOTSTRAP_METADATA_BASE
    }
    #[cfg(not(all(target_os = "none", target_arch = "x86_64")))]
    {
        carrick_el1_abi::EL1_BOOTSTRAP_METADATA_BASE
    }
}

impl MetadataStorage {
    pub const fn new() -> Self {
        Self {
            lock: SpinLock::new(MetadataAllocatorCore::new()),
        }
    }

    pub fn ensure_bootstrap_admitted(&self) {
        let guard = disable_irq_save();
        let mut core = self.lock.lock();
        if core.diagnostics().active_extents == 0 {
            let _ = core.admit_extent(
                bootstrap_metadata_base(),
                carrick_el1_abi::EL1_BOOTSTRAP_METADATA_SIZE as usize,
                ExtentKind::Bootstrap,
            );
        }
        core::mem::drop(core);
        restore_irq(guard);
    }

    pub fn admit_bootstrap_region(
        &self,
        base_va: u64,
        size: usize,
    ) -> Result<(), ExtentAdmissionError> {
        let guard = disable_irq_save();
        let mut core = self.lock.lock();
        let res = core
            .admit_extent(base_va, size, ExtentKind::Bootstrap)
            .map(|_| ());
        core::mem::drop(core);
        restore_irq(guard);
        res
    }

    #[cfg(target_os = "none")]
    fn mark_pending_host_work(slot: usize) {
        if let Some(task) = carrick_el1_abi::current_task_guest(slot) {
            task.linux.mark_pending_host_work();
        }
    }

    #[cfg(target_os = "none")]
    fn publish_request(slot: usize, request: carrick_el1_abi::MetadataGrantRequest) -> bool {
        if !carrick_el1_abi::metadata_mailbox_guest().try_publish_request_prepared(
            request,
            |generation| {
                // SAFETY: the carrier maps the zone for the complete EL1 lifetime.
                let zone = unsafe {
                    &*(carrick_el1_abi::EL1_ZONE_BASE as *const carrick_sched_core::ZoneTables)
                };
                let Some(key) =
                    carrick_sched_core::object_wait::ObjectWaitKey::metadata_request(generation)
                else {
                    return false;
                };
                zone.bind_object_wait(
                    key,
                    &carrick_sched_core::BoundedSpin(crate::substrate::sched::EL1_ZONE_LOCK_SPINS),
                )
                .is_ok()
            },
        ) {
            return false;
        }
        Self::mark_pending_host_work(slot);
        true
    }

    #[cfg(target_os = "none")]
    fn synchronize_response(core: &mut MetadataAllocatorCore, slot: usize) -> MailboxSync {
        let mailbox = carrick_el1_abi::metadata_mailbox_guest();
        let Some(response) = mailbox.claim_response() else {
            return MailboxSync::None;
        };
        let outcome = match response.op {
            carrick_el1_abi::METADATA_GRANT_OP_ALLOC => {
                if response.status != carrick_el1_abi::METADATA_GRANT_SUCCESS {
                    core.note_grant_denied();
                    MailboxSync::AllocDenied
                } else {
                    let receipt = ExtentGrantReceipt {
                        base_va: response.arg1,
                        size: response.arg2 as usize,
                        token: response.arg3,
                    };
                    if receipt.base_va == 0
                        || receipt.size == 0
                        || receipt.token == 0
                        || core
                            .admit_extent(
                                receipt.base_va,
                                receipt.size,
                                ExtentKind::Dynamic {
                                    token: receipt.token,
                                },
                            )
                            .is_err()
                    {
                        core.note_grant_denied();
                        mailbox.finish_response();
                        if Self::publish_request(
                            slot,
                            carrick_el1_abi::MetadataGrantRequest {
                                op: carrick_el1_abi::METADATA_GRANT_OP_FREE,
                                arg1: receipt.base_va,
                                arg2: receipt.size as u64,
                                arg3: receipt.token,
                                cookie: u64::MAX,
                            },
                        ) {
                            return MailboxSync::AllocDenied;
                        }
                        return MailboxSync::AllocDenied;
                    }
                    MailboxSync::AllocReady
                }
            }
            carrick_el1_abi::METADATA_GRANT_OP_FREE => {
                let slot_idx = response.cookie as usize;
                if slot_idx != usize::MAX {
                    let receipt = ExtentToReturn {
                        base_va: response.arg1,
                        size: response.arg2 as usize,
                        token: response.arg3,
                        slot_idx,
                    };
                    if response.status == carrick_el1_abi::METADATA_GRANT_SUCCESS {
                        core.complete_extent_return(receipt);
                    } else {
                        core.cancel_extent_return(receipt);
                    }
                }
                MailboxSync::ReturnFinished
            }
            _ => MailboxSync::None,
        };
        mailbox.finish_response();
        outcome
    }

    #[cfg(target_os = "none")]
    fn publish_pending_return(core: &mut MetadataAllocatorCore, slot: usize) -> bool {
        let Some(to_return) = core.next_pending_return() else {
            return false;
        };
        if !Self::publish_request(
            slot,
            carrick_el1_abi::MetadataGrantRequest {
                op: carrick_el1_abi::METADATA_GRANT_OP_FREE,
                arg1: to_return.base_va,
                arg2: to_return.size as u64,
                arg3: to_return.token,
                cookie: to_return.slot_idx as u64,
            },
        ) {
            return false;
        }
        core.mark_return_requested(to_return.slot_idx);
        true
    }

    #[cfg(target_os = "none")]
    fn service_mailbox(core: &mut MetadataAllocatorCore, slot: usize) -> MailboxSync {
        let outcome = Self::synchronize_response(core, slot);
        Self::publish_pending_return(core, slot);
        // The mailbox is carrier-wide. A participant that lost publication
        // to another vCPU must still leave through a host boundary; otherwise
        // it can consume its entire bounded retry budget in EL1 before the
        // request owner is scheduled. Any participant may service the exact
        // single-flight request once its allocator stack has unwound.
        if Self::host_work_pending(core) {
            Self::mark_pending_host_work(slot);
        }
        outcome
    }

    #[cfg(target_os = "none")]
    fn host_work_pending(core: &MetadataAllocatorCore) -> bool {
        core.has_pending_return() || carrick_el1_abi::metadata_mailbox_guest().has_guest_work()
    }

    pub fn allocate(&self, layout: Layout) -> Option<*mut u8> {
        let align = layout.align().max(16);
        let size = layout.size();

        // 1. Try allocating from existing extents under lock
        let guard = disable_irq_save();
        let mut core = self.lock.lock();
        #[cfg(target_os = "none")]
        if core.diagnostics().active_extents == 0 {
            let _ = core.admit_extent(
                bootstrap_metadata_base(),
                carrick_el1_abi::EL1_BOOTSTRAP_METADATA_SIZE as usize,
                ExtentKind::Bootstrap,
            );
        }
        #[cfg(target_os = "none")]
        let _mailbox_sync = current_el1_slot()
            .map(|slot| Self::service_mailbox(&mut core, slot))
            .unwrap_or(MailboxSync::None);
        let p = core.allocate(size, align);
        if p.is_some() {
            core::mem::drop(core);
            restore_irq(guard);
            return p;
        }

        #[cfg(target_os = "none")]
        {
            // A refusal belongs to the capacity miss that required a grant,
            // not to an unrelated smaller allocation that happened to consume
            // the shared response while bootstrap capacity remained.
            if core.take_grant_denied() {
                core::mem::drop(core);
                restore_irq(guard);
                return None;
            }
            let needed_size = core.needed_grant_size(size, align);
            if let (Some(slot), Some(needed_size)) = (current_el1_slot(), needed_size) {
                Self::publish_request(
                    slot,
                    carrick_el1_abi::MetadataGrantRequest {
                        op: carrick_el1_abi::METADATA_GRANT_OP_ALLOC,
                        arg1: needed_size as u64,
                        arg2: 0,
                        arg3: 0,
                        cookie: 0,
                    },
                );
            }
        }
        core::mem::drop(core);
        restore_irq(guard);
        None
    }

    /// Allocate using the existing allocator/mailbox policy and report the
    /// complete enclosing extent. Token zero names bootstrap storage; dynamic
    /// grants retain the host-issued nonzero token. The caller still owns the
    /// allocation and must return it through `deallocate`, never return the
    /// enclosing extent directly. Call outside reservation and descriptor locks.
    pub fn allocate_with_extent(&self, layout: Layout) -> Option<(*mut u8, ExtentGrantReceipt)> {
        let ptr = self.allocate(layout)?;
        let irq = disable_irq_save();
        let core = self.lock.lock();
        // SAFETY: allocate just returned this live payload to this caller; it
        // has not escaped and cannot have been deallocated. Header lookup is
        // constant work regardless of the number of extents or allocations.
        let receipt = unsafe { core.allocation_extent(ptr) };
        core::mem::drop(core);
        restore_irq(irq);
        receipt.map(|receipt| (ptr, receipt))
    }

    pub fn deallocate(&self, ptr: *mut u8, layout: Layout) {
        let align = layout.align().max(16);
        let guard = disable_irq_save();
        let mut core = self.lock.lock();
        #[cfg(target_os = "none")]
        if let Some(slot) = current_el1_slot() {
            Self::service_mailbox(&mut core, slot);
        }
        core.prepare_deallocate_extent(ptr, align);
        #[cfg(target_os = "none")]
        if let Some(slot) = current_el1_slot() {
            Self::publish_pending_return(&mut core, slot);
        }
        core::mem::drop(core);
        restore_irq(guard);
    }

    #[cfg(all(feature = "allocator-test-control", target_os = "none"))]
    fn service_test_host_work(&self) -> bool {
        let Some(slot) = current_el1_slot() else {
            return false;
        };
        let guard = disable_irq_save();
        let mut core = self.lock.lock();
        Self::service_mailbox(&mut core, slot);
        let pending = Self::host_work_pending(&core);
        core::mem::drop(core);
        restore_irq(guard);
        pending
    }

    #[cfg(all(feature = "allocator-test-control", not(target_os = "none")))]
    fn service_test_host_work(&self) -> bool {
        false
    }

    pub fn diagnostics(&self) -> AllocatorDiagnostics {
        let guard = disable_irq_save();
        let core = self.lock.lock();
        let diag = core.diagnostics();
        core::mem::drop(core);
        restore_irq(guard);
        diag
    }
}

// Implement GlobalAlloc for MetadataStorage so it can be installed as #[global_allocator].
unsafe impl core::alloc::GlobalAlloc for MetadataStorage {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        self.allocate(layout).unwrap_or(core::ptr::null_mut())
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        self.deallocate(ptr, layout)
    }
}

/// Global EL1 kernel metadata allocator instance.
#[cfg_attr(target_os = "none", global_allocator)]
pub static GLOBAL_ALLOCATOR: MetadataStorage = MetadataStorage::new();

/// Ensure the global metadata allocator has admitted the bootstrap region.
pub fn ensure_bootstrap_initialized() {
    #[cfg(target_os = "none")]
    {
        GLOBAL_ALLOCATOR.ensure_bootstrap_admitted();
    }
}

/// Initialize the EL1 metadata allocator with the bootstrap region.
pub fn init_bootstrap_allocator(bootstrap_base: u64, bootstrap_size: usize) {
    if GLOBAL_ALLOCATOR
        .admit_bootstrap_region(bootstrap_base, bootstrap_size)
        .is_err()
    {
        panic!("Failed to initialize EL1 bootstrap metadata allocator");
    }
}

/// In-guest allocator test execution invoked by embed test fixture via `SYS_CARRICK_EL1_CONTROL`.
#[cfg(feature = "allocator-test-control")]
static DENIAL_TEST_STAGE: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

#[cfg(feature = "allocator-test-control")]
pub fn run_guest_allocator_test(subtest: u64, _arg: u64) -> u64 {
    match subtest {
        4 => run_guest_allocator_test(2, 0),
        5 => {
            if GLOBAL_ALLOCATOR.service_test_host_work() {
                carrick_el1_abi::METADATA_GRANT_PENDING
            } else {
                0
            }
        }
        1 => {
            // Test 1: Arbitrary alignments (16, 32, 64, 128, 4096), payload pattern verification, and free
            let alignments = [16, 32, 64, 128, 4096];
            for (idx, &align) in alignments.iter().enumerate() {
                let layout = match Layout::from_size_align(128, align) {
                    Ok(l) => l,
                    Err(_) => return 100 + idx as u64,
                };
                let ptr = match GLOBAL_ALLOCATOR.allocate(layout) {
                    Some(p) => p,
                    None => return 110 + idx as u64,
                };
                if !(ptr as usize).is_multiple_of(align) {
                    GLOBAL_ALLOCATOR.deallocate(ptr, layout);
                    return 120 + idx as u64;
                }
                unsafe {
                    core::ptr::write_bytes(ptr, (0xA0 + idx) as u8, 128);
                    for j in 0..128 {
                        if *ptr.add(j) != (0xA0 + idx) as u8 {
                            GLOBAL_ALLOCATOR.deallocate(ptr, layout);
                            return 130 + idx as u64;
                        }
                    }
                }
                GLOBAL_ALLOCATOR.deallocate(ptr, layout);
            }
            0
        }
        2 => {
            // Test 2: Cross the 9 MiB bootstrap with one 10 MiB allocation.
            // Keeping the operation atomic across the pending-host-work
            // boundary models the transaction preflight required by the MMU:
            // a capacity miss unwinds before partial allocator state exists.
            let allocation_size = 10 * 1024 * 1024;
            let allocation_layout = match Layout::from_size_align(allocation_size, 64) {
                Ok(l) => l,
                Err(_) => return 200,
            };
            let ptr = match GLOBAL_ALLOCATOR.allocate(allocation_layout) {
                Some(ptr) => ptr,
                None => {
                    // Another allocator user may complete the shared mailbox
                    // between this miss losing publication and this check.
                    // Either way the transaction must retry from its bounded
                    // userspace loop; only exhaustion of that bound is a
                    // terminal progress failure.
                    let _ = GLOBAL_ALLOCATOR.service_test_host_work();
                    return carrick_el1_abi::METADATA_GRANT_PENDING;
                }
            };

            unsafe {
                core::ptr::write_bytes(ptr, 0x30, allocation_size);
                for offset in (0..allocation_size).step_by(4096) {
                    if *ptr.add(offset) != 0x30 {
                        GLOBAL_ALLOCATOR.deallocate(ptr, allocation_layout);
                        return 202;
                    }
                }
            }

            GLOBAL_ALLOCATOR.deallocate(ptr, allocation_layout);
            0
        }
        3 => {
            // Test 3: Denial failpoint recovery
            // Fill bootstrap with 8 x 1 MiB chunks
            let chunk_size = 1024 * 1024;
            let chunk_layout = match Layout::from_size_align(chunk_size, 64) {
                Ok(l) => l,
                Err(_) => return 300,
            };
            let mut ptrs = [core::ptr::null_mut(); 8];
            for (i, slot) in ptrs.iter_mut().enumerate() {
                let p = match GLOBAL_ALLOCATOR.allocate(chunk_layout) {
                    Some(p) => p,
                    None => return 301,
                };
                unsafe {
                    core::ptr::write_bytes(p, (0x50 + i) as u8, chunk_size);
                }
                *slot = p;
            }

            let big_layout = match Layout::from_size_align(2 * 1024 * 1024, 64) {
                Ok(l) => l,
                Err(_) => return 302,
            };
            let stage = DENIAL_TEST_STAGE.load(core::sync::atomic::Ordering::Acquire);
            let candidate = GLOBAL_ALLOCATOR.allocate(big_layout);
            if stage == 0 && candidate.is_none() && GLOBAL_ALLOCATOR.service_test_host_work() {
                for &p in &ptrs {
                    GLOBAL_ALLOCATOR.deallocate(p, chunk_layout);
                }
                return carrick_el1_abi::METADATA_GRANT_PENDING;
            }
            if stage == 0 {
                if let Some(p) = candidate {
                    GLOBAL_ALLOCATOR.deallocate(p, big_layout);
                    for &p in &ptrs {
                        GLOBAL_ALLOCATOR.deallocate(p, chunk_layout);
                    }
                    return 303;
                }
                // The denied host response has now been consumed. Existing
                // allocations must remain intact before publishing the retry.
                for (i, &p) in ptrs.iter().enumerate() {
                    unsafe {
                        for j in (0..chunk_size).step_by(4096) {
                            if *p.add(j) != (0x50 + i) as u8 {
                                for &to_free in &ptrs {
                                    GLOBAL_ALLOCATOR.deallocate(to_free, chunk_layout);
                                }
                                return 304;
                            }
                        }
                    }
                }
                DENIAL_TEST_STAGE.store(1, core::sync::atomic::Ordering::Release);
                let retry = GLOBAL_ALLOCATOR.allocate(big_layout);
                for &p in &ptrs {
                    GLOBAL_ALLOCATOR.deallocate(p, chunk_layout);
                }
                if retry.is_none() && GLOBAL_ALLOCATOR.service_test_host_work() {
                    return carrick_el1_abi::METADATA_GRANT_PENDING;
                }
                if let Some(p) = retry {
                    GLOBAL_ALLOCATOR.deallocate(p, big_layout);
                }
                return 305;
            }

            let retry_p = match candidate {
                Some(p) => p,
                None => {
                    for &p in &ptrs {
                        GLOBAL_ALLOCATOR.deallocate(p, chunk_layout);
                    }
                    if GLOBAL_ALLOCATOR.service_test_host_work() {
                        return carrick_el1_abi::METADATA_GRANT_PENDING;
                    }
                    return 305;
                }
            };
            unsafe {
                core::ptr::write_bytes(retry_p, 0x88, 2 * 1024 * 1024);
                for j in (0..2 * 1024 * 1024).step_by(4096) {
                    if *retry_p.add(j) != 0x88 {
                        GLOBAL_ALLOCATOR.deallocate(retry_p, big_layout);
                        for &to_free in ptrs.iter() {
                            GLOBAL_ALLOCATOR.deallocate(to_free, chunk_layout);
                        }
                        return 306;
                    }
                }
            }

            // Deallocate the 2 MiB dynamic chunk (triggering extent return)
            GLOBAL_ALLOCATOR.deallocate(retry_p, big_layout);

            // Deallocate all 8 bootstrap chunks
            for &p in ptrs.iter() {
                GLOBAL_ALLOCATOR.deallocate(p, chunk_layout);
            }
            DENIAL_TEST_STAGE.store(0, core::sync::atomic::Ordering::Release);
            0
        }
        _ => 1,
    }
}

// SAFETY: MetadataStorage owns its granted extents through carrier teardown.
unsafe impl carrick_core::mm::reservation::ReservationMetadataAllocator for MetadataStorage {
    fn allocate_with_extent(&self, layout: Layout) -> Option<(*mut u8, ExtentGrantReceipt)> {
        MetadataStorage::allocate_with_extent(self, layout)
    }
    fn deallocate(&self, ptr: *mut u8, layout: Layout) {
        MetadataStorage::deallocate(self, ptr, layout)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocation_receipt_identifies_exact_extent_without_transferring_ownership() {
        let mut backing = vec![0u8; 64 * 1024];
        let storage = MetadataStorage::new();
        storage
            .lock
            .lock()
            .admit_extent(
                backing.as_mut_ptr() as u64,
                backing.len(),
                ExtentKind::Dynamic { token: 71 },
            )
            .unwrap();
        let layout = Layout::from_size_align(4096, 4096).unwrap();
        let (ptr, receipt) = storage.allocate_with_extent(layout).unwrap();
        assert_eq!(
            receipt,
            ExtentGrantReceipt {
                base_va: backing.as_mut_ptr() as u64,
                size: backing.len(),
                token: 71
            }
        );
        assert!(
            ptr as u64 >= receipt.base_va
                && ptr as u64 + layout.size() as u64 <= receipt.base_va + receipt.size as u64
        );
        assert_eq!(storage.lock.lock().extent(0).unwrap().live_allocations, 1);
        storage.deallocate(ptr, layout);
        assert_eq!(
            storage.lock.lock().extent(0).unwrap().state,
            ExtentState::PendingReturn
        );
    }
}
