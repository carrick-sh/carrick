//! Linux binding of the neutral EL1 fault path: the COW resolvers that
//! reconcile a parent write with this personality's pending fork custody,
//! and the ARM data-abort entry that selects them.
#[cfg(target_os = "none")]
use crate::fault::*;
#[cfg(all(target_os = "none", target_arch = "aarch64"))]
use carrick_el1_abi::CurrentTask;
use carrick_el1_abi::{Action, Counters, TrapFrame};
use core::sync::atomic::Ordering;

#[cfg(all(target_os = "none", target_arch = "aarch64"))]
pub struct HardwareCowResolver {
    pub service_slot: Option<carrick_el1_abi::SlotId>,
    pub completion: Option<carrick_el1_abi::CowGrantCompletion>,
    pub publication: Option<&'static carrick_core_abi::PortalExecutableSlot>,
}

#[cfg(all(target_os = "none", target_arch = "aarch64"))]
impl CowResolver for HardwareCowResolver {
    fn reconcile_parent_write<
        W: carrick_mmu_core::aarch64::descriptor_txn::LiveDescriptorWords + ?Sized,
    >(
        &mut self,
        slot: u32,
        handle: carrick_el1_abi::El1MmHandle,
        sequence: core::num::NonZeroU64,
        completion: carrick_el1_abi::CowGrantCompletion,
        words: &W,
    ) -> Result<(), crate::personality::mm_portal::MmError> {
        crate::personality::mm_portal::reconcile_pending_parent_write(
            slot as usize,
            handle,
            sequence,
            completion,
            words,
        )?;
        Ok(())
    }

    fn take_cow_completion(&mut self) -> Option<carrick_el1_abi::CowGrantCompletion> {
        self.completion.take()
    }
    fn executable_publication(&self) -> bool {
        self.publication.is_some()
    }
    fn resolve_cow(&mut self, ttbr0: u64, mm_key: u64, far: u64) -> bool {
        self.resolve_cow_outcome(ttbr0, mm_key, far) == CowResolution::Resolved
    }
    fn resolve_cow_outcome(&mut self, ttbr0: u64, mm_key: u64, far: u64) -> CowResolution {
        let outcome =
            with_hardware_cow_venue(ttbr0, self.service_slot, self.publication, |venue| {
                crate::cow::resolve_guest_cow(
                    venue,
                    mm_key,
                    far,
                    |source, destination| {
                        // SAFETY: both aliases are mapped, distinct pages (source
                        // EL1-RO, destination EL1-RW) until the window restores them.
                        unsafe {
                            core::ptr::copy_nonoverlapping(
                                source as *const u8,
                                destination as *mut u8,
                                4096,
                            )
                        }
                    },
                    || {
                        let mut cpu = crate::substrate::sched::HardwareCpu;
                        crate::substrate::sched::ThreadCpu::invalidate_asid(&mut cpu, ttbr0);
                    },
                )
            });
        let Ok(outcome) = outcome else {
            return CowResolution::Refused;
        };
        handle_cow_outcome(outcome, &mut self.completion)
    }

    fn editor_busy(&mut self) {
        #[cfg(target_arch = "aarch64")]
        carrick_el1_abi::cow_grant_pool_guest()
            .note_declined(carrick_el1_abi::CowDecline::EditorBusy);
    }
}

/// CPL0 adapter for the same guest COW policy. The normal image uses the
/// shared pool and residency table; KVM fixtures can supply exact local
/// records while exercising the production resolver.
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub struct X86CowResolver<'a, W: carrick_mmu_core::aarch64::descriptor_txn::LiveDescriptorWords> {
    pub words: &'a W,
    pub pool: &'a dyn carrick_el1_abi::CowGrantVenue,
    pub residency: &'a carrick_el1_abi::FrameGrantResidencyTable,
    pub completion: Option<carrick_el1_abi::CowGrantCompletion>,
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
impl<D: carrick_mmu_core::aarch64::descriptor_txn::LiveDescriptorWords> CowResolver
    for X86CowResolver<'_, D>
{
    fn reconcile_parent_write<
        W: carrick_mmu_core::aarch64::descriptor_txn::LiveDescriptorWords + ?Sized,
    >(
        &mut self,
        slot: u32,
        handle: carrick_el1_abi::El1MmHandle,
        sequence: core::num::NonZeroU64,
        completion: carrick_el1_abi::CowGrantCompletion,
        words: &W,
    ) -> Result<(), crate::personality::mm_portal::MmError> {
        crate::personality::mm_portal::reconcile_pending_parent_write(
            slot as usize,
            handle,
            sequence,
            completion,
            words,
        )
    }

    fn resolve_cow(&mut self, root: u64, mm_key: u64, far: u64) -> bool {
        self.resolve_cow_outcome(root, mm_key, far) == CowResolution::Resolved
    }

    fn resolve_cow_outcome(&mut self, root: u64, mm_key: u64, far: u64) -> CowResolution {
        let copy_page = |source: u64, destination: u64| {
            // SAFETY: the x86 adapter verified both retained supervisor
            // translations for these distinct page frames.
            unsafe {
                core::ptr::copy_nonoverlapping(source as *const u8, destination as *mut u8, 4096)
            }
        };
        let invalidate = || {
            // A stale writable TLB entry can make a permission fault
            // retryable even when the live leaf is already writable.
            // SAFETY: INVLPG is local to this CPL0 CPU and the live root.
            unsafe {
                core::arch::asm!(
                    "invlpg [{}]",
                    in(reg) far & !4095,
                    options(nostack, preserves_flags)
                )
            }
        };
        let venue = carrick_core::mm::cow::GuestCowVenue::<crate::cow::X86CowMmu, _> {
            words: self.words,
            root: carrick_mmu_core::aarch64::SubstrateGpa(root),
            pool: self.pool,
            residency: self.residency,
            copy_window: carrick_core::mm::cow::CowCopyWindow::target(
                self.words,
                carrick_mmu_core::aarch64::SubstrateGpa(root),
            ),
            publish_executable: None,
        };
        // SAFETY: dispatch_classified_fault holds this MM's exact editor.
        // resolve_x86_guest_cow authenticates the live CR3 and retained
        // supplied descriptor-word authority before reading or changing descriptors.
        let outcome = unsafe {
            crate::cow::resolve_x86_guest_cow(&venue, mm_key, far, copy_page, invalidate)
        };
        handle_cow_outcome(outcome, &mut self.completion)
    }

    fn take_cow_completion(&mut self) -> Option<carrick_el1_abi::CowGrantCompletion> {
        self.completion.take()
    }

    fn editor_busy(&mut self) {
        self.pool
            .note_declined(carrick_el1_abi::CowDecline::EditorBusy);
    }
}

/// Dispatch an EL0 data abort at EL1.
///
/// Increments `counters.fault_taken`; at EL1, requests host-published bulk
/// frames, consumes refusals, or resolves in-guest COW faults.
/// Host builds retain the forward-only path.
pub fn dispatch_fault(frame: &mut TrapFrame, counters: &Counters) -> Action {
    #[cfg(all(target_os = "none", target_arch = "aarch64"))]
    {
        let current_tasks = unsafe {
            &*(carrick_el1_abi::EL1_CURRENT_TASKS_BASE
                as *const [CurrentTask; carrick_el1_abi::EL1_STACK_SLOTS as usize])
        };
        let zone =
            unsafe { &*(carrick_el1_abi::EL1_ZONE_BASE as *const carrick_el1_abi::ZoneTables) };
        let Some(mailbox) =
            carrick_el1_abi::frame_grant_mailbox_guest_for_slot(frame.slot as usize)
        else {
            counters.fault_taken.fetch_add(1, Ordering::Relaxed);
            return Action::Forward;
        };
        dispatch_fault_with_descriptor_txns(
            frame,
            counters,
            current_tasks,
            crate::substrate::sched::object_wait::space_access(
                zone,
                carrick_sched_core::SlotId::new(frame.slot as u8),
            ),
            Some(DescriptorTxnPath {
                slots: carrick_el1_abi::descriptor_txn_slots_guest(),
                applier: &mut HardwareDescriptorTxnApplier,
            }),
            GrantMailboxes {
                own: mailbox,
                peers: Some(carrick_el1_abi::frame_grant_mailboxes_guest()),
            },
            Some(PreparedFaultPath::<_> {
                residency: crate::isa::frame_grant_residency_guest(),
                resolver: &mut HardwarePreparedResolver,
                roots: Some(crate::memory::reservations::shared_guest()),
                file_slots: Some(unsafe {
                    &*(carrick_el1_abi::EL1_MM_PORTAL_BASE as *const carrick_el1_abi::MmPortalSlots)
                }),
            }),
            &mut HardwareCowResolver {
                service_slot: None,
                publication: None,
                completion: None,
            },
        )
    }
    #[cfg(all(target_os = "none", target_arch = "x86_64"))]
    {
        // CPL0 enters through `dispatch_x86_fault_with_prepared` with its
        // decoded #PF. This ARM TrapFrame entry has no x86 fault provenance.
        let _ = frame;
        counters.fault_taken.fetch_add(1, Ordering::Relaxed);
        Action::Forward
    }
    #[cfg(not(target_os = "none"))]
    {
        let _ = frame;
        counters.fault_taken.fetch_add(1, Ordering::Relaxed);
        Action::Forward
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::Ordering;

    #[test]
    fn test_dispatch_fault_increments_counter_and_forwards() {
        let mut frame = TrapFrame {
            esr: (0xFFFF_0000_u64 << 32) | (0x24 << 26) | (1 << 25) | 0x47,
            far: 0x1000_2000,
            x: {
                let mut x = [42; 31];
                x[8] = 172; // valid syscall nr (SYS_getpid) as canary
                x
            },
            ..TrapFrame::default()
        };
        let counters = Counters::default();
        assert_eq!(counters.fault_taken.load(Ordering::Relaxed), 0);

        let action = dispatch_fault(&mut frame, &counters);
        assert_eq!(action, Action::Forward);
        assert_eq!(counters.fault_taken.load(Ordering::Relaxed), 1);
        // Ensure arbitrary x8 was not dispatched as a syscall and syscall counters were not touched
        assert_eq!(counters.forwarded[172].load(Ordering::Relaxed), 0);
        assert_eq!(counters.served[172].load(Ordering::Relaxed), 0);
        assert_eq!(counters.forwarded[42].load(Ordering::Relaxed), 0);
        assert_eq!(counters.served[42].load(Ordering::Relaxed), 0);
    }
}
