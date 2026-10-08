//! Guest EL1 fork-COW resolution with host-provisioned replacement frames.
//!
//! The caller holds the faulting MM's exact page-table editor. EL1 then
//! classifies the write fault
//! ([`classify_guest_cow_write`](carrick_mmu_core::aarch64::descriptor_txn::guest_cow::classify_guest_cow_write)),
//! takes one of
//! the MM's ready grants from the shared [`carrick_el1_abi::CowGrantPool`], copies the run's
//! pages from the still-shared compound into the grant through the MM's
//! two temporary copy-window aliases, repoints the run with the shared
//! descriptor executor, invalidates the MM's ASID and only then records the
//! completion for the host. Data-only runs make no host crossing. A caller
//! with a bounded executable-publication capability invokes the existing host
//! I2 cache authority after the copy and before an executable repoint. Other
//! fault callers retain their existing decline path.

pub use carrick_core::mm::cow::{CowError, GuestCowOutcome};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Aarch64CowMmu;

impl carrick_core::mm::cow::OwnerCowMmu for Aarch64CowMmu {
    const CARRIER_MAINT_ROOT_BASE: u64 = carrick_el1_abi::EL1_CARRIER_MAINT_ROOT_BASE;
    const DEFAULT_COW_COPY_BASE: u64 = carrick_el1_abi::EL1_COW_COPY_BASE;

    fn classify_cow_write<
        W: carrick_mmu_core::aarch64::descriptor_txn::LiveDescriptorWords + ?Sized,
    >(
        words: &W,
        root: u64,
        far: u64,
        publish_executable: bool,
    ) -> carrick_core::mm::cow::CowClassifyOutcome {
        use carrick_mmu_core::aarch64::SubstrateGpa;
        use carrick_mmu_core::aarch64::descriptor_txn::guest_cow::{
            GuestCowClass, GuestCowNotArmed, classify_guest_cow_write,
        };
        match classify_guest_cow_write(words, SubstrateGpa(root), far, publish_executable) {
            Ok(run) => carrick_core::mm::cow::CowClassifyOutcome::Armed(
                carrick_core::mm::cow::GuestCowRun {
                    va: run.va,
                    len: run.len,
                    old_ipa: run.old_ipa.raw(),
                    compound_offset: run.compound_offset(),
                    executable: run.executable,
                },
            ),
            Err(GuestCowClass::AlreadyWritable) => {
                carrick_core::mm::cow::CowClassifyOutcome::AlreadyWritable
            }
            Err(class @ (GuestCowClass::NotArmed(_) | GuestCowClass::Unreachable(_))) => {
                let reason = match class {
                    GuestCowClass::NotArmed(GuestCowNotArmed::Unmapped) => {
                        carrick_el1_abi::CowDecline::Unmapped
                    }
                    GuestCowClass::NotArmed(GuestCowNotArmed::NotCowArmed) => {
                        carrick_el1_abi::CowDecline::NotCowArmed
                    }
                    GuestCowClass::NotArmed(GuestCowNotArmed::NotEl1Private) => {
                        carrick_el1_abi::CowDecline::NotEl1Private
                    }
                    GuestCowClass::NotArmed(GuestCowNotArmed::NoWriteIntent) => {
                        carrick_el1_abi::CowDecline::NoWriteIntent
                    }
                    GuestCowClass::NotArmed(GuestCowNotArmed::Executable) => {
                        carrick_el1_abi::CowDecline::Executable
                    }
                    _ => carrick_el1_abi::CowDecline::Unreachable,
                };
                carrick_core::mm::cow::CowClassifyOutcome::Declined(reason)
            }
        }
    }

    fn plan_cow_repoint<
        W: carrick_mmu_core::aarch64::descriptor_txn::LiveDescriptorWords + ?Sized,
    >(
        words: &W,
        root: u64,
        op: carrick_core::mm::cow::CowRepointOp,
    ) -> bool {
        use carrick_mmu_core::aarch64::SubstrateGpa;
        use carrick_mmu_core::aarch64::descriptor_txn::{
            CowRepointAccess, DescriptorOp, plan_descriptor_op,
        };
        let desc_op = DescriptorOp::CowRepoint {
            access: CowRepointAccess::RecordedPrivate,
            va: op.va,
            len: op.len,
            old_ipa: SubstrateGpa(op.old_ipa),
            new_ipa: SubstrateGpa(op.new_ipa),
            backing: op.backing,
        };
        match plan_descriptor_op(words, SubstrateGpa(root), desc_op) {
            Ok(plan) => plan.table_grants == 0,
            _ => false,
        }
    }

    fn with_copy_aliases<
        W: carrick_mmu_core::aarch64::descriptor_txn::LiveDescriptorWords + ?Sized,
        F: FnMut(u64, u64),
    >(
        words: &W,
        root: u64,
        copy_base: u64,
        source_ipa: u64,
        destination_ipa: u64,
        effect: &mut F,
    ) -> Result<(), carrick_core::mm::cow::CowRepointOutcome> {
        use carrick_mmu_core::aarch64::SubstrateGpa;
        use carrick_mmu_core::aarch64::descriptor_txn::DescriptorOutcome;
        carrick_mmu_core::aarch64::descriptor_txn::copy_window::with_cow_copy_aliases(
            words,
            SubstrateGpa(root),
            copy_base,
            SubstrateGpa(source_ipa),
            SubstrateGpa(destination_ipa),
            effect,
        )
        .map_err(|e| match e {
            DescriptorOutcome::Indeterminate(_) => {
                carrick_core::mm::cow::CowRepointOutcome::Indeterminate
            }
            DescriptorOutcome::RolledBack(_) => {
                carrick_core::mm::cow::CowRepointOutcome::RolledBack
            }
            _ => carrick_core::mm::cow::CowRepointOutcome::Refused,
        })
    }

    fn execute_cow_repoint<
        W: carrick_mmu_core::aarch64::descriptor_txn::LiveDescriptorWords + ?Sized,
    >(
        words: &W,
        root: u64,
        op: carrick_core::mm::cow::CowRepointOp,
    ) -> carrick_core::mm::cow::CowRepointOutcome {
        use carrick_mmu_core::aarch64::SubstrateGpa;
        use carrick_mmu_core::aarch64::descriptor_txn::{
            CowRepointAccess, DescriptorOp, DescriptorOutcome, InlineJournal, TableGrants,
            execute_descriptor_op,
        };
        let desc_op = DescriptorOp::CowRepoint {
            access: CowRepointAccess::RecordedPrivate,
            va: op.va,
            len: op.len,
            old_ipa: SubstrateGpa(op.old_ipa),
            new_ipa: SubstrateGpa(op.new_ipa),
            backing: op.backing,
        };
        let mut journal = InlineJournal::new();
        match execute_descriptor_op(
            words,
            SubstrateGpa(root),
            desc_op,
            &TableGrants::NONE,
            &mut journal,
        ) {
            DescriptorOutcome::Applied(applied) => {
                carrick_core::mm::cow::CowRepointOutcome::Applied {
                    flush_required: applied.flush_required,
                }
            }
            DescriptorOutcome::Refused(_) => carrick_core::mm::cow::CowRepointOutcome::Refused,
            DescriptorOutcome::RolledBack(_) => {
                carrick_core::mm::cow::CowRepointOutcome::RolledBack
            }
            DescriptorOutcome::Indeterminate(_) => {
                carrick_core::mm::cow::CowRepointOutcome::Indeterminate
            }
        }
    }
}

pub type CowCopyWindow<'a> = carrick_core::mm::cow::CowCopyWindow<'a, Aarch64CowMmu>;
pub type GuestCowVenue<'a, W> = carrick_core::mm::cow::GuestCowVenue<'a, Aarch64CowMmu, W>;

pub fn resolve_guest_cow<
    W: carrick_mmu_core::aarch64::descriptor_txn::LiveDescriptorWords + ?Sized,
    C: FnMut(u64, u64),
    I: FnMut(),
>(
    venue: &GuestCowVenue<'_, W>,
    mm_key: u64,
    far: u64,
    copy_page: C,
    invalidate_asid: I,
) -> Result<GuestCowOutcome, CowError> {
    carrick_core::mm::cow::resolve_guest_cow::<Aarch64CowMmu, W, C, I>(
        venue,
        mm_key,
        far,
        copy_page,
        invalidate_asid,
    )
}

/// CPL0's owner adapter reuses the common claim/copy/repoint/completion
/// policy. The x86 projection retains the caller's descriptor-word authority
/// for classification, copy-alias authentication and descriptor publication.
#[cfg(any(test, all(target_os = "none", target_arch = "x86_64")))]
pub struct X86CowMmu;

#[cfg(any(test, all(target_os = "none", target_arch = "x86_64")))]
impl carrick_core::mm::cow::OwnerCowMmu for X86CowMmu {
    const CARRIER_MAINT_ROOT_BASE: u64 = 0;
    const DEFAULT_COW_COPY_BASE: u64 = carrick_el1_abi::X86_CPL0_DIRECT_VA;

    fn classify_cow_write<
        W: carrick_mmu_core::aarch64::descriptor_txn::LiveDescriptorWords + ?Sized,
    >(
        words: &W,
        root: u64,
        far: u64,
        publish_executable: bool,
    ) -> carrick_core::mm::cow::CowClassifyOutcome {
        use carrick_core::mm::cow::{CowClassifyOutcome, GuestCowRun};
        use carrick_guest_arch::{FrameGpa, RootGpa, UserVa};
        use carrick_mmu_core::x86::descriptor_txn::{CowClass, classify_guest_cow_write};
        let Some(root) = RootGpa::page_aligned(FrameGpa::new(root)) else {
            return CowClassifyOutcome::Declined(carrick_el1_abi::CowDecline::Unreachable);
        };
        match classify_guest_cow_write(words, root, UserVa::new(far), publish_executable) {
            Ok(run) => CowClassifyOutcome::Armed(GuestCowRun {
                va: run.va,
                len: run.len,
                old_ipa: run.old_ipa.raw(),
                compound_offset: run.compound_offset,
                executable: run.executable,
            }),
            Err(CowClass::AlreadyWritable) => CowClassifyOutcome::AlreadyWritable,
            Err(reason) => CowClassifyOutcome::Declined(match reason {
                CowClass::Unmapped => carrick_el1_abi::CowDecline::Unmapped,
                CowClass::NotCowArmed => carrick_el1_abi::CowDecline::NotCowArmed,
                CowClass::NoWriteIntent => carrick_el1_abi::CowDecline::NoWriteIntent,
                CowClass::ExecutableDenied => carrick_el1_abi::CowDecline::Executable,
                CowClass::Unreachable => carrick_el1_abi::CowDecline::Unreachable,
                CowClass::AlreadyWritable => carrick_el1_abi::CowDecline::Unreachable,
            }),
        }
    }

    fn plan_cow_repoint<
        W: carrick_mmu_core::aarch64::descriptor_txn::LiveDescriptorWords + ?Sized,
    >(
        words: &W,
        root: u64,
        op: carrick_core::mm::cow::CowRepointOp,
    ) -> bool {
        use carrick_guest_arch::{FrameGpa, RootGpa};
        use carrick_mmu_core::x86::descriptor_txn::{
            DescriptorOp, DescriptorTxn, DescriptorTxnId, PageSpan, plan_descriptor_txn,
        };
        use core::num::NonZeroU64;
        let Some(root) = RootGpa::page_aligned(FrameGpa::new(root)) else {
            return false;
        };
        let (Some(mm_key), Some(generation)) =
            (NonZeroU64::new(op.mm_key), NonZeroU64::new(op.grant_epoch))
        else {
            return false;
        };
        let txn = DescriptorTxn {
            id: DescriptorTxnId { mm_key, generation },
            root,
            op: DescriptorOp::CowRepoint {
                span: PageSpan::new(op.va, op.len),
                old: FrameGpa::new(op.old_ipa),
                new: FrameGpa::new(op.new_ipa),
                backing: op.backing,
            },
            tables: &[],
        };
        if plan_descriptor_txn(words, &txn, root).is_err() {
            return false;
        }
        // Each retained supervisor alias must already map the exact copy frame.
        // No new alias or late mapping is authored.
        for offset in (0..op.len).step_by(4096) {
            if x86_copy_page_alias(words, root, op.old_ipa + offset, false).is_none()
                || x86_copy_page_alias(words, root, op.new_ipa + offset, true).is_none()
            {
                return false;
            }
        }
        true
    }

    fn with_copy_aliases<
        W: carrick_mmu_core::aarch64::descriptor_txn::LiveDescriptorWords + ?Sized,
        F: FnMut(u64, u64),
    >(
        words: &W,
        root: u64,
        copy_base: u64,
        source_ipa: u64,
        destination_ipa: u64,
        effect: &mut F,
    ) -> Result<(), carrick_core::mm::cow::CowRepointOutcome> {
        use carrick_core::mm::cow::CowRepointOutcome;
        use carrick_guest_arch::{FrameGpa, RootGpa};
        let Some(root) = RootGpa::page_aligned(FrameGpa::new(root)) else {
            return Err(CowRepointOutcome::Refused);
        };
        if copy_base != carrick_el1_abi::X86_CPL0_DIRECT_VA {
            return Err(CowRepointOutcome::Refused);
        }
        let source = x86_copy_page_alias(words, root, source_ipa, false)
            .ok_or(CowRepointOutcome::Refused)?;
        let destination = x86_copy_page_alias(words, root, destination_ipa, true)
            .ok_or(CowRepointOutcome::Refused)?;
        effect(source, destination);
        Ok(())
    }

    fn execute_cow_repoint<
        W: carrick_mmu_core::aarch64::descriptor_txn::LiveDescriptorWords + ?Sized,
    >(
        words: &W,
        root: u64,
        op: carrick_core::mm::cow::CowRepointOp,
    ) -> carrick_core::mm::cow::CowRepointOutcome {
        use carrick_core::mm::cow::CowRepointOutcome;
        use carrick_guest_arch::{FrameGpa, RootGpa};
        use carrick_mmu_core::x86::descriptor_txn::{
            DescriptorOp, DescriptorOutcome, DescriptorTxn, DescriptorTxnId, InlineJournal,
            PageSpan, execute_descriptor_txn,
        };
        use core::num::NonZeroU64;
        let (Some(root), Some(mm_key), Some(generation)) = (
            RootGpa::page_aligned(FrameGpa::new(root)),
            NonZeroU64::new(op.mm_key),
            NonZeroU64::new(op.grant_epoch),
        ) else {
            return CowRepointOutcome::Refused;
        };
        let txn = DescriptorTxn {
            id: DescriptorTxnId { mm_key, generation },
            root,
            op: DescriptorOp::CowRepoint {
                span: PageSpan::new(op.va, op.len),
                old: FrameGpa::new(op.old_ipa),
                new: FrameGpa::new(op.new_ipa),
                backing: op.backing,
            },
            tables: &[],
        };
        match execute_descriptor_txn(words, &txn, root, &mut InlineJournal::new()).outcome {
            DescriptorOutcome::Applied { .. } => CowRepointOutcome::Applied {
                // The supplied words acknowledge their exact-root drain before
                // the shared descriptor executor returns an Applied receipt.
                flush_required: false,
            },
            DescriptorOutcome::Refused(_) => CowRepointOutcome::Refused,
            DescriptorOutcome::RolledBack(_) => CowRepointOutcome::RolledBack,
            DescriptorOutcome::Indeterminate(_) => CowRepointOutcome::Indeterminate,
        }
    }
}

#[cfg(any(test, all(target_os = "none", target_arch = "x86_64")))]
fn x86_copy_page_alias<
    W: carrick_mmu_core::aarch64::descriptor_txn::LiveDescriptorWords + ?Sized,
>(
    words: &W,
    root: carrick_guest_arch::RootGpa,
    ipa: u64,
    writable: bool,
) -> Option<u64> {
    #[cfg(all(target_os = "none", target_arch = "x86_64"))]
    use crate::isa::x86::user_tables::table_alias;
    #[cfg(all(test, not(target_os = "none")))]
    use crate::isa::x86_user_tables::table_alias;
    use carrick_guest_arch::{FrameGpa, UserVa};
    use carrick_mmu_core::x86::descriptor_txn::{Access, translate};
    let va = table_alias(FrameGpa::new(ipa))?.raw();
    (translate(
        words,
        root,
        UserVa::new(va),
        if writable {
            Access::Write
        } else {
            Access::Read
        },
        false,
    ) == Ok(FrameGpa::new(ipa)))
    .then_some(va)
}

/// Resolve one CPL3 write fault with the common COW grant protocol and the
/// shared x86 descriptor transaction. The caller retains the exact-MM editor.
///
/// # Safety
/// `words` must retain the authenticated table mappings for `root` and
/// acknowledge its descriptor drains. `root` must be the live CR3 root for
/// `mm_key`; the caller excludes other descriptor writers throughout.
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub unsafe fn resolve_x86_guest_cow<
    W: carrick_mmu_core::aarch64::descriptor_txn::LiveDescriptorWords,
    C: FnMut(u64, u64),
    I: FnMut(),
>(
    words: &W,
    root: u64,
    mm_key: u64,
    far: u64,
    pool: &dyn carrick_el1_abi::CowGrantVenue,
    residency: &carrick_el1_abi::FrameGrantResidencyTable,
    copy_page: C,
    invalidate: I,
) -> Result<GuestCowOutcome, CowError> {
    use carrick_guest_arch::{FrameGpa, RootGpa};
    use carrick_mmu_core::aarch64::SubstrateGpa;
    let root_gpa = RootGpa::page_aligned(FrameGpa::new(root)).ok_or(CowError::Refused)?;
    if crate::isa::x86::hardware_live_root().map_err(|_| CowError::Refused)? != root_gpa
        || mm_key == 0
    {
        return Err(CowError::Refused);
    }
    let venue = carrick_core::mm::cow::GuestCowVenue::<X86CowMmu, _> {
        words,
        root: SubstrateGpa(root),
        pool,
        residency,
        copy_window: carrick_core::mm::cow::CowCopyWindow::target(words, SubstrateGpa(root)),
        publish_executable: None,
    };
    carrick_core::mm::cow::resolve_guest_cow(&venue, mm_key, far, copy_page, invalidate)
}

#[cfg(test)]
mod tests {
    //! The real descriptor executor and copy window over host memory: a
    //! table arena at `ROOT` (the primary arena EL1 edits through its alias)
    //! and a page-granular model of guest-physical memory that the copy
    //! window's live alias leaves select from.
    use super::*;
    use carrick_el1_abi::{CowDecline, CowGrantCompletion, CowGrantPool, FrameGrantResidencyTable};
    use carrick_mmu_core::aarch64::SubstrateGpa;
    use carrick_mmu_core::aarch64::descriptor_txn::LiveDescriptorWords;

    const PAGE: u64 = 4096;

    use crate::fault::{
        CowResolver, GrantMailboxes, NoopPreparedResolver, PreparedFaultPath,
        dispatch_fault_with_prepared,
    };
    use carrick_el1_abi::{
        Action, COW_GRANT_SIZE, Counters, CurrentTask, EL1_COW_COPY_BASE, FrameGrantMailbox,
        TrapFrame,
    };
    use carrick_mmu_core::aarch64::descriptor_txn::{
        BackingIdentity, PrimaryTableWords, TableMaintenance,
    };
    use carrick_mmu_core::aarch64::indices;
    use carrick_sched_core::AddressSpaces;
    use core::cell::{Cell, RefCell};
    use core::num::NonZeroU64;
    use core::sync::atomic::{AtomicU64, Ordering};
    use std::collections::BTreeMap;

    const ROOT: u64 = 0x8800_0000_0000;
    const ASID: u64 = 5 << 48;
    const MM: u64 = 77;
    const VA: u64 = 0x4000_0000;
    const OLD: u64 = 0x009b_4000_0000;
    const GRANT: u64 = 0x009d_0000_4000;
    const PA: u64 = 0x0000_FFFF_FFFF_F000;
    const AF: u64 = 1 << 10;
    const SH: u64 = 0b11 << 8;
    const AP_RO_EL0: u64 = 0b11 << 6;
    const AP_RW_EL0: u64 = 0b01 << 6;
    const NG: u64 = 1 << 11;
    const XN: u64 = (1 << 53) | (1 << 54);
    const COW: u64 = 1 << 55;
    const PRIVATE: u64 = 1 << 56;
    const MAY_WRITE: u64 = 1 << 57;

    struct Arena {
        words: Vec<AtomicU64>,
    }

    impl Arena {
        /// Tables for `VA` (L3 at +0x3000) and for the EL1 copy window
        /// (L2 at +0x4000, L3 at +0x5000) with its two idle leaves.
        fn new(window: bool) -> Self {
            let arena = Self {
                words: (0..8 * 512).map(|_| AtomicU64::new(0)).collect(),
            };
            let va = indices(VA);
            arena.set(ROOT + va[0] as u64 * 8, (ROOT + 0x1000) | 3);
            arena.set(ROOT + 0x1000 + va[1] as u64 * 8, (ROOT + 0x2000) | 3);
            arena.set(ROOT + 0x2000 + va[2] as u64 * 8, (ROOT + 0x3000) | 3);
            if window {
                let win = indices(EL1_COW_COPY_BASE);
                assert_eq!(win[0], va[0], "one L0 entry covers both");
                arena.set(ROOT + 0x1000 + win[1] as u64 * 8, (ROOT + 0x4000) | 3);
                arena.set(ROOT + 0x4000 + win[2] as u64 * 8, (ROOT + 0x5000) | 3);
                for page in 0..2 {
                    let alias = EL1_COW_COPY_BASE + page * 4096;
                    arena.set(ROOT + 0x5000 + indices(alias)[3] as u64 * 8, alias);
                }
            }
            arena
        }
        fn set(&self, pa: u64, value: u64) {
            self.words[((pa - ROOT) / 8) as usize].store(value, Ordering::Relaxed);
        }
        fn get(&self, pa: u64) -> u64 {
            self.words[((pa - ROOT) / 8) as usize].load(Ordering::Relaxed)
        }
        fn leaf_pa(va: u64) -> u64 {
            let l3 = if va >> 30 == EL1_COW_COPY_BASE >> 30 {
                ROOT + 0x5000
            } else {
                ROOT + 0x3000
            };
            l3 + indices(va)[3] as u64 * 8
        }
        fn leaf(&self, va: u64) -> u64 {
            self.get(Self::leaf_pa(va))
        }
        fn set_leaf(&self, va: u64, value: u64) {
            self.set(Self::leaf_pa(va), value);
        }
        fn words(&self) -> PrimaryTableWords<'_, Maintenance> {
            unsafe {
                PrimaryTableWords::new(
                    self.words.as_ptr().cast_mut(),
                    ROOT,
                    self.words.len() * 8,
                    &MAINTENANCE,
                )
            }
            .unwrap()
        }
        fn image(&self) -> Vec<u64> {
            self.words
                .iter()
                .map(|w| w.load(Ordering::Relaxed))
                .collect()
        }
    }

    struct Maintenance;
    static MAINTENANCE: Maintenance = Maintenance;
    impl TableMaintenance for Maintenance {
        fn publish_barrier(&self) {}
        fn invalidate_range(&self, _va: u64, _len: u64) {}
    }

    /// Guest-physical pages. Copies read the copy window's live leaves, so
    /// a copy through an unmapped or wrong alias fails the test.
    struct Memory(RefCell<BTreeMap<u64, Vec<u8>>>);

    impl Memory {
        fn page(&self, ipa: u64) -> Vec<u8> {
            self.0.borrow().get(&ipa).cloned().unwrap_or(vec![0; 4096])
        }
        fn copy_through(&self, arena: &Arena, source: u64, destination: u64) {
            let (from, to) = (arena.leaf(source), arena.leaf(destination));
            assert_ne!(from & 1, 0, "source alias not mapped during the copy");
            assert_ne!(to & 1, 0, "destination alias not mapped during the copy");
            assert_eq!(
                from & (0b11 << 6),
                0b10 << 6,
                "source alias is EL1 read-only"
            );
            assert_eq!(to & (0b11 << 6), 0, "destination alias is EL1 read-write");
            let bytes = self.page(from & PA);
            self.0.borrow_mut().insert(to & PA, bytes);
        }
    }

    fn nz(value: u64) -> NonZeroU64 {
        NonZeroU64::new(value).unwrap()
    }

    fn backing() -> BackingIdentity {
        BackingIdentity {
            frame_id: nz(11),
            mapping_id: nz(12),
            owner_generation: nz(13),
            inventory_revision: nz(14),
        }
    }

    fn armed(ipa: u64, may_write: bool) -> u64 {
        ipa | 3
            | AF
            | SH
            | AP_RO_EL0
            | NG
            | XN
            | COW
            | PRIVATE
            | if may_write { MAY_WRITE } else { 0 }
    }

    fn residency_table() -> std::boxed::Box<FrameGrantResidencyTable> {
        let layout = std::alloc::Layout::new::<FrameGrantResidencyTable>();
        // SAFETY: the production shared index supports zero initialization;
        // the allocation has its exact size/alignment and one Box owner.
        let ptr = unsafe { std::alloc::alloc_zeroed(layout) }.cast::<FrameGrantResidencyTable>();
        if ptr.is_null() {
            std::alloc::handle_alloc_error(layout);
        }
        unsafe { std::boxed::Box::from_raw(ptr) }
    }

    /// A forked private compound: four armed pages, lane 3 read-only in
    /// Linux, each page holding distinct bytes.
    fn forked(window: bool) -> (Arena, Memory) {
        let arena = Arena::new(window);
        let memory = Memory(RefCell::new(BTreeMap::new()));
        for lane in 0..4 {
            arena.set_leaf(VA + lane * 4096, armed(OLD + lane * 4096, lane != 3));
            memory.0.borrow_mut().insert(
                OLD + lane * 4096,
                (0..4096).map(|i| (i as u64 * 7 + lane) as u8).collect(),
            );
        }
        (arena, memory)
    }

    fn resolve(
        arena: &Arena,
        memory: &Memory,
        pool: &CowGrantPool,
        far: u64,
        invalidations: &Cell<usize>,
    ) -> GuestCowOutcome {
        resolve_guest_cow(
            &GuestCowVenue {
                publish_executable: None,
                words: &arena.words(),
                root: SubstrateGpa(ROOT),
                pool,
                residency: &residency_table(),
                copy_window: crate::cow::CowCopyWindow::target(&arena.words(), SubstrateGpa(ROOT)),
            },
            MM,
            far,
            |source, destination| memory.copy_through(arena, source, destination),
            || invalidations.set(invalidations.get() + 1),
        )
        .unwrap()
    }

    #[test]
    fn maintenance_copy_failed_alias_install_restores_before_slot_reuse() {
        use carrick_el1_abi::{
            EL1_CARRIER_MAINT_ROOT_BASE as SERVICE_ROOT, EL1_SERVICE_COPY_TABLE_BASE,
            ServiceCopyTable, SlotId,
        };
        use carrick_mmu_core::aarch64::descriptor_txn::{DescriptorRefusal, TableWindow};
        struct FailDestination<'a> {
            words: &'a dyn LiveDescriptorWords,
            destination: u64,
        }
        impl LiveDescriptorWords for FailDestination<'_> {
            fn load(&self, pa: u64) -> Result<u64, DescriptorRefusal> {
                self.words.load(pa)
            }
            fn compare_exchange(
                &self,
                pa: u64,
                old: u64,
                new: u64,
            ) -> Result<bool, DescriptorRefusal> {
                if pa == self.destination && new & 1 != 0 {
                    Ok(false)
                } else {
                    self.words.compare_exchange(pa, old, new)
                }
            }
            fn store_unlinked(&self, pa: u64, value: u64) -> Result<(), DescriptorRefusal> {
                self.words.store_unlinked(pa, value)
            }
            fn publish_barrier(&self) {
                self.words.publish_barrier();
            }
            fn invalidate_range(&self, va: u64, len: u64) {
                self.words.invalidate_range(va, len);
            }
        }
        let image = carrick_mem::memory::stage1_carrier_maintenance_page_tables();
        let root: Vec<AtomicU64> = image
            .chunks_exact(8)
            .map(|bytes| AtomicU64::new(u64::from_le_bytes(bytes.try_into().unwrap())))
            .collect();
        let table = ServiceCopyTable::new();
        let slot = SlotId::new(19);
        let lease = table.try_claim(slot).unwrap();
        let words = unsafe {
            PrimaryTableWords::new(
                root.as_ptr().cast_mut(),
                SERVICE_ROOT,
                root.len() * 8,
                &MAINTENANCE,
            )
            .unwrap()
            .with_window(TableWindow {
                words: (&table as *const ServiceCopyTable).cast_mut().cast(),
                physical_base: EL1_SERVICE_COPY_TABLE_BASE,
                byte_len: 4096,
            })
            .unwrap()
        };
        let failing = FailDestination {
            words: &words,
            destination: EL1_SERVICE_COPY_TABLE_BASE + (u64::from(slot.raw()) * 2 + 1) * 8,
        };
        let (target, _) = forked(false);
        let pool = CowGrantPool::new();
        pool.publish(MM, GRANT, backing()).unwrap();
        let outcome = resolve_guest_cow(
            &GuestCowVenue {
                words: &target.words(),
                root: SubstrateGpa(ROOT),
                pool: &pool,
                residency: &residency_table(),
                copy_window: CowCopyWindow::maintenance(&failing, SERVICE_ROOT, &lease).unwrap(),
                publish_executable: None,
            },
            MM,
            VA,
            |_, _| panic!("failed destination publication must not copy"),
            || {},
        );
        assert_eq!(outcome, Ok(GuestCowOutcome::Declined(CowDecline::Refused)));
        assert_eq!(target.leaf(VA), armed(OLD, true));
        drop(lease);
        drop(table.try_claim(slot).unwrap());
        assert!(
            pool.claim(MM).is_some(),
            "failed copy returns its physical grant"
        );
    }

    #[test]
    fn maintenance_copy_two_live_same_va_mms_use_disjoint_slots_and_restore() {
        use carrick_el1_abi::{
            EL1_CARRIER_MAINT_ROOT_BASE as SERVICE_ROOT, EL1_SERVICE_COPY_TABLE_BASE,
            ServiceCopyTable, SlotId,
        };
        use carrick_mmu_core::aarch64::descriptor_txn::TableWindow;
        let service_image = carrick_mem::memory::stage1_carrier_maintenance_page_tables();
        let service_root: Vec<AtomicU64> = service_image
            .chunks_exact(8)
            .map(|bytes| AtomicU64::new(u64::from_le_bytes(bytes.try_into().unwrap())))
            .collect();
        let table = ServiceCopyTable::new();
        let rendezvous = std::sync::Barrier::new(2);
        std::thread::scope(|scope| {
            for index in 0..2_u8 {
                let table = &table;
                let service_root = &service_root;
                let rendezvous = &rendezvous;
                scope.spawn(move || {
                    let (target, memory) = forked(false);
                    let mm = MM + u64::from(index);
                    let source_ipa = OLD + u64::from(index) * 0x10000;
                    let replacement_ipa = GRANT + u64::from(index) * 0x10000;
                    for page in 0..4 {
                        target
                            .set_leaf(VA + page * PAGE, armed(source_ipa + page * PAGE, page != 3));
                        memory
                            .0
                            .borrow_mut()
                            .insert(source_ipa + page * PAGE, vec![index + 11; 4096]);
                    }
                    let pool = CowGrantPool::new();
                    pool.publish(mm, replacement_ipa, backing()).unwrap();
                    let slot = SlotId::new(index);
                    let lease = table.try_claim(slot).unwrap();
                    let service_words = unsafe {
                        PrimaryTableWords::new(
                            service_root.as_ptr().cast_mut(),
                            SERVICE_ROOT,
                            service_root.len() * 8,
                            &MAINTENANCE,
                        )
                        .unwrap()
                        .with_window(TableWindow {
                            words: (table as *const ServiceCopyTable).cast_mut().cast(),
                            physical_base: EL1_SERVICE_COPY_TABLE_BASE,
                            byte_len: 4096,
                        })
                        .unwrap()
                    };
                    assert!(
                        CowCopyWindow::maintenance(&service_words, SERVICE_ROOT + 4096, &lease)
                            .is_none()
                    );
                    let aliases =
                        CowCopyWindow::maintenance(&service_words, SERVICE_ROOT, &lease).unwrap();
                    let outcome = resolve_guest_cow(
                        &GuestCowVenue {
                            words: &target.words(),
                            root: SubstrateGpa(ROOT),
                            pool: &pool,
                            residency: &residency_table(),
                            copy_window: aliases,
                            publish_executable: None,
                        },
                        mm,
                        VA,
                        |source, destination| {
                            rendezvous.wait(); // Both MMs have live aliases simultaneously.
                            assert!(table.try_claim(slot).is_none());
                            let leaf = |va| {
                                service_words
                                    .load(EL1_SERVICE_COPY_TABLE_BASE + indices(va)[3] as u64 * 8)
                                    .unwrap()
                            };
                            let from = leaf(source);
                            let to = leaf(destination);
                            assert_eq!(from & (3 << 6), 2 << 6);
                            assert_eq!(to & (3 << 6), 0);
                            assert_eq!(from & XN, XN);
                            assert_eq!(to & XN, XN);
                            assert!((source_ipa..source_ipa + 4 * PAGE).contains(&(from & PA)));
                            assert!(
                                (replacement_ipa..replacement_ipa + 4 * PAGE).contains(&(to & PA))
                            );
                            let copied = memory.page(from & PA);
                            memory.0.borrow_mut().insert(to & PA, copied);
                            rendezvous.wait();
                        },
                        || {},
                    );
                    assert!(
                        matches!(outcome, Ok(GuestCowOutcome::Resolved(_))),
                        "{outcome:?}"
                    );
                    assert_eq!(memory.page(replacement_ipa), vec![index + 11; 4096]);
                    assert_eq!(target.leaf(VA) & PA, replacement_ipa);
                    drop(lease); // Asserts both leaves have been restored before reuse.
                    drop(table.try_claim(slot).unwrap());
                });
            }
        });
    }

    #[test]
    fn maintenance_copy_uses_service_root_without_target_aliases() {
        let (target, memory) = forked(false);
        let service = Arena::new(true);
        let before = service.image();
        let pool = CowGrantPool::new();
        pool.publish(MM, GRANT, backing()).unwrap();
        let outcome = resolve_guest_cow(
            &GuestCowVenue {
                publish_executable: None,
                words: &target.words(),
                root: SubstrateGpa(ROOT),
                pool: &pool,
                residency: &residency_table(),
                copy_window: crate::cow::CowCopyWindow::target(
                    &service.words(),
                    SubstrateGpa(ROOT),
                ),
            },
            MM,
            VA,
            |source, destination| memory.copy_through(&service, source, destination),
            || {},
        );
        assert!(
            matches!(outcome, Ok(GuestCowOutcome::Resolved(_))),
            "maintenance-root COW must resolve without target-root copy aliases: {outcome:?}"
        );
        assert_eq!(memory.page(GRANT), memory.page(OLD));
        assert_eq!(
            service.image(),
            before,
            "all service aliases must be restored"
        );
    }

    #[test]
    fn cow_replaces_the_residency_identity_with_the_granted_owner() {
        let (arena, memory) = forked(true);
        let pool = CowGrantPool::new();
        let grant = pool.publish(MM, GRANT, backing()).unwrap();
        let residency = residency_table();
        let old = carrick_el1_abi::FrameGrantResidencyIdentity {
            mm_key: MM,
            semantic_base: VA,
            physical_ipa: OLD,
            len: 4 * PAGE,
            mapping_id: 101,
            frame_id: 102,
            owner_generation: 103,
            inventory_revision: 104,
        };
        residency.publish(old).unwrap();
        let stale = residency.lookup(MM, VA).unwrap();
        assert!(residency.record_commit(stale));
        let outcome = resolve_guest_cow(
            &GuestCowVenue {
                publish_executable: None,
                words: &arena.words(),
                root: SubstrateGpa(ROOT),
                pool: &pool,
                residency: &residency,
                copy_window: crate::cow::CowCopyWindow::target(&arena.words(), SubstrateGpa(ROOT)),
            },
            MM,
            VA,
            |source, destination| memory.copy_through(&arena, source, destination),
            || {},
        );
        assert!(matches!(outcome, Ok(GuestCowOutcome::Resolved(_))));
        assert!(!residency.record_commit(stale));
        for offset in (0..4 * PAGE).step_by(PAGE as usize) {
            let page = residency.lookup(MM, VA + offset).unwrap();
            assert_eq!(page.expected_ipa, GRANT + offset);
            assert_eq!(
                page.identity.owner_generation,
                grant.backing.owner_generation.get()
            );
            assert_eq!(page.identity.frame_id, grant.backing.frame_id.get());
            assert!(residency.is_guest_committed(MM, VA + offset));
        }
    }

    #[test]
    fn cow_defers_before_copying_a_leased_grant_window() {
        let (arena, memory) = forked(true);
        let pool = CowGrantPool::new();
        pool.publish(MM, GRANT, backing()).unwrap();
        let residency = residency_table();
        let identity = carrick_el1_abi::FrameGrantResidencyIdentity {
            mm_key: MM,
            semantic_base: VA,
            physical_ipa: OLD,
            len: 4 * PAGE,
            mapping_id: 101,
            frame_id: 102,
            owner_generation: 103,
            inventory_revision: 104,
        };
        residency.publish(identity).unwrap();
        let page = residency.lookup(MM, VA).unwrap();
        let lease = residency.pin_transfer(page).unwrap();
        let words = arena.words();
        let venue = GuestCowVenue {
            publish_executable: None,
            words: &arena.words(),
            root: SubstrateGpa(ROOT),
            pool: &pool,
            residency: &residency,
            copy_window: crate::cow::CowCopyWindow::target(&words, SubstrateGpa(ROOT)),
        };
        assert_eq!(
            resolve_guest_cow(
                &venue,
                MM,
                VA,
                |_, _| panic!("leased grant must not be copied"),
                || panic!("unchanged leaves")
            ),
            Ok(GuestCowOutcome::Declined(CowDecline::Refused))
        );
        assert_eq!(arena.leaf(VA) & PA, OLD);
        assert_eq!(residency.lookup(MM, VA).unwrap(), page);
        drop(lease);
        assert!(matches!(
            resolve_guest_cow(
                &venue,
                MM,
                VA,
                |source, destination| memory.copy_through(&arena, source, destination),
                || {}
            ),
            Ok(GuestCowOutcome::Resolved(_))
        ));
    }

    #[test]
    fn el1_copies_and_repoints_a_forked_compound_with_a_pool_grant() {
        let (arena, memory) = forked(true);
        let window_before = [
            arena.leaf(EL1_COW_COPY_BASE),
            arena.leaf(EL1_COW_COPY_BASE + 4096),
        ];
        let pool = CowGrantPool::new();
        let grant = pool.publish(MM, GRANT, backing()).unwrap();
        let invalidations = Cell::new(0);

        let outcome = resolve(&arena, &memory, &pool, VA + 0x1abc, &invalidations);

        let expected = CowGrantCompletion {
            purpose: carrick_el1_abi::CowGrantPurpose::UserWrite,
            grant,
            span_va: VA,
            span_len: 4 * 4096,
            old_ipa: OLD,
            new_ipa: GRANT,
        };
        assert_eq!(outcome, GuestCowOutcome::Resolved(expected));
        for lane in 0..4 {
            let leaf = arena.leaf(VA + lane * 4096);
            assert_eq!(
                leaf & PA,
                GRANT + lane * 4096,
                "lane {lane} moved to the grant"
            );
            assert_eq!(leaf & COW, 0, "lane {lane} is private now");
            let writable = leaf & (0b11 << 6) == AP_RW_EL0;
            assert_eq!(
                writable,
                lane != 3,
                "lane {lane} recovers its recorded intent"
            );
            assert_eq!(
                memory.page(GRANT + lane * 4096),
                memory.page(OLD + lane * 4096),
                "lane {lane} bytes copied"
            );
        }
        assert_eq!(
            [
                arena.leaf(EL1_COW_COPY_BASE),
                arena.leaf(EL1_COW_COPY_BASE + 4096)
            ],
            window_before,
            "the copy window is idle again"
        );
        assert!(
            invalidations.get() >= 1,
            "the MM's stale RO translations are invalidated"
        );
        let spaces = AddressSpaces::new();
        let excluded = spaces.unpublished(MM).unwrap();
        assert_eq!(
            pool.completions(&excluded).collect::<Vec<_>>(),
            vec![expected]
        );
        assert_eq!(pool.resolved(), 1);
        assert_eq!(pool.ready(MM).count(), 0);
    }

    #[test]
    fn el1_moves_only_the_run_of_the_faulting_compound() {
        let (arena, memory) = forked(true);
        // Lane 0 was already privatized by an earlier COW.
        arena.set_leaf(
            VA,
            (0x0077_0000_0000 | 3 | AF | SH | NG | XN | PRIVATE | MAY_WRITE) | AP_RW_EL0,
        );
        let pool = CowGrantPool::new();
        let grant = pool.publish(MM, GRANT, backing()).unwrap();
        let outcome = resolve(&arena, &memory, &pool, VA + 2 * 4096, &Cell::new(0));
        assert_eq!(
            outcome,
            GuestCowOutcome::Resolved(CowGrantCompletion {
                purpose: carrick_el1_abi::CowGrantPurpose::UserWrite,
                grant,
                span_va: VA + 4096,
                span_len: 3 * 4096,
                old_ipa: OLD + 4096,
                new_ipa: GRANT + 4096,
            })
        );
        assert_eq!(
            arena.leaf(VA) & PA,
            0x0077_0000_0000,
            "the private lane is untouched"
        );
    }

    #[test]
    fn an_empty_pool_or_another_mms_grant_leaves_the_fault_to_the_host() {
        let (arena, memory) = forked(true);
        let before = arena.image();
        let pool = CowGrantPool::new();
        pool.publish(MM + 1, GRANT, backing()).unwrap();
        assert_eq!(
            resolve(&arena, &memory, &pool, VA, &Cell::new(0)),
            GuestCowOutcome::Declined(CowDecline::PoolEmpty)
        );
        assert_eq!(arena.image(), before);
        assert_eq!(
            pool.ready(MM + 1).count(),
            1,
            "the other MM's grant is untouched"
        );
        assert_eq!(pool.declined()[CowDecline::PoolEmpty as usize], 1);
    }

    #[test]
    fn unclassified_writes_keep_their_grant_ready() {
        let (arena, memory) = forked(true);
        // mprotect(PROT_READ) after the fork: an armed page without write
        // intent is a SIGSEGV for the host to deliver, never a copy.
        arena.set_leaf(VA, armed(OLD, false));
        let pool = CowGrantPool::new();
        pool.publish(MM, GRANT, backing()).unwrap();
        let before = arena.image();
        assert_eq!(
            resolve(&arena, &memory, &pool, VA, &Cell::new(0)),
            GuestCowOutcome::Declined(CowDecline::NoWriteIntent)
        );
        // An untagged backend leaf.
        arena.set_leaf(VA, OLD | 3 | AF | SH | AP_RO_EL0 | NG);
        assert_eq!(
            resolve(&arena, &memory, &pool, VA, &Cell::new(0)),
            GuestCowOutcome::Declined(CowDecline::NotEl1Private)
        );
        assert_eq!(pool.ready(MM).count(), 1);
        arena.set_leaf(VA, before[((Arena::leaf_pa(VA) - ROOT) / 8) as usize]);
        assert_eq!(arena.image(), before);
    }

    #[test]
    fn a_refused_copy_returns_the_grant_and_changes_nothing() {
        // No copy window provisioned in this MM's tables.
        let (arena, memory) = forked(false);
        let before = arena.image();
        let pool = CowGrantPool::new();
        let grant = pool.publish(MM, GRANT, backing()).unwrap();
        assert_eq!(
            resolve(&arena, &memory, &pool, VA, &Cell::new(0)),
            GuestCowOutcome::Declined(CowDecline::Refused)
        );
        assert_eq!(arena.image(), before);
        assert_eq!(pool.ready(MM).collect::<Vec<_>>(), vec![grant]);
        assert!(
            memory.0.borrow().get(&GRANT).is_none(),
            "nothing was copied"
        );
    }

    #[test]
    fn an_already_writable_leaf_retries_after_invalidation() {
        let (arena, memory) = forked(true);
        arena.set_leaf(
            VA,
            (OLD | 3 | AF | SH | NG | XN | PRIVATE | MAY_WRITE) | AP_RW_EL0,
        );
        let pool = CowGrantPool::new();
        pool.publish(MM, GRANT, backing()).unwrap();
        let invalidations = Cell::new(0);
        assert_eq!(
            resolve(&arena, &memory, &pool, VA, &invalidations),
            GuestCowOutcome::AlreadyWritable
        );
        assert_eq!(invalidations.get(), 1);
        assert_eq!(pool.ready(MM).count(), 1);
    }

    /// The fault dispatcher's resolver over the model arena.
    struct ArenaResolver<'a> {
        arena: &'a Arena,
        memory: &'a Memory,
        pool: &'a CowGrantPool,
    }

    impl CowResolver for ArenaResolver<'_> {
        fn resolve_cow(&mut self, ttbr0: u64, mm_key: u64, far: u64) -> bool {
            assert_eq!(ttbr0 & PA, ROOT);
            let outcome = resolve_guest_cow(
                &GuestCowVenue {
                    publish_executable: None,
                    words: &self.arena.words(),
                    root: SubstrateGpa(ttbr0 & PA),
                    pool: self.pool,
                    residency: &residency_table(),
                    copy_window: crate::cow::CowCopyWindow::target(
                        &self.arena.words(),
                        SubstrateGpa(ttbr0 & PA),
                    ),
                },
                mm_key,
                far,
                |source, destination| self.memory.copy_through(self.arena, source, destination),
                || {},
            );
            crate::fault::handle_cow_outcome(outcome, &mut None)
                == crate::fault::CowResolution::Resolved
        }
        fn editor_busy(&mut self) {
            self.pool.note_declined(CowDecline::EditorBusy);
        }
    }

    fn dispatch(spaces: &AddressSpaces, resolver: &mut ArenaResolver<'_>) -> Action {
        let task = CurrentTask::new();
        task.mm.key.store(MM, Ordering::Release);
        let mut frame = TrapFrame {
            esr: (0x24 << 26) | (1 << 6) | 0x0f,
            far: VA + 0x10,
            slot: 0,
            ..TrapFrame::default()
        };
        dispatch_fault_with_prepared(
            &mut frame,
            &Counters::default(),
            &[task],
            carrick_sched_core::spaces::notification::SpaceAccess::source_free(spaces),
            GrantMailboxes::own(&FrameGrantMailbox::new()),
            None::<PreparedFaultPath<'_, NoopPreparedResolver>>,
            resolver,
        )
    }

    #[test]
    fn a_guest_cow_fault_is_served_in_el1_unless_the_host_holds_the_mm() {
        let (arena, memory) = forked(true);
        let pool = CowGrantPool::new();
        pool.publish(MM, GRANT, backing()).unwrap();
        let mut resolver = ArenaResolver {
            arena: &arena,
            memory: &memory,
            pool: &pool,
        };
        // A host pause of the MM closes its gate: EL1 never edits under it.
        let closed = AddressSpaces::new();
        closed.publish_closed(MM, ROOT | ASID, ROOT | ASID).unwrap();
        let before = arena.image();
        assert_eq!(dispatch(&closed, &mut resolver), Action::Forward);
        assert_eq!(arena.image(), before);
        assert_eq!(pool.declined()[CowDecline::EditorBusy as usize], 1);
        assert_eq!(pool.ready(MM).count(), 1);

        let open = AddressSpaces::new();
        let index = open.publish_closed(MM, ROOT | ASID, ROOT | ASID).unwrap();
        open.open(index);
        assert_eq!(dispatch(&open, &mut resolver), Action::Served);
        // The host settles with the MM's editor excluded (here: unpublished).
        let host = AddressSpaces::new();
        let excluded = host.unpublished(MM).unwrap();
        assert_eq!(pool.completions(&excluded).count(), 1);
        assert_eq!(arena.leaf(VA) & PA, GRANT);
        const _: () = assert!(GRANT.is_multiple_of(COW_GRANT_SIZE));
    }
    #[test]
    fn admitted_private_file_source_resolves_in_el1_and_preserves_source_bytes() {
        use carrick_mmu_core::aarch64::descriptor_txn::{
            DescriptorOp, DescriptorOutcome, DescriptorTxn, DescriptorTxnId, InlineJournal,
            PageSpan, TableGrants, TerminalEdit, execute_descriptor_txn,
        };
        use carrick_mmu_core::aarch64::{PtOp, TerminalRule};
        let (arena, memory) = forked(true);
        for lane in 0..4 {
            arena.set_leaf(
                VA + lane * 4096,
                (OLD + lane * 4096) | 3 | AF | SH | AP_RO_EL0 | NG | XN,
            );
        }
        let txn = DescriptorTxn {
            id: DescriptorTxnId {
                mm_key: nz(MM),
                generation: nz(1),
            },
            root: SubstrateGpa(ROOT),
            tables: TableGrants::new(&[]).unwrap(),
            op: DescriptorOp::Terminal {
                span: PageSpan::new(VA, 4 * 4096),
                edit: TerminalEdit {
                    rule: TerminalRule::Pt {
                        op: Some(PtOp::ReadWrite { exec: false }),
                        reset_retired: false,
                        deny_host_buffers: false,
                        fork_arm: true,
                        adopt_private: true,
                    },
                    asid_scoped: true,
                    excluded_ipa: 0,
                    excluded_len: 0,
                    reclaim_budget: 0,
                },
            },
        };
        assert!(matches!(
            execute_descriptor_txn(
                &arena.words(),
                SubstrateGpa(ROOT),
                &txn,
                &mut InlineJournal::new()
            )
            .outcome,
            DescriptorOutcome::Applied(_)
        ));
        let source = memory.page(OLD + 4096);
        let adjacent = memory.page(OLD);
        let pool = CowGrantPool::new();
        pool.publish(MM, GRANT, backing()).unwrap();
        assert!(matches!(
            resolve(&arena, &memory, &pool, VA + 4096, &Cell::new(0)),
            GuestCowOutcome::Resolved(_)
        ));
        assert_eq!(memory.page(GRANT + 4096), source);
        memory.0.borrow_mut().get_mut(&(GRANT + 4096)).unwrap()[..4].copy_from_slice(b"edit");
        assert_eq!(memory.page(OLD + 4096), source);
        assert_eq!(memory.page(OLD), adjacent);
        assert_eq!(&memory.page(GRANT + 4096)[..4], b"edit");
    }

    #[test]
    #[should_panic(expected = "EL1 COW translation state indeterminate")]
    fn a_failed_copy_window_restore_panics_and_does_not_forward() {
        let (arena, memory) = forked(true);
        let pool = CowGrantPool::new();
        pool.publish(MM, GRANT, backing()).unwrap();

        let open = AddressSpaces::new();
        let index = open.publish_closed(MM, ROOT | ASID, ROOT | ASID).unwrap();
        open.open(index);

        struct CorruptingResolver<'a> {
            arena: &'a Arena,
            memory: &'a Memory,
            pool: &'a CowGrantPool,
        }

        impl CowResolver for CorruptingResolver<'_> {
            fn resolve_cow(&mut self, ttbr0: u64, mm_key: u64, far: u64) -> bool {
                assert_eq!(ttbr0 & PA, ROOT);
                let outcome = resolve_guest_cow(
                    &GuestCowVenue {
                        publish_executable: None,
                        words: &self.arena.words(),
                        root: SubstrateGpa(ttbr0 & PA),
                        pool: self.pool,
                        residency: &residency_table(),
                        copy_window: crate::cow::CowCopyWindow::target(
                            &self.arena.words(),
                            SubstrateGpa(ttbr0 & PA),
                        ),
                    },
                    mm_key,
                    far,
                    |source, destination| {
                        self.memory.copy_through(self.arena, source, destination);
                        // Corrupt the alias descriptor in the arena after copying so the copy window restore CAS fails
                        self.arena.set_leaf(EL1_COW_COPY_BASE, 0xdead_beef);
                    },
                    || {},
                );
                assert_eq!(outcome, Err(CowError::Indeterminate));
                crate::fault::handle_cow_outcome(outcome, &mut None)
                    == crate::fault::CowResolution::Resolved
            }
            fn editor_busy(&mut self) {
                self.pool.note_declined(CowDecline::EditorBusy);
            }
        }

        let mut resolver = CorruptingResolver {
            arena: &arena,
            memory: &memory,
            pool: &pool,
        };

        let task = CurrentTask::new();
        task.mm.key.store(MM, Ordering::Release);
        let mut frame = TrapFrame {
            esr: (0x24 << 26) | (1 << 6) | 0x0f,
            far: VA + 0x10,
            slot: 0,
            ..TrapFrame::default()
        };
        let action = dispatch_fault_with_prepared(
            &mut frame,
            &Counters::default(),
            &[task],
            carrick_sched_core::spaces::notification::SpaceAccess::source_free(&open),
            GrantMailboxes::own(&FrameGrantMailbox::new()),
            None::<PreparedFaultPath<'_, NoopPreparedResolver>>,
            &mut resolver,
        );
        // The old code returned Action::Forward instead of terminating.
        assert_ne!(
            action,
            Action::Forward,
            "must not continue via Action::Forward"
        );
    }
}

#[cfg(test)]
mod x86_cow_tests {
    use super::X86CowMmu;
    use carrick_core::mm::cow::OwnerCowMmu;
    use carrick_mmu_core::aarch64::descriptor_txn::{DescriptorRefusal, LiveDescriptorWords};
    use carrick_mmu_core::x86::descriptor_txn::{ADDRESS, PRESENT, WRITE};
    use core::cell::{Cell, RefCell};
    use std::collections::BTreeMap;

    const ROOT: u64 = 0x4001000;
    const SOURCE: u64 = 0x4100000;
    const DESTINATION: u64 = 0x800000;

    struct Words {
        image: RefCell<BTreeMap<u64, u64>>,
        next: Cell<u64>,
        loads: Cell<usize>,
        drains: Cell<usize>,
    }
    impl Words {
        fn new() -> Self {
            Self {
                image: RefCell::new(BTreeMap::new()),
                next: Cell::new(ROOT + 4096),
                loads: Cell::new(0),
                drains: Cell::new(0),
            }
        }
        fn map(&self, va: u64, output: u64, flags: u64) {
            let mut table = ROOT;
            for shift in [39, 30, 21] {
                let pa = table + ((va >> shift) & 511) * 8;
                let existing = self.image.borrow().get(&pa).copied();
                table = match existing {
                    Some(word) => word & ADDRESS,
                    None => {
                        let next = self.next.get();
                        self.next.set(next + 4096);
                        self.image
                            .borrow_mut()
                            .insert(pa, next | PRESENT | WRITE | 4);
                        next
                    }
                };
            }
            self.image
                .borrow_mut()
                .insert(table + ((va >> 12) & 511) * 8, output | flags);
        }
    }
    impl LiveDescriptorWords for Words {
        fn load(&self, pa: u64) -> Result<u64, DescriptorRefusal> {
            self.loads.set(self.loads.get() + 1);
            Ok(self.image.borrow().get(&pa).copied().unwrap_or(0))
        }
        fn compare_exchange(&self, pa: u64, old: u64, new: u64) -> Result<bool, DescriptorRefusal> {
            let mut image = self.image.borrow_mut();
            if image.get(&pa).copied().unwrap_or(0) != old {
                return Ok(false);
            }
            image.insert(pa, new);
            Ok(true)
        }
        fn store_unlinked(&self, pa: u64, value: u64) -> Result<(), DescriptorRefusal> {
            self.image.borrow_mut().insert(pa, value);
            Ok(())
        }
        fn publish_barrier(&self) {}
        fn invalidate_range(&self, _va: u64, _len: u64) {
            self.drains.set(self.drains.get() + 1);
        }
    }

    #[test]
    fn x86_cow_uses_supplied_initial_extent_source_and_direct_replacement() {
        let words = Words::new();
        let source = carrick_el1_abi::X86_CPL0_INITIAL_EXTENT_VA + SOURCE
            - carrick_el1_abi::X86_CPL0_INITIAL_EXTENT_GPA;
        let destination = carrick_el1_abi::X86_CPL0_DIRECT_VA + DESTINATION;
        words.map(source, SOURCE, PRESENT);
        words.map(destination, DESTINATION, PRESENT | WRITE);
        let mut aliases = None;
        let result = X86CowMmu::with_copy_aliases(
            &words,
            ROOT,
            carrick_el1_abi::X86_CPL0_DIRECT_VA,
            SOURCE,
            DESTINATION,
            &mut |from, to| aliases = Some((from, to)),
        );
        assert_eq!(
            result,
            Ok(()),
            "inherited source has only its authenticated initial-extent alias"
        );
        assert_eq!(aliases, Some((source, destination)));
        assert_eq!(
            words.loads.get(),
            8,
            "one bounded four-level walk per copy alias"
        );
    }
    #[test]
    fn x86_cow_repoint_executes_and_drains_supplied_words() {
        use carrick_core::mm::cow::{CowRepointOp, CowRepointOutcome};
        use carrick_guest_arch::{FrameGpa, RootGpa, UserVa};
        use carrick_mmu_core::x86::descriptor_txn::{
            Access, BackingIdentity, COW, MAY_WRITE, NX, PRIVATE, USER, translate,
        };
        use core::num::NonZeroU64;
        let words = Words::new();
        let va = 0x401000;
        words.map(va, SOURCE, PRESENT | USER | NX | COW | PRIVATE | MAY_WRITE);
        let id = NonZeroU64::new(1).unwrap();
        let outcome = X86CowMmu::execute_cow_repoint(
            &words,
            ROOT,
            CowRepointOp {
                mm_key: 77,
                grant_epoch: 1,
                va,
                len: 4096,
                old_ipa: SOURCE,
                new_ipa: DESTINATION,
                backing: BackingIdentity {
                    frame_id: id,
                    mapping_id: id,
                    owner_generation: id,
                    inventory_revision: id,
                },
            },
        );
        assert_eq!(
            outcome,
            CowRepointOutcome::Applied {
                flush_required: false
            }
        );
        assert_eq!(
            words.drains.get(),
            1,
            "supplied words acknowledge descriptor publication drain"
        );
        assert_eq!(
            translate(
                &words,
                RootGpa::page_aligned(FrameGpa::new(ROOT)).unwrap(),
                UserVa::new(va),
                Access::Write,
                true
            ),
            Ok(FrameGpa::new(DESTINATION))
        );
    }
    #[test]
    fn x86_cow_refuses_wrong_or_nonwritable_copy_aliases_without_copying() {
        use carrick_core::mm::cow::CowRepointOutcome;
        let source = carrick_el1_abi::X86_CPL0_INITIAL_EXTENT_VA + SOURCE
            - carrick_el1_abi::X86_CPL0_INITIAL_EXTENT_GPA;
        let destination = carrick_el1_abi::X86_CPL0_DIRECT_VA + DESTINATION;
        for (source_output, destination_output, destination_flags) in [
            (SOURCE + 4096, DESTINATION, PRESENT | WRITE),
            (SOURCE, DESTINATION + 4096, PRESENT | WRITE),
            (SOURCE, DESTINATION, PRESENT),
        ] {
            let words = Words::new();
            words.map(source, source_output, PRESENT);
            words.map(destination, destination_output, destination_flags);
            let mut copies = 0;
            assert_eq!(
                X86CowMmu::with_copy_aliases(
                    &words,
                    ROOT,
                    carrick_el1_abi::X86_CPL0_DIRECT_VA,
                    SOURCE,
                    DESTINATION,
                    &mut |_, _| copies += 1
                ),
                Err(CowRepointOutcome::Refused)
            );
            assert_eq!(copies, 0);
            assert!(
                words.loads.get() <= 8,
                "at most two bounded permission walks"
            );
            assert_eq!(words.drains.get(), 0);
        }
    }
    #[test]
    fn x86_cow_refuses_unpublished_high_gpa_copy_alias() {
        use carrick_core::mm::cow::CowRepointOutcome;
        let words = Words::new();
        let destination_gpa = 0x2_0000_0000;
        assert!(
            carrick_el1_abi::X86_CPL0_DIRECT_VA
                .checked_add(destination_gpa)
                .is_none()
        );
        let source = carrick_el1_abi::X86_CPL0_INITIAL_EXTENT_VA + SOURCE
            - carrick_el1_abi::X86_CPL0_INITIAL_EXTENT_GPA;
        words.map(source, SOURCE, PRESENT);
        let mut copies = 0;
        assert_eq!(
            X86CowMmu::with_copy_aliases(
                &words,
                ROOT,
                carrick_el1_abi::X86_CPL0_DIRECT_VA,
                SOURCE,
                destination_gpa,
                &mut |_, _| copies += 1
            ),
            Err(CowRepointOutcome::Refused)
        );
        assert_eq!(copies, 0);
    }
}
