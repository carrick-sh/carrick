// Real descriptor editors and live walkers for the two-ISA peer witness.
use carrick_mmu_core::x86::descriptor_txn::{DescriptorRefusal, LiveDescriptorWords};
use core::sync::atomic::AtomicU64;
use std::sync::Arc;
const LIVE_ROOT: u64 = 0x1000;
const LIVE_FRAME: u64 = 0x0900_0000;
struct LiveTables {
    isa: carrick_guest_arch::GuestIsa,
    words: Vec<AtomicU64>,
    bytes: [AtomicU64; 3],
    drains: AtomicU64,
}
impl LiveTables {
    fn new(isa: carrick_guest_arch::GuestIsa) -> Self {
        let words: Vec<_> = (0..2048).map(|_| AtomicU64::new(0)).collect();
        let flags = if isa == carrick_guest_arch::GuestIsa::X86_64 {
            7
        } else {
            3
        };
        for (index, table) in [(0, 0x2000), (512, 0x3000), (1024, 0x4000)] {
            words[index].store(table | flags, Ordering::Release);
        }
        Self {
            isa,
            words,
            bytes: core::array::from_fn(|_| AtomicU64::new(0x35)),
            drains: AtomicU64::new(0),
        }
    }
    fn populate(&self) {
        if self.isa == carrick_guest_arch::GuestIsa::X86_64 {
            use carrick_mmu_core::x86::descriptor_txn::*;
            for page in 0..3 {
                self.words[1536 + 256 + page].store(
                    (LIVE_FRAME + page as u64 * 4096)
                        | PRIVATE
                        | PRESENT
                        | WRITE
                        | USER
                        | MAY_WRITE
                        | NX,
                    Ordering::Release,
                );
            }
        } else {
            // Initial resident fixture: AF, nG, inner-shareable EL0 RW,
            // PXN/UXN, private ownership and the original write ceiling.
            let flags = (1_u64 << 53)
                | (1 << 54)
                | (1 << 10)
                | (1 << 11)
                | (3 << 8)
                | (1 << 6)
                | 3
                | (1 << 56)
                | (1 << 57);
            for page in 0..3 {
                self.words[1536 + 256 + page]
                    .store((LIVE_FRAME + page as u64 * 4096) | flags, Ordering::Release);
            }
        }
    }
    fn touch(&self, address: u64, write: bool) -> Option<u64> {
        let output = if self.isa == carrick_guest_arch::GuestIsa::X86_64 {
            use carrick_mmu_core::x86::descriptor_txn::{Access, translate};
            translate(
                self,
                carrick_guest_arch::RootGpa::page_aligned(carrick_guest_arch::FrameGpa::new(
                    LIVE_ROOT,
                ))?,
                carrick_guest_arch::UserVa::new(address),
                if write { Access::Write } else { Access::Read },
                true,
            )
            .ok()?
            .raw()
        } else {
            use carrick_mmu_core::aarch64::{
                LeafAccess, terminal_descriptor, terminal_descriptor_permits_el0,
                walk_descriptors_host,
            };
            // SAFETY: Arc retains the atomic arena throughout this live walk.
            let walk = unsafe {
                walk_descriptors_host(
                    self.words.as_ptr().cast(),
                    self.words.len() * 8,
                    LIVE_ROOT,
                    address,
                )
            };
            let leaf = terminal_descriptor(walk);
            if !terminal_descriptor_permits_el0(
                leaf,
                if write {
                    LeafAccess::Write
                } else {
                    LeafAccess::Read
                },
            ) {
                return None;
            }
            (leaf & 0x0000_ffff_ffff_f000) | (address & 4095)
        };
        let page = usize::try_from(output.checked_sub(LIVE_FRAME)? / 4096).ok()?;
        Some(self.bytes.get(page)?.load(Ordering::Acquire))
    }
    fn protect(&self, sequence: ReservationSequence, edit: GuestPermissionEdit) {
        if self.isa == carrick_guest_arch::GuestIsa::X86_64 {
            self.x86_edit(
                sequence,
                edit.va,
                edit.len,
                carrick_guest_arch::EditOperation::Protect {
                    permissions: carrick_guest_arch::EditPermissions {
                        readable: edit.readable,
                        writable: edit.writable,
                        executable: edit.executable,
                        user: true,
                    },
                },
            );
        } else {
            // SAFETY: the shared entry retains the exact-MM editor; all words
            // are initialized atomics and publication precedes the peer wake.
            unsafe {
                carrick_mmu_core::aarch64::protect_existing_el1_private_pages(
                    self.words.as_ptr().cast_mut(),
                    LIVE_ROOT,
                    self.words.len() * 8,
                    None,
                    edit,
                )
            }
            .unwrap();
            self.drains.fetch_add(1, Ordering::Release);
        }
    }
    fn retire(&self, sequence: ReservationSequence, address: u64, len: u64) {
        if self.isa == carrick_guest_arch::GuestIsa::X86_64 {
            self.x86_edit(
                sequence,
                address,
                len,
                carrick_guest_arch::EditOperation::Unmap,
            );
        } else {
            // SAFETY: same exact-MM exclusion and retained atomic arena as protect.
            unsafe {
                carrick_mmu_core::aarch64::retire_existing_el1_private_pages(
                    self.words.as_ptr().cast_mut(),
                    LIVE_ROOT,
                    self.words.len() * 8,
                    None,
                    address,
                    len,
                )
            }
            .unwrap();
            self.drains.fetch_add(1, Ordering::Release);
        }
    }
    fn x86_edit(
        &self,
        sequence: ReservationSequence,
        address: u64,
        len: u64,
        operation: carrick_guest_arch::EditOperation,
    ) {
        use carrick_guest_arch::{
            EditIntent, EditOwner, FrameGpa, GuestLen, RootGpa, UserRange, UserVa,
        };
        use carrick_mmu_core::x86::descriptor_txn::{
            DescriptorOutcome, DescriptorTxn, InlineJournal, execute_descriptor_txn,
        };
        let root = RootGpa::page_aligned(FrameGpa::new(LIVE_ROOT)).unwrap();
        // SAFETY: issued by the real reservation operation under the shared
        // exact-MM editor; root and MM are this fixture's admitted identities.
        let owner = unsafe {
            EditOwner::issue(
                root,
                NonZeroU64::new(17).unwrap(),
                NonZeroU64::new(sequence.raw()).unwrap(),
            )
        };
        let intent = EditIntent::checked(
            owner,
            UserRange::checked(UserVa::new(address), GuestLen::new(len)).unwrap(),
            operation,
            &[],
        )
        .unwrap();
        let txn = DescriptorTxn::from_intent(&intent).unwrap();
        assert!(matches!(
            execute_descriptor_txn(self, &txn, root, &mut InlineJournal::new()).outcome,
            DescriptorOutcome::Applied { .. }
        ));
    }
}
impl LiveDescriptorWords for LiveTables {
    fn load(&self, pa: u64) -> Result<u64, DescriptorRefusal> {
        self.words
            .get(
                ((pa.checked_sub(LIVE_ROOT)
                    .ok_or(DescriptorRefusal::BadRange)?)
                    / 8) as usize,
            )
            .map(|word| word.load(Ordering::Acquire))
            .ok_or(DescriptorRefusal::BadRange)
    }
    fn compare_exchange(
        &self,
        pa: u64,
        before: u64,
        after: u64,
    ) -> Result<bool, DescriptorRefusal> {
        let word = self
            .words
            .get(
                ((pa.checked_sub(LIVE_ROOT)
                    .ok_or(DescriptorRefusal::BadRange)?)
                    / 8) as usize,
            )
            .ok_or(DescriptorRefusal::BadRange)?;
        Ok(word
            .compare_exchange(before, after, Ordering::AcqRel, Ordering::Acquire)
            .is_ok())
    }
    fn store_unlinked(&self, _: u64, _: u64) -> Result<(), DescriptorRefusal> {
        Err(DescriptorRefusal::BadRange)
    }
    fn publish_barrier(&self) {
        core::sync::atomic::fence(Ordering::SeqCst);
    }
    fn invalidate_range(&self, _: u64, _: u64) {
        self.drains.fetch_add(1, Ordering::Release);
    }
}
