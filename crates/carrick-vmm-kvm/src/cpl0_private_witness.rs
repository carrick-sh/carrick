//! Historical proof of PRIVATE anonymous leaves, authenticated while live at settlement.
//! Work is bounded by the edited grant; no process census or inventory scan is retained.
use carrick_guest_arch::CpuId;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicU32, Ordering};

pub(crate) struct SettledPrivateGrant<'a> {
    pub cpu: CpuId,
    pub memory: &'a crate::carrier_memory::CarrierMemory,
    pub inventory: &'a dyn carrick_hal::PhysicalFrameInventory,
    pub binding: carrick_el1_abi::ExecutionBinding,
    pub context: carrick_guest_arch::AddressContext<carrick_guest_arch::RootGpa>,
    pub window: carrick_el1_abi::PortalGrantWindow,
    pub txn: &'a carrick_mmu_core::aarch64::descriptor_txn::DescriptorTxn,
    pub publication: carrick_el1_abi::GuestMmuPublication,
    pub peer: PeerActivity,
}
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct PeerActivity(bool);
impl PeerActivity {
    pub(crate) fn observe(actual_run: &AtomicU32) -> Self {
        Self(actual_run.load(Ordering::Acquire) != 0)
    }
    pub(crate) fn combine(self, other: Self) -> Self {
        Self(self.0 || other.0)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrivateAnonymousMmEvidence {
    pub mm: u64,
    pub root: u64,
    pub incarnation: u64,
    pub generation: u64,
    pub private_pages: u64,
    pub cpu_mask: u64,
}
#[derive(Default)]
pub(crate) struct PrivateAnonymousWitness {
    carrier: Option<crate::carrier_memory::CarrierVmId>,
    rows: BTreeMap<(u64, u64, u64, u64), BTreeSet<u64>>,
    cpu_masks: BTreeMap<(u64, u64, u64, u64), u64>,
    physical: BTreeMap<(u64, u64), u64>,
    grants: BTreeSet<(u64, u64, u64)>,
    aliases: u64,
    peer_grants: u64,
}
impl PrivateAnonymousWitness {
    pub(crate) fn record_settled(
        &mut self,
        grant: SettledPrivateGrant<'_>,
    ) -> Result<(), carrick_hal::TrapError> {
        use carrick_guest_arch::{FrameGpa, UserVa};
        use carrick_mmu_core::x86::descriptor_txn::{
            ADDRESS, COW, DescriptorOp, PAGE, PREPARED, PRESENT, PRIVATE, RETIRED,
            read_terminal_descriptor,
        };
        let fail = |message: &str| carrick_hal::TrapError::Hypervisor(message.to_owned());
        let mm = grant.context.mm.raw();
        if grant.memory.is_quarantined()
            || grant.memory.root(mm) != Some(grant.context)
            || grant.binding.mm.raw() != mm.get()
            || grant.binding.task.raw() == 0
            || self.carrier.is_some_and(|id| id != grant.memory.identity())
            || grant.window.operation.carrier != grant.memory.identity().nonzero()
            || grant.window.operation.mm.raw() != mm.get()
            || grant.window.operation.incarnation != grant.context.generation.raw()
            || !grant.window.valid()
            || grant.window.host_backing.is_some()
        {
            return Err(fail("private witness caller/context mismatch"));
        }
        let leaves = carrick_mmu_core::x86::owner_mmu::X86Mmu::project_grant(
            grant.txn.root.raw(),
            grant.txn,
            |txn| {
                if txn.root != grant.context.root
                    || txn.id.mm_key != mm
                    || txn.id.generation != grant.window.operation.sequence
                    || !grant.publication.matches_x86_txn(txn)
                {
                    return Err(fail("private witness receipt mismatch"));
                }
                let DescriptorOp::Prepare {
                    span,
                    output,
                    permissions,
                    backing,
                    ..
                } = txn.op
                else {
                    return Err(fail("private witness requires anonymous prepare"));
                };
                if !permissions.user
                    || span.va != grant.window.range.start()
                    || span.len != grant.window.range.len()
                    || !span.len.is_multiple_of(PAGE)
                {
                    return Err(fail("private witness grant span mismatch"));
                }
                let inventory = grant.inventory.bind(grant.context.mm);
                let length = std::num::NonZeroU64::new(span.len)
                    .ok_or_else(|| fail("private witness empty grant"))?;
                if !inventory.mapping_is_live_exact_generation(
                    carrick_hal::MappingId::from_kernel_allocation(backing.mapping_id),
                    carrick_hal::FrameId::from_kernel_allocation(backing.frame_id),
                    carrick_hal::MappingGeneration::from_backend_counter(backing.owner_generation),
                    carrick_guest_mem::Gpa(output.raw()),
                    carrick_hal::FrameLength::from_mapping_extent(length),
                ) {
                    return Err(fail("private witness inventory not settled"));
                }
                let mut leaves = Vec::with_capacity((span.len / PAGE) as usize);
                for offset in (0..span.len).step_by(PAGE as usize) {
                    let va = span
                        .va
                        .checked_add(offset)
                        .ok_or_else(|| fail("private witness VA overflow"))?;
                    let pa = output
                        .raw()
                        .checked_add(offset)
                        .ok_or_else(|| fail("private witness PA overflow"))?;
                    let (entry, size) =
                        read_terminal_descriptor(&grant.memory.words(), txn.root, UserVa::new(va))
                            .map_err(|_| fail("private witness terminal unavailable"))?;
                    if size != PAGE
                        || entry & PRIVATE == 0
                        || entry & (PRESENT | PREPARED) == 0
                        || entry & (RETIRED | COW) != 0
                        || entry & ADDRESS != pa
                        || grant
                            .memory
                            .frame_identity(mm, FrameGpa::new(pa))
                            .map_err(|_| fail("private witness frame unavailable"))?
                            != backing
                    {
                        return Err(fail("private witness terminal/backing mismatch"));
                    }
                    leaves.push((va, pa, backing.frame_id.get()));
                }
                Ok(leaves)
            },
        )
        .map_err(|_| fail("private witness projection refused"))??;
        self.record(
            grant.cpu,
            (
                mm.get(),
                grant.context.root.address().raw(),
                grant.context.generation.raw().get(),
                grant.window.generation.raw(),
            ),
            grant.window.operation.sequence.get(),
            &leaves,
            grant.peer,
        )
        .map_err(fail)?;
        self.carrier = Some(grant.memory.identity());
        Ok(())
    }
    fn record(
        &mut self,
        cpu: CpuId,
        key: (u64, u64, u64, u64),
        sequence: u64,
        leaves: &[(u64, u64, u64)],
        peer: PeerActivity,
    ) -> Result<(), &'static str> {
        let cpu_mask = 1_u64
            .checked_shl(cpu.raw())
            .ok_or("private witness CPU mask exhausted")?;
        if leaves.iter().any(|&(_, pa, frame)| {
            self.physical
                .get(&(pa, frame))
                .is_some_and(|&mm| mm != key.0)
        }) {
            self.aliases = self
                .aliases
                .checked_add(1)
                .ok_or("private alias counter overflow")?;
            return Err("cross-MM PRIVATE physical alias");
        }
        let operation = (key.0, key.2, sequence);
        let first = !self.grants.contains(&operation);
        let peers = if first && peer.0 {
            self.peer_grants
                .checked_add(1)
                .ok_or("private peer counter overflow")?
        } else {
            self.peer_grants
        };
        for &(va, pa, frame) in leaves {
            self.rows.entry(key).or_default().insert(va);
            self.physical.insert((pa, frame), key.0);
        }
        self.cpu_masks
            .entry(key)
            .and_modify(|mask| *mask |= cpu_mask)
            .or_insert(cpu_mask);
        self.grants.insert(operation);
        self.peer_grants = peers;
        Ok(())
    }
    pub(crate) fn rows(&self) -> Vec<PrivateAnonymousMmEvidence> {
        self.rows
            .iter()
            .map(
                |(&(mm, root, incarnation, generation), pages)| PrivateAnonymousMmEvidence {
                    mm,
                    root,
                    incarnation,
                    generation,
                    private_pages: pages.len() as u64,
                    cpu_mask: self
                        .cpu_masks
                        .get(&(mm, root, incarnation, generation))
                        .copied()
                        .unwrap_or(0),
                },
            )
            .collect()
    }
    /// Count authenticated anonymous leaves, excluding other physical loans
    /// such as an inherited process-entry stack's COW replacement.
    pub(crate) fn private_pages(&self) -> u64 {
        self.rows.values().map(|pages| pages.len() as u64).sum()
    }
    pub(crate) fn cross_mm_private_aliases(&self) -> u64 {
        self.aliases
    }
    pub(crate) fn peer_active_private_grants(&self) -> u64 {
        self.peer_grants
    }
}

impl crate::cpl0_boot::Cpl0Carrier {
    pub fn anonymous_private_mms(&self) -> Vec<PrivateAnonymousMmEvidence> {
        self.custody.private_anonymous_witness.rows()
    }
    pub fn cross_mm_private_aliases(&self) -> u64 {
        self.custody
            .private_anonymous_witness
            .cross_mm_private_aliases()
    }
    pub fn peer_active_private_grants(&self) -> u64 {
        self.custody
            .private_anonymous_witness
            .peer_active_private_grants()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn private_mm_cpu_evidence_uses_each_actual_settled_caller() {
        let mut witness = PrivateAnonymousWitness::default();
        witness
            .record(
                CpuId::new(0),
                (7, 0x1000, 1, 4),
                1,
                &[(0x8000, 0x20000, 19)],
                PeerActivity(false),
            )
            .unwrap();
        witness
            .record(
                CpuId::new(1),
                (8, 0x3000, 1, 4),
                2,
                &[(0x8000, 0x24000, 20)],
                PeerActivity(true),
            )
            .unwrap();
        assert_eq!(
            witness
                .rows()
                .iter()
                .map(|row| row.cpu_mask)
                .collect::<Vec<_>>(),
            [1, 2]
        );
    }

    #[test]
    fn cpu_evidence_accumulates_real_migration_without_duplicating_pages() {
        let mut witness = PrivateAnonymousWitness::default();
        let key = (7, 0x1000, 1, 4);
        let leaves = [(0x8000, 0x20000, 19)];
        witness
            .record(CpuId::new(0), key, 1, &leaves, PeerActivity(false))
            .unwrap();
        witness
            .record(CpuId::new(1), key, 2, &leaves, PeerActivity(false))
            .unwrap();
        assert_eq!(witness.rows()[0].cpu_mask, 3);
        assert_eq!(witness.rows()[0].private_pages, 1);
        assert_eq!(witness.private_pages(), 1);
        assert_eq!(witness.peer_active_private_grants(), 0);
    }

    #[test]
    fn an_unrepresentable_cpu_cannot_publish_partial_evidence() {
        let mut witness = PrivateAnonymousWitness::default();
        assert!(
            witness
                .record(
                    CpuId::new(64),
                    (7, 0x1000, 1, 4),
                    1,
                    &[(0x8000, 0x20000, 19)],
                    PeerActivity(true)
                )
                .is_err()
        );
        assert!(witness.rows().is_empty());
        assert_eq!(witness.peer_active_private_grants(), 0);
    }

    #[test]
    fn actual_peer_samples_and_repeated_settlement_count_one_grant() {
        let actual = AtomicU32::new(0);
        let selected = PeerActivity::observe(&actual);
        actual.store(1, Ordering::Release);
        let settled = PeerActivity::observe(&actual);
        let mut witness = PrivateAnonymousWitness::default();
        let key = (7, 0x1000, 1, 4);
        let leaves = [(0x8000, 0x20000, 19)];
        witness
            .record(CpuId::new(0), key, 1, &leaves, selected.combine(settled))
            .unwrap();
        witness
            .record(CpuId::new(0), key, 1, &leaves, settled)
            .unwrap();
        assert_eq!(witness.rows()[0].private_pages, 1);
        assert_eq!(witness.private_pages(), 1);
        assert_eq!(witness.peer_active_private_grants(), 1);
    }

    #[test]
    fn two_mms_same_va_retain_distinct_private_physical_proof() {
        let mut witness = PrivateAnonymousWitness::default();
        witness
            .record(
                CpuId::new(0),
                (7, 0x1000, 1, 4),
                1,
                &[(0x8000, 0x20000, 19)],
                PeerActivity(false),
            )
            .unwrap();
        witness
            .record(
                CpuId::new(0),
                (8, 0x3000, 1, 4),
                2,
                &[(0x8000, 0x24000, 20)],
                PeerActivity(true),
            )
            .unwrap();
        assert_eq!(witness.rows().len(), 2);
        assert_eq!(
            witness.rows().iter().map(|r| r.private_pages).sum::<u64>(),
            2
        );
        assert_eq!(witness.cross_mm_private_aliases(), 0);
        assert_eq!(witness.peer_active_private_grants(), 1);
    }
    #[test]
    fn duplicate_physical_frame_across_mms_is_rejected_without_partial_row() {
        let mut witness = PrivateAnonymousWitness::default();
        witness
            .record(
                CpuId::new(0),
                (7, 0x1000, 1, 4),
                1,
                &[(0x8000, 0x20000, 19)],
                PeerActivity(false),
            )
            .unwrap();
        assert!(
            witness
                .record(
                    CpuId::new(0),
                    (8, 0x3000, 1, 4),
                    2,
                    &[(0x9000, 0x24000, 20), (0x8000, 0x20000, 19)],
                    PeerActivity(true)
                )
                .is_err()
        );
        assert_eq!(witness.rows().len(), 1);
        assert_eq!(witness.cross_mm_private_aliases(), 1);
        assert_eq!(witness.peer_active_private_grants(), 0);
    }
    #[test]
    fn physical_address_reuse_with_new_frame_identity_is_not_aliasing() {
        let mut witness = PrivateAnonymousWitness::default();
        witness
            .record(
                CpuId::new(0),
                (7, 0x1000, 1, 4),
                1,
                &[(0x8000, 0x20000, 19)],
                PeerActivity(false),
            )
            .unwrap();
        witness
            .record(
                CpuId::new(0),
                (8, 0x3000, 1, 4),
                2,
                &[(0x8000, 0x20000, 21)],
                PeerActivity(false),
            )
            .unwrap();
        assert_eq!(witness.rows().len(), 2);
    }
}
