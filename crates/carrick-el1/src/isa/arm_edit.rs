//! Pure lowering of a reviewed MM edit intent into the existing EL1 slot ABI.
//! No instruction or host-visible ARM record layout changes here.

use super::ArchError;
use carrick_guest_arch::{
    Access, EditBacking, EditCowAccess, EditIntent, EditLeafSize, EditOperation, RootGpa,
};
use carrick_mmu_core::aarch64::SubstrateGpa;
use carrick_mmu_core::aarch64::descriptor_txn::{
    AliasAccess, BackingIdentity, CowRepointAccess, DescriptorOp, DescriptorTxn, DescriptorTxnId,
    MAX_TABLE_GRANTS, PageSpan, TableGrants, TerminalEdit,
};
use carrick_mmu_core::aarch64::{GuestLeafPublication, GuestPermissionEdit, LeafAccess};

fn backing(value: EditBacking) -> BackingIdentity {
    BackingIdentity {
        frame_id: value.frame_id,
        mapping_id: value.mapping_id,
        owner_generation: value.owner_generation,
        inventory_revision: value.inventory_revision,
    }
}

/// Lower only intents the existing ARM descriptor contract can express
/// exactly. Other intents refuse before publication.
pub fn lower_edit_intent(intent: EditIntent<'_, RootGpa>) -> Result<DescriptorTxn, ArchError> {
    let owner = intent.owner();
    let range = intent.range();
    let span = PageSpan::new(range.start().raw(), range.len().raw());
    let op = match intent.operation() {
        EditOperation::Prepare {
            output,
            permissions,
            resident,
            backing: source,
        } if permissions.user && permissions.readable => DescriptorOp::Prepare {
            publication: GuestLeafPublication {
                va: span.va,
                ipa: output.raw(),
                len: span.len,
                writable: permissions.writable,
                executable: permissions.executable,
            },
            resident: PageSpan::new(resident.start().raw(), resident.len().raw()),
            backing: backing(source),
        },
        EditOperation::Map {
            output,
            permissions,
            size: EditLeafSize::Page,
            resident: true,
            backing: source,
        } if permissions.user && permissions.readable => DescriptorOp::MapAlias {
            access: AliasAccess::User {
                writable: permissions.writable,
                executable: permissions.executable,
            },
            span,
            target_ipa: SubstrateGpa(output.raw()),
            backing: backing(source),
        },
        EditOperation::Protect { permissions } if permissions.user => {
            DescriptorOp::Protect(GuestPermissionEdit {
                va: span.va,
                len: span.len,
                readable: permissions.readable,
                writable: permissions.writable,
                executable: permissions.executable,
            })
        }
        EditOperation::Publish { expected, access } => DescriptorOp::Publish {
            span,
            expected_ipa: SubstrateGpa(expected.raw()),
            access: match access {
                Access::Read => LeafAccess::Read,
                Access::Write => LeafAccess::Write,
                Access::Execute => LeafAccess::Execute,
            },
        },
        EditOperation::CowRepoint {
            old,
            new,
            backing: source,
            access,
        } => DescriptorOp::CowRepoint {
            access: match access {
                EditCowAccess::Retired => CowRepointAccess::Retired,
                EditCowAccess::RecordedPrivate => CowRepointAccess::RecordedPrivate,
                EditCowAccess::User { writable_pages } => CowRepointAccess::User { writable_pages },
                EditCowAccess::Kernel => CowRepointAccess::Kernel,
            },
            va: span.va,
            len: span.len,
            old_ipa: SubstrateGpa(old.raw()),
            new_ipa: SubstrateGpa(new.raw()),
            backing: backing(source),
        },
        EditOperation::ArmCow {
            kernel_only,
            executable,
            adopt_private,
            asid_scoped,
            excluded_ipa,
            excluded_len,
        } => DescriptorOp::Terminal {
            span,
            edit: TerminalEdit::fork_arm(
                kernel_only,
                executable,
                adopt_private,
                asid_scoped,
                excluded_ipa.raw(),
                excluded_len.raw(),
            ),
        },
        EditOperation::Unmap => DescriptorOp::Retire(span),
        _ => return Err(ArchError::Unbound),
    };
    let grants = intent.table_grants();
    if grants.len() > MAX_TABLE_GRANTS {
        return Err(ArchError::Unbound);
    }
    let mut pages = [SubstrateGpa(0); MAX_TABLE_GRANTS];
    for (page, grant) in pages.iter_mut().zip(grants) {
        *page = SubstrateGpa(grant.address().raw());
    }
    let tables = TableGrants::new(&pages[..grants.len()]).ok_or(ArchError::Unbound)?;
    Ok(DescriptorTxn {
        id: DescriptorTxnId {
            mm_key: owner.mm_key(),
            generation: owner.generation(),
        },
        root: SubstrateGpa(owner.root().address().raw()),
        op,
        tables,
    })
}

#[cfg(all(target_os = "none", target_arch = "aarch64"))]
impl carrick_guest_arch::MmuEditBackend for super::aarch64::Aarch64Backend {
    type EditReceipt = carrick_mmu_core::aarch64::descriptor_txn::DescriptorReceipt;

    unsafe fn execute_edit(
        &mut self,
        intent: EditIntent<'_, RootGpa>,
        tables: carrick_guest_arch::TableWindow,
    ) -> Result<Self::EditReceipt, Self::Error> {
        use carrick_mmu_core::aarch64::descriptor_txn::{
            DescriptorOutcome, InlineJournal, PrimaryTableWords, execute_descriptor_txn,
        };
        let txn = lower_edit_intent(intent)?;
        if tables.physical().raw() != txn.root.raw()
            || tables.bytes().raw() != carrick_el1_abi::AARCH64_STAGE1_TABLES_PRIMARY_SIZE
        {
            return Err(ArchError::Unbound);
        }
        let live = super::aarch64::hardware_live_ttbr();
        let table = carrick_el1_abi::service_target_table_window(live, txn.root.raw())
            .ok_or(ArchError::Unbound)?;
        if tables.mapped().raw() != table.words as u64 {
            return Err(ArchError::Unbound);
        }
        let maintenance = El1TableMaintenance {
            ttbr0: txn.root.raw(),
        };
        // SAFETY: the exact-MM editor and table-window requirements are
        // inherited from the trait call; the service lookup authenticated
        // this ARM primary alias against the live TTBR above.
        let words = unsafe {
            PrimaryTableWords::new(
                table.words,
                table.physical_base,
                tables.bytes().raw() as usize,
                &maintenance,
            )
            .and_then(|words| words.with_window(carrick_el1_abi::stage1_table_pool_window()))
        }
        .map_err(|_| ArchError::Unbound)?;
        let receipt = execute_descriptor_txn(&words, txn.root, &txn, &mut InlineJournal::new());
        if matches!(receipt.outcome, DescriptorOutcome::Indeterminate(_)) {
            return Err(ArchError::Busy);
        }
        Ok(receipt)
    }
}

#[cfg(all(target_os = "none", target_arch = "aarch64"))]
pub(crate) struct El1TableMaintenance {
    pub(crate) ttbr0: u64,
}

#[cfg(all(target_os = "none", target_arch = "aarch64"))]
impl carrick_mmu_core::aarch64::descriptor_txn::TableMaintenance for El1TableMaintenance {
    fn publish_barrier(&self) {
        // Complete unlinked fills and invalidate the exact live ASID before
        // a new link can be observed by another walker.
        let mut cpu = crate::substrate::sched::HardwareCpu;
        crate::substrate::sched::ThreadCpu::invalidate_asid(&mut cpu, self.ttbr0);
    }

    fn invalidate_range(&self, _va: u64, _len: u64) {
        // The whole ASID is a superset of the break-before-make range.
        let mut cpu = crate::substrate::sched::HardwareCpu;
        crate::substrate::sched::ThreadCpu::invalidate_asid(&mut cpu, self.ttbr0);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use carrick_guest_arch::{EditOwner, EditPermissions, FrameGpa, GuestLen, UserRange, UserVa};
    use core::num::NonZeroU64;

    fn intent(operation: EditOperation) -> EditIntent<'static, RootGpa> {
        let root = RootGpa::page_aligned(FrameGpa::new(0x6000)).unwrap();
        // SAFETY: this VM-free fixture uniquely owns the synthetic MM editor
        // and its operation generation until the lowering result is checked.
        let owner = unsafe { EditOwner::issue(root, NonZeroU64::MIN, NonZeroU64::MIN) };
        let range = UserRange::checked(UserVa::new(0x4000), GuestLen::new(4096)).unwrap();
        EditIntent::checked(owner, range, operation, &[]).unwrap()
    }

    #[test]
    fn protect_intent_preserves_arm_slot_semantics_and_identity() {
        let permissions = EditPermissions {
            readable: true,
            writable: false,
            executable: false,
            user: true,
        };
        let txn = lower_edit_intent(intent(EditOperation::Protect { permissions })).unwrap();
        assert_eq!(txn.root, SubstrateGpa(0x6000));
        assert_eq!(txn.id.mm_key, NonZeroU64::MIN);
        assert_eq!(txn.id.generation, NonZeroU64::MIN);
        assert_eq!(txn.tables.len(), 0);
        assert_eq!(
            txn.op,
            DescriptorOp::Protect(GuestPermissionEdit {
                va: 0x4000,
                len: 4096,
                readable: true,
                writable: false,
                executable: false,
            })
        );
    }

    #[test]
    fn unsupported_native_shape_does_not_mint_an_arm_receipt() {
        assert!(matches!(
            lower_edit_intent(intent(EditOperation::Coalesce {
                size: EditLeafSize::Block2M
            })),
            Err(ArchError::Unbound)
        ));
    }
}
