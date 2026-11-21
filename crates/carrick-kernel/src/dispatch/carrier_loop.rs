//! Shared host-carrier stage-1 alias publication and first-touch + stale-leaf
//! fault resolution.
//!
//! Moved out of the HVPatch vCPU run loop (`carrick-runtime`) so every carrier
//! lane (HVF/KVM runtime, the soft AArch64 runner) commits alias frame
//! inventory and resolves first-touch/stale-stage-1 faults through one path.

use carrick_abi::LinuxProtFlags;
use carrick_guest_mem::{Gpa, GuestVa, MappingSharing, MemoryError};
use carrick_hal::{
    FrameEventCapacity, FrameInventoryCommit, HostAliasBacking, ThreadedEngine, TrapError,
};
use carrick_mmu_core::aarch64::{LeafAccess, Stage1FaultKind};

use crate::dispatch::host_alias::{HostAliasInstallGuard, HostAliasTransaction};
use crate::dispatch::mem::ReservationBusy;
use crate::dispatch::mm_mutation::MmMutationGuard;
use crate::dispatch::{DispatchOutcome, SyscallDispatcher};
use crate::kernel::debug::HvpatchAliasInstallSite;
use crate::kernel::{FrameInventoryError, KernelContext};
use crate::linux_abi::{
    LINUX_ENOMEM, LINUX_PAGE_SIZE, LINUX_PROT_EXEC, LINUX_PROT_READ, LINUX_PROT_WRITE,
};

/// Publish a backend-staged alias [`FrameInventoryCommit`] to the kernel's
/// authoritative [`crate::kernel::FrameInventoryAuthority`] for `context`'s MM.
pub fn apply_alias_frame_inventory(
    context: &KernelContext,
    commit: FrameInventoryCommit<()>,
) -> Result<(), FrameInventoryError> {
    context
        .kernel()
        .frame_inventory()
        .apply(context.shared().mm().id(), commit)
        .map(|_| ())
}

/// Structured failure from [`finish_host_alias_stage1_install`] after stage-2
/// alias publication has already committed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AliasStage1InstallFailure {
    pub site: HvpatchAliasInstallSite,
    pub message: String,
}

/// Complete post-inventory stage-1 protection, sharing, `SIGBUS` tail arming,
/// and dispatcher VMA commit for an installed host alias mapping.
#[allow(clippy::too_many_arguments)]
pub fn finish_host_alias_stage1_install<E: ThreadedEngine>(
    engine: &mut E,
    dispatcher: &SyscallDispatcher,
    install: HostAliasInstallGuard<'_>,
    va: GuestVa,
    len: u64,
    prot: u64,
    prot_none: bool,
    shared: bool,
    success_retval: i64,
) -> Result<DispatchOutcome, AliasStage1InstallFailure> {
    use HvpatchAliasInstallSite as Site;

    let Ok(len_bytes) = usize::try_from(len) else {
        return Err(AliasStage1InstallFailure {
            site: Site::LenOverflow,
            message: "range length does not fit usize".to_owned(),
        });
    };
    // Backends publish aliases read-only or read/write and never executable;
    // `PROT_NONE` and `PROT_EXEC` are applied on stage-1 before the guest sees
    // the mapping.
    let prot_flags = LinuxProtFlags::from_bits_truncate(prot);
    let exec = prot_flags.contains(LinuxProtFlags::EXEC);
    if (prot_none || exec)
        && let Err(error) =
            engine.protect_range(va.raw(), len_bytes, if prot_none { 0 } else { prot })
    {
        return Err(AliasStage1InstallFailure {
            site: Site::ProtectNone,
            message: error.to_string(),
        });
    }
    engine.set_mapping_protection_and_sharing(
        va.raw(),
        len_bytes,
        prot_none,
        !prot_flags.contains(LinuxProtFlags::WRITE),
        if shared {
            MappingSharing::Shared
        } else {
            MappingSharing::Private
        },
    );
    if let Some((bus_start, bus_len)) = install.bus_fault_range() {
        let Ok(bus_len) = usize::try_from(bus_len) else {
            return Err(AliasStage1InstallFailure {
                site: Site::BusFaultLenOverflow,
                message: format!("bus-fault tail length {bus_len:#x} does not fit usize"),
            });
        };
        if let Err(error) = engine.protect_range(bus_start, bus_len, 0) {
            return Err(AliasStage1InstallFailure {
                site: Site::BusFaultProtect,
                message: format!("bus-fault tail {bus_start:#x}+{bus_len:#x}: {error}"),
            });
        }
        engine.set_no_access(bus_start, bus_len, true);
    }
    if let Err(error) = dispatcher.commit_host_alias_install(install) {
        return Err(AliasStage1InstallFailure {
            site: Site::DispatcherCommit,
            message: format!("{error:?}"),
        });
    }
    Ok(DispatchOutcome::Returned {
        value: success_retval,
    })
}

/// Reserve frame inventory, install a host alias through `engine`, apply its
/// [`FrameInventoryCommit`] to `context`'s kernel authority, and finish the
/// stage-1 protection/VMA commit under `dispatcher`'s MM mutation lease.
#[allow(clippy::too_many_arguments)]
pub fn install_host_alias_with_inventory<E: ThreadedEngine>(
    engine: &mut E,
    dispatcher: &mut SyscallDispatcher,
    context: &KernelContext,
    transaction: HostAliasTransaction,
    va: GuestVa,
    ipa: Gpa,
    len: u64,
    payload: &[u8],
    backing: HostAliasBacking,
    prot: u64,
    prot_none: bool,
    success_retval: i64,
) -> Result<i64, String> {
    let shared = backing.is_shared();
    dispatcher
        .with_mm_executor_mutation(|disp, mutation| -> Result<i64, String> {
            let permit = mutation.host_alias_permit();
            let Some(install) = transaction.claim(&permit) else {
                drop(backing);
                return Ok(LINUX_ENOMEM.guest_retval());
            };
            let capacity = FrameEventCapacity::for_event_count(2)
                .map_err(|e| format!("alias frame event capacity: {e}"))?;
            let reservation = context
                .kernel()
                .reserve_frame_inventory(1, 1, capacity)
                .map_err(|e| format!("reserve alias frame inventory: {e}"))?;
            let inventory_transaction = reservation.transaction();
            if let Err(error) = engine.begin_alias_inventory(reservation) {
                let _ = context
                    .kernel()
                    .frame_inventory()
                    .abandon(inventory_transaction);
                return Err(format!("begin_alias_inventory: {error}"));
            }
            if let Err(_error) = engine.map_host_alias(va, ipa, len, payload, backing) {
                engine.abandon_alias_inventory();
                let _ = context
                    .kernel()
                    .frame_inventory()
                    .abandon(inventory_transaction);
                drop(install);
                return Ok(LINUX_ENOMEM.guest_retval());
            }
            let Some(commit) = engine.take_alias_inventory() else {
                return Err("backend staged no alias inventory commit".to_owned());
            };
            apply_alias_frame_inventory(context, commit).map_err(|error| {
                format!(
                    "apply_alias_frame_inventory(frame={:?}): {error}",
                    error.frame()
                )
            })?;
            match finish_host_alias_stage1_install(
                engine,
                disp,
                install,
                va,
                len,
                prot,
                prot_none,
                shared,
                success_retval,
            ) {
                Ok(DispatchOutcome::Returned { value }) => Ok(value),
                Ok(other) => Err(format!("unexpected alias install outcome: {other:?}")),
                Err(failure) => Err(format!(
                    "alias stage-1 install failed at {:?}: {}",
                    failure.site, failure.message
                )),
            }
        })
        .map_err(|e| format!("MM executor mutation for MapHostAlias: {e}"))?
}

/// Apply Linux stage-1 first-touch permission rules: any accessible leaf in
/// Carrick's lowering satisfies a read fault; write and execute require their
/// respective permission bits.
pub fn apply_first_touch(
    prot: u64,
    access: Option<LeafAccess>,
    protect: impl FnOnce() -> bool,
    commit: impl FnOnce(),
) -> Option<bool> {
    let required = match access {
        Some(LeafAccess::Read) => LINUX_PROT_READ | LINUX_PROT_WRITE | LINUX_PROT_EXEC,
        Some(LeafAccess::Write) => LINUX_PROT_WRITE,
        Some(LeafAccess::Execute) => LINUX_PROT_EXEC,
        None => return Some(false),
    };
    if prot & required == 0 {
        return Some(false);
    }
    if !protect() {
        return None;
    }
    commit();
    Some(true)
}

/// Resident-fault sub-step result inside [`HostFirstTouchStep`].
#[derive(Debug)]
pub enum HostResidentAttempt {
    NotReached,
    NoPlan,
    Committed,
    ArmingDenied,
    BackendRefused {
        page: u64,
        prot: u64,
        error: MemoryError,
    },
}

/// `MAP_GROWSDOWN` sub-step result inside [`HostFirstTouchStep`].
#[derive(Debug)]
pub enum HostGrowdownAttempt {
    NotReached,
    NoPlan,
    Committed,
    ProtectFailed { start: u64, error: MemoryError },
}

/// Stale stage-1 leaf retry sub-step result inside [`HostFirstTouchStep`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostStaleAttempt {
    NotReached,
    AccessUnknown,
    Retried,
    NotRetried,
}

/// Combined outcome of one host first-touch + `MAP_GROWSDOWN` + stale-stage-1
/// fault-resolution attempt under an outer [`MmMutationGuard`].
#[derive(Debug)]
pub struct HostFirstTouchStep {
    pub resolved: bool,
    pub resident: HostResidentAttempt,
    pub growdown: HostGrowdownAttempt,
    pub stale: HostStaleAttempt,
}

/// Run one host-side resident first-touch, `MAP_GROWSDOWN`, and stale-stage-1
/// leaf retry pass under `mutation`. Returns `Ok(Err(busy))` on
/// [`ReservationBusy`] so the caller releases `mutation`, enrols on the
/// holder's release, probes once, and reruns.
pub fn resolve_host_first_touch_or_stale<E: ThreadedEngine>(
    dispatcher: &SyscallDispatcher,
    engine: &mut E,
    mutation: &MmMutationGuard<'_>,
    address: u64,
    access: Option<LeafAccess>,
    fault_kind: Option<Stage1FaultKind>,
) -> Result<Result<HostFirstTouchStep, ReservationBusy>, TrapError> {
    let mut step = HostFirstTouchStep {
        resolved: false,
        resident: HostResidentAttempt::NotReached,
        growdown: HostGrowdownAttempt::NotReached,
        stale: HostStaleAttempt::NotReached,
    };

    {
        let permit = mutation.host_alias_permit();
        let plan = match dispatcher.resident_fault_plan(&permit, address) {
            Ok(plan) => plan,
            Err(busy) => return Ok(Err(busy)),
        };
        if let Some(plan) = plan {
            let page = plan.page();
            let prot = plan.prot();
            let mut backend_error = None;
            match apply_first_touch(
                prot,
                access,
                || match engine.protect_range(page, LINUX_PAGE_SIZE as usize, prot) {
                    Ok(()) => true,
                    Err(err) => {
                        backend_error = Some(err);
                        false
                    }
                },
                || dispatcher.commit_resident_fault(plan),
            ) {
                Some(true) => {
                    step.resolved = true;
                    step.resident = HostResidentAttempt::Committed;
                    return Ok(Ok(step));
                }
                Some(false) => {
                    step.resident = HostResidentAttempt::ArmingDenied;
                    return Ok(Ok(step));
                }
                None => {
                    step.resident = HostResidentAttempt::BackendRefused {
                        page,
                        prot,
                        error: backend_error.unwrap_or_else(|| {
                            MemoryError::HostMap("protect_range refused resident fault".to_owned())
                        }),
                    };
                }
            }
        } else {
            step.resident = HostResidentAttempt::NoPlan;
        }
    }

    {
        let permit = mutation.host_alias_permit();
        step.growdown = match dispatcher.mmap_growdown_fault_plan(&permit, address) {
            None => HostGrowdownAttempt::NoPlan,
            Some(plan) => {
                let start = plan.start();
                let len = plan.len();
                match engine.protect_range(start, len, LINUX_PROT_READ | LINUX_PROT_WRITE) {
                    Ok(()) => {
                        dispatcher.commit_mmap_growdown(plan);
                        step.resolved = true;
                        step.growdown = HostGrowdownAttempt::Committed;
                        return Ok(Ok(step));
                    }
                    Err(error) => HostGrowdownAttempt::ProtectFailed { start, error },
                }
            }
        };
    }

    let (Some(access), Some(fault_kind)) = (access, fault_kind) else {
        step.stale = HostStaleAttempt::AccessUnknown;
        return Ok(Ok(step));
    };
    let retried = engine.resolve_stale_stage1_fault(address, access, fault_kind)?;
    step.resolved = retried;
    step.stale = if retried {
        HostStaleAttempt::Retried
    } else {
        HostStaleAttempt::NotRetried
    };
    Ok(Ok(step))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_first_touch_enforces_linux_stage1_access_matrix() {
        let mut committed = false;
        assert_eq!(
            apply_first_touch(
                LINUX_PROT_WRITE,
                Some(LeafAccess::Read),
                || true,
                || committed = true
            ),
            Some(true)
        );
        assert!(committed);

        assert_eq!(
            apply_first_touch(LINUX_PROT_READ, Some(LeafAccess::Write), || true, || {}),
            Some(false)
        );
        assert_eq!(
            apply_first_touch(
                LINUX_PROT_READ | LINUX_PROT_WRITE,
                Some(LeafAccess::Execute),
                || true,
                || {}
            ),
            Some(false)
        );
        assert_eq!(
            apply_first_touch(LINUX_PROT_READ, None, || true, || {}),
            Some(false)
        );
        assert_eq!(
            apply_first_touch(LINUX_PROT_WRITE, Some(LeafAccess::Write), || false, || {}),
            None
        );
    }
}
