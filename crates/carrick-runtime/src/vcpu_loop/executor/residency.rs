//! Lazy vCPU register residency tracking and materialization authority for HVPatch executors.

use crate::trap::TrapError;
use carrick_hal::threaded::GuestCpuState;
use carrick_kernel::kernel::objects::ExecutorId;

/// Typed residency generation counter for a persistent executor vCPU.
///
/// Bumping this generation invalidates any previous resident tokens held by
/// tasks that ran on this vCPU.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct ResidencyGeneration(u64);

impl ResidencyGeneration {
    pub const INITIAL: Self = Self(1);

    pub const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    pub const fn raw(self) -> u64 {
        self.0
    }

    pub fn next(self) -> Self {
        Self(self.0.wrapping_add(1).max(1))
    }
}

/// The authoritative register residency of a parked task.
///
/// A task is either `Materialized` with an exact architectural [`GuestCpuState`],
/// or `Resident` on an executor's vCPU with an exact [`ResidencyGeneration`].
///
/// Under the "rule in a comment is a bug" standard, this enum has no method
/// returning registers directly from `Resident`; consumers that need registers
/// must go through the typed accessor (`materialize` / `materialize_with`), which
/// requests materialization from the owning executor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TaskCpuResidency {
    Materialized(GuestCpuState),
    Resident {
        executor: ExecutorId,
        generation: ResidencyGeneration,
    },
    /// Parked in the in-guest zone: the EL0 registers are in the zone
    /// record, which the host owns by the time the task is loaded (its
    /// handback made it runnable). The loader combines them with `base`.
    Zone {
        base: GuestCpuState,
        record: carrick_el1_abi::RecordRef,
    },
}

impl TaskCpuResidency {
    pub fn is_resident_on(&self, executor: ExecutorId, generation: ResidencyGeneration) -> bool {
        match self {
            Self::Resident {
                executor: resident_executor,
                generation: resident_generation,
            } => *resident_executor == executor && *resident_generation == generation,
            Self::Materialized(_) | Self::Zone { .. } => false,
        }
    }

    pub fn resident_authority(&self) -> Option<(ExecutorId, ResidencyGeneration)> {
        match self {
            Self::Resident {
                executor,
                generation,
            } => Some((*executor, *generation)),
            Self::Materialized(_) | Self::Zone { .. } => None,
        }
    }

    pub fn as_materialized(&self) -> Option<&GuestCpuState> {
        match self {
            Self::Materialized(cpu) => Some(cpu),
            Self::Resident { .. } | Self::Zone { .. } => None,
        }
    }

    /// Obtain the materialized CPU state through the typed accessor.
    ///
    /// If currently resident, forces snapshot through `materialize`, transitions
    /// self to `Materialized`, and returns a reference to the registers.
    pub fn materialize_with(
        &mut self,
        materialize: impl FnOnce(ExecutorId, ResidencyGeneration) -> Result<GuestCpuState, TrapError>,
    ) -> Result<&GuestCpuState, TrapError> {
        if let Self::Zone { base, record } = self {
            let cpu = materialize_zone(base, *record)?;
            *self = Self::Materialized(cpu);
        }
        match self {
            Self::Zone { .. } => unreachable!("zone residency materialized above"),
            Self::Materialized(cpu) => Ok(cpu),
            Self::Resident {
                executor,
                generation,
            } => {
                let cpu = materialize(*executor, *generation)?;
                *self = Self::Materialized(cpu);
                match self {
                    Self::Materialized(cpu) => Ok(cpu),
                    Self::Resident { .. } | Self::Zone { .. } => unreachable!(),
                }
            }
        }
    }
}

/// Combine a zone-parked task's invariant state with the EL0 context in its
/// zone record, into the state a loader overlays: the task resumes directly
/// at EL0 (the record's PC and PSTATE), with no syscall pending, exactly as a
/// task preempted at EL0 does. The record must be host-owned (the task's
/// handback made it runnable); a record EL1 still owns is refused.
pub(crate) fn materialize_zone(
    base: &GuestCpuState,
    record: carrick_el1_abi::RecordRef,
) -> Result<GuestCpuState, TrapError> {
    let GuestCpuState::Aarch64V1(base) = base else {
        return Err(TrapError::Hypervisor(
            "zone residency on a non-AArch64 task".to_owned(),
        ));
    };
    let zone = carrick_el1_abi::zone_tables()
        .ok_or_else(|| TrapError::Hypervisor("zone residency without zone tables".to_owned()))?;
    let rec = zone
        .live(record)
        .ok_or_else(|| TrapError::Hypervisor(format!("zone record {record:?} is gone")))?;
    if !matches!(rec.claim(), carrick_el1_abi::Claim::Host { .. }) {
        return Err(TrapError::Hypervisor(format!(
            "zone record {record:?} is not host-owned: {:?}",
            rec.claim()
        )));
    }
    // SAFETY: the host owns the record (checked above); its context is
    // frozen until the loader frees it.
    let ctx = unsafe { *rec.ctx_mut() };
    let mut state = (**base).clone();
    state.gprs = ctx.x;
    state.pc = ctx.pc;
    state.pstate = ctx.pstate;
    state.trap_pc = ctx.pc;
    state.trap_pstate = ctx.pstate;
    state.elr_el1 = ctx.pc;
    state.spsr_el1 = ctx.pstate;
    state.sp_el0 = ctx.sp_el0;
    state.tpidr_el0 = ctx.tpidr_el0;
    state.tpidrro_el0 = ctx.tpidrro_el0;
    state.contextidr_el1 = ctx.contextidr_el1;
    state.vregs = ctx.v;
    state.fpsr = ctx.fpsr as u32;
    state.fpcr = ctx.fpcr as u32;
    state.pending_resume_pc = None;
    state.last_syscall_nr = None;
    state.last_syscall_orig_x0 = 0;
    state.last_fault_esr = 0;
    state.syscall_continuation = None;
    Ok(GuestCpuState::from_aarch64_v1(state))
}
