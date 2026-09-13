//! Lazy vCPU register residency tracking and materialization authority for HVPatch executors.

use crate::kernel::objects::ExecutorId;
use crate::trap::TrapError;
use carrick_hal::threaded::GuestCpuState;

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
}

impl TaskCpuResidency {
    pub fn is_resident_on(&self, executor: ExecutorId, generation: ResidencyGeneration) -> bool {
        match self {
            Self::Resident {
                executor: resident_executor,
                generation: resident_generation,
            } => *resident_executor == executor && *resident_generation == generation,
            Self::Materialized(_) => false,
        }
    }

    pub fn resident_authority(&self) -> Option<(ExecutorId, ResidencyGeneration)> {
        match self {
            Self::Resident {
                executor,
                generation,
            } => Some((*executor, *generation)),
            Self::Materialized(_) => None,
        }
    }

    pub fn as_materialized(&self) -> Option<&GuestCpuState> {
        match self {
            Self::Materialized(cpu) => Some(cpu),
            Self::Resident { .. } => None,
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
        match self {
            Self::Materialized(cpu) => Ok(cpu),
            Self::Resident {
                executor,
                generation,
            } => {
                let cpu = materialize(*executor, *generation)?;
                *self = Self::Materialized(cpu);
                match self {
                    Self::Materialized(cpu) => Ok(cpu),
                    Self::Resident { .. } => unreachable!(),
                }
            }
        }
    }
}

/// The authoritative typed accessor for obtaining materialized CPU register state.
///
/// Any consumer that needs the register file — a claim by a different executor,
/// fork/clone/vfork child construction, exec, signal delivery/sigframe construction,
/// ptrace, crash capture, kernel-debug snapshot, executor destroy — must obtain a
/// materialized state through this accessor. No path may read a `Resident` token
/// as if it were registers.
#[allow(dead_code)]
pub(crate) fn materialize_task_state<E: crate::vcpu_loop::executor::backend::PersistentExecutor>(
    residency: &mut TaskCpuResidency,
    executor: &mut E,
) -> Result<GuestCpuState, TrapError> {
    match residency {
        TaskCpuResidency::Materialized(cpu) => Ok(cpu.clone()),
        TaskCpuResidency::Resident {
            executor: _,
            generation,
        } => {
            let cpu = executor.snapshot_resident_task(*generation)?;
            *residency = TaskCpuResidency::Materialized(cpu.clone());
            Ok(cpu)
        }
    }
}
