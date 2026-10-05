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

/// Restore a zone-parked task after its exact record returns to the host.
/// Guest operations resume from the record's EL0 context. A host-owned
/// operation only received a notification: its original syscall snapshot
/// remains authoritative until the host completes that operation.
pub(crate) fn materialize_zone(
    base: &GuestCpuState,
    record: carrick_el1_abi::RecordRef,
) -> Result<GuestCpuState, TrapError> {
    let zone = carrick_el1_abi::zone_tables()
        .ok_or_else(|| TrapError::Hypervisor("zone residency without zone tables".to_owned()))?;
    materialize_zone_in(zone, base, record)
}

fn materialize_zone_in(
    zone: &carrick_sched_core::ZoneTables,
    base: &GuestCpuState,
    record: carrick_el1_abi::RecordRef,
) -> Result<GuestCpuState, TrapError> {
    let GuestCpuState::Aarch64V1(base) = base else {
        return Err(TrapError::Hypervisor(
            "zone residency on a non-AArch64 task".to_owned(),
        ));
    };
    let rec = zone
        .live(record)
        .ok_or_else(|| TrapError::Hypervisor(format!("zone record {record:?} is gone")))?;
    if !matches!(rec.claim(), carrick_el1_abi::Claim::Host { .. }) {
        return Err(TrapError::Hypervisor(format!(
            "zone record {record:?} is not host-owned: {:?}",
            rec.claim()
        )));
    }
    if rec.object_host_continuation() {
        if !rec.has_object_operation() || base.syscall_continuation.is_none() {
            return Err(TrapError::Hypervisor(
                "host-owned zone wait lost its operation or syscall continuation".to_owned(),
            ));
        }
        // park_host_rechecked excludes guest execution of this operation.
        // Its record is a wake receipt, not a completed EL0 syscall frame.
        // In particular, preserve the mailbox request across repeated owner
        // waits and executor migration so only complete_returned consumes it.
        return Ok(GuestCpuState::Aarch64V1(base.clone()));
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

#[cfg(test)]
mod tests {
    use super::*;
    use carrick_hal::threaded::Aarch64SyscallContinuationV1;
    use carrick_sched_core::object_wait::{ObjectWaitKey, OperationToken, OwnedObjectWakeEffects};
    use carrick_sched_core::{BoundedSpin, ThreadIdentity, Waker, ZoneTables};
    use std::cell::RefCell;

    fn zone() -> Box<ZoneTables> {
        // SAFETY: the shared zone ABI has an all-zero initial state. Heap
        // allocation avoids placing the complete carrier tables on the stack.
        unsafe {
            let raw = std::alloc::alloc_zeroed(std::alloc::Layout::new::<ZoneTables>());
            assert!(!raw.is_null());
            Box::from_raw(raw.cast())
        }
    }

    fn pending_read() -> GuestCpuState {
        let GuestCpuState::Aarch64V1(cpu) =
            crate::vcpu_loop::executor::tests::test_guest_cpu_state(0x100)
        else {
            panic!("AArch64 fixture");
        };
        let mut cpu = (*cpu).clone();
        cpu.trap_pc = 0x8000;
        cpu.trap_pstate = 0x3c5;
        cpu.pending_resume_pc = Some(0x4004);
        cpu.last_syscall_nr = Some(63);
        cpu.last_syscall_orig_x0 = 7;
        cpu.syscall_continuation = Some(Aarch64SyscallContinuationV1 {
            sequence: 73,
            state: 1,
            trap_kind: 1,
            response_action: 0,
            flags: 0,
            native_nr: 63,
            args: [7, 0x6000, 0x2000, 0, 0, 0],
            x8: 63,
            resume_pc: 0x4004,
            spsr: 0,
            fp: 0x7000,
            lr: 0x4100,
            sp: 0x7100,
            esr: 0x15 << 26,
            return_value: 0,
            resume_x16: 0x1616,
            resume_x17: 0x1717,
        });
        GuestCpuState::from_aarch64_v1(cpu)
    }

    #[test]
    fn host_owned_memory_wait_keeps_syscall_through_two_wakes() {
        exercise_zone_wakes(true);
    }

    #[test]
    fn guest_zone_wait_resumes_el0_without_replaying_the_completed_syscall() {
        exercise_zone_wakes(false);
    }

    fn exercise_zone_wakes(host_owned: bool) {
        let zone = zone();
        let key = ObjectWaitKey::metadata_request(17).unwrap();
        let delivered = RefCell::new(Vec::new());
        let complete = |owned: OwnedObjectWakeEffects<'_>| {
            let (_, effects) =
                owned.deliver_handbacks(&mut |record| delivered.borrow_mut().push(record));
            assert!(!effects.queued_own);
        };
        zone.bind_object_wait_with_completion(key, &BoundedSpin(0), &complete)
            .unwrap();
        let original = pending_read();
        let mut saved = original.clone();
        for round in 0..if host_owned { 2 } else { 1 } {
            let source = zone
                .admit_object_notification(key, &BoundedSpin(0), &complete)
                .unwrap();
            let record = zone
                .alloc_record(ThreadIdentity {
                    tid: 101,
                    serial: 101,
                    mm: 1,
                    file_table: 1,
                    generation: 1,
                    affinity: 0,
                    lifecycle_page: 0,
                    control_slot: 0,
                })
                .unwrap();
            let reference = zone.record_ref(record);
            let ctx = crate::vcpu_loop::zone::zone_ctx_from_state(
                &saved,
                crate::vcpu_loop::zone::ZoneExit::Syscall { completed: true },
            )
            .expect("a repeated owner wait still owns its syscall");
            // SAFETY: this newly allocated record has not been published.
            unsafe { *zone.record(record).ctx_mut() = ctx };
            {
                let guard = zone
                    .object_wait_with_completion(key, &BoundedSpin(0), &complete)
                    .unwrap();
                let operation = OperationToken::metadata_request(17).unwrap();
                if host_owned {
                    guard.park_host_rechecked(guard.snapshot(), record, operation, || true)
                } else {
                    guard.park_rechecked(guard.snapshot(), record, operation, || true)
                }
                .unwrap();
            }
            assert!(materialize_zone_in(&zone, &saved, reference).is_err());
            source.publish(Waker::Host, &complete);
            assert_eq!(delivered.borrow_mut().pop(), Some(reference));
            saved = materialize_zone_in(&zone, &saved, reference).unwrap();
            let GuestCpuState::Aarch64V1(cpu) = &saved else {
                panic!("AArch64 restore");
            };
            if host_owned {
                assert_eq!(
                    cpu.syscall_continuation
                        .as_ref()
                        .map(|request| request.sequence),
                    Some(73),
                    "owner wake {round} must retain the original request"
                );
                assert_eq!(
                    saved, original,
                    "a host notification is not a syscall return"
                );
            } else {
                assert!(cpu.syscall_continuation.is_none());
                assert!(cpu.pending_resume_pc.is_none());
                assert!(cpu.last_syscall_nr.is_none());
                assert_eq!((cpu.trap_pc, cpu.trap_pstate), (ctx.pc, ctx.pstate));
                assert_eq!(cpu.gprs, ctx.x);
            }
            let rec = zone.record(record);
            assert_eq!(rec.object_host_continuation(), host_owned);
            // SAFETY: the completion handed this exact record to the host.
            assert_eq!(
                unsafe { rec.take_object_operation() }
                    .unwrap()
                    .metadata_generation(),
                Some(17)
            );
            // SAFETY: the same host owns the record; consuming is one-shot.
            assert!(unsafe { rec.take_object_operation() }.is_none());
            zone.free_record(record);
            assert!(materialize_zone_in(&zone, &saved, reference).is_err());
        }
    }
}
