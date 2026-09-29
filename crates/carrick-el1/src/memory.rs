//! Resident private-anonymous memory operations served inside guest EL1.

#[path = "personality/reservations.rs"]
pub mod reservations;

use carrick_el1_abi::{CurrentTask, TrapFrame};
use carrick_mmu_core::aarch64::{
    GuestPermissionEdit, GuestPermissionEditError, GuestRetirementError,
};
use carrick_sched_core::AddressSpaces;
use core::num::NonZeroU64;
use core::sync::atomic::Ordering;

const SYS_BRK: u64 = 214;
const SYS_MUNMAP: u64 = 215;
const SYS_MMAP: u64 = 222;
const SYS_MPROTECT: u64 = 226;
const PROT_READ: u64 = 1;
const PROT_WRITE: u64 = 2;
const PROT_EXEC: u64 = 4;
const MAP_SHARED: u64 = 0x01;
const MAP_PRIVATE: u64 = 0x02;
const MAP_FIXED: u64 = 0x10;
const MAP_ANONYMOUS: u64 = 0x20;
const MAP_GROWSDOWN: u64 = 0x0100;
const MAP_STACK: u64 = 0x20000;
const MAP_HUGETLB: u64 = 0x40000;
const MAP_FIXED_NOREPLACE: u64 = 0x100000;

const EINVAL: i64 = 22;
const ENOMEM: i64 = 12;
const PAGE_SIZE: u64 = 4096;

/// Decision before T2's descriptor/backing service. `Work` retains the exact
/// originating frame identity; it must survive the host boundary as an owned
/// continuation, never as a request to replay the Linux syscall.
pub enum ReservationDisposition {
    Forward,
    /// Admission/capacity service; never replay on a second VMA authority.
    Unavailable(reservations::Refusal),
    Return(i64),
    Work(PendingReservationSyscall),
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct ReservationOrigin {
    task: carrick_el1_abi::El1TaskId,
    serial: NonZeroU64,
    mm: carrick_el1_abi::ReservationMm,
}
impl ReservationOrigin {
    fn capture(current: &CurrentTask) -> Option<Self> {
        let raw = current.task_id.load(Ordering::Acquire);
        let tid = i32::try_from(raw).ok().filter(|tid| *tid > 0)?;
        Some(Self {
            task: carrick_el1_abi::El1TaskId::from_linux_tid(tid),
            serial: NonZeroU64::new(current.thread_serial.load(Ordering::Acquire))?,
            mm: carrick_el1_abi::ReservationMm::new(current.zone_mm.load(Ordering::Acquire))?,
        })
    }
}

pub struct PendingReservationSyscall {
    request: carrick_el1_abi::ReservationRequest,
    origin: ReservationOrigin,
    elr: u64,
    syscall: u64,
    args: [u64; 6],
}
impl PendingReservationSyscall {
    pub fn request(&self) -> carrick_el1_abi::ReservationRequest {
        self.request
    }
    /// Complete exactly once, on the saved originating frame after T2 completed
    /// descriptors and authenticated backing. Failed authentication keeps the
    /// pending proposal intact so its owner can explicitly refuse/settle it.
    pub fn complete(
        &mut self,
        frame: &mut TrapFrame,
        current: &CurrentTask,
        counters: &carrick_el1_abi::Counters,
        model: &mut reservations::Reservations<'_>,
        completion: carrick_el1_abi::ReservationCompletion,
    ) -> Result<(), reservations::Refusal> {
        if !self.owns_frame(frame, current) || !completion.authenticates(self.request) {
            return Err(reservations::Refusal::Stale);
        }
        let result = model.complete(completion)?;
        frame.x[0] = result;
        counters.served[self.syscall as usize].fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
    fn owns_frame(&self, frame: &TrapFrame, current: &CurrentTask) -> bool {
        ReservationOrigin::capture(current) == Some(self.origin)
            && frame.elr == self.elr
            && frame.x[8] == self.syscall
            && frame.x[..6] == self.args
    }
    /// Finish a clean backing/descriptor refusal on the originating thread.
    /// The service must roll back before invoking this method.
    pub fn refuse(
        &mut self,
        frame: &mut TrapFrame,
        current: &CurrentTask,
        counters: &carrick_el1_abi::Counters,
        model: &mut reservations::Reservations<'_>,
    ) -> Result<(), reservations::Refusal> {
        if !self.owns_frame(frame, current) {
            return Err(reservations::Refusal::Stale);
        }
        model.refuse(self.request)?;
        frame.x[0] = if self.syscall == SYS_BRK {
            model.brk_current()
        } else {
            (-ENOMEM) as u64
        };
        counters.served[self.syscall as usize].fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
    /// Cancel after service rollback when the originating thread is gone.
    /// Cancellation delivers no syscall result and increments no served count.
    pub fn cancel(
        self,
        model: &mut reservations::Reservations<'_>,
    ) -> Result<(), reservations::Refusal> {
        model.refuse(self.request)
    }
}

/// The Linux decoder used by both host and guest adapters. Caller owns the
/// exact-MM reservation guard. No descriptor operation occurs in this layer.
/// T2 integration replaces the existing dispatch fallback with this decision,
/// retaining `Work` until completion instead of forwarding the original SVC.
pub fn decide_anonymous_syscall(
    frame: &TrapFrame,
    current: &CurrentTask,
    model: &mut reservations::Reservations<'_>,
) -> ReservationDisposition {
    use carrick_el1_abi::{ReservationProtection, ReservationRange};
    use reservations::{Decision, Placement, Refusal};
    let Some(origin) = ReservationOrigin::capture(current) else {
        return ReservationDisposition::Unavailable(Refusal::Stale);
    };
    if origin.mm != model.mm() || !model.is_admitted() {
        return ReservationDisposition::Unavailable(Refusal::Stale);
    }
    let nr = frame.x[8];
    let result = match nr {
        SYS_BRK => model.brk(frame.x[0]),
        SYS_MMAP => {
            let flags = frame.x[3];
            let supported = MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED | MAP_FIXED_NOREPLACE;
            if flags & (MAP_ANONYMOUS | MAP_PRIVATE | MAP_SHARED) != MAP_ANONYMOUS | MAP_PRIVATE
                || flags & (MAP_GROWSDOWN | MAP_STACK | MAP_HUGETLB) != 0
                || flags & !supported != 0
            {
                return ReservationDisposition::Forward;
            }
            let Some(prot) = ReservationProtection::from_bits(frame.x[2]) else {
                return ReservationDisposition::Return(-EINVAL);
            };
            if !frame.x[5].is_multiple_of(PAGE_SIZE) {
                return ReservationDisposition::Return(-EINVAL);
            }
            let placement = if flags & MAP_FIXED_NOREPLACE != 0 {
                Placement::NoReplace(frame.x[0])
            } else if flags & MAP_FIXED != 0 {
                Placement::Fixed(frame.x[0])
            } else if frame.x[0] == 0 {
                Placement::Anywhere
            } else {
                Placement::Hint(frame.x[0])
            };
            model.mmap(placement, frame.x[1], prot)
        }
        SYS_MUNMAP | SYS_MPROTECT => {
            if !frame.x[0].is_multiple_of(PAGE_SIZE) {
                return ReservationDisposition::Return(-EINVAL);
            }
            let prot = if nr == SYS_MPROTECT {
                let Some(prot) = ReservationProtection::from_bits(frame.x[2]) else {
                    return ReservationDisposition::Return(-EINVAL);
                };
                prot
            } else {
                ReservationProtection::NONE
            };
            if frame.x[1] == 0 {
                return ReservationDisposition::Return(if nr == SYS_MUNMAP { -EINVAL } else { 0 });
            }
            let range = frame.x[1]
                .checked_add(PAGE_SIZE - 1)
                .map(|v| v & !(PAGE_SIZE - 1))
                .and_then(|len| frame.x[0].checked_add(len))
                .and_then(|end| ReservationRange::new(frame.x[0], end));
            let Some(range) = range else {
                return ReservationDisposition::Return(-ENOMEM);
            };
            if nr == SYS_MUNMAP {
                model.munmap(range)
            } else {
                model.mprotect(range, prot)
            }
        }
        _ => return ReservationDisposition::Forward,
    };
    match result {
        Ok(Decision::Complete(value)) => ReservationDisposition::Return(value as i64),
        Ok(Decision::Work(request)) => ReservationDisposition::Work(PendingReservationSyscall {
            request,
            origin,
            elr: frame.elr,
            syscall: nr,
            args: [
                frame.x[0], frame.x[1], frame.x[2], frame.x[3], frame.x[4], frame.x[5],
            ],
        }),
        Err(Refusal::Collision) => ReservationDisposition::Return(-17),
        Err(Refusal::Invalid) => ReservationDisposition::Return(-EINVAL),
        Err(Refusal::Hole | Refusal::Limit) => ReservationDisposition::Return(-ENOMEM),
        Err(Refusal::ForeignMapping) => ReservationDisposition::Forward,
        Err(error @ (Refusal::Busy | Refusal::Stale | Refusal::MetadataRequired)) => {
            ReservationDisposition::Unavailable(error)
        }
    }
}

/// Result of attempting the bounded EL1 `mprotect` vertical.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MprotectDisposition {
    Forward,
    Return(i64),
}

/// Result of attempting the bounded EL1 `munmap` vertical.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MunmapDisposition {
    Forward,
    Return(i64),
    /// Stage-1 is retired. The original syscall must cross once so the host
    /// can authenticate and return the physical extent and commit VMA metadata.
    Retired,
}

/// Exact-MM live-leaf operation behind the syscall policy.
pub trait AnonymousPermissionEditor {
    fn protect_and_invalidate(
        &mut self,
        ttbr0: u64,
        edit: GuestPermissionEdit,
    ) -> Result<(), GuestPermissionEditError>;
}

/// Exact-MM live-terminal retirement behind the syscall policy.
pub trait AnonymousRetirementEditor {
    fn retire_and_invalidate(
        &mut self,
        ttbr0: u64,
        address: u64,
        len: u64,
    ) -> Result<(), GuestRetirementError>;
}

#[cfg(target_os = "none")]
pub struct HardwareAnonymousPermissionEditor;

#[cfg(target_os = "none")]
impl AnonymousPermissionEditor for HardwareAnonymousPermissionEditor {
    fn protect_and_invalidate(
        &mut self,
        ttbr0: u64,
        edit: GuestPermissionEdit,
    ) -> Result<(), GuestPermissionEditError> {
        const TTBR_BADDR_MASK: u64 = 0x0000_FFFF_FFFF_F000;
        let physical_base = ttbr0 & TTBR_BADDR_MASK;
        let words =
            carrick_el1_abi::AARCH64_STAGE1_TABLES_ALIAS_BASE as *mut core::sync::atomic::AtomicU64;
        let byte_len = carrick_el1_abi::AARCH64_STAGE1_TABLES_PRIMARY_SIZE as usize;
        unsafe {
            carrick_mmu_core::aarch64::protect_existing_el1_private_pages(
                words,
                physical_base,
                byte_len,
                edit,
            )?;
        }
        let mut cpu = crate::sched::HardwareCpu;
        crate::sched::ThreadCpu::invalidate_asid(&mut cpu, ttbr0);
        Ok(())
    }
}

#[cfg(target_os = "none")]
pub struct HardwareAnonymousRetirementEditor;

#[cfg(target_os = "none")]
impl AnonymousRetirementEditor for HardwareAnonymousRetirementEditor {
    fn retire_and_invalidate(
        &mut self,
        ttbr0: u64,
        address: u64,
        len: u64,
    ) -> Result<(), GuestRetirementError> {
        const TTBR_BADDR_MASK: u64 = 0x0000_FFFF_FFFF_F000;
        let physical_base = ttbr0 & TTBR_BADDR_MASK;
        let words =
            carrick_el1_abi::AARCH64_STAGE1_TABLES_ALIAS_BASE as *mut core::sync::atomic::AtomicU64;
        let byte_len = carrick_el1_abi::AARCH64_STAGE1_TABLES_PRIMARY_SIZE as usize;
        unsafe {
            carrick_mmu_core::aarch64::retire_existing_el1_private_pages(
                words,
                physical_base,
                byte_len,
                address,
                len,
            )?;
        }
        let mut cpu = crate::sched::HardwareCpu;
        crate::sched::ThreadCpu::invalidate_asid(&mut cpu, ttbr0);
        Ok(())
    }
}

/// Try to retire a complete resident private-anonymous `munmap(2)` range in
/// EL1. Policy and backing retirement still cross one host boundary after a
/// successful edit; every mapping shape that is not proven by live tagged
/// terminals stays on the existing host path without mutation.
pub fn try_serve_munmap<E: AnonymousRetirementEditor>(
    frame: &TrapFrame,
    current_tasks: &[CurrentTask],
    spaces: &AddressSpaces,
    editor: &mut E,
) -> MunmapDisposition {
    if frame.x[8] != SYS_MUNMAP {
        return MunmapDisposition::Forward;
    }
    let address = frame.x[0];
    let requested_len = frame.x[1];
    if !address.is_multiple_of(PAGE_SIZE) || requested_len == 0 {
        return MunmapDisposition::Return(-EINVAL);
    }
    let Some(len) = requested_len
        .checked_add(PAGE_SIZE - 1)
        .map(|value| value & !(PAGE_SIZE - 1))
    else {
        return MunmapDisposition::Return(-ENOMEM);
    };
    if address.checked_add(len).is_none() {
        return MunmapDisposition::Return(-ENOMEM);
    }
    let Some(task) = current_tasks.get(frame.slot as usize) else {
        return MunmapDisposition::Forward;
    };
    let mm_key = task.zone_mm.load(Ordering::Acquire);
    let Some(index) = spaces.find(mm_key) else {
        return MunmapDisposition::Forward;
    };
    let Some(grant) = spaces.grant(index, mm_key) else {
        return MunmapDisposition::Forward;
    };
    let Some(owner) = NonZeroU64::new(frame.slot + 1) else {
        return MunmapDisposition::Forward;
    };
    let Some(_guard) = spaces.try_begin_edit(index, mm_key, owner) else {
        return MunmapDisposition::Forward;
    };
    match editor.retire_and_invalidate(grant.ttbr0, address, len) {
        Ok(()) => {
            #[cfg(target_os = "none")]
            carrick_el1_abi::frame_grant_residency_guest().retire_overlapping(mm_key, address, len);
            MunmapDisposition::Retired
        }
        Err(GuestRetirementError::BadRange) => MunmapDisposition::Return(-EINVAL),
        Err(
            GuestRetirementError::TableOutsidePrimary
            | GuestRetirementError::MissingTable
            | GuestRetirementError::NotPrivateAnonymous,
        ) => MunmapDisposition::Forward,
    }
}

/// Try to serve canonical AArch64 `mprotect(2)` for a fully resident
/// private-anonymous range. Every other mapping shape remains on the host path.
pub fn try_serve_mprotect<E: AnonymousPermissionEditor>(
    frame: &TrapFrame,
    current_tasks: &[CurrentTask],
    spaces: &AddressSpaces,
    editor: &mut E,
) -> MprotectDisposition {
    if frame.x[8] != SYS_MPROTECT {
        return MprotectDisposition::Forward;
    }
    let address = frame.x[0];
    let requested_len = frame.x[1];
    let prot = frame.x[2];
    if !address.is_multiple_of(PAGE_SIZE) || prot & !(PROT_READ | PROT_WRITE | PROT_EXEC) != 0 {
        return MprotectDisposition::Return(-EINVAL);
    }
    if requested_len == 0 {
        return MprotectDisposition::Forward;
    }
    let Some(len) = requested_len
        .checked_add(PAGE_SIZE - 1)
        .map(|value| value & !(PAGE_SIZE - 1))
    else {
        return MprotectDisposition::Return(-EINVAL);
    };
    if address.checked_add(len).is_none() {
        return MprotectDisposition::Return(-EINVAL);
    }
    let Some(task) = current_tasks.get(frame.slot as usize) else {
        return MprotectDisposition::Forward;
    };
    let mm_key = task.zone_mm.load(Ordering::Acquire);
    let Some(index) = spaces.find(mm_key) else {
        return MprotectDisposition::Forward;
    };
    let Some(grant) = spaces.grant(index, mm_key) else {
        return MprotectDisposition::Forward;
    };
    let Some(owner) = NonZeroU64::new(frame.slot + 1) else {
        return MprotectDisposition::Forward;
    };
    let Some(_guard) = spaces.try_begin_edit(index, mm_key, owner) else {
        return MprotectDisposition::Forward;
    };
    let edit = GuestPermissionEdit {
        va: address,
        len,
        readable: prot & PROT_READ != 0,
        writable: prot & PROT_WRITE != 0,
        executable: prot & PROT_EXEC != 0,
    };
    match editor.protect_and_invalidate(grant.ttbr0, edit) {
        Ok(()) => MprotectDisposition::Return(0),
        Err(GuestPermissionEditError::BadRange) => MprotectDisposition::Return(-EINVAL),
        Err(GuestPermissionEditError::PermissionWidening) => MprotectDisposition::Forward,
        Err(
            GuestPermissionEditError::TableOutsidePrimary
            | GuestPermissionEditError::MissingTable
            | GuestPermissionEditError::NotPrivateAnonymous
            | GuestPermissionEditError::Manager(_),
        ) => MprotectDisposition::Forward,
        Err(GuestPermissionEditError::RollbackFailed) => {
            panic!("EL1 anonymous permission rollback failed")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct RecordingEditor {
        calls: Vec<(u64, GuestPermissionEdit)>,
        result: Option<GuestPermissionEditError>,
    }

    impl AnonymousPermissionEditor for RecordingEditor {
        fn protect_and_invalidate(
            &mut self,
            ttbr0: u64,
            edit: GuestPermissionEdit,
        ) -> Result<(), GuestPermissionEditError> {
            self.calls.push((ttbr0, edit));
            self.result.map_or(Ok(()), Err)
        }
    }

    fn fixture(prot: u64) -> (TrapFrame, [CurrentTask; 1], AddressSpaces, u64) {
        let mm = 17;
        let ttbr0 = (9_u64 << 48) | 0x8800_0000_0000;
        let task = CurrentTask::new();
        task.zone_mm.store(mm, Ordering::Release);
        let spaces = AddressSpaces::new();
        let index = spaces.publish_closed(mm, ttbr0, ttbr0).unwrap();
        spaces.open(index);
        let mut frame = TrapFrame::default();
        frame.x[8] = SYS_MPROTECT;
        frame.x[0] = 0x6000_0000;
        frame.x[1] = 0x2001;
        frame.x[2] = prot;
        (frame, [task], spaces, ttbr0)
    }

    #[test]
    fn resident_anonymous_mprotect_rounds_and_edits_under_exact_mm_guard() {
        let (frame, tasks, spaces, ttbr0) = fixture(PROT_READ);
        let mut editor = RecordingEditor::default();
        assert_eq!(
            try_serve_mprotect(&frame, &tasks, &spaces, &mut editor),
            MprotectDisposition::Return(0)
        );
        assert_eq!(
            editor.calls,
            vec![(
                ttbr0,
                GuestPermissionEdit {
                    va: frame.x[0],
                    len: 0x3000,
                    readable: true,
                    writable: false,
                    executable: false,
                }
            )]
        );
        assert_eq!(spaces.active_editor(spaces.find(17).unwrap()), None);
    }

    #[test]
    fn ineligible_mapping_and_permission_widening_forward() {
        let (frame, tasks, spaces, _) = fixture(PROT_READ | PROT_WRITE);
        let mut ineligible = RecordingEditor {
            result: Some(GuestPermissionEditError::NotPrivateAnonymous),
            ..RecordingEditor::default()
        };
        assert_eq!(
            try_serve_mprotect(&frame, &tasks, &spaces, &mut ineligible),
            MprotectDisposition::Forward
        );

        let mut widening = RecordingEditor {
            result: Some(GuestPermissionEditError::PermissionWidening),
            ..RecordingEditor::default()
        };
        assert_eq!(
            try_serve_mprotect(&frame, &tasks, &spaces, &mut widening),
            MprotectDisposition::Forward
        );
    }

    #[derive(Default)]
    struct RecordingRetirementEditor {
        calls: Vec<(u64, u64, u64)>,
        result: Option<GuestRetirementError>,
    }

    impl AnonymousRetirementEditor for RecordingRetirementEditor {
        fn retire_and_invalidate(
            &mut self,
            ttbr0: u64,
            address: u64,
            len: u64,
        ) -> Result<(), GuestRetirementError> {
            self.calls.push((ttbr0, address, len));
            self.result.map_or(Ok(()), Err)
        }
    }

    #[test]
    fn resident_anonymous_munmap_retires_under_exact_mm_guard() {
        let (mut frame, tasks, spaces, ttbr0) = fixture(PROT_READ | PROT_WRITE);
        frame.x[8] = SYS_MUNMAP;
        frame.x[1] = 0x2001;
        let mut editor = RecordingRetirementEditor::default();
        assert_eq!(
            try_serve_munmap(&frame, &tasks, &spaces, &mut editor),
            MunmapDisposition::Retired
        );
        assert_eq!(editor.calls, vec![(ttbr0, frame.x[0], 0x3000)]);
        assert_eq!(spaces.active_editor(spaces.find(17).unwrap()), None);
    }

    #[test]
    fn malformed_or_ineligible_munmap_preserves_linux_fallback() {
        let (mut frame, tasks, spaces, _) = fixture(PROT_READ | PROT_WRITE);
        frame.x[8] = SYS_MUNMAP;
        frame.x[0] += 1;
        let mut editor = RecordingRetirementEditor::default();
        assert_eq!(
            try_serve_munmap(&frame, &tasks, &spaces, &mut editor),
            MunmapDisposition::Return(-EINVAL)
        );
        assert!(editor.calls.is_empty());

        frame.x[0] -= 1;
        editor.result = Some(GuestRetirementError::NotPrivateAnonymous);
        assert_eq!(
            try_serve_munmap(&frame, &tasks, &spaces, &mut editor),
            MunmapDisposition::Forward
        );

        frame.x[1] = 0;
        editor.result = None;
        assert_eq!(
            try_serve_munmap(&frame, &tasks, &spaces, &mut editor),
            MunmapDisposition::Return(-EINVAL)
        );
    }
}
