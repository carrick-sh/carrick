//! Resident private-anonymous memory operations served inside guest EL1.

use carrick_el1_abi::{CurrentTask, TrapFrame};
use carrick_mmu_core::aarch64::{GuestPermissionEdit, GuestPermissionEditError};
use carrick_sched_core::AddressSpaces;
use core::num::NonZeroU64;
use core::sync::atomic::Ordering;

const SYS_MPROTECT: u64 = 226;
const PROT_READ: u64 = 1;
const PROT_WRITE: u64 = 2;
const PROT_EXEC: u64 = 4;
const EACCES: i64 = 13;
const EINVAL: i64 = 22;
const PAGE_SIZE: u64 = 4096;

/// Result of attempting the bounded EL1 `mprotect` vertical.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MprotectDisposition {
    Forward,
    Return(i64),
}

/// Exact-MM live-leaf operation behind the syscall policy.
pub trait AnonymousPermissionEditor {
    fn protect_and_invalidate(
        &mut self,
        ttbr0: u64,
        edit: GuestPermissionEdit,
    ) -> Result<(), GuestPermissionEditError>;
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
        Err(GuestPermissionEditError::PermissionWidening) => MprotectDisposition::Return(-EACCES),
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
    fn ineligible_mapping_forwards_and_permission_widening_returns_eacces() {
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
            MprotectDisposition::Return(-EACCES)
        );
    }
}
