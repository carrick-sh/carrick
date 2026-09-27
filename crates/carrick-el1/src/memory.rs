//! Resident private-anonymous memory operations served inside guest EL1.

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
const MAP_NORESERVE: u64 = 0x4000;

const LINUX_HEAP_BASE: u64 = 0x40_0000_0000;
const LINUX_HEAP_SIZE: u64 = 128 * 1024 * 1024;
#[cfg(test)]
const LINUX_MMAP_BASE: u64 = 0x60_0000_0000;

const EACCES: i64 = 13;
const EINVAL: i64 = 22;
const ENOMEM: i64 = 12;
const PAGE_SIZE: u64 = 4096;

/// Result of attempting the bounded EL1 `brk` vertical.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrkDisposition {
    Forward,
    Return(u64),
}

/// Result of attempting the bounded EL1 `mmap` vertical.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MmapDisposition {
    Forward,
    Return(i64),
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
        Ok(()) => MunmapDisposition::Retired,
        Err(GuestRetirementError::BadRange) => MunmapDisposition::Return(-EINVAL),
        Err(
            GuestRetirementError::TableOutsidePrimary
            | GuestRetirementError::MissingTable
            | GuestRetirementError::NotPrivateAnonymous,
        ) => MunmapDisposition::Forward,
    }
}

/// Try to serve `brk(2)` for the heap in EL1.
pub fn try_serve_brk<E: AnonymousRetirementEditor>(
    frame: &TrapFrame,
    current_tasks: &[CurrentTask],
    spaces: &AddressSpaces,
    editor: &mut E,
) -> BrkDisposition {
    if frame.x[8] != SYS_BRK {
        return BrkDisposition::Forward;
    }
    let requested = frame.x[0];
    let Some(task) = current_tasks.get(frame.slot as usize) else {
        return BrkDisposition::Forward;
    };
    let mm_key = task.zone_mm.load(Ordering::Acquire);
    let Some(index) = spaces.find(mm_key) else {
        return BrkDisposition::Forward;
    };
    let Some(grant) = spaces.grant(index, mm_key) else {
        return BrkDisposition::Forward;
    };
    let Some(owner) = NonZeroU64::new(frame.slot + 1) else {
        return BrkDisposition::Forward;
    };
    let Some(editor_guard) = spaces.try_begin_edit(index, mm_key, owner) else {
        return BrkDisposition::Forward;
    };
    let mut current = editor_guard.brk_current();
    if current == 0 {
        current = LINUX_HEAP_BASE;
        editor_guard.set_brk_current(current);
    }
    if requested == 0 {
        return BrkDisposition::Return(current);
    }
    if !(LINUX_HEAP_BASE..=LINUX_HEAP_BASE + LINUX_HEAP_SIZE).contains(&requested) {
        return BrkDisposition::Return(current);
    }
    let Some(old_page_end) = current
        .checked_add(PAGE_SIZE - 1)
        .map(|v| v & !(PAGE_SIZE - 1))
    else {
        return BrkDisposition::Return(current);
    };
    let Some(new_page_end) = requested
        .checked_add(PAGE_SIZE - 1)
        .map(|v| v & !(PAGE_SIZE - 1))
    else {
        return BrkDisposition::Return(current);
    };

    if new_page_end < old_page_end {
        let shrink_len = old_page_end - new_page_end;
        if editor
            .retire_and_invalidate(grant.ttbr0, new_page_end, shrink_len)
            .is_err()
        {
            return BrkDisposition::Forward;
        }
    }
    editor_guard.set_brk_current(requested);
    BrkDisposition::Return(requested)
}

/// Try to serve private-anonymous `mmap(2)` in EL1.
pub fn try_serve_mmap<E: AnonymousRetirementEditor>(
    frame: &TrapFrame,
    current_tasks: &[CurrentTask],
    spaces: &AddressSpaces,
    editor: &mut E,
) -> MmapDisposition {
    if frame.x[8] != SYS_MMAP {
        return MmapDisposition::Forward;
    }
    let requested_addr = frame.x[0];
    let requested_len = frame.x[1];
    let prot = frame.x[2];
    let flags = frame.x[3];

    if flags & MAP_ANONYMOUS == 0 || flags & MAP_PRIVATE == 0 || flags & MAP_SHARED != 0 {
        return MmapDisposition::Forward;
    }
    if flags & !(MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE) != 0 {
        return MmapDisposition::Forward;
    }
    if prot & !(PROT_READ | PROT_WRITE | PROT_EXEC) != 0 {
        return MmapDisposition::Return(-EINVAL);
    }
    if requested_len == 0 {
        return MmapDisposition::Return(-EINVAL);
    }
    let Some(len) = requested_len
        .checked_add(PAGE_SIZE - 1)
        .map(|v| v & !(PAGE_SIZE - 1))
    else {
        return MmapDisposition::Return(-ENOMEM);
    };

    let Some(task) = current_tasks.get(frame.slot as usize) else {
        return MmapDisposition::Forward;
    };
    let mm_key = task.zone_mm.load(Ordering::Acquire);
    let Some(index) = spaces.find(mm_key) else {
        return MmapDisposition::Forward;
    };
    let Some(grant) = spaces.grant(index, mm_key) else {
        return MmapDisposition::Forward;
    };
    let Some(owner) = NonZeroU64::new(frame.slot + 1) else {
        return MmapDisposition::Forward;
    };
    let Some(editor_guard) = spaces.try_begin_edit(index, mm_key, owner) else {
        return MmapDisposition::Forward;
    };

    // Only a hint-free, non-fixed reservation is EL1's: it comes from the
    // window the host placer never uses, so the two allocators cannot
    // collide. The host replays `[mmap_drained, mmap_next)` as one
    // MAP_FIXED mapping at its next boundary for this MM (see
    // `AddressSpaces::take_pending`), so a pending run must share one
    // protection; a differing one forwards and the host drains first.
    if flags & MAP_FIXED != 0 || requested_addr != 0 {
        return MmapDisposition::Forward;
    }
    let window_end = editor_guard.mmap_window_end();
    let cursor = editor_guard.mmap_next();
    if window_end == 0 || cursor == 0 {
        return MmapDisposition::Forward;
    }
    let pending = editor_guard.mmap_drained() != cursor;
    if pending && editor_guard.mmap_pending_prot() != prot {
        return MmapDisposition::Forward;
    }
    let Some(end) = cursor.checked_add(len).filter(|end| *end <= window_end) else {
        return MmapDisposition::Forward;
    };
    let _ = (grant, editor);
    if !pending {
        editor_guard.set_mmap_pending_prot(prot);
    }
    editor_guard.set_mmap_next(end);
    MmapDisposition::Return(cursor as i64)
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

    #[test]
    fn resident_anonymous_brk_manages_heap_break() {
        let (mut frame, tasks, spaces, ttbr0) = fixture(PROT_READ | PROT_WRITE);
        frame.x[8] = SYS_BRK;
        frame.x[0] = 0; // query
        let mut editor = RecordingRetirementEditor::default();
        assert_eq!(
            try_serve_brk(&frame, &tasks, &spaces, &mut editor),
            BrkDisposition::Return(LINUX_HEAP_BASE)
        );
        assert!(editor.calls.is_empty());

        // Grow by 2 pages
        frame.x[0] = LINUX_HEAP_BASE + 0x2000;
        assert_eq!(
            try_serve_brk(&frame, &tasks, &spaces, &mut editor),
            BrkDisposition::Return(LINUX_HEAP_BASE + 0x2000)
        );
        assert!(editor.calls.is_empty());

        // Shrink by 1 page: must retire the released page in stage 1
        frame.x[0] = LINUX_HEAP_BASE + 0x1000;
        assert_eq!(
            try_serve_brk(&frame, &tasks, &spaces, &mut editor),
            BrkDisposition::Return(LINUX_HEAP_BASE + 0x1000)
        );
        assert_eq!(
            editor.calls,
            vec![(ttbr0, LINUX_HEAP_BASE + 0x1000, 0x1000)]
        );

        // Out of bounds requested break returns unchanged current break
        frame.x[0] = LINUX_HEAP_BASE + LINUX_HEAP_SIZE + 0x1000;
        assert_eq!(
            try_serve_brk(&frame, &tasks, &spaces, &mut editor),
            BrkDisposition::Return(LINUX_HEAP_BASE + 0x1000)
        );
    }

    #[test]
    fn anonymous_mmap_reserves_from_the_window_and_logs_one_pending_run() {
        let mm = 17;
        let ttbr0 = (9_u64 << 48) | 0x8800_0000_0000;
        let task = CurrentTask::new();
        task.zone_mm.store(mm, Ordering::Release);
        let tasks = [task];
        let spaces = AddressSpaces::new();
        let window = LINUX_MMAP_BASE + 0x1_0000_0000;
        let index = spaces
            .publish_closed_with_layout(mm, ttbr0, ttbr0, 0, window, window + 0x6000)
            .unwrap();
        spaces.open(index);
        let mut frame = TrapFrame::default();
        frame.x[8] = SYS_MMAP;
        frame.x[1] = 0x3000;
        frame.x[2] = PROT_READ | PROT_WRITE;
        frame.x[3] = MAP_PRIVATE | MAP_ANONYMOUS;
        frame.x[4] = u64::MAX;
        let mut editor = RecordingRetirementEditor::default();
        assert!(!spaces.has_pending(index));

        assert_eq!(
            try_serve_mmap(&frame, &tasks, &spaces, &mut editor),
            MmapDisposition::Return(window as i64)
        );
        frame.x[1] = 0x1000;
        assert_eq!(
            try_serve_mmap(&frame, &tasks, &spaces, &mut editor),
            MmapDisposition::Return((window + 0x3000) as i64)
        );
        // A different protection cannot join the pending run.
        frame.x[2] = PROT_READ;
        assert_eq!(
            try_serve_mmap(&frame, &tasks, &spaces, &mut editor),
            MmapDisposition::Forward
        );
        assert!(spaces.has_pending(index));
        assert_eq!(
            spaces.take_pending(index).mmap,
            Some((window, 0x4000, PROT_READ | PROT_WRITE))
        );
        assert!(!spaces.has_pending(index));
        // After the host replayed the run, a new protection starts a new one.
        assert_eq!(
            try_serve_mmap(&frame, &tasks, &spaces, &mut editor),
            MmapDisposition::Return((window + 0x4000) as i64)
        );
        // Window exhausted: the host serves it.
        frame.x[1] = 0x2000;
        assert_eq!(
            try_serve_mmap(&frame, &tasks, &spaces, &mut editor),
            MmapDisposition::Forward
        );
        // Fixed, hinted, shared and populate mappings stay on the host.
        frame.x[1] = 0x1000;
        for (addr, flags) in [
            (window, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED),
            (window + 0x8000, MAP_PRIVATE | MAP_ANONYMOUS),
            (0, MAP_SHARED | MAP_ANONYMOUS),
            (0, MAP_PRIVATE | MAP_ANONYMOUS | 0x8000),
        ] {
            frame.x[0] = addr;
            frame.x[3] = flags;
            assert_eq!(
                try_serve_mmap(&frame, &tasks, &spaces, &mut editor),
                MmapDisposition::Forward
            );
        }
        assert!(editor.calls.is_empty());
        frame.x[0] = 0;
        frame.x[1] = 0;
        frame.x[3] = MAP_PRIVATE | MAP_ANONYMOUS;
        assert_eq!(
            try_serve_mmap(&frame, &tasks, &spaces, &mut editor),
            MmapDisposition::Return(-EINVAL)
        );
    }
}
