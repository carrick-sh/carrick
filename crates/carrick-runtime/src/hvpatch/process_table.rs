// Fork/exec/exit consumers land immediately after the root-process wiring.
// Keeping the whole lifecycle API together avoids a root-only placeholder API.
#![allow(dead_code)]

use std::collections::BTreeMap;

use parking_lot::Mutex;

use super::asid::{Asid, AsidAllocator, AsidError, RetiredAsid};

/// Guest-visible process identity. This is deliberately distinct from a host
/// PID: hvpatch processes share one host process.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct GuestPid(i32);

impl GuestPid {
    pub(crate) fn root() -> Self {
        Self(std::process::id() as i32)
    }

    pub(crate) fn raw(self) -> i32 {
        self.0
    }

    #[cfg(test)]
    fn new_for_tests(raw: i32) -> Self {
        assert!(raw > 0);
        Self(raw)
    }
}

/// Address-space identity for one live in-process guest. Dispatcher/fd/signal
/// state is paired with this record by the process's `KernelState`; this table
/// is the shared lifecycle index used by fork, exec, exit, and wait.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct GuestProcess {
    pid: GuestPid,
    parent: Option<GuestPid>,
    asid: Asid,
    stage1_root: u64,
    ttbr0: u64,
}

impl GuestProcess {
    pub(crate) fn pid(self) -> GuestPid {
        self.pid
    }

    pub(crate) fn parent(self) -> Option<GuestPid> {
        self.parent
    }

    pub(crate) fn asid(self) -> Asid {
        self.asid
    }

    pub(crate) fn stage1_root(self) -> u64 {
        self.stage1_root
    }

    pub(crate) fn ttbr0(self) -> u64 {
        self.ttbr0
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct RetiredProcess {
    pid: GuestPid,
    asid: RetiredAsid,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum ProcessTableError {
    #[error("guest process {0:?} is not live")]
    UnknownProcess(GuestPid),
    #[error("guest PID space is exhausted")]
    PidExhausted,
    #[error("guest ASID space is exhausted")]
    AsidExhausted,
    #[error(transparent)]
    Asid(AsidError),
}

impl From<AsidError> for ProcessTableError {
    fn from(error: AsidError) -> Self {
        match error {
            AsidError::Exhausted => Self::AsidExhausted,
            other => Self::Asid(other),
        }
    }
}

#[derive(Debug)]
struct ProcessTableInner {
    next_pid: i32,
    asids: AsidAllocator,
    processes: BTreeMap<GuestPid, GuestProcess>,
}

/// Shared registry for every Linux process multiplexed in one hvpatch VM.
#[derive(Debug)]
pub(crate) struct ProcessTable {
    inner: Mutex<ProcessTableInner>,
}

impl ProcessTable {
    pub(crate) fn new_root(
        root_pid: GuestPid,
        stage1_root: u64,
    ) -> Result<Self, ProcessTableError> {
        Self::with_allocator(root_pid, stage1_root, AsidAllocator::new())
    }

    #[cfg(test)]
    fn new_for_tests(
        root_pid: GuestPid,
        stage1_root: u64,
        asid_limit: u16,
    ) -> Result<Self, ProcessTableError> {
        Self::with_allocator(
            root_pid,
            stage1_root,
            AsidAllocator::with_limit_for_tests(asid_limit),
        )
    }

    fn with_allocator(
        root_pid: GuestPid,
        stage1_root: u64,
        mut asids: AsidAllocator,
    ) -> Result<Self, ProcessTableError> {
        let asid = asids.allocate()?;
        let root = GuestProcess {
            pid: root_pid,
            parent: None,
            asid,
            stage1_root,
            ttbr0: asid.ttbr0(stage1_root)?,
        };
        let next_pid = root_pid.raw().checked_add(1).unwrap_or(1);
        Ok(Self {
            inner: Mutex::new(ProcessTableInner {
                next_pid,
                asids,
                processes: BTreeMap::from([(root_pid, root)]),
            }),
        })
    }

    pub(crate) fn process(&self, pid: GuestPid) -> Option<GuestProcess> {
        self.inner.lock().processes.get(&pid).copied()
    }

    pub(crate) fn live_process_count(&self) -> usize {
        self.inner.lock().processes.len()
    }

    pub(crate) fn fork_process(
        &self,
        parent: GuestPid,
        child_stage1_root: u64,
    ) -> Result<GuestProcess, ProcessTableError> {
        let mut inner = self.inner.lock();
        if !inner.processes.contains_key(&parent) {
            return Err(ProcessTableError::UnknownProcess(parent));
        }
        let pid = allocate_pid(&mut inner)?;
        let asid = inner.asids.allocate()?;
        let process = GuestProcess {
            pid,
            parent: Some(parent),
            asid,
            stage1_root: child_stage1_root,
            ttbr0: asid.ttbr0(child_stage1_root)?,
        };
        inner.processes.insert(pid, process);
        Ok(process)
    }

    pub(crate) fn exec_process(
        &self,
        pid: GuestPid,
        new_stage1_root: u64,
    ) -> Result<GuestProcess, ProcessTableError> {
        let mut inner = self.inner.lock();
        let process = inner
            .processes
            .get_mut(&pid)
            .ok_or(ProcessTableError::UnknownProcess(pid))?;
        process.stage1_root = new_stage1_root;
        process.ttbr0 = process.asid.ttbr0(new_stage1_root)?;
        Ok(*process)
    }

    pub(crate) fn exit_process(&self, pid: GuestPid) -> Result<RetiredProcess, ProcessTableError> {
        let mut inner = self.inner.lock();
        let process = inner
            .processes
            .remove(&pid)
            .ok_or(ProcessTableError::UnknownProcess(pid))?;
        let asid = inner.asids.retire(process.asid)?;
        Ok(RetiredProcess { pid, asid })
    }

    /// Complete process retirement only after every vCPU has observed the ASID
    /// invalidation. Keeping this separate makes stale-ASID reuse impossible by
    /// construction at the lifecycle layer.
    pub(crate) fn acknowledge_tlb_flush(
        &self,
        retired: RetiredProcess,
    ) -> Result<(), ProcessTableError> {
        self.inner
            .lock()
            .asids
            .acknowledge_tlb_flush(retired.asid)?;
        Ok(())
    }
}

fn allocate_pid(inner: &mut ProcessTableInner) -> Result<GuestPid, ProcessTableError> {
    let start = inner.next_pid;
    loop {
        let raw = inner.next_pid;
        inner.next_pid = raw.checked_add(1).filter(|next| *next > 0).unwrap_or(1);
        let pid = GuestPid(raw);
        if raw > 0 && !inner.processes.contains_key(&pid) {
            return Ok(pid);
        }
        if inner.next_pid == start {
            return Err(ProcessTableError::PidExhausted);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{GuestPid, ProcessTable, ProcessTableError};

    #[test]
    fn fork_allocates_child_pid_asid_and_independent_stage1_root() {
        let table = ProcessTable::new_for_tests(GuestPid::new_for_tests(40), 0x4000, 3)
            .expect("root process");

        let child = table
            .fork_process(GuestPid::new_for_tests(40), 0x8000)
            .expect("child process");
        let root = table
            .process(GuestPid::new_for_tests(40))
            .expect("root record");

        assert_eq!(child.parent(), Some(root.pid()));
        assert_ne!(child.pid(), root.pid());
        assert_ne!(child.asid(), root.asid());
        assert_eq!(child.stage1_root(), 0x8000);
        assert_eq!(table.live_process_count(), 2);
    }

    #[test]
    fn exec_reuses_asid_while_replacing_stage1_root() {
        let table = ProcessTable::new_for_tests(GuestPid::new_for_tests(50), 0x4000, 2)
            .expect("root process");
        let before = table
            .process(GuestPid::new_for_tests(50))
            .expect("root record");

        let after = table
            .exec_process(GuestPid::new_for_tests(50), 0xc000)
            .expect("exec replacement");

        assert_eq!(after.asid(), before.asid());
        assert_eq!(after.stage1_root(), 0xc000);
        assert_ne!(after.ttbr0(), before.ttbr0());
    }

    #[test]
    fn exited_asid_is_not_reused_before_tlb_flush() {
        let table = ProcessTable::new_for_tests(GuestPid::new_for_tests(60), 0x4000, 2)
            .expect("root process");
        let first = table
            .fork_process(GuestPid::new_for_tests(60), 0x8000)
            .expect("first child");
        let retired = table.exit_process(first.pid()).expect("exit child");

        assert_eq!(
            table.fork_process(GuestPid::new_for_tests(60), 0x10000),
            Err(ProcessTableError::AsidExhausted)
        );

        table
            .acknowledge_tlb_flush(retired)
            .expect("flush acknowledgement");
        let second = table
            .fork_process(GuestPid::new_for_tests(60), 0x10000)
            .expect("second child");
        assert_eq!(second.asid(), first.asid());
    }

    #[test]
    fn fork_rejects_unknown_parent() {
        let table = ProcessTable::new_for_tests(GuestPid::new_for_tests(70), 0x4000, 2)
            .expect("root process");

        assert_eq!(
            table.fork_process(GuestPid::new_for_tests(999), 0x8000),
            Err(ProcessTableError::UnknownProcess(GuestPid::new_for_tests(
                999
            )))
        );
    }
}
