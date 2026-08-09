// Fork/exec/exit consumers land immediately after the root-process wiring.
// Keeping the whole lifecycle API together avoids a root-only placeholder API.
#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Weak};

use parking_lot::{Condvar, Mutex};

use super::asid::{Asid, AsidAllocator, AsidError, RetiredAsid};

const PROCESS_BANK_SIZE: u64 = 40 * 1024 * 1024 * 1024;
const PROCESS_BANK_COUNT: u8 =
    1 + (carrick_mem::memory::LINUX_PROCESS_BANK_SIZE / PROCESS_BANK_SIZE) as u8;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct ProcessBank(u8);

impl ProcessBank {
    pub(crate) fn base(self) -> u64 {
        if self.0 == 0 {
            carrick_mem::memory::LINUX_PROCESS_AUX_BANK_BASE
        } else {
            carrick_mem::memory::LINUX_PROCESS_BANK_BASE + u64::from(self.0 - 1) * PROCESS_BANK_SIZE
        }
    }

    pub(crate) fn size(self) -> u64 {
        PROCESS_BANK_SIZE
    }
}

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

    pub(crate) fn from_raw(raw: i32) -> Option<Self> {
        (raw > 0).then_some(Self(raw))
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
    pgid: GuestPid,
    sid: GuestPid,
    asid: Asid,
    stage1_root: u64,
    ttbr0: u64,
    bank: Option<ProcessBank>,
}

impl GuestProcess {
    pub(crate) fn pid(self) -> GuestPid {
        self.pid
    }

    pub(crate) fn parent(self) -> Option<GuestPid> {
        self.parent
    }

    pub(crate) fn pgid(self) -> GuestPid {
        self.pgid
    }

    pub(crate) fn sid(self) -> GuestPid {
        self.sid
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

    pub(crate) fn bank(self) -> Option<ProcessBank> {
        self.bank
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct RetiredProcess {
    pid: GuestPid,
    asid: RetiredAsid,
    bank: Option<ProcessBank>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ChildExit {
    pid: GuestPid,
    parent: GuestPid,
    status: i32,
}

impl ChildExit {
    pub(crate) fn pid(self) -> GuestPid {
        self.pid
    }

    pub(crate) fn status(self) -> i32 {
        self.status
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WaitResult {
    Exited(ChildExit),
    StillRunning,
    NoChild,
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
    #[error("all hvpatch process address-space banks are live or awaiting teardown")]
    BankExhausted,
    #[error("hvpatch process-group/session operation is not permitted")]
    IdentityPermission,
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
    exited: BTreeMap<GuestPid, ChildExit>,
    /// Weak readiness subscribers for guest-virtual pidfds. The fd table owns
    /// each watch; this lifecycle index only fires watches that remain open.
    pidfd_watchers: BTreeMap<GuestPid, Vec<Weak<crate::dispatch::fd_table::PidfdWatch>>>,
    free_banks: BTreeSet<ProcessBank>,
}

/// Shared registry for every Linux process multiplexed in one hvpatch VM.
#[derive(Debug)]
pub(crate) struct ProcessTable {
    inner: Mutex<ProcessTableInner>,
    child_changed: Condvar,
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
            pgid: root_pid,
            sid: root_pid,
            asid,
            stage1_root,
            ttbr0: asid.ttbr0(stage1_root)?,
            bank: None,
        };
        let next_pid = root_pid.raw().checked_add(1).unwrap_or(1);
        Ok(Self {
            inner: Mutex::new(ProcessTableInner {
                next_pid,
                asids,
                processes: BTreeMap::from([(root_pid, root)]),
                exited: BTreeMap::new(),
                pidfd_watchers: BTreeMap::new(),
                free_banks: (0..PROCESS_BANK_COUNT).map(ProcessBank).collect(),
            }),
            child_changed: Condvar::new(),
        })
    }

    pub(crate) fn process(&self, pid: GuestPid) -> Option<GuestProcess> {
        self.inner.lock().processes.get(&pid).copied()
    }

    pub(crate) fn is_live(&self, pid: GuestPid) -> bool {
        self.inner.lock().processes.contains_key(&pid)
    }

    pub(crate) fn register_pidfd_watch(
        &self,
        pid: GuestPid,
        watch: &Arc<crate::dispatch::fd_table::PidfdWatch>,
    ) -> bool {
        let mut inner = self.inner.lock();
        if inner.processes.contains_key(&pid) {
            inner
                .pidfd_watchers
                .entry(pid)
                .or_default()
                .push(Arc::downgrade(watch));
            return true;
        }
        let exited = inner.exited.contains_key(&pid);
        drop(inner);
        if exited {
            watch.publish_exit();
        }
        exited
    }

    pub(crate) fn live_process_count(&self) -> usize {
        self.inner.lock().processes.len()
    }

    /// Allocate one id from the shared Linux task-id sequence. Processes and
    /// threads inhabit the same PID namespace; per-process ThreadRegistry bump
    /// cursors produce duplicate tids once several processes coexist in one
    /// host, corrupting host-global signal/run-state tables keyed by tid.
    pub(crate) fn allocate_task_id(&self) -> Result<i32, ProcessTableError> {
        let mut inner = self.inner.lock();
        allocate_pid(&mut inner).map(GuestPid::raw)
    }

    pub(crate) fn fork_process(&self, parent: GuestPid) -> Result<GuestProcess, ProcessTableError> {
        let mut inner = self.inner.lock();
        if !inner.processes.contains_key(&parent) {
            return Err(ProcessTableError::UnknownProcess(parent));
        }
        let pid = allocate_pid(&mut inner)?;
        let bank = inner
            .free_banks
            .pop_first()
            .ok_or(ProcessTableError::BankExhausted)?;
        let asid = match inner.asids.allocate() {
            Ok(asid) => asid,
            Err(error) => {
                inner.free_banks.insert(bank);
                return Err(error.into());
            }
        };
        let child_stage1_root = bank.base();
        let process = GuestProcess {
            pid,
            parent: Some(parent),
            pgid: inner.processes[&parent].pgid,
            sid: inner.processes[&parent].sid,
            asid,
            stage1_root: child_stage1_root,
            ttbr0: asid.ttbr0(child_stage1_root)?,
            bank: Some(bank),
        };
        inner.processes.insert(pid, process);
        Ok(process)
    }

    pub(crate) fn process_group(
        &self,
        caller: GuestPid,
        target: Option<GuestPid>,
    ) -> Result<GuestPid, ProcessTableError> {
        let inner = self.inner.lock();
        let pid = target.unwrap_or(caller);
        inner
            .processes
            .get(&pid)
            .map(|process| process.pgid)
            .ok_or(ProcessTableError::UnknownProcess(pid))
    }

    pub(crate) fn session_id(
        &self,
        caller: GuestPid,
        target: Option<GuestPid>,
    ) -> Result<GuestPid, ProcessTableError> {
        let inner = self.inner.lock();
        let pid = target.unwrap_or(caller);
        inner
            .processes
            .get(&pid)
            .map(|process| process.sid)
            .ok_or(ProcessTableError::UnknownProcess(pid))
    }

    pub(crate) fn set_process_group(
        &self,
        caller: GuestPid,
        target: Option<GuestPid>,
        requested_group: Option<GuestPid>,
    ) -> Result<(), ProcessTableError> {
        let mut inner = self.inner.lock();
        let target = target.unwrap_or(caller);
        let caller_record = inner
            .processes
            .get(&caller)
            .copied()
            .ok_or(ProcessTableError::UnknownProcess(caller))?;
        let target_record = inner
            .processes
            .get(&target)
            .copied()
            .ok_or(ProcessTableError::UnknownProcess(target))?;
        if target != caller && target_record.parent != Some(caller) {
            return Err(ProcessTableError::UnknownProcess(target));
        }
        if target_record.sid != caller_record.sid || target_record.pid == target_record.sid {
            return Err(ProcessTableError::IdentityPermission);
        }
        let pgid = requested_group.unwrap_or(target);
        if pgid != target
            && !inner
                .processes
                .values()
                .any(|process| process.pgid == pgid && process.sid == caller_record.sid)
        {
            return Err(ProcessTableError::IdentityPermission);
        }
        inner
            .processes
            .get_mut(&target)
            .ok_or(ProcessTableError::UnknownProcess(target))?
            .pgid = pgid;
        Ok(())
    }

    pub(crate) fn create_session(&self, caller: GuestPid) -> Result<GuestPid, ProcessTableError> {
        let mut inner = self.inner.lock();
        let process = inner
            .processes
            .get_mut(&caller)
            .ok_or(ProcessTableError::UnknownProcess(caller))?;
        if process.pgid == caller {
            return Err(ProcessTableError::IdentityPermission);
        }
        process.pgid = caller;
        process.sid = caller;
        Ok(caller)
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
        inner.pidfd_watchers.remove(&pid);
        Ok(RetiredProcess {
            pid,
            asid,
            bank: process.bank,
        })
    }

    /// Publish a terminal Linux wait status after the process's vCPU, stage-2
    /// mappings, and stale ASID translations have been torn down. The process
    /// becomes a zombie visible to its parent until a consuming wait reaps it.
    pub(crate) fn publish_exit(&self, pid: GuestPid, status: i32) -> Result<(), ProcessTableError> {
        let mut inner = self.inner.lock();
        let process = inner
            .processes
            .remove(&pid)
            .ok_or(ProcessTableError::UnknownProcess(pid))?;
        let parent = process
            .parent
            .ok_or(ProcessTableError::UnknownProcess(pid))?;
        let retired = inner.asids.retire(process.asid)?;
        inner.asids.acknowledge_tlb_flush(retired)?;
        if let Some(bank) = process.bank {
            inner.free_banks.insert(bank);
        }
        inner.exited.insert(
            pid,
            ChildExit {
                pid,
                parent,
                status,
            },
        );
        let watchers = inner.pidfd_watchers.remove(&pid).unwrap_or_default();
        drop(inner);
        for watcher in watchers.into_iter().filter_map(|watcher| watcher.upgrade()) {
            watcher.publish_exit();
        }
        self.child_changed.notify_all();
        Ok(())
    }

    pub(crate) fn wait_child(
        &self,
        parent: GuestPid,
        target: Option<GuestPid>,
        nohang: bool,
        nowait: bool,
    ) -> WaitResult {
        let matches = |process: &GuestProcess| {
            process.parent == Some(parent) && target.is_none_or(|pid| process.pid == pid)
        };
        let exit_matches =
            |exit: &&ChildExit| exit.parent == parent && target.is_none_or(|pid| exit.pid == pid);
        let mut inner = self.inner.lock();
        loop {
            if let Some(exit) = inner.exited.values().find(exit_matches).copied() {
                if !nowait {
                    inner.exited.remove(&exit.pid);
                }
                return WaitResult::Exited(exit);
            }
            if !inner.processes.values().any(matches) {
                return WaitResult::NoChild;
            }
            if nohang {
                return WaitResult::StillRunning;
            }
            self.child_changed.wait(&mut inner);
        }
    }

    /// Complete process retirement only after every vCPU has observed the ASID
    /// invalidation. Keeping this separate makes stale-ASID reuse impossible by
    /// construction at the lifecycle layer.
    pub(crate) fn acknowledge_tlb_flush(
        &self,
        retired: RetiredProcess,
    ) -> Result<(), ProcessTableError> {
        let mut inner = self.inner.lock();
        inner.asids.acknowledge_tlb_flush(retired.asid)?;
        if let Some(bank) = retired.bank {
            inner.free_banks.insert(bank);
        }
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
    use std::collections::BTreeSet;
    use std::sync::Arc;

    use super::{GuestPid, ProcessTable, ProcessTableError, WaitResult};

    fn virtual_pidfd_watch() -> Arc<crate::dispatch::fd_table::PidfdWatch> {
        let mut mux = crate::event_mux::make_event_multiplexer().expect("event multiplexer");
        mux.register_user(0).expect("register pidfd user wake");
        Arc::new(crate::dispatch::fd_table::PidfdWatch::new(mux))
    }

    fn poll_readable(fd: i32) -> bool {
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let rc = unsafe { libc::poll(&mut pfd, 1, 0) };
        rc == 1 && pfd.revents & libc::POLLIN != 0
    }

    #[test]
    fn fork_allocates_child_pid_asid_and_independent_stage1_root() {
        let table = ProcessTable::new_for_tests(GuestPid::new_for_tests(40), 0x4000, 3)
            .expect("root process");

        let child = table
            .fork_process(GuestPid::new_for_tests(40))
            .expect("child process");
        let root = table
            .process(GuestPid::new_for_tests(40))
            .expect("root record");

        assert_eq!(child.parent(), Some(root.pid()));
        assert_eq!(child.pgid(), root.pgid());
        assert_eq!(child.sid(), root.sid());
        assert_ne!(child.pid(), root.pid());
        assert_ne!(child.asid(), root.asid());
        assert_eq!(
            child.stage1_root(),
            carrick_mem::memory::LINUX_PROCESS_AUX_BANK_BASE
        );
        assert_eq!(
            child.bank().expect("child bank").size(),
            super::PROCESS_BANK_SIZE
        );
        assert_eq!(table.live_process_count(), 2);
    }

    #[test]
    fn process_and_thread_ids_share_one_monotonic_namespace() {
        let root = GuestPid::new_for_tests(45);
        let table = ProcessTable::new_for_tests(root, 0x4000, 3).expect("root process");

        let thread_id = table.allocate_task_id().expect("thread id");
        let child = table.fork_process(root).expect("child process");
        let child_thread_id = table.allocate_task_id().expect("child thread id");

        assert_eq!(thread_id, 46);
        assert_eq!(child.pid().raw(), 47);
        assert_eq!(child_thread_id, 48);
    }

    #[test]
    fn eleven_process_banks_cover_ten_way_tool_fanout_plus_coordinator() {
        let root = GuestPid::new_for_tests(49);
        let table = ProcessTable::new_for_tests(root, 0x4000, 13).expect("root process");
        let mut bases = BTreeSet::new();
        for _ in 0..11 {
            let child = table.fork_process(root).expect("available process bank");
            bases.insert(child.bank().expect("child bank").base());
        }

        assert_eq!(bases.len(), 11);
        assert!(bases.contains(&carrick_mem::memory::LINUX_PROCESS_AUX_BANK_BASE));
        assert_eq!(
            table.fork_process(root),
            Err(ProcessTableError::BankExhausted)
        );
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
            .fork_process(GuestPid::new_for_tests(60))
            .expect("first child");
        let retired = table.exit_process(first.pid()).expect("exit child");

        assert_eq!(
            table.fork_process(GuestPid::new_for_tests(60)),
            Err(ProcessTableError::AsidExhausted)
        );

        table
            .acknowledge_tlb_flush(retired)
            .expect("flush acknowledgement");
        let second = table
            .fork_process(GuestPid::new_for_tests(60))
            .expect("second child");
        assert_eq!(second.asid(), first.asid());
    }

    #[test]
    fn fork_rejects_unknown_parent() {
        let table = ProcessTable::new_for_tests(GuestPid::new_for_tests(70), 0x4000, 2)
            .expect("root process");

        assert_eq!(
            table.fork_process(GuestPid::new_for_tests(999)),
            Err(ProcessTableError::UnknownProcess(GuestPid::new_for_tests(
                999
            )))
        );
    }

    #[test]
    fn wait_reports_running_then_consumes_published_exit() {
        let parent = GuestPid::new_for_tests(80);
        let table = ProcessTable::new_for_tests(parent, 0x4000, 2).expect("root process");
        let child = table.fork_process(parent).expect("child process");

        assert_eq!(
            table.wait_child(parent, Some(child.pid()), true, false),
            WaitResult::StillRunning
        );
        table
            .publish_exit(child.pid(), 23 << 8)
            .expect("publish child exit");
        let WaitResult::Exited(exit) = table.wait_child(parent, None, false, false) else {
            panic!("published exit was not waitable");
        };
        assert_eq!(exit.pid(), child.pid());
        assert_eq!(exit.status(), 23 << 8);
        assert_eq!(
            table.wait_child(parent, None, true, false),
            WaitResult::NoChild
        );
    }

    #[test]
    fn virtual_pidfd_becomes_readable_when_guest_process_exit_is_published() {
        let parent = GuestPid::new_for_tests(85);
        let table = ProcessTable::new_for_tests(parent, 0x4000, 2).expect("root process");
        let child = table.fork_process(parent).expect("child process");
        let watch = virtual_pidfd_watch();

        assert!(table.register_pidfd_watch(child.pid(), &watch));
        assert!(!poll_readable(watch.poll_fd()));

        table
            .publish_exit(child.pid(), 0)
            .expect("publish child exit");

        assert!(poll_readable(watch.poll_fd()));
    }

    #[test]
    fn pidfd_open_after_exit_gets_immediate_readiness_but_unknown_pid_is_rejected() {
        let parent = GuestPid::new_for_tests(86);
        let table = ProcessTable::new_for_tests(parent, 0x4000, 2).expect("root process");
        let child = table.fork_process(parent).expect("child process");
        table
            .publish_exit(child.pid(), 0)
            .expect("publish child exit");
        let exited_watch = virtual_pidfd_watch();
        let unknown_watch = virtual_pidfd_watch();

        assert!(table.register_pidfd_watch(child.pid(), &exited_watch));
        assert!(poll_readable(exited_watch.poll_fd()));
        assert!(!table.register_pidfd_watch(GuestPid::new_for_tests(9999), &unknown_watch));
        assert!(!poll_readable(unknown_watch.poll_fd()));
    }

    #[test]
    fn fork_child_can_create_an_independent_session() {
        let parent = GuestPid::new_for_tests(90);
        let table = ProcessTable::new_for_tests(parent, 0x4000, 2).expect("root process");
        let child = table.fork_process(parent).expect("child process");

        assert_eq!(
            table.create_session(parent),
            Err(ProcessTableError::IdentityPermission)
        );
        assert_eq!(table.create_session(child.pid()), Ok(child.pid()));
        let after = table.process(child.pid()).expect("live child");
        assert_eq!(after.pgid(), child.pid());
        assert_eq!(after.sid(), child.pid());
        assert_eq!(table.process(parent).expect("live parent").sid(), parent);
    }
}
