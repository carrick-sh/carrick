use parking_lot::Mutex;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};

use super::{
    ExitStatus, FastPathVisibility, ProcessInfo, SyscallAction, SyscallInfo, SyscallObserver,
    SyscallOutcome,
};
use crate::kernel::TaskKey;
use crate::kernel::ThreadKey;

/// Bounded audit event recorded by [`AuditObserver`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditEvent {
    Syscall {
        pid: i32,
        tid: i32,
        task_key: TaskKey,
        thread_key: ThreadKey,
        syscall_number: u64,
        syscall_name: &'static str,
        args: [u64; 6],
    },
    SyscallReturn {
        pid: i32,
        tid: i32,
        task_key: TaskKey,
        thread_key: ThreadKey,
        syscall_number: u64,
        syscall_name: &'static str,
        outcome: SyscallOutcome,
    },
    ProcessCreate {
        parent_pid: i32,
        parent_task: TaskKey,
        child_task: TaskKey,
    },
    Exec {
        pid: i32,
        task_key: TaskKey,
        path: Vec<u8>,
        argv: Vec<Vec<u8>>,
    },
    ProcessExit {
        pid: i32,
        task_key: TaskKey,
        status: ExitStatus,
    },
}

/// A thread-safe, bounded-ring audit observer with drop counting.
pub struct AuditObserver {
    capacity: usize,
    events: Mutex<VecDeque<AuditEvent>>,
    dropped: AtomicU64,
    fast_path_visibility: FastPathVisibility,
}

impl AuditObserver {
    pub const DEFAULT_CAPACITY: usize = 1024;

    pub fn new() -> Self {
        Self::with_capacity(Self::DEFAULT_CAPACITY)
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            events: Mutex::new(VecDeque::with_capacity(capacity.max(1))),
            dropped: AtomicU64::new(0),
            fast_path_visibility: FastPathVisibility::Blind,
        }
    }

    pub fn with_fast_path_visibility(mut self, visibility: FastPathVisibility) -> Self {
        self.fast_path_visibility = visibility;
        self
    }

    pub fn require_fast_path_visibility(mut self) -> Self {
        self.fast_path_visibility = FastPathVisibility::Required;
        self
    }

    pub fn events(&self) -> Vec<AuditEvent> {
        self.events.lock().iter().cloned().collect()
    }

    pub fn len(&self) -> usize {
        self.events.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.lock().is_empty()
    }

    pub fn drain(&self) -> Vec<AuditEvent> {
        self.events.lock().drain(..).collect()
    }

    pub fn dropped_count(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    pub fn clear(&self) {
        let mut guard = self.events.lock();
        guard.clear();
        self.dropped.store(0, Ordering::Relaxed);
    }

    fn push_event(&self, event: AuditEvent) {
        let mut guard = self.events.lock();
        if guard.len() >= self.capacity {
            guard.pop_front();
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
        guard.push_back(event);
    }
}

impl Default for AuditObserver {
    fn default() -> Self {
        Self::new()
    }
}

impl SyscallObserver for AuditObserver {
    fn on_syscall(&self, p: &ProcessInfo<'_>, s: &SyscallInfo<'_>) -> SyscallAction {
        self.push_event(AuditEvent::Syscall {
            pid: p.pid(),
            tid: p.tid(),
            task_key: p.task_key(),
            thread_key: p.thread_key(),
            syscall_number: s.number(),
            syscall_name: s.name(),
            args: s.args(),
        });
        SyscallAction::Allow
    }

    fn on_syscall_return(&self, p: &ProcessInfo<'_>, s: &SyscallInfo<'_>, o: &SyscallOutcome) {
        self.push_event(AuditEvent::SyscallReturn {
            pid: p.pid(),
            tid: p.tid(),
            task_key: p.task_key(),
            thread_key: p.thread_key(),
            syscall_number: s.number(),
            syscall_name: s.name(),
            outcome: *o,
        });
    }

    fn on_process_create(&self, parent: &ProcessInfo<'_>, child: TaskKey) {
        self.push_event(AuditEvent::ProcessCreate {
            parent_pid: parent.pid(),
            parent_task: parent.task_key(),
            child_task: child,
        });
    }

    fn on_exec(&self, p: &ProcessInfo<'_>, exe: &[u8], argv: &[&[u8]]) -> SyscallAction {
        self.push_event(AuditEvent::Exec {
            pid: p.pid(),
            task_key: p.task_key(),
            path: exe.to_vec(),
            argv: argv.iter().map(|arg| arg.to_vec()).collect(),
        });
        SyscallAction::Allow
    }

    fn on_process_exit(&self, p: &ProcessInfo<'_>, status: ExitStatus) {
        self.push_event(AuditEvent::ProcessExit {
            pid: p.pid(),
            task_key: p.task_key(),
            status,
        });
    }

    fn wants_fast_path_visibility(&self) -> FastPathVisibility {
        self.fast_path_visibility
    }
}
