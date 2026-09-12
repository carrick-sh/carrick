//! Process wait and child reap operations.
//!
//! Enforces POSIX waitpid/waitid semantics, zombie lifecycle transitions,
//! child exit-signal classification, and lost-wake prevention across the
//! child wait precheck.

use carrick_abi::{LinuxWaitOptions, NsUid};
use carrick_fatal::carrick_fatal;

use super::{KernelOperationError, ensure_task_unreserved, next_revision};
use crate::kernel::core::{Kernel, RegistryState};
use crate::kernel::ids::{ChildExitSignal, LinuxSignal, ProcessGroupId, TaskId};
use crate::kernel::objects::{TaskJobControlEvent, TaskKey, Zombie};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WaitMode {
    Observe,
    Consume,
}

/// Which children a `wait(2)` call can see, by the child's exit signal.
///
/// Linux partitions a parent's children into ordinary ones (exit signal
/// `SIGCHLD`) and "clone children" (any other exit signal, or none). A plain
/// wait sees only the former; `__WCLONE` selects only the latter and
/// `__WALL` both (wait(2)). The partition applies to real children in every
/// arm of the wait -- the zombie scan, job-control state changes, and the
/// `ECHILD`/block decision -- but not to ptrace tracees a tracer waits on
/// without being their parent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WaitChildClass {
    /// The default: children whose exit signal is `SIGCHLD`.
    Sigchld,
    /// `__WCLONE`: only clone children.
    Clone,
    /// `__WALL`: every child regardless of exit signal.
    All,
}

impl WaitChildClass {
    pub fn from_wait_options(options: LinuxWaitOptions) -> Self {
        if options.contains(LinuxWaitOptions::WALL) {
            Self::All
        } else if options.contains(LinuxWaitOptions::WCLONE) {
            Self::Clone
        } else {
            Self::Sigchld
        }
    }

    pub fn admits(self, exit_signal: ChildExitSignal) -> bool {
        match self {
            Self::Sigchld => !exit_signal.is_clone_child(),
            Self::Clone => exit_signal.is_clone_child(),
            Self::All => true,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct WaitJobControl {
    stopped: bool,
    continued: bool,
}

/// Which children one wait call may reap: the `pid` argument of
/// `wait4`/`waitid` lowered to a single typed selector, so a pid, an exact
/// generation and a process group can never be combined inconsistently.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WaitTarget {
    Any,
    Pid(TaskId),
    Exact(TaskKey),
    ProcessGroup(ProcessGroupId),
}

impl WaitTarget {
    fn admits(self, child: TaskKey, process_group: ProcessGroupId) -> bool {
        match self {
            Self::Any => true,
            Self::Pid(target) => target == child.id,
            Self::Exact(target) => target == child,
            Self::ProcessGroup(group) => group == process_group,
        }
    }
}

impl WaitJobControl {
    const NONE: Self = Self {
        stopped: false,
        continued: false,
    };
}

/// The waiting parent's task-wake generation, sampled by the SAME registry
/// read that concluded no child was reapable.
///
/// Linux enqueues the waiter on the parent's wait queue BEFORE it rescans the
/// child list, so a child that exits between the scan and the sleep still
/// wakes the sleeper. This token is carrick's equivalent, and it exists as a
/// type because the generation is only correct when it is sampled at that one
/// moment: a producer edge for a child exit is published only after the exit
/// has committed under the registry WRITE lock, so any edge that happens after
/// this read necessarily carries a greater generation and the parked
/// continuation's probe sees it.
///
/// Sampling it later — when the continuation is captured, after the syscall
/// has already decided to block — silently loses every edge published in
/// between. That is how a `go build` wedged with its child already a zombie,
/// its parent's `wait4` continuation `enrolled` and quiet, and no SIGCHLD ever
/// posted (`target/perf/wedges/ohw-r2c-32079`). The only constructor is inside
/// the wait query, so "sampled at the wrong time" is not expressible.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
pub struct ChildWaitPrecheck(u64);

impl ChildWaitPrecheck {
    /// The parent's wake generation as of the scan that found nothing to reap.
    pub const fn wake_generation(self) -> u64 {
        self.0
    }

    /// Only for reconstructing a wait that never ran a scan (the host-process
    /// compatibility families, which have no kernel-graph child to observe).
    pub const fn unsampled() -> Self {
        Self(0)
    }

    /// Stand in for a scan's reading in a test that drives the race directly.
    #[cfg(test)]
    pub(crate) const fn for_test(wake_generation: u64) -> Self {
        Self(wake_generation)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WaitOutcome {
    Exited(Zombie),
    Stopped {
        task: TaskId,
        signal: LinuxSignal,
        ruid: NsUid,
    },
    Continued {
        task: TaskId,
        ruid: NsUid,
    },
    StillRunning(ChildWaitPrecheck),
    NoChild,
}

impl Kernel {
    /// A plain `wait`: `SIGCHLD` children only, exit events only.
    pub fn wait_child(
        &self,
        parent_id: TaskId,
        target: Option<TaskId>,
        mode: WaitMode,
    ) -> Result<WaitOutcome, KernelOperationError> {
        self.wait_child_matching(
            parent_id,
            target.map_or(WaitTarget::Any, WaitTarget::Pid),
            WaitChildClass::Sigchld,
            WaitJobControl::NONE,
            mode,
        )
    }

    pub fn wait_child_with_job_control(
        &self,
        parent_id: TaskId,
        target: Option<TaskId>,
        class: WaitChildClass,
        include_stopped: bool,
        include_continued: bool,
        mode: WaitMode,
    ) -> Result<WaitOutcome, KernelOperationError> {
        self.wait_child_matching(
            parent_id,
            target.map_or(WaitTarget::Any, WaitTarget::Pid),
            class,
            WaitJobControl {
                stopped: include_stopped,
                continued: include_continued,
            },
            mode,
        )
    }

    pub fn wait_child_key(
        &self,
        parent_id: TaskId,
        target: TaskKey,
        class: WaitChildClass,
        mode: WaitMode,
    ) -> Result<WaitOutcome, KernelOperationError> {
        self.wait_child_matching(
            parent_id,
            WaitTarget::Exact(target),
            class,
            WaitJobControl::NONE,
            mode,
        )
    }

    pub fn wait_child_in_process_group(
        &self,
        parent_id: TaskId,
        process_group: ProcessGroupId,
        mode: WaitMode,
    ) -> Result<WaitOutcome, KernelOperationError> {
        self.wait_child_matching(
            parent_id,
            WaitTarget::ProcessGroup(process_group),
            WaitChildClass::Sigchld,
            WaitJobControl::NONE,
            mode,
        )
    }

    pub fn wait_child_in_process_group_with_job_control(
        &self,
        parent_id: TaskId,
        process_group: ProcessGroupId,
        class: WaitChildClass,
        include_stopped: bool,
        include_continued: bool,
        mode: WaitMode,
    ) -> Result<WaitOutcome, KernelOperationError> {
        self.wait_child_matching(
            parent_id,
            WaitTarget::ProcessGroup(process_group),
            class,
            WaitJobControl {
                stopped: include_stopped,
                continued: include_continued,
            },
            mode,
        )
    }

    fn wait_child_matching(
        &self,
        parent_id: TaskId,
        target: WaitTarget,
        class: WaitChildClass,
        job_control: WaitJobControl,
        mode: WaitMode,
    ) -> Result<WaitOutcome, KernelOperationError> {
        self.sweep_retired_threads_for_process(Some(parent_id));

        // Read-only path:
        // For WaitMode::Observe, wait never modifies state; evaluate entirely under read lock.
        // For WaitMode::Consume, check under read lock if any child is reapable or has a job control
        // event. If none does, return StillRunning or NoChild without acquiring the write lock.
        // Under NO circumstance does the read lock return Exited or job control state changes in
        // WaitMode::Consume — check-and-consume must happen atomically under the write lock.
        {
            let state = self.registry().state.read();
            if mode == WaitMode::Consume {
                ensure_task_unreserved(&state, parent_id)?;
            }
            let Some((parent, _, children, tracees)) = state.tasks.get(&parent_id).map(|record| {
                (
                    record.task.key(),
                    record.task.pid_ns_region(),
                    record.task.children(),
                    record.task.ptrace_tracees(),
                )
            }) else {
                return Err(KernelOperationError::UnknownTask(parent_id));
            };
            let traced_non_children: Vec<TaskKey> = tracees
                .into_iter()
                .filter(|key| !children.contains(key))
                .collect();

            if mode == WaitMode::Observe {
                let exited = children.iter().find_map(|child_key| {
                    let record = state.zombies.get(&child_key.id)?;
                    if record.zombie.key == *child_key
                        && record.zombie.parent == Some(parent)
                        && class.admits(record.zombie.exit_signal)
                        && target.admits(*child_key, record.zombie.process_group)
                    {
                        Some((child_key.id, record.zombie.clone()))
                    } else {
                        None
                    }
                });
                if let Some((_id, zombie)) = exited {
                    return Ok(WaitOutcome::Exited(zombie));
                }

                let state_change = children.iter().find_map(|child_key| {
                    let record = state.tasks.get(&child_key.id)?;
                    if record.task.key() == *child_key
                        && record.task.parent() == Some(parent)
                        && class.admits(record.task.exit_signal())
                        && target.admits(*child_key, record.task.process_group())
                    {
                        record
                            .task
                            .waitable_job_control_event(
                                job_control.stopped,
                                job_control.continued,
                                false,
                            )
                            .map(|event| match event {
                                TaskJobControlEvent::Stopped(signal) => WaitOutcome::Stopped {
                                    task: child_key.id,
                                    signal,
                                    ruid: record.task.process_credentials().ruid(),
                                },
                                TaskJobControlEvent::Continued => WaitOutcome::Continued {
                                    task: child_key.id,
                                    ruid: record.task.process_credentials().ruid(),
                                },
                            })
                    } else {
                        None
                    }
                });
                if let Some(state_change) = state_change {
                    return Ok(state_change);
                }

                let tracee_stop = traced_non_children.iter().find_map(|tracee_key| {
                    let record = state.tasks.get(&tracee_key.id)?;
                    if record.task.key() == *tracee_key
                        && record.task.ptrace_tracer() == Some(parent)
                        && target.admits(*tracee_key, record.task.process_group())
                    {
                        record
                            .task
                            .waitable_job_control_event(true, job_control.continued, false)
                            .map(|event| match event {
                                TaskJobControlEvent::Stopped(signal) => WaitOutcome::Stopped {
                                    task: tracee_key.id,
                                    signal,
                                    ruid: record.task.process_credentials().ruid(),
                                },
                                TaskJobControlEvent::Continued => WaitOutcome::Continued {
                                    task: tracee_key.id,
                                    ruid: record.task.process_credentials().ruid(),
                                },
                            })
                    } else {
                        None
                    }
                });
                if let Some(tracee_stop) = tracee_stop {
                    return Ok(tracee_stop);
                }

                let live_tracee = traced_non_children.iter().any(|tracee_key| {
                    let Some(record) = state.tasks.get(&tracee_key.id) else {
                        return false;
                    };
                    record.task.key() == *tracee_key
                        && record.task.ptrace_tracer() == Some(parent)
                        && target.admits(*tracee_key, record.task.process_group())
                });
                let live_child = live_tracee
                    || children.iter().any(|child_key| {
                        let Some(record) = state.tasks.get(&child_key.id) else {
                            return false;
                        };
                        record.task.key() == *child_key
                            && record.task.parent() == Some(parent)
                            && class.admits(record.task.exit_signal())
                            && target.admits(*child_key, record.task.process_group())
                    });
                return Ok(if live_child {
                    WaitOutcome::StillRunning(sample_precheck(&state, parent_id))
                } else {
                    WaitOutcome::NoChild
                });
            } else {
                let has_exited_child = children.iter().any(|child_key| {
                    state.zombies.get(&child_key.id).is_some_and(|record| {
                        record.zombie.key == *child_key
                            && record.zombie.parent == Some(parent)
                            && class.admits(record.zombie.exit_signal)
                            && target.admits(*child_key, record.zombie.process_group)
                    })
                });
                let has_job_control = children.iter().any(|child_key| {
                    state.tasks.get(&child_key.id).is_some_and(|record| {
                        record.task.key() == *child_key
                            && record.task.parent() == Some(parent)
                            && class.admits(record.task.exit_signal())
                            && target.admits(*child_key, record.task.process_group())
                            && record
                                .task
                                .waitable_job_control_event(
                                    job_control.stopped,
                                    job_control.continued,
                                    false,
                                )
                                .is_some()
                    })
                }) || traced_non_children.iter().any(|tracee_key| {
                    state.tasks.get(&tracee_key.id).is_some_and(|record| {
                        record.task.key() == *tracee_key
                            && record.task.ptrace_tracer() == Some(parent)
                            && target.admits(*tracee_key, record.task.process_group())
                            && record
                                .task
                                .waitable_job_control_event(true, job_control.continued, false)
                                .is_some()
                    })
                });

                if !has_exited_child && !has_job_control {
                    let live_tracee = traced_non_children.iter().any(|tracee_key| {
                        let Some(record) = state.tasks.get(&tracee_key.id) else {
                            return false;
                        };
                        record.task.key() == *tracee_key
                            && record.task.ptrace_tracer() == Some(parent)
                            && target.admits(*tracee_key, record.task.process_group())
                    });
                    let live_child = live_tracee
                        || children.iter().any(|child_key| {
                            let Some(record) = state.tasks.get(&child_key.id) else {
                                return false;
                            };
                            record.task.key() == *child_key
                                && record.task.parent() == Some(parent)
                                && class.admits(record.task.exit_signal())
                                && target.admits(*child_key, record.task.process_group())
                        });
                    return Ok(if live_child {
                        WaitOutcome::StillRunning(sample_precheck(&state, parent_id))
                    } else {
                        WaitOutcome::NoChild
                    });
                }
            }
        }

        let mut state = self.registry().state.write();
        if mode == WaitMode::Consume {
            ensure_task_unreserved(&state, parent_id)?;
        }
        let Some((parent, parent_pid_region, children, tracees)) =
            state.tasks.get(&parent_id).map(|record| {
                (
                    record.task.key(),
                    record.task.pid_ns_region(),
                    record.task.children(),
                    record.task.ptrace_tracees(),
                )
            })
        else {
            return Err(KernelOperationError::UnknownTask(parent_id));
        };
        // ptrace(2): a tracer waits for its tracees' ptrace stops whether or
        // not it is their parent. Only stop/continue events are reported for
        // a non-child tracee here; its exit still belongs to the real parent
        // (Linux would report that exit to the tracer first), so a tracer
        // waiting on a non-child tracee that exits sees ECHILD instead.
        let traced_non_children: Vec<TaskKey> = tracees
            .into_iter()
            .filter(|key| !children.contains(key))
            .collect();
        let exited = children.iter().find_map(|child_key| {
            let record = state.zombies.get(&child_key.id)?;
            if record.zombie.key == *child_key
                && record.zombie.parent == Some(parent)
                && class.admits(record.zombie.exit_signal)
                && target.admits(*child_key, record.zombie.process_group)
            {
                Some((child_key.id, record.zombie.clone()))
            } else {
                None
            }
        });
        if let Some((id, zombie)) = exited {
            if mode == WaitMode::Consume {
                ensure_task_unreserved(&state, id)?;
                let parent_revision = state
                    .tasks
                    .get(&parent_id)
                    .map(|record| next_revision(record.revision))
                    .transpose()?
                    .ok_or(KernelOperationError::UnknownTask(parent_id))?;
                state.zombies.remove(&id);
                if let Some(parent_record) = state.tasks.get_mut(&parent_id) {
                    parent_record.task.remove_child(zombie.key);
                    // Reaping is the moment Linux moves a child's CPU into the
                    // parent's CHILDREN ledger — the child's own time plus what
                    // it had already reaped from its own children. Doing it here
                    // means only a CONSUMING wait charges it, so a WNOHANG poll
                    // or a WNOWAIT peek cannot double-count.
                    parent_record
                        .task
                        .charge_reaped_child(zombie.total_charge_to_reaper());
                    parent_record.revision = parent_revision;
                }
                drop(state);
                self.auditors().reaped(parent, zombie.key);
                if let Some(region) = parent_pid_region {
                    let internal = u32::try_from(id.raw()).unwrap_or_else(|_| {
                        carrick_fatal!(
                            "kernel::child_reaping",
                            "zombie id exceeds u32 in wait_child_matching"
                        );
                    });
                    if !region.unregister_reaped(internal) {
                        carrick_fatal!(
                            "kernel::child_reaping",
                            "failed to unregister reaped child in wait_child_matching"
                        );
                    }
                }
            }
            return Ok(WaitOutcome::Exited(zombie));
        }

        {
            let state_change = children.iter().find_map(|child_key| {
                let record = state.tasks.get(&child_key.id)?;
                if record.task.key() == *child_key
                    && record.task.parent() == Some(parent)
                    && class.admits(record.task.exit_signal())
                    && target.admits(*child_key, record.task.process_group())
                {
                    record
                        .task
                        .waitable_job_control_event(
                            job_control.stopped,
                            job_control.continued,
                            mode == WaitMode::Consume,
                        )
                        .map(|event| match event {
                            TaskJobControlEvent::Stopped(signal) => WaitOutcome::Stopped {
                                task: child_key.id,
                                signal,
                                ruid: record.task.process_credentials().ruid(),
                            },
                            TaskJobControlEvent::Continued => WaitOutcome::Continued {
                                task: child_key.id,
                                ruid: record.task.process_credentials().ruid(),
                            },
                        })
                } else {
                    None
                }
            });
            if let Some(state_change) = state_change {
                return Ok(state_change);
            }
        }
        {
            let tracee_stop = traced_non_children.iter().find_map(|tracee_key| {
                let record = state.tasks.get(&tracee_key.id)?;
                if record.task.key() == *tracee_key
                    && record.task.ptrace_tracer() == Some(parent)
                    && target.admits(*tracee_key, record.task.process_group())
                {
                    record
                        .task
                        .waitable_job_control_event(
                            true,
                            job_control.continued,
                            mode == WaitMode::Consume,
                        )
                        .map(|event| match event {
                            TaskJobControlEvent::Stopped(signal) => WaitOutcome::Stopped {
                                task: tracee_key.id,
                                signal,
                                ruid: record.task.process_credentials().ruid(),
                            },
                            TaskJobControlEvent::Continued => WaitOutcome::Continued {
                                task: tracee_key.id,
                                ruid: record.task.process_credentials().ruid(),
                            },
                        })
                } else {
                    None
                }
            });
            if let Some(tracee_stop) = tracee_stop {
                return Ok(tracee_stop);
            }
        }

        let live_tracee = traced_non_children.iter().any(|tracee_key| {
            let Some(record) = state.tasks.get(&tracee_key.id) else {
                return false;
            };
            record.task.key() == *tracee_key
                && record.task.ptrace_tracer() == Some(parent)
                && target.admits(*tracee_key, record.task.process_group())
        });
        let live_child = live_tracee
            || children.iter().any(|child_key| {
                let Some(record) = state.tasks.get(&child_key.id) else {
                    return false;
                };
                record.task.key() == *child_key
                    && record.task.parent() == Some(parent)
                    && class.admits(record.task.exit_signal())
                    && target.admits(*child_key, record.task.process_group())
            });
        Ok(if live_child {
            WaitOutcome::StillRunning(sample_precheck(&state, parent_id))
        } else {
            WaitOutcome::NoChild
        })
    }
}

/// Sample the waiting parent's wake generation under the registry lock that
/// just concluded nothing was reapable. See [`ChildWaitPrecheck`]: taking this
/// reading anywhere else reintroduces the lost wake it exists to prevent.
fn sample_precheck(state: &RegistryState, parent_id: TaskId) -> ChildWaitPrecheck {
    ChildWaitPrecheck(
        state
            .tasks
            .get(&parent_id)
            .map_or(0, |record| record.task.wake_generation()),
    )
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::kernel::objects::LinuxWaitStatus;
    use carrick_abi::LinuxCloneFlags;
    use carrick_hal::ThreadId;

    use super::*;
    use crate::kernel::clone_plan::ClonePlan;
    use crate::kernel::ids::{ChildExitSignal, LinuxTid};
    use crate::kernel::operations::tests::{bootstrap, fork_child, fork_child_with_plan};

    #[test]
    fn wait_child_can_select_an_authoritative_guest_process_group() {
        let (kernel, root) = bootstrap(1);
        let root_id = root.task().key().id;
        let child_id = fork_child(&kernel, &root, "wait group child", 702);
        let child_ruid = carrick_abi::NsUid::new(4_702);
        let child_euid = carrick_abi::NsUid::new(6_702);
        let child = kernel
            .context(child_id, LinuxTid::for_task_leader(child_id))
            .expect("child context");
        let _child = kernel
            .update_credentials(&child, |credentials| {
                credentials.seed_identity(child_euid, carrick_abi::NsGid::new(6_702));
                credentials.set_uid_triple(child_ruid, child_euid, child_euid);
            })
            .expect("set distinct child real and effective credentials");
        let group = kernel
            .create_process_group(child_id, None)
            .expect("child process group");
        kernel
            .exit_task(child_id, LinuxWaitStatus::from_wait_encoding(0), None)
            .expect("retire child");

        let outcome = kernel
            .wait_child_in_process_group(root_id, group, WaitMode::Consume)
            .expect("wait child group");
        let WaitOutcome::Exited(zombie) = outcome else {
            panic!("wait must select the child from its guest process group: {outcome:?}");
        };
        assert_eq!(zombie.key.id, child_id);
        assert_eq!(zombie.ruid, child_ruid, "waitid retains the real uid");
        assert_eq!(
            zombie.euid, child_euid,
            "ownership retains the effective uid"
        );
    }

    /// wait(2): a child whose exit signal is not `SIGCHLD` is a "clone child"
    /// that a plain wait must not see -- neither as a zombie nor as a reason
    /// to block -- while `__WCLONE` sees only it and `__WALL` sees everything.
    /// The retained `lifecycleflagmatrix` probe depends on the ECHILD arm: its
    /// parent polls `waitpid(WNOHANG)` on a `clone(CLONE_VM|0xff, stack=NULL)`
    /// child and, on Linux, gets ECHILD at once and SIGKILLs the child before
    /// it runs. Reaping it instead let the child run on the parent's stack.
    #[test]
    fn wait_partitions_children_by_exit_signal() {
        let (kernel, root) = bootstrap(1);
        let root_id = root.task().key().id;
        let clone_plan = ClonePlan::from_flags(LinuxCloneFlags::VM)
            .expect("clone plan")
            .with_exit_signal(ChildExitSignal::None);
        let clone_child = fork_child_with_plan(&kernel, &root, clone_plan, "clone-child", 21);
        let fork_child_id = fork_child(&kernel, &root, "fork-child", 22);

        // Both alive: a plain wait blocks only on the SIGCHLD child, a
        // __WCLONE wait only on the clone child.
        for (class, expected) in [
            (
                WaitChildClass::Sigchld,
                WaitOutcome::StillRunning(ChildWaitPrecheck::unsampled()),
            ),
            (
                WaitChildClass::Clone,
                WaitOutcome::StillRunning(ChildWaitPrecheck::unsampled()),
            ),
            (
                WaitChildClass::All,
                WaitOutcome::StillRunning(ChildWaitPrecheck::unsampled()),
            ),
        ] {
            assert_eq!(
                kernel
                    .wait_child_with_job_control(
                        root_id,
                        None,
                        class,
                        false,
                        false,
                        WaitMode::Consume
                    )
                    .expect("wait"),
                expected,
                "{class:?} with both children live"
            );
        }
        assert_eq!(
            kernel
                .wait_child_with_job_control(
                    root_id,
                    Some(clone_child),
                    WaitChildClass::Sigchld,
                    false,
                    false,
                    WaitMode::Consume
                )
                .expect("wait"),
            WaitOutcome::NoChild,
            "a plain wait naming a live clone child is ECHILD, not a block"
        );
        assert_eq!(
            kernel
                .wait_child_with_job_control(
                    root_id,
                    Some(fork_child_id),
                    WaitChildClass::Clone,
                    false,
                    false,
                    WaitMode::Consume
                )
                .expect("wait"),
            WaitOutcome::NoChild,
            "__WCLONE naming a live SIGCHLD child is ECHILD"
        );

        kernel
            .exit_task(clone_child, LinuxWaitStatus::from_wait_encoding(0), None)
            .expect("exit clone child");

        // The clone child's zombie is invisible to a plain wait, which still
        // blocks on the live fork child ...
        assert!(
            matches!(
                kernel
                    .wait_child(root_id, None, WaitMode::Consume)
                    .expect("wait"),
                WaitOutcome::StillRunning(_)
            ),
            "plain wait must not reap a clone child"
        );
        assert_eq!(
            kernel
                .wait_child(root_id, Some(clone_child), WaitMode::Consume)
                .expect("wait"),
            WaitOutcome::NoChild,
            "plain wait naming a clone-child zombie is ECHILD"
        );
        // ... and __WCLONE reaps it.
        let WaitOutcome::Exited(zombie) = kernel
            .wait_child_with_job_control(
                root_id,
                None,
                WaitChildClass::Clone,
                false,
                false,
                WaitMode::Consume,
            )
            .expect("wait")
        else {
            panic!("__WCLONE did not reap the clone child");
        };
        assert_eq!(zombie.key.id, clone_child);
        assert_eq!(zombie.exit_signal, ChildExitSignal::None);
        assert_eq!(
            kernel
                .wait_child_with_job_control(
                    root_id,
                    None,
                    WaitChildClass::Clone,
                    false,
                    false,
                    WaitMode::Consume
                )
                .expect("wait"),
            WaitOutcome::NoChild,
            "no clone children remain"
        );

        kernel
            .exit_task(fork_child_id, LinuxWaitStatus::from_wait_encoding(0), None)
            .expect("exit fork child");
        let WaitOutcome::Exited(zombie) = kernel
            .wait_child_with_job_control(
                root_id,
                None,
                WaitChildClass::All,
                false,
                false,
                WaitMode::Consume,
            )
            .expect("wait")
        else {
            panic!("__WALL did not reap the fork child");
        };
        assert_eq!(zombie.key.id, fork_child_id);
        assert_eq!(zombie.exit_signal, ChildExitSignal::SIGCHLD);
    }

    #[test]
    fn wait_child_class_follows_wait_options() {
        assert_eq!(
            WaitChildClass::from_wait_options(LinuxWaitOptions::WNOHANG),
            WaitChildClass::Sigchld
        );
        assert_eq!(
            WaitChildClass::from_wait_options(LinuxWaitOptions::WCLONE),
            WaitChildClass::Clone
        );
        assert_eq!(
            WaitChildClass::from_wait_options(LinuxWaitOptions::WALL | LinuxWaitOptions::WCLONE),
            WaitChildClass::All
        );
        assert_eq!(ChildExitSignal::for_clone_request(0), ChildExitSignal::None);
        assert_eq!(
            ChildExitSignal::for_clone_request(17),
            ChildExitSignal::SIGCHLD
        );
        assert!(ChildExitSignal::for_clone_request(9).is_clone_child());
        assert!(!ChildExitSignal::SIGCHLD.is_clone_child());
    }

    #[test]
    fn wait_consume_never_returns_unconsumed_zombie_under_interleaved_exit() {
        let (kernel, root) = bootstrap(199);
        let fork_plan = ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan");
        for i in 0..100 {
            let child = kernel
                .fork_task(
                    &root,
                    fork_plan,
                    ThreadId::synthetic_for_tests(10_000 + i),
                    format!("child-{i}"),
                    None,
                )
                .expect("fork");
            let child_id = child.task().key().id;
            drop(child);

            let waiter_kernel = Arc::clone(&kernel);
            let root_id = root.task().key().id;

            let waiter = std::thread::spawn(move || {
                loop {
                    match waiter_kernel.wait_child(root_id, Some(child_id), WaitMode::Consume) {
                        Ok(WaitOutcome::StillRunning(_)) => {
                            std::thread::yield_now();
                        }
                        Ok(WaitOutcome::Exited(zombie)) => {
                            assert_eq!(zombie.key.id, child_id);
                            assert_eq!(
                                waiter_kernel.registry().zombie_count(),
                                0,
                                "zombie must be consumed when WaitMode::Consume returns Exited"
                            );
                            assert!(
                                matches!(
                                    waiter_kernel.wait_child(
                                        root_id,
                                        Some(child_id),
                                        WaitMode::Consume
                                    ),
                                    Ok(WaitOutcome::NoChild)
                                ),
                                "second wait in WaitMode::Consume must return NoChild, not double reap"
                            );
                            break;
                        }
                        other => panic!("unexpected wait outcome: {other:?}"),
                    }
                }
            });

            std::thread::yield_now();
            kernel
                .exit_task(child_id, LinuxWaitStatus::from_wait_encoding(0), None)
                .expect("exit");

            waiter.join().expect("waiter thread join");
        }
    }

    #[test]
    fn zombie_holds_numeric_claim_until_consuming_wait() {
        let (kernel, root) = bootstrap(400);
        let child = kernel
            .fork_task(
                &root,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
                ThreadId::synthetic_for_tests(401),
                "child".to_string(),
                None,
            )
            .expect("fork");
        let child_id = child.task.key().id;
        drop(child);

        assert!(matches!(
            kernel.wait_child(root.task.key().id, Some(child_id), WaitMode::Observe),
            Ok(WaitOutcome::StillRunning(_))
        ));
        kernel
            .exit_task(child_id, LinuxWaitStatus::from_wait_encoding(7 << 8), None)
            .expect("exit");
        assert!(kernel.ids().is_reserved_number(child_id.raw()));
        assert!(matches!(
            kernel.wait_child(root.task.key().id, Some(child_id), WaitMode::Observe),
            Ok(WaitOutcome::Exited(_))
        ));
        assert!(kernel.ids().is_reserved_number(child_id.raw()));
        assert!(matches!(
            kernel.wait_child(root.task.key().id, Some(child_id), WaitMode::Consume),
            Ok(WaitOutcome::Exited(_))
        ));
        kernel.sweep_retired_threads();
        assert!(!kernel.ids().is_reserved_number(child_id.raw()));
        assert_eq!(kernel.registry().zombie_count(), 0);
    }
}
