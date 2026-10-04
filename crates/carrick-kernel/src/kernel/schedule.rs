//! Graph-owned scheduling seams for explicitly selected VM-free debug tests.
//! Never invoke a suspending observer while holding a subsystem guard.

use super::{
    KernelContext, TaskKey,
    objects::{ExecutionGeneration, ThreadKey},
};
use serde::{Deserialize, Serialize};

/// Stable operation boundaries, independent of host thread or function address.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Point {
    BeforeCredentialAdmission,
    CredentialWaiting,
    CredentialResumed,
    CredentialPublished,
    BeforeThreadReservation,
    ThreadPublished,
    BirthRecorded,
    BeforeFirstEntry,
    FirstEntryFinished,
    BeforeExecAdmission,
    ExecAdmitted,
    BeforeWaitEnrollment,
    WaitEnrolled,
    WakePublished,
    BeforeLock,
    AfterUnlock,
    AdmissionReleased,
}

impl Point {
    /// Publication under a registry guard and asynchronous wake delivery only
    /// observe; they cannot transfer a coordinator permit.
    pub const fn observation_only(self) -> bool {
        matches!(self, Self::CredentialPublished | Self::WakePublished)
    }
}

/// A scheduling actor names the exact kernel incarnation it is executing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Subject {
    pub task: TaskKey,
    pub thread: ThreadKey,
    pub generation: Option<ExecutionGeneration>,
}
impl Subject {
    pub fn from_context(context: &KernelContext) -> Self {
        Self {
            task: context.task().key(),
            thread: context.thread().key(),
            generation: context.thread().execution_state().generation(),
        }
    }
}

/// Authority involved in a boundary, authenticated independently of the actor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Authority {
    Thread(Subject),
    Wait(super::continuation::ContinuationWakeToken),
    Object(carrick_sched_core::object_wait::ObjectWaitKey),
}

/// Pointer-free authority DTO retained by a replay receipt, never used to
/// authorize a kernel operation. Generation absence is distinct from zero.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ThreadStamp {
    pub task_id: i32,
    pub task_serial: u64,
    pub thread_id: i32,
    pub thread_serial: u64,
    pub execution_generation: Option<u64>,
}
impl From<Subject> for ThreadStamp {
    fn from(subject: Subject) -> Self {
        Self {
            task_id: subject.task.id.raw(),
            task_serial: subject.task.serial.raw(),
            thread_id: subject.thread.tid.raw(),
            thread_serial: subject.thread.serial.raw(),
            execution_generation: subject.generation.map(|g| g.raw()),
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum AuthorityStamp {
    Thread(ThreadStamp),
    Object {
        index: u32,
        generation: u64,
    },
    Wait {
        continuation: u64,
        recipient: ThreadStamp,
        thread_serial: u64,
        execution_raw: u64,
        mm_generation: u64,
        asid_generation: u64,
        resource_generation: u64,
        registration_generation: u64,
    },
}
impl Authority {
    pub fn stamp(self) -> AuthorityStamp {
        match self {
            Self::Thread(subject) => AuthorityStamp::Thread(subject.into()),
            Self::Object(object) => AuthorityStamp::Object {
                index: object.index(),
                generation: object.generation(),
            },
            Self::Wait(token) => AuthorityStamp::Wait {
                continuation: token.continuation.raw(),
                recipient: Subject {
                    task: token.task,
                    thread: token.thread,
                    generation: Some(token.execution),
                }
                .into(),
                thread_serial: token.thread_serial,
                execution_raw: token.execution_raw,
                mm_generation: token.mm_generation,
                asid_generation: token.asid_generation,
                resource_generation: token.resource_generation,
                registration_generation: token.registration_generation,
            },
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Event {
    pub point: Point,
    pub actor: Option<Subject>,
    pub authority: Authority,
}
impl Event {
    pub fn thread(context: &KernelContext, point: Point) -> Self {
        let subject = Subject::from_context(context);
        Self {
            point,
            actor: Some(subject),
            authority: Authority::Thread(subject),
        }
    }
}

#[cfg(all(debug_assertions, feature = "schedule-hooks"))]
mod enabled {
    use super::Event;
    use parking_lot::RwLock;
    use std::sync::Arc;

    type Observer = Arc<dyn Fn(Event) + Send + Sync>;

    /// No ambient observer: each kernel graph/service owns its subscription.
    #[derive(Default)]
    pub struct Hooks(RwLock<Option<Observer>>);
    impl std::fmt::Debug for Hooks {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("ScheduleHooks").finish_non_exhaustive()
        }
    }
    impl Hooks {
        pub fn set(&self, observer: Option<Observer>) {
            *self.0.write() = observer;
        }
        pub fn emit(&self, event: Event) {
            let observer = self.0.read().clone();
            if let Some(observer) = observer {
                observer(event);
            }
        }
    }
}
#[cfg(all(debug_assertions, feature = "schedule-hooks"))]
pub use enabled::Hooks;

/// One hook API for kernel and harness; the kernel feature decides whether
/// operation arguments are even evaluated. Product/release calls expand empty.
#[cfg(all(debug_assertions, feature = "schedule-hooks"))]
#[macro_export]
macro_rules! schedule_point {
    ($hooks:expr, $event:expr) => {
        $hooks.emit($event)
    };
    ($shared:expr, $task:expr, $point:expr) => {{
        if let Some(schedule) = &$shared.schedule {
            schedule.point($task.schedule_actor(), $point)
        } else {
            Ok(())
        }
    }};
}

#[cfg(not(all(debug_assertions, feature = "schedule-hooks")))]
#[macro_export]
macro_rules! schedule_point {
    ($hooks:expr, $event:expr) => {};
    ($shared:expr, $task:expr, $point:expr) => {
        Ok::<(), String>(())
    };
}
