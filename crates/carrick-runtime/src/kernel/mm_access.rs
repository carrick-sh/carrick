//! Kernel-minted authority for one exact Linux address-space incarnation.

use std::marker::PhantomData;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};

use carrick_guest_mem::GuestVa;

use super::{
    Kernel, KernelContext, Mm, MmBackendSnapshot, MmId, SnapshotError, TaskKey, TaskLifecycle,
};

const MM_SNAPSHOT_TIMEOUT: Duration = Duration::from_millis(50);

/// A retained, coherent observation of one exact `mm` incarnation.
///
/// Construction is confined to the kernel graph. The retained [`Arc`] keeps
/// the old address space alive across target exec and retirement without
/// retaining or following the task itself.
#[derive(Clone, Debug)]
pub struct MmToken {
    task: TaskKey,
    mm: Arc<Mm>,
    snapshot: MmBackendSnapshot,
}

impl MmToken {
    pub const fn task_key(&self) -> TaskKey {
        self.task
    }

    pub fn mm_id(&self) -> MmId {
        self.mm.id()
    }

    pub fn mm(&self) -> &Arc<Mm> {
        &self.mm
    }

    pub fn read_range(
        &self,
        start: GuestVa,
        len: usize,
    ) -> Result<Option<MmReadRange<'_>>, MmAccessError> {
        let Some(len) = NonZeroUsize::new(len) else {
            return Ok(None);
        };
        self.validate_range(start, len, RangeAccess::Read)?;
        Ok(Some(MmReadRange {
            token: self,
            start,
            len,
        }))
    }

    pub fn kernel_read_range(
        &self,
        start: GuestVa,
        len: usize,
    ) -> Result<Option<MmReadRange<'_>>, MmAccessError> {
        let Some(len) = NonZeroUsize::new(len) else {
            return Ok(None);
        };
        self.validate_range(start, len, RangeAccess::KernelRead)?;
        Ok(Some(MmReadRange {
            token: self,
            start,
            len,
        }))
    }

    pub fn write_range(
        &self,
        start: GuestVa,
        len: usize,
    ) -> Result<Option<MmWriteRange<'_>>, MmAccessError> {
        let Some(len) = NonZeroUsize::new(len) else {
            return Ok(None);
        };
        self.validate_range(start, len, RangeAccess::Write)?;
        Ok(Some(MmWriteRange {
            token: self,
            start,
            len,
        }))
    }

    fn validate_range(
        &self,
        start: GuestVa,
        len: NonZeroUsize,
        requested: RangeAccess,
    ) -> Result<(), MmAccessError> {
        let len_u64 = u64::try_from(len.get()).map_err(|_| MmAccessError::RangeOverflow {
            start,
            len: len.get(),
        })?;
        let end = start
            .raw()
            .checked_add(len_u64)
            .ok_or(MmAccessError::RangeOverflow {
                start,
                len: len.get(),
            })?;
        let mut cursor = start.raw();

        for vma in &self.snapshot.vmas {
            if vma.end.raw() <= cursor {
                continue;
            }
            if vma.start.raw() > cursor {
                return Err(MmAccessError::Unmapped {
                    address: GuestVa(cursor),
                });
            }

            let access_error = match requested {
                RangeAccess::Read if !vma.access.readable => Some(MmAccessError::ReadDenied {
                    address: GuestVa(cursor),
                }),
                RangeAccess::Write if !vma.access.writable => Some(MmAccessError::WriteDenied {
                    address: GuestVa(cursor),
                }),
                RangeAccess::KernelRead if !vma.access.kernel_visible => {
                    Some(MmAccessError::KernelHidden {
                        address: GuestVa(cursor),
                    })
                }
                RangeAccess::KernelRead if !vma.access.readable => {
                    Some(MmAccessError::ReadDenied {
                        address: GuestVa(cursor),
                    })
                }
                _ => None,
            };
            if let Some(error) = access_error {
                return Err(error);
            }

            cursor = vma.end.raw().min(end);
            if cursor == end {
                return Ok(());
            }
        }

        Err(MmAccessError::Unmapped {
            address: GuestVa(cursor),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RangeAccess {
    Read,
    KernelRead,
    Write,
}

/// A readable non-empty range bound by lifetime to its exact MM token.
#[derive(Clone, Copy, Debug)]
pub struct MmReadRange<'mm> {
    token: &'mm MmToken,
    start: GuestVa,
    len: NonZeroUsize,
}

impl MmReadRange<'_> {
    pub const fn start(&self) -> GuestVa {
        self.start
    }

    pub const fn len(&self) -> NonZeroUsize {
        self.len
    }

    pub fn mm_id(&self) -> MmId {
        self.token.mm_id()
    }
}

/// A writable non-empty range bound by lifetime to its exact MM token.
#[derive(Debug)]
pub struct MmWriteRange<'mm> {
    token: &'mm MmToken,
    start: GuestVa,
    len: NonZeroUsize,
}

impl MmWriteRange<'_> {
    pub const fn start(&self) -> GuestVa {
        self.start
    }

    pub const fn len(&self) -> NonZeroUsize {
        self.len
    }

    pub fn mm_id(&self) -> MmId {
        self.token.mm_id()
    }
}

/// Current-MM authority tied to the exact captured kernel context.
#[derive(Clone, Debug)]
pub struct CurrentMm<'context> {
    token: MmToken,
    context: PhantomData<&'context KernelContext>,
}

impl CurrentMm<'_> {
    pub fn mm_id(&self) -> MmId {
        self.token.mm_id()
    }
}

/// Foreign-MM authority retaining an exact target address space.
#[derive(Clone, Debug)]
pub struct ForeignMm {
    token: MmToken,
}

impl ForeignMm {
    pub fn mm_id(&self) -> MmId {
        self.token.mm_id()
    }

    pub fn mm(&self) -> &Arc<Mm> {
        self.token.mm()
    }
}

#[derive(Clone, Debug)]
pub enum MmRelation<'context> {
    Current(CurrentMm<'context>),
    Foreign(ForeignMm),
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum MmAccessError {
    #[error("kernel task {0:?} is not live at the requested generation")]
    UnknownTask(TaskKey),
    #[error("kernel context for task {0:?} no longer names its exact live task/MM binding")]
    StaleContext(TaskKey),
    #[error("MM {0:?} has no backend snapshot authority")]
    MissingBackendAuthority(MmId),
    #[error(transparent)]
    Snapshot(#[from] SnapshotError),
    #[error("MM snapshot contains malformed or overlapping VMA {start:?}..{end:?}")]
    MalformedVma { start: GuestVa, end: GuestVa },
    #[error("MM range {start:?} + {len} bytes overflows the guest VA domain")]
    RangeOverflow { start: GuestVa, len: usize },
    #[error("guest address {address:?} is not mapped in this MM")]
    Unmapped { address: GuestVa },
    #[error("guest address {address:?} is not readable in this MM")]
    ReadDenied { address: GuestVa },
    #[error("guest address {address:?} is not writable in this MM")]
    WriteDenied { address: GuestVa },
    #[error("guest address {address:?} is hidden from kernel memory access")]
    KernelHidden { address: GuestVa },
}

impl KernelContext {
    pub fn current_mm(&self) -> Result<CurrentMm<'_>, MmAccessError> {
        let mm = self.authenticate_current_mm()?;
        let token = snapshot_token(self.task.key(), mm)?;
        Ok(CurrentMm {
            token,
            context: PhantomData,
        })
    }

    fn authenticate_current_mm(&self) -> Result<Arc<Mm>, MmAccessError> {
        let key = self.task.key();
        if self.task.lifecycle() != TaskLifecycle::Live || self.thread.task_key() != key {
            return Err(MmAccessError::StaleContext(key));
        }
        let Some(live_task) = self.kernel.registry().task(key.id) else {
            return Err(MmAccessError::StaleContext(key));
        };
        let Some(live_thread) = live_task.thread(self.thread.key().tid) else {
            return Err(MmAccessError::StaleContext(key));
        };
        let live_shared = live_task.shared();
        let context_mm = self.shared.mm();
        let live_mm = live_shared.mm();
        if live_task.key() != key
            || !Arc::ptr_eq(&live_task, &self.task)
            || !Arc::ptr_eq(&live_thread, &self.thread)
            || !Arc::ptr_eq(&live_shared, &self.shared)
            || live_mm.id() != context_mm.id()
            || !Arc::ptr_eq(&live_mm, &context_mm)
        {
            return Err(MmAccessError::StaleContext(key));
        }
        Ok(context_mm)
    }
}

impl Kernel {
    pub fn foreign_mm<'context>(
        &self,
        caller: &'context KernelContext,
        target: TaskKey,
    ) -> Result<MmRelation<'context>, MmAccessError> {
        if !std::ptr::eq(self, caller.kernel.as_ref()) {
            return Err(MmAccessError::StaleContext(caller.task.key()));
        }
        let caller_mm = caller.authenticate_current_mm()?;
        let Some(task) = self.registry().task(target.id) else {
            return Err(MmAccessError::UnknownTask(target));
        };
        if task.key() != target || task.lifecycle() != TaskLifecycle::Live {
            return Err(MmAccessError::UnknownTask(target));
        }
        let target_mm = task.shared().mm();
        let token = snapshot_token(target, target_mm)?;
        if token.mm_id() == caller_mm.id() && Arc::ptr_eq(token.mm(), &caller_mm) {
            Ok(MmRelation::Current(CurrentMm {
                token,
                context: PhantomData,
            }))
        } else {
            Ok(MmRelation::Foreign(ForeignMm { token }))
        }
    }
}

fn snapshot_token(task: TaskKey, mm: Arc<Mm>) -> Result<MmToken, MmAccessError> {
    let backend = mm
        .backend()
        .ok_or(MmAccessError::MissingBackendAuthority(mm.id()))?;
    let deadline = Instant::now() + MM_SNAPSHOT_TIMEOUT;
    let mut snapshot = backend.snapshot(deadline)?;
    if backend.revision() != snapshot.revision
        || backend.vma_revision(deadline)? != snapshot.vma_revision
    {
        return Err(MmAccessError::Snapshot(
            SnapshotError::ChangedDuringObservation,
        ));
    }
    snapshot
        .vmas
        .sort_unstable_by_key(|vma| (vma.start.raw(), vma.end.raw()));
    let mut previous_end = None;
    for vma in &snapshot.vmas {
        if vma.start.raw() >= vma.end.raw() || previous_end.is_some_and(|end| vma.start.raw() < end)
        {
            return Err(MmAccessError::MalformedVma {
                start: vma.start,
                end: vma.end,
            });
        }
        previous_end = Some(vma.end.raw());
    }
    Ok(MmToken { task, mm, snapshot })
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU16;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Instant;

    use carrick_abi::LinuxCloneFlags;
    use carrick_guest_mem::{Gpa, GuestVa};
    use carrick_hal::ThreadId;

    use super::super::{
        Asid, ClonePlan, Kernel, KernelContext, LinuxWaitStatus, MmAccessError, MmBackend,
        MmBackendSnapshot, MmBinding, MmReadRange, MmRelation, MmToken, MmWriteRange,
        RootBootstrap, SnapshotError, Stage1Root, TaskKey, VmaAccess, VmaRevision, VmaSummary,
    };

    #[derive(Debug)]
    struct FixtureBackend {
        binding: MmBinding,
    }

    impl MmBackend for FixtureBackend {
        fn snapshot(&self, _deadline: Instant) -> Result<MmBackendSnapshot, SnapshotError> {
            Ok(MmBackendSnapshot {
                revision: 17,
                binding: self.binding,
                vmas: vec![
                    VmaSummary {
                        start: GuestVa(0x1000),
                        end: GuestVa(0x2000),
                        access: VmaAccess {
                            readable: true,
                            writable: false,
                            executable: false,
                            kernel_visible: true,
                        },
                    },
                    VmaSummary {
                        start: GuestVa(0x2000),
                        end: GuestVa(0x3000),
                        access: VmaAccess {
                            readable: true,
                            writable: false,
                            executable: false,
                            kernel_visible: true,
                        },
                    },
                    VmaSummary {
                        start: GuestVa(0x3000),
                        end: GuestVa(0x4000),
                        access: VmaAccess {
                            readable: true,
                            writable: true,
                            executable: false,
                            kernel_visible: true,
                        },
                    },
                    VmaSummary {
                        start: GuestVa(0x4000),
                        end: GuestVa(0x5000),
                        access: VmaAccess {
                            readable: true,
                            writable: false,
                            executable: false,
                            kernel_visible: false,
                        },
                    },
                ],
                vma_revision: Some(VmaRevision::from_authority_raw(19)),
                mapping_ids: Vec::new(),
                frame_inventory_revision: Some(23),
            })
        }

        fn revision(&self) -> u64 {
            17
        }

        fn vma_revision(&self, _deadline: Instant) -> Result<Option<VmaRevision>, SnapshotError> {
            Ok(Some(VmaRevision::from_authority_raw(19)))
        }
    }

    #[derive(Debug)]
    struct ChurningBackend {
        backend_revision: AtomicU64,
    }

    impl MmBackend for ChurningBackend {
        fn snapshot(&self, _deadline: Instant) -> Result<MmBackendSnapshot, SnapshotError> {
            let observed = self.backend_revision.load(Ordering::Acquire);
            let changed = self.backend_revision.fetch_add(1, Ordering::AcqRel) + 1;
            if observed != changed {
                return Err(SnapshotError::ChangedDuringObservation);
            }
            unreachable!("the fixture mutates the revision during every snapshot")
        }

        fn revision(&self) -> u64 {
            self.backend_revision.load(Ordering::Acquire)
        }

        fn vma_revision(&self, _deadline: Instant) -> Result<Option<VmaRevision>, SnapshotError> {
            Ok(Some(VmaRevision::from_authority_raw(31)))
        }
    }

    fn fixture_backend() -> Arc<dyn MmBackend> {
        let asid = Asid::from_registry_allocation(NonZeroU16::new(7).expect("nonzero ASID"));
        let root = Stage1Root::for_aarch64_4k(Gpa(0x8000)).expect("aligned stage-1 root");
        Arc::new(FixtureBackend {
            binding: MmBinding::for_aarch64(asid, root),
        })
    }

    fn bootstrap(pid: i32) -> (Arc<Kernel>, KernelContext) {
        let input = RootBootstrap::with_mm_backend(
            pid,
            ThreadId::synthetic_for_tests(pid),
            fixture_backend(),
            "mm-authority root".to_owned(),
        )
        .expect("root bootstrap");
        Kernel::bootstrap_root(input).expect("root kernel")
    }

    fn fork_with_backend(
        kernel: &Arc<Kernel>,
        parent: &KernelContext,
        registry_id: i32,
        name: &str,
        backend: Arc<dyn MmBackend>,
    ) -> KernelContext {
        kernel
            .reserve_fork(
                parent,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("copied-mm fork plan"),
                name.to_owned(),
                None,
            )
            .expect("reserve copied-mm fork")
            .prepare_with_mm_backend(backend, ThreadId::synthetic_for_tests(registry_id))
            .expect("prepare copied-mm fork")
            .commit()
            .expect("publish copied-mm fork")
            .into_parts()
            .expect("start copied-mm child")
            .0
    }

    fn foreign_mm(
        kernel: &Arc<Kernel>,
        caller: &KernelContext,
        target: TaskKey,
    ) -> super::super::ForeignMm {
        match kernel
            .foreign_mm(caller, target)
            .expect("foreign MM authority")
        {
            MmRelation::Foreign(foreign) => foreign,
            MmRelation::Current(_) => panic!("copied-MM target must be foreign"),
        }
    }

    #[test]
    fn retained_foreign_token_keeps_the_exact_mm_across_target_exec_and_retirement() {
        let (kernel, root) = bootstrap(31_100);
        let child = fork_with_backend(
            &kernel,
            &root,
            31_101,
            "retained-mm child",
            fixture_backend(),
        );
        let old_mm_arc = child.shared().mm();
        let old_mm_weak = Arc::downgrade(&old_mm_arc);
        let old_mm = old_mm_arc.id();
        let token = foreign_mm(&kernel, &root, child.task().key());

        let replacement = kernel
            .commit_exec(
                kernel
                    .prepare_exec_with_mm_backend(&child, fixture_backend(), None)
                    .expect("prepare target exec"),
                None,
            )
            .expect("commit target exec");
        let replacement_key = replacement.task().key();

        assert_eq!(token.mm_id(), old_mm);
        assert_ne!(replacement.shared().mm().id(), token.mm_id());
        drop(child);
        drop(old_mm_arc);
        let retained_after_exec = old_mm_weak
            .upgrade()
            .expect("foreign token must retain the pre-exec MM");
        assert!(Arc::ptr_eq(token.mm(), &retained_after_exec));
        drop(retained_after_exec);

        kernel
            .exit_task_key_eventually(replacement_key, LinuxWaitStatus::from_wait_encoding(0))
            .expect("retire exec replacement");
        drop(replacement);
        let _ = kernel
            .wait_child_key(
                root.task().key().id,
                replacement_key,
                super::super::WaitMode::Consume,
            )
            .expect("reap retired replacement");
        kernel.sweep_retired_threads();

        let retained_after_retirement = old_mm_weak
            .upgrade()
            .expect("foreign token must retain the retired MM");
        assert!(Arc::ptr_eq(token.mm(), &retained_after_retirement));
    }

    #[test]
    fn stale_task_key_is_rejected_after_pid_reuse() {
        let (kernel, root) = bootstrap(31_110);
        let root_binding = root.task_binding();
        let root_tid = root.thread().key().tid;
        let child = fork_with_backend(&kernel, &root, 31_111, "stale-mm child", fixture_backend());
        let stale_key = child.task().key();

        kernel
            .exit_task_key_eventually(stale_key, LinuxWaitStatus::from_wait_encoding(0))
            .expect("retire target");
        drop(child);
        let _ = kernel
            .wait_child_key(
                root.task().key().id,
                stale_key,
                super::super::WaitMode::Consume,
            )
            .expect("reap target");
        kernel.sweep_retired_threads();
        kernel.ids().set_next_for_tests(stale_key.id.raw());

        let fresh_root = root_binding.capture(root_tid).expect("fresh root context");
        let replacement = fork_with_backend(
            &kernel,
            &fresh_root,
            31_112,
            "replacement child",
            fixture_backend(),
        );
        assert_eq!(replacement.task().key().id, stale_key.id);
        assert_ne!(replacement.task().key(), stale_key);

        assert!(matches!(
            kernel.foreign_mm(&fresh_root, stale_key),
            Err(MmAccessError::UnknownTask(key)) if key == stale_key
        ));
    }

    #[test]
    fn token_bound_ranges_require_permissions_and_complete_vma_coverage() {
        let (kernel, root) = bootstrap(31_120);
        let child = fork_with_backend(&kernel, &root, 31_121, "range-mm child", fixture_backend());
        let foreign = foreign_mm(&kernel, &root, child.task().key());
        let token: &MmToken = &foreign.token;

        assert_eq!(foreign.token.snapshot.revision, 17);
        assert_eq!(
            foreign.token.snapshot.vma_revision,
            Some(VmaRevision::from_authority_raw(19))
        );
        assert_eq!(foreign.token.snapshot.frame_inventory_revision, Some(23));

        let read: MmReadRange<'_> = token
            .read_range(GuestVa(0x1000), 16)
            .expect("readable range")
            .expect("nonempty read range");
        let write: MmWriteRange<'_> = token
            .write_range(GuestVa(0x3000), 16)
            .expect("writable range")
            .expect("nonempty write range");
        let _ = (read, write);
        assert!(matches!(
            token.write_range(GuestVa(0x2000), 16),
            Err(MmAccessError::WriteDenied { .. })
        ));
        assert!(token.write_range(GuestVa(0x3000), 16).is_ok());
        assert!(matches!(
            token.kernel_read_range(GuestVa(0x4000), 16),
            Err(MmAccessError::KernelHidden { .. })
        ));
        assert!(token.read_range(GuestVa(0x1ff0), 0x20).is_ok());
        assert!(matches!(
            token.write_range(GuestVa(0x3ff0), 0x20),
            Err(MmAccessError::WriteDenied { .. })
        ));
        assert!(matches!(
            token.kernel_read_range(GuestVa(0x3ff0), 0x20),
            Err(MmAccessError::KernelHidden { .. })
        ));
        assert!(token.read_range(GuestVa(0x4ff0), 0x20).is_err());
        assert!(token.read_range(GuestVa(u64::MAX - 7), 16).is_err());
        assert!(token.read_range(GuestVa(0x5000), 16).is_err());
        assert!(matches!(token.read_range(GuestVa(0x5000), 0), Ok(None)));
        assert!(matches!(token.write_range(GuestVa(u64::MAX), 0), Ok(None)));
    }

    #[test]
    fn foreign_mm_rejects_a_churning_backend_snapshot() {
        let (kernel, root) = bootstrap(31_130);
        let child = fork_with_backend(
            &kernel,
            &root,
            31_131,
            "churning-mm child",
            Arc::new(ChurningBackend {
                backend_revision: AtomicU64::new(29),
            }),
        );

        assert!(matches!(
            kernel.foreign_mm(&root, child.task().key()),
            Err(MmAccessError::Snapshot(
                SnapshotError::ChangedDuringObservation
            ))
        ));
    }
}
