//! Compile-pressure contracts for kernel-minted MM authority.
//!
//! The authority types deliberately do not exist yet. These tests state the
//! required kernel boundary before Task 3 supplies its opaque implementation.

#[cfg(test)]
mod tests {
    use std::num::NonZeroU16;
    use std::sync::Arc;
    use std::time::Instant;

    use carrick_abi::LinuxCloneFlags;
    use carrick_guest_mem::{Gpa, GuestVa};
    use carrick_hal::ThreadId;

    use super::super::{
        Asid, ClonePlan, Kernel, KernelContext, LinuxWaitStatus, MmAccessError, MmBackend,
        MmBackendSnapshot, MmBinding, MmReadRange, MmRelation, MmToken, MmWriteRange,
        RootBootstrap, SnapshotError, Stage1Root, TaskKey, VmaAccess, VmaSummary,
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
                vma_revision: None,
                mapping_ids: Vec::new(),
                frame_inventory_revision: Some(23),
            })
        }

        fn revision(&self) -> u64 {
            17
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
    ) -> KernelContext {
        kernel
            .reserve_fork(
                parent,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("copied-mm fork plan"),
                name.to_owned(),
                None,
            )
            .expect("reserve copied-mm fork")
            .prepare_with_mm_backend(
                fixture_backend(),
                ThreadId::synthetic_for_tests(registry_id),
            )
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
    fn retained_foreign_token_keeps_the_exact_mm_across_target_exec() {
        let (kernel, root) = bootstrap(31_100);
        let child = fork_with_backend(&kernel, &root, 31_101, "retained-mm child");
        let old_mm_arc = child.shared().mm();
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

        assert_eq!(token.mm_id(), old_mm);
        assert_ne!(replacement.shared().mm().id(), token.mm_id());
        assert!(Arc::ptr_eq(token.mm(), &old_mm_arc));
    }

    #[test]
    fn stale_task_key_is_rejected_after_pid_reuse() {
        let (kernel, root) = bootstrap(31_110);
        let root_binding = root.task_binding();
        let root_tid = root.thread().key().tid;
        let child = fork_with_backend(&kernel, &root, 31_111, "stale-mm child");
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
        let replacement = fork_with_backend(&kernel, &fresh_root, 31_112, "replacement child");
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
        let child = fork_with_backend(&kernel, &root, 31_121, "range-mm child");
        let foreign = foreign_mm(&kernel, &root, child.task().key());
        let token: &MmToken = &foreign.token;

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
        assert!(token.read_range(GuestVa(0x4ff0), 0x20).is_err());
        assert!(token.read_range(GuestVa(u64::MAX - 7), 16).is_err());
        assert!(token.read_range(GuestVa(0x5000), 16).is_err());
        assert!(token.read_range(GuestVa(0x1000), 0).is_ok());
        assert!(token.write_range(GuestVa(0x1000), 0).is_ok());
    }
}
