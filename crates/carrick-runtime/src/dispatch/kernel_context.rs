//! Kernel context capture, task adapter bootstrap, and thread lifecycle management.

use std::sync::Arc;

use carrick_fatal::carrick_fatal;

use super::{SyscallDispatcher, close_open_file, resources};

/// How carrick's own kernel graph sees a guest-supplied pid that names some
/// OTHER Linux process. See [`SyscallDispatcher::guest_process_target`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum GuestProcessTarget {
    /// A live Linux process, running as `euid`.
    Live { euid: carrick_abi::NsUid },
    /// Exited but not yet reaped — still addressable, still owned by the `euid`
    /// it held at exit.
    Zombie { euid: carrick_abi::NsUid },
    /// No such Linux process — ESRCH.
    Missing,
}

impl GuestProcessTarget {
    /// The euid to compare a caller against, or `None` when no such process
    /// exists.
    pub(crate) fn euid(self) -> Option<carrick_abi::NsUid> {
        match self {
            Self::Live { euid } | Self::Zombie { euid } => Some(euid),
            Self::Missing => None,
        }
    }
}

pub(crate) fn try_bootstrap_one_task_binding()
-> Result<(crate::kernel::KernelTaskBinding, crate::kernel::MmId), crate::run_result::RuntimeError>
{
    let observed_pid = i32::try_from(std::process::id()).unwrap_or(1);
    let registry_id = crate::thread::ThreadId::main_from_host_pid();
    let bootstrap = crate::kernel::RootBootstrap::for_reference_model(
        observed_pid,
        registry_id,
        "one-task-dispatch-adapter".to_owned(),
    )
    .map_err(|error| {
        tracing::error!(%error, "cannot build mandatory one-task kernel adapter");
        crate::run_result::RuntimeError::CarrierFailed(format!(
            "cannot build mandatory one-task kernel adapter: {error}"
        ))
    })?;
    let (_, context) = crate::kernel::Kernel::bootstrap_root(bootstrap).map_err(|error| {
        tracing::error!(%error, "cannot bootstrap mandatory one-task kernel adapter");
        crate::run_result::RuntimeError::CarrierFailed(format!(
            "cannot bootstrap mandatory one-task kernel adapter: {error}"
        ))
    })?;
    let mm_id = context.shared().mm().id();
    Ok((context.task_binding(), mm_id))
}

#[allow(clippy::expect_used)]
pub(crate) fn bootstrap_one_task_binding() -> (crate::kernel::KernelTaskBinding, crate::kernel::MmId)
{
    try_bootstrap_one_task_binding().expect("mandatory one-task kernel adapter")
}

impl SyscallDispatcher {
    pub(crate) fn launch_fs_context_for_hvpatch_bind(
        &self,
    ) -> Result<Option<(String, Option<String>)>, crate::kernel::KernelError> {
        if self.hvpatch_process().is_some() {
            // An in-process fork already cloned the authoritative kernel
            // FsContext. Its dispatcher still carries the parent binding until
            // child publication, but that parent leader may legitimately have
            // exited. Never recapture through that stale binding or overwrite
            // the child's exact inherited filesystem authority.
            return Ok(None);
        }
        let launch_context = self.capture_one_task_context()?;
        let launch_fs_context = launch_context.resources().fs_context();
        Ok(Some((
            launch_fs_context.cwd(),
            launch_fs_context.chroot_root(),
        )))
    }

    pub(crate) fn bind_hvpatch_process(&self, process: crate::hvpatch::ProcessContext) {
        let launch_fs_context = self
            .launch_fs_context_for_hvpatch_bind()
            .unwrap_or_else(|error| {
                tracing::error!(%error, "cannot capture filesystem context before HVPatch binding");
                carrick_fatal!(
                    "dispatch::hvpatch_binding",
                    "cannot capture filesystem context before HVPatch binding"
                );
            });
        let process_context = process
            .context_for_linux_tid(crate::kernel::LinuxTid::for_task_leader(process.task_id()))
            .unwrap_or_else(|error| {
                tracing::error!(%error, "cannot capture HVPatch root filesystem context");
                carrick_fatal!(
                    "dispatch::hvpatch_binding",
                    "cannot capture HVPatch root filesystem context"
                );
            });
        self.bind_hvpatch_process_exact(process, &process_context, launch_fs_context);
    }

    /// Bind a newly prepared container root using the exact context returned
    /// by its kernel transaction. This avoids recapturing through the registry
    /// before a later root's atomic commit, while preserving every dispatcher
    /// mount, interceptor, observer and filesystem setting already installed.
    pub(crate) fn bind_hvpatch_process_exact(
        &self,
        process: crate::hvpatch::ProcessContext,
        process_context: &crate::kernel::KernelContext,
        launch_fs_context: Option<(String, Option<String>)>,
    ) {
        if let Some((launch_cwd, launch_chroot_root)) = launch_fs_context {
            let process_fs_context = process_context.resources().fs_context();
            process_fs_context.set_cwd(launch_cwd);
            process_fs_context.set_chroot_root(launch_chroot_root);
        }
        super::HVPATCH_LANE.store(true, std::sync::atomic::Ordering::Release);
        let namespace_pid = self.identity_snapshot(process_context).pid;
        self.mm_binding
            .rebind_prepared_root(process_context.shared().mm().id());
        process.bind_vma_source(self.vma_snapshot_source());
        let stage1 = process.stage1_mm_lease().unwrap_or_else(|error| {
            tracing::error!(%error, "cannot bind exact HVPatch stage-1 mutation authority");
            carrick_fatal!(
                "dispatch::hvpatch_binding",
                "cannot bind exact HVPatch stage-1 mutation authority"
            );
        });
        process.bind_mm_mutation_authority(self.foreign_mm_mutation_authority(stage1));
        *self.kernel_binding.write() = process.task_binding();
        *self.timer_delivery.write() = Some(process.process_timer_delivery());
        self.commit_sysv_fork_inheritance();
        // HVPatch multiplexes Linux tasks inside one host PID, so the mature
        // one-task adapter's host-PID credential projection is inapplicable.
        crate::cred_ipc::unpublish();
        let mut proc = self.proc.lock();
        proc.bind_hvpatch_identity(process.pid() as u32, namespace_pid);
        proc.hvpatch_process = Some(process);
    }

    pub fn capture_kernel_context(
        &self,
        tid: crate::kernel::LinuxTid,
    ) -> Result<crate::kernel::KernelContext, crate::kernel::KernelError> {
        self.kernel_binding.read().capture(tid)
    }

    /// Run lifecycle work with credentials from the already captured syscall
    /// boundary. This extends that exact context across deferred exec loading;
    /// it never consults the current registry binding or substitutes a leader.
    pub(crate) fn with_kernel_credentials<R>(
        &self,
        context: &crate::kernel::KernelContext,
        operation: impl FnOnce() -> R,
    ) -> R {
        self.with_kernel_resources(context, operation)
    }

    /// Run one lifecycle transaction against the exact captured task resource
    /// graph. Logical exec uses this after target-user/workdir configuration so
    /// credential, file-table, filesystem-context, MM, PATH, and image reads
    /// cannot fall back to a leader or ambient dispatcher binding.
    pub(crate) fn with_kernel_resources<R>(
        &self,
        context: &crate::kernel::KernelContext,
        operation: impl FnOnce() -> R,
    ) -> R {
        resources::with_captured_resources(context, operation)
    }

    pub(crate) fn prepare_one_task_kernel_exec(
        &self,
        context: &crate::kernel::KernelContext,
    ) -> Result<crate::kernel::PreparedExec, crate::kernel::ExecPrepareError> {
        Ok(context.kernel().prepare_exec(context, None)?)
    }

    pub(crate) fn commit_one_task_kernel_exec(
        &self,
        prepared: crate::kernel::PreparedExec,
    ) -> Result<crate::kernel::KernelContext, crate::kernel::ExecPrepareError> {
        let old_files = prepared.old_file_table();
        let kernel = Arc::clone(self.kernel_binding.read().kernel());
        let context = kernel.commit_exec(prepared, None)?;
        *self.kernel_binding.write() = context.task_binding();
        self.publish_external_credential_projection(&context, &context.resources().credentials());
        let successor_files = context.resources().files();
        self.close_draining_file_table(
            &kernel,
            &old_files,
            Some(context.task().key()),
            Some(&successor_files),
        );
        Ok(context)
    }

    pub(crate) fn close_draining_file_table(
        &self,
        kernel: &Arc<crate::kernel::Kernel>,
        files: &Arc<crate::kernel::FileTable>,
        owner: Option<crate::kernel::TaskKey>,
        exec_successor: Option<&Arc<crate::kernel::FileTable>>,
    ) {
        if let (Some(owner), Some(successor)) = (owner, exec_successor) {
            self.mqueue_rebind_exec_file_table(owner, files, successor);
        }
        kernel.retire_file_table_if_unreferenced(files);
        self.drain_file_table_close_events(kernel, files, owner);
    }

    /// Consume the typed close events of a retired `files` generation and
    /// close each description's logical fd reference. Split from
    /// [`Self::close_draining_file_table`] so the process-terminal path can
    /// retire the exiting task's table with the exiting-task census first.
    pub(in crate::dispatch) fn drain_file_table_close_events(
        &self,
        kernel: &Arc<crate::kernel::Kernel>,
        files: &Arc<crate::kernel::FileTable>,
        owner: Option<crate::kernel::TaskKey>,
    ) {
        let pid = self.event_ring_guest_pid();
        let events = kernel.take_file_close_events(files.id());
        resources::with_retiring_file_table(Arc::clone(files), || {
            for event in events {
                match event.disposition {
                    crate::kernel::core::FileCloseDisposition::Closed => {
                        self.dnotify_close_fd(event.fd);
                        self.inotify_close_for_fd(event.fd);
                        self.detach_fd_from_epolls(event.fd);
                        // The whole retiring generation has lost its final
                        // live Kernel reference, so every alias in it is
                        // closing. Retire a registration bound to this exact
                        // owner-local table/description before releasing the
                        // description's logical fd reference.
                        self.mqueue_retire_file_table_registration(files.id(), &event.slot);
                        self.record_fd_close_owner(event.fd, pid, &event.slot);
                        if let Some(owner) = owner {
                            self.release_hvpatch_classic_record_locks(owner, &event.slot);
                        }
                        self.close_open_file_and_free_pty(&event.slot);
                    }
                    crate::kernel::core::FileCloseDisposition::Transferred => {
                        close_open_file(&event.slot);
                    }
                }
            }
        });
    }

    pub(crate) fn reset_one_task_kernel_binding_for_current_process(
        &self,
        inherited: &crate::kernel::KernelContext,
        registry_id: crate::thread::ThreadId,
    ) -> Result<crate::kernel::KernelContext, crate::kernel::ExecPrepareError> {
        let observed_pid = i32::try_from(std::process::id())?;
        let inherited_credentials = inherited.resources().credentials();
        let inherited_fs_context = inherited.resources().fs_context();
        let inherited_files = inherited.resources().files();
        let inherited_mm = inherited.shared().mm();
        let inherited_signal_state = inherited.thread().signal_state();
        let bootstrap = crate::kernel::RootBootstrap::for_reference_model(
            observed_pid,
            registry_id,
            "one-task-fork-child-adapter".to_owned(),
        )?;
        let (kernel, context) = crate::kernel::Kernel::bootstrap_root(bootstrap)?;
        let context = kernel.copy_file_table_for_host_fork(&context, &inherited_files)?;
        context
            .shared()
            .mm()
            .copy_io_uring_mappings_for_host_fork(&inherited_mm)?;
        let replacement_fs_context = context.resources().fs_context();
        replacement_fs_context.set_cwd(inherited_fs_context.cwd());
        replacement_fs_context.set_chroot_root(inherited_fs_context.chroot_root());
        let context = kernel.update_credentials(&context, |credentials| {
            credentials.copy_values_from(&inherited_credentials);
        })?;
        context
            .shared()
            .sighand()
            .replace_actions(inherited.shared().sighand().actions());
        // The per-process attributes Linux inherits across fork. This path
        // bootstraps a BRAND-NEW root task, so nothing carries them implicitly;
        // the in-process fork path calls the same helper (see
        // `Task::inherit_fork_attributes_from`). Before these moved off
        // process-global `static`s, `libc::fork` copied them for free and the
        // omission here was invisible.
        context
            .task()
            .inherit_fork_attributes_from(inherited.task());
        context
            .kernel()
            .cpu_limit_watch()
            .ensure_watching(context.kernel(), context.task());
        // A host fork copies only the calling thread. Preserve its blocked
        // mask, altstack and active handler-frame restoration state while
        // clearing both task- and thread-directed pending signals, exactly as
        // `Kernel::reserve_fork` does for an in-process child.
        context
            .thread()
            .replace_signal_state(crate::kernel::ThreadSignalState::for_fork(
                &inherited_signal_state,
            ));
        *self.kernel_binding.write() = context.task_binding();
        self.publish_external_credential_projection(&context, &context.resources().credentials());
        Ok(context)
    }

    /// The leader `LinuxTid` of the task this dispatcher is bound to, read from
    /// the kernel binding rather than recomputed.
    ///
    /// Two call sites used to derive this independently from
    /// `std::process::id()`, which happens to agree today only because the
    /// kernel's root task id is currently seeded from the host pid. That is a
    /// second source of truth for the same fact, and it would break silently
    /// the moment the id space is reseeded — so it asks the binding instead.
    pub(crate) fn root_leader_linux_tid(&self) -> crate::kernel::LinuxTid {
        let binding = self.kernel_binding.read();
        crate::kernel::LinuxTid::for_task_leader(binding.task_id())
    }

    pub fn capture_one_task_context(
        &self,
    ) -> Result<crate::kernel::KernelContext, crate::kernel::KernelError> {
        let binding = self.kernel_binding.read();
        binding.capture(crate::kernel::LinuxTid::for_task_leader(binding.task_id()))
    }

    pub fn register_one_task_thread(
        &self,
        parent: &crate::kernel::KernelContext,
        registry_id: crate::thread::ThreadId,
    ) -> Result<crate::kernel::LinuxTid, crate::kernel::KernelOperationError> {
        let flags = carrick_abi::LinuxCloneFlags::VM
            | carrick_abi::LinuxCloneFlags::FS
            | carrick_abi::LinuxCloneFlags::FILES
            | carrick_abi::LinuxCloneFlags::SIGHAND
            | carrick_abi::LinuxCloneFlags::THREAD;
        let plan = crate::kernel::ClonePlan::from_flags(flags)
            .map_err(crate::kernel::KernelOperationError::ClonePlan)?;
        parent
            .kernel()
            .reserve_thread_clone(parent, plan, None)?
            .prepare(registry_id)?
            .commit()?
            .into_context()
            .map(|context| context.thread().key().tid)
    }

    pub(crate) fn hvpatch_process(&self) -> Option<crate::hvpatch::ProcessContext> {
        self.proc.lock().hvpatch_process.clone()
    }

    /// The network namespace the CALLING guest process belongs to.
    ///
    /// Resolved through the exact syscall context; no dispatcher-global root
    /// exists for a second container to overwrite.
    pub(crate) fn caller_net_ns(
        &self,
        context: &crate::kernel::KernelContext,
    ) -> Arc<crate::kernel::NetNs> {
        context.task().net_ns()
    }

    /// Does `pid` name a LIVE Linux process, according to carrick's own kernel?
    ///
    /// `None` means this lane has no kernel task registry to ask — the caller
    /// must keep whatever host probe it already used. That is what makes every
    /// call site correct on `native` and `vmm`, where a Linux process IS a host
    /// process and `kill(pid, 0)` is the right question.
    ///
    /// On the kernel lane it is the wrong question and will get worse. A Linux
    /// process there is a THREAD of one host process, so the host process table
    /// knows nothing about it: probing with a guest pid today matches nothing
    /// and reports ESRCH, which is merely wrong. It becomes actively dangerous
    /// the moment guest pids are small — a guest pid of 1 would probe the host's
    /// pid 1, which on macOS is `launchd`. Routing these through the kernel is
    /// therefore a prerequisite for seeding the guest id space at 1, not a
    /// consequence of it; see
    /// `docs/perf-results/2026-08-13-hvpatch-guest-pid-identity-design.md`.
    #[cfg(test)]
    pub(crate) fn guest_pid_is_live(&self, pid: i32) -> Option<bool> {
        let process = self.hvpatch_process()?;
        let Ok(task) = crate::kernel::TaskId::from_abi_positive(pid) else {
            // Not a well-formed positive pid: the kernel cannot own an answer,
            // so hand the question back rather than inventing one.
            return None;
        };
        Some(process.kernel_graph().task_is_live(task))
    }

    /// Resolve a guest-supplied positive pid to another Linux PROCESS and the
    /// effective uid that process runs as.
    ///
    /// `None` means this lane has no guest-kernel task registry to consult; this lane
    /// has no kernel task registry, so the caller keeps its host probe.
    ///
    /// Otherwise the answer comes entirely from carrick's kernel graph. That is
    /// the whole point: the caller's own credentials already come from there
    /// (`cred_snapshot`), while the TARGET's used to come from
    /// `cred_ipc::read_target(host_pid)` — one host file keyed by the carrier's
    /// pid, therefore the same file for every HVPatch logical process. The two
    /// halves of one ownership comparison were reading different authorities.
    ///
    /// A zombie is reported, not dropped: Linux keeps an exited-but-unreaped
    /// process addressable by `sched_*`, `setpriority` and `process_vm_*`, and
    /// applies the same ownership rule using the credentials it held at exit.
    /// The task whose per-task state a pid-taking syscall must act on.
    ///
    /// `0` and the caller's own pid resolve to the CALLER without a registry
    /// lookup, exactly as Linux treats them. Any other pid resolves through the
    /// kernel graph — never through a host probe, because a guest pid is not a
    /// host pid at all under HVPatch, so `kill(pid, 0)` asks Darwin about a
    /// namespace it knows nothing about and answers by coincidence.
    ///
    /// `None` means the pid names no live guest task, which the caller reports
    /// as `ESRCH`.
    pub(crate) fn task_for_guest_pid(
        &self,
        context: &crate::kernel::KernelContext,
        pid: i32,
    ) -> Option<crate::kernel::TaskRef> {
        if pid == 0 || u32::try_from(pid).is_ok_and(|pid| pid == self.identity_pid()) {
            return Some(std::sync::Arc::clone(context.task()));
        }
        let process = self.hvpatch_process()?;
        // ns-pid -> task id: the caller's number is the guest's namespace view.
        let namespace_id = u32::try_from(pid).ok()?;
        let host = crate::namespace::pid::ns_to_kernel_for(context, namespace_id)?;
        let host = i32::try_from(host).ok()?;
        let task = crate::kernel::TaskId::from_abi_positive(host).ok()?;
        let task = process.kernel_graph().live_task(task)?;
        (task.container().id() == context.container().id()).then_some(task)
    }

    pub(crate) fn guest_process_target(
        &self,
        context: &crate::kernel::KernelContext,
        pid: i32,
    ) -> Option<GuestProcessTarget> {
        let process = self.hvpatch_process()?;
        let namespace_id = u32::try_from(pid).ok()?;
        let pid = crate::namespace::pid::ns_to_kernel_for(context, namespace_id)
            .and_then(|pid| i32::try_from(pid).ok())?;
        let Ok(task) = crate::kernel::TaskId::from_abi_positive(pid) else {
            return None;
        };
        let kernel = process.kernel_graph();
        if let Some(target) = kernel.live_task(task) {
            return (target.container().id() == context.container().id()).then(|| {
                GuestProcessTarget::Live {
                    euid: target.process_credentials().euid(),
                }
            });
        }
        Some(match kernel.registry().zombie(task) {
            Some(zombie) if zombie.container == context.container().id() => {
                GuestProcessTarget::Zombie { euid: zombie.euid }
            }
            None => GuestProcessTarget::Missing,
            Some(_) => GuestProcessTarget::Missing,
        })
    }

    /// Apply Linux's process-exit fd lifetime at the HvPatch process boundary.
    ///
    /// HvPatch multiplexes Linux processes inside one host process, so host fd
    /// lifetime cannot rely on host `_exit`. After Kernel exit publication has
    /// made this exact table generation draining, consume its typed close
    /// events without erasing the rows retained for coherent snapshots.
    pub(crate) fn retire_hvpatch_process_fds(&self, context: &crate::kernel::KernelContext) {
        let owner = context.task().key();
        self.fs.classic_record_locks.release_owner(owner);
        let files = self.file_table_for_context(context);
        self.mqueue_retire_task_owner(owner, &files);
        // The exiting task is still registered when the terminal path calls
        // this, ahead of the retirement topology lock; it must not hold its
        // own table alive.
        context
            .kernel()
            .retire_file_table_for_exiting_task(&files, owner);
        self.drain_file_table_close_events(context.kernel(), &files, Some(owner));
    }

    pub fn exit_one_task_thread(
        &self,
        tid: crate::kernel::LinuxTid,
    ) -> Result<(), crate::kernel::KernelOperationError> {
        let binding = self.kernel_binding.read().clone();
        let context = match binding.capture(tid) {
            Ok(context) => context,
            Err(crate::kernel::KernelError::UnknownThread(_)) => return Ok(()),
            Err(_) if !binding.kernel().task_is_live(binding.task_id()) => return Ok(()),
            Err(_) => {
                return Err(crate::kernel::KernelOperationError::UnknownTask(
                    binding.task_id(),
                ));
            }
        };
        loop {
            let observed = binding.kernel().reservation_epoch();
            match binding.kernel().exit_thread(&context, None) {
                Ok(_) => {
                    self.close_draining_file_table(
                        context.kernel(),
                        &context.resources().files(),
                        Some(context.task().key()),
                        None,
                    );
                    return Ok(());
                }
                Err(crate::kernel::KernelOperationError::TaskBusy(_)) => {
                    binding.kernel().wait_for_reservation_change(observed);
                }
                Err(crate::kernel::KernelOperationError::UnknownThread(_))
                    if !context.exact_thread_is_live() =>
                {
                    return Ok(());
                }
                Err(crate::kernel::KernelOperationError::ParentExited)
                | Err(crate::kernel::KernelOperationError::UnknownTask(_))
                    if !binding.kernel().task_is_live(binding.task_id()) =>
                {
                    return Ok(());
                }
                Err(error) => return Err(error),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dispatch::fd_table::kernel_file_description;
    use crate::dispatch::{OpenDescription, OpenDescriptionBase, OpenFile};
    use crate::fs_backend::FsBackend;
    use carrick_abi::LINUX_FD_CLOEXEC;
    use parking_lot::RwLock;

    #[test]
    fn one_task_adapter_registers_explicit_linux_tid_for_backend_thread() {
        let dispatcher = SyscallDispatcher::new();
        let registry_id = crate::thread::ThreadId::synthetic_for_tests(91_337);
        let parent = dispatcher.capture_one_task_context().unwrap();
        let linux_tid = dispatcher
            .register_one_task_thread(&parent, registry_id)
            .expect("register one-task thread");
        let context = dispatcher
            .capture_kernel_context(linux_tid)
            .expect("capture registered Linux tid");

        assert_eq!(context.thread().key().tid, linux_tid);
        assert_eq!(context.thread().registry_id(), registry_id);
        dispatcher
            .exit_one_task_thread(linux_tid)
            .expect("retire one-task thread");
        assert!(dispatcher.capture_kernel_context(linux_tid).is_err());
    }

    #[test]
    fn one_task_thread_registration_copies_the_exact_nonleader_credentials() {
        let dispatcher = SyscallDispatcher::new();
        let leader = dispatcher.capture_one_task_context().unwrap();
        let sibling_tid = dispatcher
            .register_one_task_thread(
                &leader,
                crate::thread::ThreadId::synthetic_for_tests(91_340),
            )
            .expect("register sibling");
        let sibling = dispatcher.capture_kernel_context(sibling_tid).unwrap();
        let sibling = sibling
            .kernel()
            .update_credentials(&sibling, |credentials| {
                credentials.set_fsuid(carrick_abi::NsUid::new(7_777));
                credentials.set_supplementary_groups(vec![carrick_abi::NsGid::new(77)]);
            })
            .expect("diverge sibling credentials");

        let child_tid = dispatcher
            .register_one_task_thread(
                &sibling,
                crate::thread::ThreadId::synthetic_for_tests(91_341),
            )
            .expect("register from nonleader");
        let child = dispatcher.capture_kernel_context(child_tid).unwrap();

        assert_eq!(
            leader.resources().credentials().fsuid(),
            carrick_abi::NsUid::ROOT
        );
        assert_eq!(
            child.resources().credentials().fsuid(),
            carrick_abi::NsUid::new(7_777)
        );
        assert_eq!(
            child
                .resources()
                .credentials()
                .supplementary_groups_override(),
            Some([carrick_abi::NsGid::new(77)].as_slice())
        );
    }

    #[test]
    fn lifecycle_credential_scope_uses_the_exact_nonleader_context() {
        let dispatcher = SyscallDispatcher::new();
        let leader = dispatcher.capture_one_task_context().unwrap();
        let sibling_tid = dispatcher
            .register_one_task_thread(
                &leader,
                crate::thread::ThreadId::synthetic_for_tests(91_342),
            )
            .expect("register sibling");
        let sibling = dispatcher.capture_kernel_context(sibling_tid).unwrap();
        let sibling = sibling
            .kernel()
            .update_credentials(&sibling, |credentials| {
                credentials.set_uid_triple(
                    carrick_abi::NsUid::new(71),
                    carrick_abi::NsUid::new(72),
                    carrick_abi::NsUid::new(73),
                );
            })
            .expect("diverge sibling credentials");

        let observed =
            dispatcher.with_kernel_credentials(&sibling, || dispatcher.cred_snapshot().euid);

        assert_eq!(observed, carrick_abi::NsUid::new(72));
        assert_eq!(
            leader.resources().credentials().euid(),
            carrick_abi::NsUid::ROOT
        );
    }

    #[test]
    fn one_task_rebind_copies_complete_credential_values() {
        let dispatcher = SyscallDispatcher::new();
        let original = dispatcher
            .capture_one_task_context()
            .expect("original context");
        original
            .resources()
            .fs_context()
            .set_cwd("/inherited/cwd".to_owned());
        original
            .resources()
            .fs_context()
            .set_chroot_root(Some("/inherited/root".to_owned()));
        let description = kernel_file_description(
            Arc::new(RwLock::new(OpenDescription::SyntheticFile {
                base: OpenDescriptionBase::new(crate::linux_abi::LINUX_O_RDONLY),
                path: "/inherited/file".to_owned(),
                contents: Vec::new(),
                offset: 0,
            })),
            crate::linux_abi::LINUX_O_RDONLY,
        );
        let inherited_fd = dispatcher
            .install_fd_at_or_above(3, OpenFile::new(Arc::clone(&description), LINUX_FD_CLOEXEC))
            .unwrap();
        original
            .resources()
            .files()
            .write_fd_open_paths()
            .insert(inherited_fd, "/inherited/file".to_owned());
        original
            .thread()
            .replace_signal_state(crate::kernel::ThreadSignalState::new(
                carrick_abi::SigSet::EMPTY.with(2),
                carrick_abi::SigSet::EMPTY.with(3),
                true,
                1,
            ));
        original.shared().pending_signals().enqueue_standard(
            crate::kernel::LinuxSignal::for_signal_number(4).expect("task signal"),
            None,
        );
        let original = original
            .kernel()
            .update_credentials(&original, |credentials| {
                credentials
                    .seed_identity(carrick_abi::NsUid::new(1001), carrick_abi::NsGid::new(2001));
                credentials.set_fsuid(carrick_abi::NsUid::new(1002));
                credentials.set_fsgid(carrick_abi::NsGid::new(2002));
                credentials.set_umask(0o077);
                credentials.set_supplementary_groups(vec![
                    carrick_abi::NsGid::new(9),
                    carrick_abi::NsGid::new(10),
                ]);
            })
            .expect("seed inherited credentials");
        let old_kernel = Arc::clone(original.kernel());

        let rebound = dispatcher
            .reset_one_task_kernel_binding_for_current_process(
                &original,
                crate::thread::ThreadId::synthetic_for_tests(91_338),
            )
            .expect("rebind one-task authority");
        let credentials = rebound.resources().credentials();
        let rebound_files = rebound.resources().files();
        let rebound_signals = rebound.thread().signal_state();

        assert!(!Arc::ptr_eq(&old_kernel, rebound.kernel()));
        assert!(!Arc::ptr_eq(&original.resources().files(), &rebound_files));
        let rebound_slot = rebound_files
            .read_open_files()
            .get(&inherited_fd)
            .cloned()
            .expect("inherited fd slot");
        assert!(Arc::ptr_eq(&description, &rebound_slot.description));
        assert_eq!(rebound_slot.fd_flags, LINUX_FD_CLOEXEC);
        assert_eq!(
            rebound_files
                .read_fd_open_paths()
                .get(&inherited_fd)
                .map(String::as_str),
            Some("/inherited/file")
        );
        assert_eq!(
            rebound_signals.blocked(),
            carrick_abi::SigSet::EMPTY.with(2)
        );
        assert_eq!(rebound_signals.pending(), carrick_abi::SigSet::EMPTY);
        assert!(rebound_signals.altstack_enabled());
        assert_eq!(rebound_signals.handler_frame_depth(), 1);
        assert_eq!(rebound.shared().pending_signals().pending_count(), 0);
        let post_fork_description = kernel_file_description(
            Arc::new(RwLock::new(OpenDescription::SyntheticFile {
                base: OpenDescriptionBase::new(crate::linux_abi::LINUX_O_RDONLY),
                path: "/post-fork/file".to_owned(),
                contents: Vec::new(),
                offset: 0,
            })),
            crate::linux_abi::LINUX_O_RDONLY,
        );
        assert_ne!(description.id(), post_fork_description.id());
        assert!(description.id() < post_fork_description.id());
        assert_eq!(
            (credentials.ruid(), credentials.rgid()),
            (carrick_abi::NsUid::new(1001), carrick_abi::NsGid::new(2001))
        );
        assert_eq!(
            (credentials.fsuid(), credentials.fsgid()),
            (carrick_abi::NsUid::new(1002), carrick_abi::NsGid::new(2002))
        );
        assert_eq!(credentials.umask(), 0o077);
        assert_eq!(rebound.resources().fs_context().cwd(), "/inherited/cwd");
        assert_eq!(
            rebound.resources().fs_context().chroot_root().as_deref(),
            Some("/inherited/root")
        );
        assert_eq!(
            credentials.supplementary_groups_override(),
            Some([carrick_abi::NsGid::new(9), carrick_abi::NsGid::new(10)].as_slice())
        );
    }

    #[test]
    fn logical_exec_workdir_is_validated_before_exact_context_mutation() {
        let dispatcher = SyscallDispatcher::new();
        let context = dispatcher
            .capture_one_task_context()
            .expect("logical exec context");
        context
            .resources()
            .fs_context()
            .set_cwd("/before".to_owned());

        assert!(matches!(
            dispatcher.configure_logical_exec_context(
                &context,
                Some("/definitely/missing/logical-exec-workdir"),
                None,
            ),
            Err(errno) if errno == crate::linux_abi::LINUX_ENOENT,
        ));
        assert_eq!(context.resources().fs_context().cwd(), "/before");
        dispatcher
            .configure_logical_exec_context(&context, Some("/"), None)
            .expect("root workdir");
        assert_eq!(context.resources().fs_context().cwd(), "/");
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn logical_execvp_skips_non_executable_path_candidates() {
        let mut dispatcher = SyscallDispatcher::new();
        let backend = crate::fs_backend::MemoryBackend::new();
        backend.make_dir("/blocked").expect("blocked dir");
        backend.make_dir("/allowed").expect("allowed dir");
        backend
            .set_file_contents("/blocked/tool", b"bad".to_vec())
            .expect("blocked tool");
        backend
            .set_mode("/blocked/tool", 0o644)
            .expect("blocked mode");
        backend
            .set_file_contents("/allowed/tool", b"good".to_vec())
            .expect("allowed tool");
        backend
            .set_mode("/allowed/tool", 0o755)
            .expect("allowed mode");
        let _ = dispatcher.set_fs_backend(Box::new(backend));

        assert_eq!(
            dispatcher.resolve_execvp_path("tool", "/blocked:/allowed"),
            Ok("/allowed/tool".to_owned())
        );
        assert_eq!(
            dispatcher.resolve_execvp_path("tool", "/missing:/blocked"),
            Err(crate::linux_abi::LINUX_EACCES),
            "an executable-looking candidate that denied access wins over ENOENT",
        );
        assert_eq!(
            dispatcher.resolve_execvp_path("tool", "/missing:/also-missing"),
            Err(crate::linux_abi::LINUX_ENOENT),
        );
    }

    #[test]
    fn logical_exec_workdir_checks_target_credentials_before_mutation() {
        let mut dispatcher = SyscallDispatcher::new();
        let scratch = tempfile::tempdir().expect("scratch root");
        let backend =
            crate::fs_backend::HostFsBackend::from_path(scratch.path()).expect("scratch backend");
        backend.make_dir("/secret").expect("secret dir");
        backend.set_mode("/secret", 0o710).expect("secret mode");
        backend
            .set_owner(
                "/secret",
                Some(carrick_abi::NsUid::ROOT),
                Some(carrick_abi::NsGid::new(2000)),
            )
            .expect("secret owner");
        let _ = dispatcher.set_fs_backend(Box::new(backend));
        let context = dispatcher.capture_one_task_context().expect("context");
        context
            .resources()
            .fs_context()
            .set_cwd("/before".to_owned());

        assert!(matches!(
            dispatcher.configure_logical_exec_context(
                &context,
                Some("/secret"),
                Some((
                    carrick_abi::NsUid::new(1000),
                    carrick_abi::NsGid::new(1000),
                    Vec::new(),
                )),
            ),
            Err(errno) if errno == crate::linux_abi::LINUX_EACCES
        ));
        assert_eq!(context.resources().fs_context().cwd(), "/before");
        assert!(context.resources().credentials().fsuid().is_root());

        let configured = dispatcher
            .configure_logical_exec_context(
                &context,
                Some("/secret"),
                Some((
                    carrick_abi::NsUid::new(1000),
                    carrick_abi::NsGid::new(1000),
                    vec![carrick_abi::NsGid::new(2000)],
                )),
            )
            .expect("supplementary group search permission");
        assert_eq!(context.resources().fs_context().cwd(), "/secret");
        assert_eq!(
            configured.resources().credentials().fsuid(),
            carrick_abi::NsUid::new(1000)
        );
    }

    #[test]
    fn logical_exec_target_user_workdir_and_path_share_one_exact_resource_scope() {
        let mut dispatcher = SyscallDispatcher::new();
        let scratch = tempfile::tempdir().expect("scratch root");
        let backend =
            crate::fs_backend::HostFsBackend::from_path(scratch.path()).expect("scratch backend");
        backend.make_dir("/private-bin").expect("private bin");
        backend
            .set_owner(
                "/private-bin",
                Some(carrick_abi::NsUid::ROOT),
                Some(carrick_abi::NsGid::new(2000)),
            )
            .expect("private bin owner");
        backend
            .set_mode("/private-bin", 0o710)
            .expect("private bin search mode");
        backend
            .set_file_contents("/private-bin/tool", b"fixture".to_vec())
            .expect("tool");
        backend
            .set_owner(
                "/private-bin/tool",
                Some(carrick_abi::NsUid::ROOT),
                Some(carrick_abi::NsGid::new(2000)),
            )
            .expect("tool owner");
        backend
            .set_mode("/private-bin/tool", 0o750)
            .expect("tool mode");
        let _ = dispatcher.set_fs_backend(Box::new(backend));
        let context = dispatcher.capture_one_task_context().expect("context");
        let configured = dispatcher
            .configure_logical_exec_context(
                &context,
                Some("/private-bin"),
                Some((
                    carrick_abi::NsUid::new(1000),
                    carrick_abi::NsGid::new(2000),
                    Vec::new(),
                )),
            )
            .expect("target user may search workdir");

        let resolved = dispatcher.with_kernel_resources(&configured, || {
            assert_eq!(
                dispatcher.cred_snapshot().fsuid,
                carrick_abi::NsUid::new(1000)
            );
            assert_eq!(
                dispatcher.cred_snapshot().fsgid,
                carrick_abi::NsGid::new(2000)
            );
            dispatcher.resolve_execvp_path("tool", "/missing:/private-bin")
        });
        assert_eq!(resolved, Ok("/private-bin/tool".to_owned()));
        assert_eq!(configured.resources().fs_context().cwd(), "/private-bin");
    }

    #[test]
    fn try_bootstrap_one_task_binding_succeeds() {
        let res = try_bootstrap_one_task_binding();
        assert!(res.is_ok());
    }
}
