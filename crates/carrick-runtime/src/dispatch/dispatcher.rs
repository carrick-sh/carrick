// Copyright 2026 Carrick Authors
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Core `SyscallDispatcher` type definition, constructors, process-fork cloning,
//! and executable identity state management.

use std::sync::Arc;

use parking_lot::{Mutex, RwLock};

use super::AsyncSignalWakeOwner;
use super::DispatchMmAuthority;
use super::DispatchMmBinding;
use super::OpenFile;
use super::PrepareDispatchMmForkError;
use super::PreparedDispatchMmFork;
use super::bootstrap_one_task_binding;
use super::fs;
use super::linux_task_name_from_bytes;
use super::mm_mutation;
use super::mqueue;
use super::normalize_abs_path;
use super::proc;
use super::sysv;
use crate::fs_backend::FsBackend;
use crate::rootfs::{RootFs, RootFsMetadata};

pub struct SyscallDispatcher {
    /// Generation-safe task adapter used to capture the mandatory kernel
    /// context at each backend dispatch boundary. HVPatch replaces the initial
    /// one-task binding when its root/child task is published.
    pub(crate) kernel_binding: RwLock<crate::kernel::KernelTaskBinding>,
    /// The container `Runtime::execute` built for this run (the same `Arc`
    /// B2 hands a pid region and B4 admits/retires), handed to the HVPatch
    /// root bootstrap so the root task is created inside it. `None` until
    /// execute installs it; C2 Task 28 (`Runtime::prepare`) makes it
    /// mandatory.
    pub(crate) container: RwLock<Option<Arc<crate::kernel::Container>>>,
    /// Process-scoped timer delivery for lanes that multiplex multiple Linux
    /// processes inside one host process. HVPatch binds an exact-task delivery
    /// here; VMM/native leave it empty and use their established run-global
    /// backend registered in `crate::timer_delivery`.
    pub(crate) timer_delivery: RwLock<Option<Arc<dyn carrick_hal::TimerDelivery>>>,
    /// The direct in-carrier FileAuthority endpoint for this run. Activated
    /// immediately after the final root process binding (in HVPatch or the
    /// mature VMM one-task loop) on the captured root `FileTable`. Syscall
    /// families route through canonical authority transactions; in this
    /// slice, only `F_SETPIPE_SZ` capacity mutation is migrated.
    pub(crate) file_authority: RwLock<Option<Arc<crate::file_authority::FileAuthorityRun>>>,
    /// Process-local output buffering/streaming only. Linux descriptor state is
    /// owned exclusively by each captured Kernel [`crate::kernel::FileTable`].
    pub(in crate::dispatch) io: fs::RuntimeIo,
    /// Per-dispatcher selection of an MM-scoped authority. `CLONE_VM`
    /// dispatchers begin on the same authority but retain separate bindings so
    /// a successful exec can promote only the caller's staged replacement.
    pub(crate) mm_binding: Arc<DispatchMmBinding>,
    /// Serializes mapping syscalls across the dispatcher/runtime split. A
    /// `MapHostAlias` remains `Pending` until its runtime consumer claims it,
    /// then `Installing` until exact metadata commit or abort, so no sibling
    /// can race a host `MAP_FIXED` install or have its unrelated state erased
    /// by rollback.
    ///
    /// Deadlock invariant (the 2026-08-06 policy-ON go-build wedge): a
    /// `Pending`/`Installing` phase must never await a lock a `begin_dispatch`
    /// waiter can hold. On the darwin native lane, handlers wait here while
    /// holding the `:3440` dispatch guard on the guest-memory `RwLock`, so the
    /// install must complete under the PUBLISHER's own exclusive guard
    /// (`install_native_host_alias` inside `dispatch_native_syscall_inner`) —
    /// never deferred past its release. `HostAliasDispatchGuard::publish`
    /// fail-closes the one shape that breaks this (publishing from under a
    /// SHARED dispatch guard).
    /// Owned process subsystem state (executable path, personality,
    /// task comm name). See [`proc::ProcState`].
    pub(in crate::dispatch) proc: Mutex<proc::ProcState>,
    /// Owned filesystem subsystem state (unified VFS mount table plus
    /// the `/` rootfs + writable overlay). See [`fs::FsState`]. Handlers
    /// that touch only fs state borrow `self.fs` narrowly.
    pub(in crate::dispatch) fs: fs::FsState,
    /// Installed seccomp(2) cBPF filters, checked before every syscall once
    /// active. Internally locked; `libc::fork` inherits the filters via the
    /// process memory copy and sibling threads share them (process-wide), which
    /// matches Linux's filter-inheritance semantics. See [`crate::seccomp`].
    pub(crate) seccomp: crate::seccomp::SeccompState,
    /// Observer chain for syscall and lifecycle interception (container deny policy,
    /// compat reporting, audit, user observers). `None` when unconfined and no observers.
    pub(crate) observers: Option<Arc<crate::observe::ObserverChain>>,
    /// Immutable trusted interceptor membership, sealed before guest boot and
    /// inherited by exact `Arc` identity across logical process forks.
    pub(crate) interceptors: Option<Arc<crate::observe::intercept::InterceptorChain>>,
    /// SysV IPC namespace shared by every logical process in this run.
    pub(crate) sysv: Arc<sysv::SysvIpcNamespace>,
    /// Per-process shmat/shmdt bookkeeping, inherited by value at fork.
    pub(crate) sysv_process: Mutex<sysv::SysvProcessAttachments>,
    /// POSIX message queue registry (in-memory, fork-coherent).
    pub(crate) mqueue: Arc<mqueue::MqueueRegistry>,
    /// Active network namespace provider lease for this run. Host mode uses a
    /// no-op provider; bridge mode carries the socket namespace provider.
    pub(crate) network: std::sync::Arc<crate::network::RuntimeNetwork>,
    /// Linux/host page geometry selected for this run. Default dispatch stays
    /// 4 KiB Linux pages; native-only lanes can override before first syscall.
    pub(crate) page_geometry: crate::page_profile::PageGeometry,
    /// Set by syscall handlers that make process-directed async signal delivery
    /// observable while guest userspace is spinning. The threaded runtime drains
    /// this after completing the syscall and starts the signal pump before
    /// re-entering guest code.
    pub(crate) signal_pump_requested: std::sync::atomic::AtomicBool,
    /// Backend-selected owner for out-of-band signal wakes. Plain Copy state
    /// is fixed before the first guest instruction, inherited through host
    /// fork, and retained across emulated execve with the dispatcher.
    pub(crate) async_signal_wake_owner: AsyncSignalWakeOwner,
    /// Whether `execve` image loading may fall back to reading the LITERAL host
    /// filesystem (`std::fs::read` at the absolute guest path) when the target
    /// is absent from the overlay/rootfs/bind-mounts. `true` only for bare
    /// run-elf boots (no container image — the guest IS a host ELF and its
    /// execve targets are host-staged test fixtures). Container runs (run-oci,
    /// `with_rootfs*`, `--fs host`/`--fs memory`) set this `false`: a guest
    /// execve of a path not in the container filesystem must `ENOENT`, never
    /// silently load the matching HOST binary (a containment hole that, e.g.,
    /// loaded the host's glibc `/usr/bin/echo` into a musl rootfs during an
    /// execvp PATH search). Plain `bool`: set once at construction, read at
    /// execve through `&self`.
    pub(crate) exec_host_fs_fallback: bool,
}

impl Default for SyscallDispatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl SyscallDispatcher {
    pub fn new() -> Self {
        Self::new_with_host_resolver(None)
    }

    fn new_with_host_resolver(snapshot: Option<&crate::vfs::HostResolverSnapshot>) -> Self {
        let (kernel_binding, mm_id) = bootstrap_one_task_binding();
        let mm_authority = Arc::new(DispatchMmAuthority::new(mm_id));
        Self {
            kernel_binding: RwLock::new(kernel_binding),
            container: RwLock::new(None),
            timer_delivery: RwLock::new(None),
            file_authority: RwLock::new(None),
            io: fs::RuntimeIo::new(),
            mm_binding: DispatchMmBinding::new(mm_authority),
            proc: Mutex::new(proc::ProcState::new()),
            fs: fs::FsState::new_with_host_resolver(snapshot),
            seccomp: crate::seccomp::SeccompState::default(),
            // Unconfined until a frontend applies a policy or installs observers.
            observers: None,
            interceptors: None,
            sysv: Arc::new(sysv::SysvIpcNamespace::new()),
            sysv_process: Mutex::new(sysv::SysvProcessAttachments::default()),
            mqueue: Arc::new(mqueue::MqueueRegistry::default()),
            network: std::sync::Arc::new(crate::network::RuntimeNetwork::host_default()),
            page_geometry: crate::page_profile::PageGeometry {
                host_page_size: crate::page_profile::DEFAULT_LINUX_PAGE_SIZE,
                linux_page_size: crate::page_profile::DEFAULT_LINUX_PAGE_SIZE,
                native_profile: None,
            },
            signal_pump_requested: std::sync::atomic::AtomicBool::new(false),
            async_signal_wake_owner: AsyncSignalWakeOwner::SignalPump,
            // Default: bare run-elf boot — allow the host-fs execve fallback.
            // Container constructors flip this off (see `with_rootfs*` /
            // `sandbox_exec_to_container`).
            exec_host_fs_fallback: true,
        }
    }

    pub fn with_network(network: std::sync::Arc<crate::network::RuntimeNetwork>) -> Self {
        Self::with_network_and_host_resolver(network, None)
    }

    pub fn with_network_and_host_resolver(
        network: std::sync::Arc<crate::network::RuntimeNetwork>,
        snapshot: Option<&crate::vfs::HostResolverSnapshot>,
    ) -> Self {
        let mut dispatcher = Self::new_with_host_resolver(snapshot);
        // Bare/reference-model callers do not subsequently install the
        // product container that `Runtime::prepare` supplies. Give those
        // callers one coherent namespace object now so `/sys`, rtnetlink,
        // ioctls and `/proc/net` all render the exact supplied model. Build it
        // from that model directly: probing a host mirror here and replacing
        // it immediately is both wasted work and a transient wrong authority.
        dispatcher.set_container(Arc::new(
            crate::kernel::Container::for_reference_model_with_network(network.model.clone()),
        ));
        if should_mount_network_resolv_conf(&network.model) {
            let contents = resolv_conf_contents_for_network(&network.model);
            dispatcher.fs.vfs_mounts_mut().mount(
                "/etc/resolv.conf",
                Box::new(crate::vfs::ResolvConfVfs::from_contents(contents)),
            );
        }
        dispatcher.network = network;
        dispatcher
    }

    /// Install the container the root bootstrap boots into.
    pub fn set_container(&mut self, container: Arc<crate::kernel::Container>) {
        self.fs.vfs_mounts_mut().mount(
            "/sys",
            Box::new(crate::vfs::SysVfs::in_namespace(Arc::clone(
                container.net_ns(),
            ))),
        );
        *self.container.write() = Some(container);
    }

    /// Seal this run's mount table for terminal retirement. Call only after
    /// every image/spec/embed mount has been installed: holding the token is
    /// intentionally an additional `Arc` owner, so later reconfiguration
    /// would fail the dispatcher's pre-boot uniqueness invariant.
    pub(crate) fn prepare_mount_retirement(&self) -> fs::MountRetirement {
        fs::MountRetirement::new(self.container().id(), Arc::clone(&self.fs.vfs_mounts))
    }

    /// The container installed by `Runtime::execute`, if any. The HVPatch
    /// root bootstrap uses this to decide whether to fall back to the process
    /// environment (`run-elf`, in-crate fixtures).
    pub(crate) fn installed_container(&self) -> Option<Arc<crate::kernel::Container>> {
        self.container.read().clone()
    }

    /// The container this dispatcher serves. Every product entry installs
    /// one before the first syscall; a dispatcher that reaches this without
    /// one (a bare in-crate fixture) is given the reference-model container
    /// so callers never see a carrier-wide answer.
    pub fn container(&self) -> Arc<crate::kernel::Container> {
        if let Some(container) = self.installed_container() {
            return container;
        }
        let mut slot = self.container.write();
        Arc::clone(
            slot.get_or_insert_with(|| Arc::new(crate::kernel::Container::for_reference_model())),
        )
    }

    /// Name the run's UTS namespace (`--hostname`, or the container name).
    ///
    /// The name goes into this dispatcher's container namespace. Preparation
    /// installs the final value before graph publication; this setter remains
    /// for the one-task compatibility constructors.
    pub fn set_guest_hostname(&self, hostname: impl Into<String>) {
        let hostname = hostname.into();
        self.container().uts_ns().set_nodename(&hostname);
    }

    pub fn set_host_resolver_snapshot(&mut self, snapshot: &crate::vfs::HostResolverSnapshot) {
        self.fs.vfs_mounts_mut().mount(
            "/etc/resolv.conf",
            Box::new(crate::vfs::ResolvConfVfs::from_host_snapshot(snapshot)),
        );
    }

    pub fn with_page_geometry(page_geometry: crate::page_profile::PageGeometry) -> Self {
        let mut dispatcher = Self::new();
        dispatcher.page_geometry = page_geometry;
        dispatcher
    }

    pub(crate) fn set_page_geometry(&mut self, page_geometry: crate::page_profile::PageGeometry) {
        self.page_geometry = page_geometry;
    }

    #[allow(dead_code)]
    pub(crate) fn async_signal_wake_owner(&self) -> AsyncSignalWakeOwner {
        self.async_signal_wake_owner
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn publish_rlimit_cpu_signal_for_test(&self, signum: i32) {
        self.async_signal_wake_owner.publish_process_signal(signum);
    }

    pub fn page_geometry(&self) -> crate::page_profile::PageGeometry {
        self.page_geometry
    }

    pub(crate) fn linux_page_size(&self) -> u64 {
        self.page_geometry.linux_page_size
    }

    pub(crate) fn request_signal_pump(&self) {
        self.signal_pump_requested
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    pub(crate) fn take_signal_pump_request(&self) -> bool {
        self.signal_pump_requested
            .swap(false, std::sync::atomic::Ordering::SeqCst)
    }

    pub fn with_rootfs(rootfs: RootFs) -> Self {
        let mut s = Self::new();
        s.fs.rootfs_vfs_mut().rootfs = Some(rootfs);
        // A rootfs means a sandboxed container filesystem: no host-fs execve escape.
        s.exec_host_fs_fallback = false;
        s
    }

    pub fn with_rootfs_and_executable(rootfs: RootFs, executable_path: impl Into<String>) -> Self {
        let mut s = Self::new();
        s.fs.rootfs_vfs_mut().rootfs = Some(rootfs);
        s.exec_host_fs_fallback = false;
        s.set_executable_path(executable_path);
        s
    }

    /// Mark this dispatcher as running a sandboxed CONTAINER filesystem (an
    /// extracted OCI image on a cap-std overlay), so `execve` never falls back
    /// to the literal host filesystem. Call after constructing a container
    /// dispatcher via `new()` + `set_fs_backend` (the run-oci / `--fs host`
    /// paths, which do not go through `with_rootfs*`). `with_rootfs*` already
    /// imply this; this is for the overlay-only container construction.
    pub fn sandbox_exec_to_container(&mut self) {
        self.exec_host_fs_fallback = false;
    }

    /// Whether `execve` image loading may read the literal host filesystem for a
    /// target absent from the overlay/rootfs/mounts. See `exec_host_fs_fallback`.
    pub fn exec_host_fs_fallback(&self) -> bool {
        self.exec_host_fs_fallback
    }

    /// Swap the in-memory default for any other [`FsBackend`]. Used by
    /// the CLI's `--fs host` to switch to a cap-std-sandboxed scratch
    /// directory. Returns the previously-installed backend so the
    /// caller can decide what to do with it (normally just drop).
    pub fn set_fs_backend(&mut self, backend: Box<dyn FsBackend>) -> Box<dyn FsBackend> {
        self.fs.rootfs_vfs_mut().set_overlay(backend)
    }

    /// Install an immutable lower beneath the current writable backend. Used
    /// by Darwin's cached-rootfs setup, which constructs the network-aware
    /// dispatcher before the layer cache is acquired.
    pub fn set_rootfs_layer(&mut self, rootfs: RootFs) {
        let vfs = self.fs.rootfs_vfs_mut();
        vfs.reset_dentry_cache();
        vfs.rootfs = Some(rootfs);
        self.exec_host_fs_fallback = false;
    }

    /// Drop the immutable in-memory rootfs layer. Valid ONLY once the
    /// overlay backend holds the complete materialised filesystem (i.e.
    /// after `HostFsBackend::seed_from_rootfs` for `--fs host`): from then
    /// on the disk overlay is authoritative for every read, so the
    /// in-memory rootfs is redundant and just wastes RAM. All layered VFS
    /// reads and `read_exec_file` already fall back gracefully to "overlay
    /// only" when the rootfs is `None`. Never call this for `--fs memory`,
    /// whose overlay starts empty and relies on the rootfs for reads.
    pub fn drop_rootfs_layer(&mut self) {
        let vfs = self.fs.rootfs_vfs_mut();
        vfs.reset_dentry_cache();
        vfs.rootfs = None;
    }

    /// Clone process-private dispatcher state for an hvpatch in-process fork.
    /// Shared kernel objects (open descriptions, filesystem namespace, network)
    /// stay shared; fd numbers, signals, credentials, memory metadata, and
    /// process controls become independent child state.
    #[cfg(test)]
    pub(crate) fn fork_clone_in_process(
        &self,
        _parent_tid: crate::thread::ThreadId,
        _child_tid: crate::thread::ThreadId,
        parent_guest_pid: u32,
        child_guest_pid: u32,
    ) -> Self {
        self.fork_clone_in_process_with_mm_mode(
            _parent_tid,
            _child_tid,
            parent_guest_pid,
            child_guest_pid,
            crate::kernel::CloneObjectMode::Copy,
        )
    }

    pub(crate) fn prepare_fork_mm(
        &self,
        parent_mm_id: crate::kernel::MmId,
        child_mm_id: crate::kernel::MmId,
        mode: crate::kernel::CloneObjectMode,
    ) -> Result<PreparedDispatchMmFork, PrepareDispatchMmForkError> {
        match mode {
            crate::kernel::CloneObjectMode::Share if parent_mm_id != child_mm_id => {
                return Err(PrepareDispatchMmForkError::SharedIdentityMismatch);
            }
            crate::kernel::CloneObjectMode::Copy if parent_mm_id == child_mm_id => {
                return Err(PrepareDispatchMmForkError::CopiedIdentityCollision);
            }
            _ => {}
        }
        // Fork preparation reads an exact revision and produces a private
        // projection. Publication validates the revision below; no host alias
        // is acquired while taking this snapshot.
        let parent_mm = self.mm_binding.current.load_full();
        let (parent_revision, child_mm, backend_plan) = match mode {
            crate::kernel::CloneObjectMode::Share => {
                let (revision, ranges) = parent_mm.fork_projection_with_revision()?;
                (revision, Arc::clone(&parent_mm), ranges)
            }
            crate::kernel::CloneObjectMode::Copy => {
                let (forked, revision, ranges) = parent_mm.fork_private_with_policy(child_mm_id)?;
                (revision, Arc::new(forked), ranges)
            }
        };
        Ok(PreparedDispatchMmFork {
            parent_mm_id,
            child_mm_id,
            parent_mm,
            parent_revision,
            mode,
            child_mm,
            backend_plan,
        })
    }

    pub(crate) fn fork_clone_with_prepared_mm_authorized(
        &self,
        observed_parent_mm_id: crate::kernel::MmId,
        observed_child_mm_id: crate::kernel::MmId,
        parent_guest_pid: u32,
        child_guest_pid: u32,
        prepared_mm: PreparedDispatchMmFork,
        permit: &mm_mutation::HostAliasPermit<'_>,
    ) -> Result<Self, crate::kernel::SnapshotError> {
        self.fork_clone_with_prepared_mm_authorized_observed(
            observed_parent_mm_id,
            observed_child_mm_id,
            parent_guest_pid,
            child_guest_pid,
            prepared_mm,
            permit,
            |_| {},
        )
    }

    #[cfg(test)]
    pub(crate) fn fork_clone_with_prepared_mm(
        &self,
        observed_parent_mm_id: crate::kernel::MmId,
        observed_child_mm_id: crate::kernel::MmId,
        parent_guest_pid: u32,
        child_guest_pid: u32,
        prepared_mm: PreparedDispatchMmFork,
    ) -> Result<Self, crate::kernel::SnapshotError> {
        mm_mutation::test_support::with_permit(self.mm_mutation_coordinator(), |permit| {
            self.fork_clone_with_prepared_mm_authorized(
                observed_parent_mm_id,
                observed_child_mm_id,
                parent_guest_pid,
                child_guest_pid,
                prepared_mm,
                permit,
            )
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn fork_clone_with_prepared_mm_authorized_observed(
        &self,
        observed_parent_mm_id: crate::kernel::MmId,
        observed_child_mm_id: crate::kernel::MmId,
        parent_guest_pid: u32,
        child_guest_pid: u32,
        prepared_mm: PreparedDispatchMmFork,
        permit: &mm_mutation::HostAliasPermit<'_>,
        mut observe_install: impl FnMut(bool),
    ) -> Result<Self, crate::kernel::SnapshotError> {
        if observed_parent_mm_id != prepared_mm.parent_mm_id
            || observed_child_mm_id != prepared_mm.child_mm_id
        {
            return Err(crate::kernel::SnapshotError::ChangedDuringObservation);
        }
        // The permit and the prepared parent were both captured before the
        // copy phase; an exec promotion during the copy makes them stale
        // together. Refuse that as a retryable observation failure rather than
        // letting `begin_alias` abort the carrier over a foreign permit.
        let dispatch = self
            .mm_binding
            .begin_dispatch_for(permit, &prepared_mm.parent_mm)
            .ok_or(crate::kernel::SnapshotError::ChangedDuringObservation)?;
        if prepared_mm.parent_mm.vma_revision() != prepared_mm.parent_revision {
            return Err(crate::kernel::SnapshotError::ChangedDuringObservation);
        }
        observe_install(false);
        let child_binding = DispatchMmBinding::new(prepared_mm.child_mm);
        let child_dispatcher = Self {
            kernel_binding: RwLock::new(self.kernel_binding.read().clone()),
            container: RwLock::new(self.container.read().clone()),
            timer_delivery: RwLock::new(None),
            file_authority: RwLock::new(self.file_authority.read().clone()),
            io: self.io.fork_clone(),
            mm_binding: child_binding,
            proc: Mutex::new(
                self.proc
                    .lock()
                    .fork_clone(parent_guest_pid, child_guest_pid),
            ),
            fs: self.fs.fork_clone(),
            seccomp: self.seccomp.fork_clone(),
            observers: self.observers.clone(),
            interceptors: self.interceptors.clone(),
            sysv: Arc::clone(&self.sysv),
            sysv_process: Mutex::new(self.fork_sysv_process_attachments()),
            mqueue: Arc::clone(&self.mqueue),
            network: Arc::clone(&self.network),
            page_geometry: self.page_geometry,
            signal_pump_requested: std::sync::atomic::AtomicBool::new(false),
            async_signal_wake_owner: self.async_signal_wake_owner,
            exec_host_fs_fallback: self.exec_host_fs_fallback,
        };
        observe_install(true);
        drop(dispatch);
        Ok(child_dispatcher)
    }

    #[cfg(test)]
    pub(crate) fn fork_clone_with_prepared_mm_observed(
        &self,
        observed_parent_mm_id: crate::kernel::MmId,
        observed_child_mm_id: crate::kernel::MmId,
        parent_guest_pid: u32,
        child_guest_pid: u32,
        prepared_mm: PreparedDispatchMmFork,
        observe_install: impl FnMut(bool),
    ) -> Result<Self, crate::kernel::SnapshotError> {
        mm_mutation::test_support::with_permit(self.mm_mutation_coordinator(), |permit| {
            self.fork_clone_with_prepared_mm_authorized_observed(
                observed_parent_mm_id,
                observed_child_mm_id,
                parent_guest_pid,
                child_guest_pid,
                prepared_mm,
                permit,
                observe_install,
            )
        })
    }

    #[cfg(test)]
    pub(crate) fn fork_clone_in_process_with_mm_mode(
        &self,
        _parent_tid: crate::thread::ThreadId,
        _child_tid: crate::thread::ThreadId,
        parent_guest_pid: u32,
        child_guest_pid: u32,
        mm_mode: crate::kernel::CloneObjectMode,
    ) -> Self {
        let parent_mm_id = crate::kernel::MmId::from_registry_allocation(std::num::NonZeroU64::MIN);
        let child_mm_id = match mm_mode {
            crate::kernel::CloneObjectMode::Share => parent_mm_id,
            crate::kernel::CloneObjectMode::Copy => crate::kernel::MmId::from_registry_allocation(
                std::num::NonZeroU64::new(2).expect("nonzero synthetic child MM id"),
            ),
        };
        let prepared_mm = self
            .prepare_fork_mm(parent_mm_id, child_mm_id, mm_mode)
            .unwrap_or_else(|error| {
                tracing::error!(?error, "dispatcher fork preparation failed");
                std::process::abort()
            });
        let child = self
            .fork_clone_with_prepared_mm(
                parent_mm_id,
                child_mm_id,
                parent_guest_pid,
                child_guest_pid,
                prepared_mm,
            )
            .unwrap_or_else(|_| {
                tracing::error!("fork_clone_in_process_with_mm_mode stale revision");
                std::process::abort()
            });
        // This test-only helper does not publish the synthetic child through
        // the kernel graph, where production binds the exact namespace-local
        // identity before the child may execute. Its callers model the
        // no-PID-namespace case, so complete that lifecycle step explicitly
        // instead of weakening `identity_pid`'s fail-closed production check.
        child
            .proc
            .lock()
            .bind_hvpatch_identity(child_guest_pid, child_guest_pid);
        child
    }

    #[cfg(test)]
    pub(crate) fn replace_current_mm_for_test(&self, replacement: Arc<DispatchMmAuthority>) {
        self.mm_binding.current.store(replacement);
    }

    pub(crate) fn event_ring_guest_pid(&self) -> i32 {
        self.proc
            .lock()
            .virtual_pid
            .and_then(|pid| i32::try_from(pid).ok())
            .unwrap_or_else(|| std::process::id() as i32)
    }

    /// Bind an fd-table removal to the multiplexed Linux process/thread that
    /// performed it, plus the pre-removal logical ownership count. The
    /// historical FDCLOSE record cannot carry this because its other fields
    /// are already the guest/host fd pair.
    pub(crate) fn record_fd_close_owner(&self, fd: i32, guest_tid: i32, open_file: &OpenFile) {
        let guest_pid = self.event_ring_guest_pid();
        let refs_before = open_file.description.fd_ref_count();
        crate::event_ring::rec(crate::event_ring::FDOWNER, guest_pid, guest_tid, fd);
        crate::event_ring::rec(
            crate::event_ring::FDREF,
            guest_pid,
            fd,
            i32::try_from(refs_before).unwrap_or(i32::MAX),
        );
    }

    /// Set the executable path recorded in `/proc/self/cmdline`,
    /// `/proc/self/comm`, and `/proc/self/status`. Used when a
    /// dispatcher is constructed via `SyscallDispatcher::new()` without
    /// a rootfs (the `--fs host` streaming path) so that `/proc` reads
    /// reflect the correct binary name.
    pub fn set_executable_path(&self, path: impl Into<String>) {
        let path = path.into();
        let mut proc = self.proc.lock();
        proc.executable_path = path.clone();
        proc.argv = vec![path];
    }

    /// Enter a `binfmt_misc` redirect (Apple's Rosetta). `executable_path` stays
    /// the target (a binfmt redirect is transparent on real Linux), so this:
    ///  - flags the guest binfmt-interpreted, so `uname(2)` reports x86_64; and
    ///  - sets `/proc/self/cmdline` to `stack_argv` — the argv carrick puts on the
    ///    guest stack for Rosetta (`[argv0, target, args…]`). Rosetta serves the
    ///    guest's cmdline by applying its argv-skip to what it received on the
    ///    stack; if `proc.argv` instead held the bare program argv (no target
    ///    entry), that skip would strip the program's real `argv[0]`. Matching the
    ///    stack form makes the post-skip cmdline the faithful program argv.
    pub fn enter_binfmt(&self, stack_argv: &[Vec<u8>]) {
        let mut proc = self.proc.lock();
        proc.binfmt_interpreted = true;
        proc.argv = stack_argv
            .iter()
            .map(|a| String::from_utf8_lossy(a).into_owned())
            .collect();
    }

    /// Record whether the guest's native ISA is x86_64 so `uname(2)` (and other
    /// arch-dependent syscalls) report it. Set once at run-image setup from
    /// `E::Arch::elf_machine()`; native aarch64 guests leave it false.
    pub fn set_native_x86_64(&self, native_x86_64: bool) {
        self.proc.lock().native_x86_64 = native_x86_64;
    }

    pub fn set_executable_identity(
        &self,
        path: impl Into<String>,
        argv: Vec<String>,
        env: Vec<Vec<u8>>,
    ) {
        let path = path.into();
        // `/proc/self/exe` MUST resolve to an absolute path: the Linux kernel
        // always stores the absolute, resolved executable path regardless of how
        // execve was called. glibc's dynamic loader asserts this
        // (`_dl_get_origin`: `linkval[0] == '/'`) and aborts the process if the
        // readlink result is relative — which is exactly what happens when a
        // program execs itself by a RELATIVE path (e.g. Go's os/exec
        // TestCommandRelativeName). Absolutize a relative execve path against the
        // guest cwd so the stored identity matches kernel semantics.
        let abs = if path.starts_with('/') {
            normalize_abs_path(&path)
        } else {
            let cwd = self.cwd();
            normalize_abs_path(&format!("{}/{}", cwd.trim_end_matches('/'), path))
        };
        let mut proc = self.proc.lock();
        proc.executable_path = abs.clone();
        proc.argv = if argv.is_empty() { vec![abs] } else { argv };
        let base = path.rsplit('/').next().unwrap_or(&path);
        proc.task_name = linux_task_name_from_bytes(base.as_bytes());
        proc.env = env;
        // A fresh image identity: clear the binfmt flag. The binfmt redirect
        // re-sets it (via set_binfmt_interpreted) iff THIS image is foreign-arch,
        // so the flag tracks the current image across execve (x86 -> native and
        // native -> x86).
        proc.binfmt_interpreted = false;
    }

    pub(crate) fn current_exec_env(&self) -> Vec<Vec<u8>> {
        self.proc.lock().env.clone()
    }
}

fn should_mount_network_resolv_conf(model: &crate::network::model::LinuxNetworkModel) -> bool {
    model.has_resolver_config()
}

pub(crate) fn resolv_conf_contents_for_network(
    model: &crate::network::model::LinuxNetworkModel,
) -> Vec<u8> {
    model.render_resolv_conf()
}

// ============================================================================
// Subsystem Views
// ============================================================================

/// Cross-subsystem capabilities required during filesystem operations (such as fd close lifecycle).
pub(in crate::dispatch) trait FsCrossSubsystem: Send + Sync {
    fn detach_fd_from_epolls(&self, _fd: i32) {}
    fn close_open_file_and_free_pty(&self, _open_file: &OpenFile) {}
    fn mqueue_owner_alias_closed(
        &self,
        _files: &Arc<crate::kernel::FileTable>,
        _open_file: &OpenFile,
    ) {
    }
    fn mqueue_owner_alias_closed_known(
        &self,
        _file_table: crate::kernel::FileTableId,
        _open_file: &OpenFile,
        _alias_remains: bool,
    ) {
    }
    fn close_draining_file_table(
        &self,
        _kernel: &Arc<crate::kernel::Kernel>,
        _files: &Arc<crate::kernel::FileTable>,
        _owner: Option<crate::kernel::TaskKey>,
        _exec_successor: Option<&Arc<crate::kernel::FileTable>>,
    ) {
    }
    fn has_deliverable_dispatch_pending_for_wait(
        &self,
        _context: &crate::kernel::KernelContext,
        _tid: crate::thread::ThreadId,
        _sig_mask: carrick_abi::WaitSigMask,
    ) -> bool {
        false
    }
    fn take_signalfd_bytes(
        &self,
        _context: &crate::kernel::KernelContext,
        _tid: crate::thread::ThreadId,
        _mask: carrick_abi::SigSet,
        _max: usize,
    ) -> Vec<u8> {
        Vec::new()
    }
    fn perf_event_read_bytes(
        &self,
        _state: &Arc<crate::dispatch::perf::PerfEventState>,
        _length: usize,
    ) -> Result<Vec<u8>, carrick_abi::LinuxErrno> {
        Err(carrick_abi::LINUX_EINVAL)
    }
    fn perf_event_ioctl_out(
        &self,
        _reporter: &carrick_observability::compat::CompatReporter,
        _fd: i32,
        _state: &Arc<crate::dispatch::perf::PerfEventState>,
        _request: u64,
        _arg: u64,
    ) -> Result<Option<[u8; 8]>, carrick_abi::LinuxErrno> {
        Err(carrick_abi::LINUX_ENOTTY)
    }
    fn memfd_has_writable_shared_map(
        &self,
        _description: &Arc<crate::kernel::FileDescription>,
    ) -> bool {
        false
    }
    fn range_touches_secretmem(&self, _start: u64, _len: u64) -> bool {
        false
    }
    fn is_synthetic_virtual_path(
        &self,
        _context: &crate::kernel::KernelContext,
        _path: &str,
    ) -> bool {
        false
    }
    fn complete_wait_fd_authority(
        &self,
        outcome: super::DispatchOutcome,
        _files: &crate::kernel::objects::FileTable,
        _wait_fds: &[i32],
    ) -> super::DispatchOutcome {
        outcome
    }
    fn captured_fs_context(&self) -> Arc<crate::kernel::FsContext>;
    fn captured_file_table(&self) -> Arc<crate::kernel::FileTable>;
    fn captured_mm(&self) -> Arc<crate::kernel::Mm>;
    fn cred_snapshot(&self) -> Arc<crate::kernel::Credentials>;
    fn cwd(&self) -> String;
    fn mem_snapshot(&self) -> super::mem::MemState;
    fn identity_pid(&self) -> u32;
    /// Live `/proc/sysvipc/{shm,sem,msg}` tables (header plus one row per
    /// object); the SysV IPC state lives outside the fs subsystem.
    fn sysvipc_shm_table(&self) -> String;
    fn sysvipc_sem_table(&self) -> String;
    fn sysvipc_msg_table(&self) -> String;
    fn captured_slot_authority(
        &self,
        _fd: i32,
    ) -> Option<crate::kernel::objects::FileSlotAuthority> {
        None
    }
    fn rename_open_paths(&self, _resolved_old: &str, _resolved_new: &str) {}
    fn authority_call(
        &self,
        _table: Arc<crate::kernel::FileTable>,
        _slot: crate::kernel::objects::FileSlotAuthority,
        _command: crate::file_authority::Command,
    ) -> Result<crate::file_authority::Outcome, super::AuthorityCallError> {
        Err(super::AuthorityCallError::Fatal(
            crate::file_authority::AuthorityFatal::TransportUnavailable,
        ))
    }
    fn io_uring_description(&self, _fd: i32) -> Option<Arc<crate::kernel::FileDescription>> {
        None
    }
    fn notify_inmem_epoll(&self) {}
    fn host_socket_lookup(
        &self,
        _fd: i32,
    ) -> Result<(super::HostFd, i32), carrick_abi::LinuxErrno> {
        Err(carrick_abi::LINUX_EBADF)
    }
    fn socket_guest_type(&self, _fd: i32) -> Option<i32> {
        None
    }
    fn perf_event_state(&self, _fd: i32) -> Option<Arc<super::perf::PerfEventState>> {
        None
    }
    fn write_eventfd(&self, _bytes: &[u8], _state: &super::EventFdState) -> super::DispatchOutcome {
        super::DispatchOutcome::errno(carrick_abi::LINUX_EINVAL)
    }
}

impl FsCrossSubsystem for SyscallDispatcher {
    fn detach_fd_from_epolls(&self, fd: i32) {
        self.detach_fd_from_epolls(fd);
    }
    fn close_open_file_and_free_pty(&self, open_file: &OpenFile) {
        self.close_open_file_and_free_pty(open_file);
    }
    fn mqueue_owner_alias_closed(
        &self,
        files: &Arc<crate::kernel::FileTable>,
        open_file: &OpenFile,
    ) {
        self.mqueue_owner_alias_closed(files, open_file);
    }
    fn mqueue_owner_alias_closed_known(
        &self,
        file_table: crate::kernel::FileTableId,
        open_file: &OpenFile,
        alias_remains: bool,
    ) {
        self.mqueue_owner_alias_closed_known(file_table, open_file, alias_remains);
    }
    fn close_draining_file_table(
        &self,
        kernel: &Arc<crate::kernel::Kernel>,
        files: &Arc<crate::kernel::FileTable>,
        owner: Option<crate::kernel::TaskKey>,
        exec_successor: Option<&Arc<crate::kernel::FileTable>>,
    ) {
        self.close_draining_file_table(kernel, files, owner, exec_successor);
    }
    fn has_deliverable_dispatch_pending_for_wait(
        &self,
        context: &crate::kernel::KernelContext,
        tid: crate::thread::ThreadId,
        sig_mask: carrick_abi::WaitSigMask,
    ) -> bool {
        self.has_deliverable_dispatch_pending_for_wait(context, tid, sig_mask)
    }
    fn take_signalfd_bytes(
        &self,
        context: &crate::kernel::KernelContext,
        tid: crate::thread::ThreadId,
        mask: carrick_abi::SigSet,
        max: usize,
    ) -> Vec<u8> {
        self.take_signalfd_bytes(context, tid, mask, max)
    }
    fn perf_event_read_bytes(
        &self,
        state: &Arc<crate::dispatch::perf::PerfEventState>,
        length: usize,
    ) -> Result<Vec<u8>, carrick_abi::LinuxErrno> {
        self.perf_event_read_bytes(state, length)
    }
    fn perf_event_ioctl_out(
        &self,
        reporter: &carrick_observability::compat::CompatReporter,
        fd: i32,
        state: &Arc<crate::dispatch::perf::PerfEventState>,
        request: u64,
        arg: u64,
    ) -> Result<Option<[u8; 8]>, carrick_abi::LinuxErrno> {
        self.perf_event_ioctl_out(reporter, fd, state, request, arg)
    }
    fn memfd_has_writable_shared_map(
        &self,
        description: &Arc<crate::kernel::FileDescription>,
    ) -> bool {
        self.memfd_has_writable_shared_map(description)
    }
    fn range_touches_secretmem(&self, start: u64, len: u64) -> bool {
        self.range_touches_secretmem(start, len)
    }
    fn is_synthetic_virtual_path(
        &self,
        context: &crate::kernel::KernelContext,
        path: &str,
    ) -> bool {
        self.is_synthetic_virtual_path(context, path)
    }
    fn complete_wait_fd_authority(
        &self,
        outcome: super::DispatchOutcome,
        files: &crate::kernel::objects::FileTable,
        wait_fds: &[i32],
    ) -> super::DispatchOutcome {
        self.complete_wait_fd_authority(outcome, files, wait_fds.iter().copied())
    }
    fn captured_fs_context(&self) -> Arc<crate::kernel::FsContext> {
        self.captured_fs_context()
    }
    fn captured_file_table(&self) -> Arc<crate::kernel::FileTable> {
        self.captured_file_table()
    }
    fn captured_mm(&self) -> Arc<crate::kernel::Mm> {
        self.captured_mm()
    }
    fn cred_snapshot(&self) -> Arc<crate::kernel::Credentials> {
        self.cred_snapshot()
    }
    fn cwd(&self) -> String {
        self.cwd()
    }
    fn mem_snapshot(&self) -> super::mem::MemState {
        self.mem_snapshot()
    }
    fn identity_pid(&self) -> u32 {
        self.identity_pid()
    }
    fn sysvipc_shm_table(&self) -> String {
        SyscallDispatcher::sysvipc_shm_table(self)
    }
    fn sysvipc_sem_table(&self) -> String {
        SyscallDispatcher::sysvipc_sem_table(self)
    }
    fn sysvipc_msg_table(&self) -> String {
        SyscallDispatcher::sysvipc_msg_table(self)
    }
    fn captured_slot_authority(
        &self,
        fd: i32,
    ) -> Option<crate::kernel::objects::FileSlotAuthority> {
        self.captured_slot_authority(fd)
    }
    fn rename_open_paths(&self, resolved_old: &str, resolved_new: &str) {
        self.rename_open_paths(resolved_old, resolved_new);
    }
    fn authority_call(
        &self,
        table: Arc<crate::kernel::FileTable>,
        slot: crate::kernel::objects::FileSlotAuthority,
        command: crate::file_authority::Command,
    ) -> Result<crate::file_authority::Outcome, super::AuthorityCallError> {
        self.authority_call(table, slot, command)
    }
    fn io_uring_description(&self, fd: i32) -> Option<Arc<crate::kernel::FileDescription>> {
        self.io_uring_description(fd)
    }
    fn notify_inmem_epoll(&self) {
        self.notify_inmem_epoll();
    }
    fn host_socket_lookup(&self, fd: i32) -> Result<(super::HostFd, i32), carrick_abi::LinuxErrno> {
        self.host_socket_lookup(fd)
    }
    fn socket_guest_type(&self, fd: i32) -> Option<i32> {
        self.socket_guest_type(fd)
    }
    fn perf_event_state(&self, fd: i32) -> Option<Arc<super::perf::PerfEventState>> {
        self.perf_event_state(fd)
    }
    fn write_eventfd(&self, bytes: &[u8], state: &super::EventFdState) -> super::DispatchOutcome {
        super::write_eventfd(self, bytes, state)
    }
}

/// Cross-subsystem capabilities required during network operations (such as fd lifecycle and signal suspend).
pub(in crate::dispatch) trait NetCrossSubsystem: Send + Sync {
    fn caller_net_ns(&self, context: &crate::kernel::KernelContext) -> Arc<crate::kernel::NetNs>;
    fn captured_file_table(&self) -> Arc<crate::kernel::FileTable>;
    fn cred_snapshot(&self) -> Arc<crate::kernel::Credentials>;
    fn identity_pid(&self) -> u32;
    fn has_deliverable_dispatch_pending_for_wait(
        &self,
        context: &crate::kernel::KernelContext,
        tid: crate::thread::ThreadId,
        sig_mask: carrick_abi::WaitSigMask,
    ) -> bool;
    fn begin_sigsuspend(
        &self,
        context: &crate::kernel::KernelContext,
        tid: crate::thread::ThreadId,
        suspend_mask: carrick_abi::SigSet,
    ) -> carrick_abi::SigSet;
    fn resolve_at_path(&self, dirfd: u64, path: &str) -> Result<String, carrick_abi::LinuxErrno>;
    fn layered_metadata(&self, path: &str) -> Result<RootFsMetadata, carrick_abi::LinuxErrno>;
    fn layered_lstat(&self, path: &str) -> Result<RootFsMetadata, carrick_abi::LinuxErrno>;
    fn stamp_new_node_owner(&self, path: &str, node_mode: u32);
    fn nofile_limit(&self) -> i32;
    fn staged_splice_pipe_bytes(&self, fd: i32) -> usize;
    fn staged_splice_description_bytes(&self, id: crate::kernel::FileDescriptionId) -> usize;
    fn host_pipe_capacity_room(
        &self,
        pipe_capacity: i64,
        pipe_id: u64,
        is_read_end: bool,
        bidirectional: bool,
        host_fd: i32,
    ) -> Option<usize>;
    fn note_fd_closed(&self, fd: i32);
    fn close_open_file_and_free_pty(&self, open_file: &OpenFile);
    fn notify_inmem_epoll(&self);
    fn open_file(&self, fd: i32) -> Option<OpenFile>;
    fn fd_is_valid(&self, fd: i32) -> bool;
    fn stdio_is_closed(&self, fd: i32) -> bool;
    fn bare_stdio_description(
        &self,
        fd: i32,
    ) -> Result<Arc<crate::kernel::FileDescription>, carrick_abi::LinuxErrno>;
    fn install_fd(
        &self,
        description: super::OpenDescription,
        fd_flags: u64,
    ) -> super::DispatchOutcome;
    fn install_fd_at_or_above(&self, min_fd: i32, open_file: OpenFile) -> Result<i32, OpenFile>;
    fn install_fd_pair_at_or_above(
        &self,
        min_fd: i32,
        first: OpenFile,
        second: OpenFile,
    ) -> Result<(i32, i32), (OpenFile, OpenFile)>;
    fn install_fd_with_status_flags(
        &self,
        description: super::OpenDescription,
        status_flags: u64,
        fd_flags: u64,
    ) -> super::DispatchOutcome;
}

impl NetCrossSubsystem for SyscallDispatcher {
    fn caller_net_ns(&self, context: &crate::kernel::KernelContext) -> Arc<crate::kernel::NetNs> {
        self.caller_net_ns(context)
    }
    fn captured_file_table(&self) -> Arc<crate::kernel::FileTable> {
        self.captured_file_table()
    }
    fn cred_snapshot(&self) -> Arc<crate::kernel::Credentials> {
        self.cred_snapshot()
    }
    fn identity_pid(&self) -> u32 {
        self.identity_pid()
    }
    fn has_deliverable_dispatch_pending_for_wait(
        &self,
        context: &crate::kernel::KernelContext,
        tid: crate::thread::ThreadId,
        sig_mask: carrick_abi::WaitSigMask,
    ) -> bool {
        self.has_deliverable_dispatch_pending_for_wait(context, tid, sig_mask)
    }
    fn begin_sigsuspend(
        &self,
        context: &crate::kernel::KernelContext,
        tid: crate::thread::ThreadId,
        suspend_mask: carrick_abi::SigSet,
    ) -> carrick_abi::SigSet {
        self.begin_sigsuspend(context, tid, suspend_mask)
    }
    fn resolve_at_path(&self, dirfd: u64, path: &str) -> Result<String, carrick_abi::LinuxErrno> {
        self.resolve_at_path(dirfd, path)
    }
    fn layered_metadata(&self, path: &str) -> Result<RootFsMetadata, carrick_abi::LinuxErrno> {
        self.layered_metadata(path)
    }
    fn layered_lstat(&self, path: &str) -> Result<RootFsMetadata, carrick_abi::LinuxErrno> {
        self.layered_lstat(path)
    }
    fn stamp_new_node_owner(&self, path: &str, node_mode: u32) {
        self.stamp_new_node_owner(path, node_mode);
    }
    fn nofile_limit(&self) -> i32 {
        self.nofile_limit()
    }
    fn staged_splice_pipe_bytes(&self, fd: i32) -> usize {
        self.staged_splice_pipe_bytes(fd)
    }
    fn staged_splice_description_bytes(&self, id: crate::kernel::FileDescriptionId) -> usize {
        self.staged_splice_description_bytes(id)
    }
    fn host_pipe_capacity_room(
        &self,
        pipe_capacity: i64,
        pipe_id: u64,
        is_read_end: bool,
        bidirectional: bool,
        host_fd: i32,
    ) -> Option<usize> {
        self.host_pipe_capacity_room(pipe_capacity, pipe_id, is_read_end, bidirectional, host_fd)
    }
    fn note_fd_closed(&self, fd: i32) {
        self.note_fd_closed(fd);
    }
    fn close_open_file_and_free_pty(&self, open_file: &OpenFile) {
        self.close_open_file_and_free_pty(open_file);
    }
    fn notify_inmem_epoll(&self) {
        self.notify_inmem_epoll();
    }
    fn open_file(&self, fd: i32) -> Option<OpenFile> {
        self.open_file(fd)
    }
    fn fd_is_valid(&self, fd: i32) -> bool {
        self.fd_is_valid(fd)
    }
    fn stdio_is_closed(&self, fd: i32) -> bool {
        self.stdio_is_closed(fd)
    }
    fn bare_stdio_description(
        &self,
        fd: i32,
    ) -> Result<Arc<crate::kernel::FileDescription>, carrick_abi::LinuxErrno> {
        self.bare_stdio_description(fd)
    }
    fn install_fd(
        &self,
        description: super::OpenDescription,
        fd_flags: u64,
    ) -> super::DispatchOutcome {
        self.install_fd(description, fd_flags)
    }
    fn install_fd_at_or_above(&self, min_fd: i32, open_file: OpenFile) -> Result<i32, OpenFile> {
        self.install_fd_at_or_above(min_fd, open_file)
    }
    fn install_fd_pair_at_or_above(
        &self,
        min_fd: i32,
        first: OpenFile,
        second: OpenFile,
    ) -> Result<(i32, i32), (OpenFile, OpenFile)> {
        self.install_fd_pair_at_or_above(min_fd, first, second)
    }
    fn install_fd_with_status_flags(
        &self,
        description: super::OpenDescription,
        status_flags: u64,
        fd_flags: u64,
    ) -> super::DispatchOutcome {
        self.install_fd_with_status_flags(description, status_flags, fd_flags)
    }
}

/// Subsystem view for filesystem operations.
pub struct FsView<'a> {
    pub(in crate::dispatch) fs: &'a fs::FsState,
    #[allow(dead_code)]
    pub(in crate::dispatch) file_authority:
        &'a RwLock<Option<Arc<crate::file_authority::FileAuthorityRun>>>,
    pub(in crate::dispatch) io: &'a fs::RuntimeIo,
    pub(in crate::dispatch) mm_binding: &'a Arc<DispatchMmBinding>,
    pub(in crate::dispatch) proc: &'a Mutex<proc::ProcState>,
    pub(in crate::dispatch) kernel_binding: &'a RwLock<crate::kernel::KernelTaskBinding>,
    pub(in crate::dispatch) network: &'a Arc<crate::network::RuntimeNetwork>,
    pub(in crate::dispatch) page_geometry: crate::page_profile::PageGeometry,
    #[allow(dead_code)]
    pub(in crate::dispatch) sysv: Option<&'a Arc<sysv::SysvIpcNamespace>>,
    pub(in crate::dispatch) exec_host_fs_fallback: bool,
    pub(in crate::dispatch) cross: &'a (dyn FsCrossSubsystem + 'a),
}

/// Subsystem view for network operations.
pub struct NetView<'a> {
    pub(in crate::dispatch) network: &'a Arc<crate::network::RuntimeNetwork>,
    #[allow(dead_code)]
    pub(in crate::dispatch) file_authority:
        &'a RwLock<Option<Arc<crate::file_authority::FileAuthorityRun>>>,
    #[allow(dead_code)]
    pub(in crate::dispatch) kernel_binding: &'a RwLock<crate::kernel::KernelTaskBinding>,
    #[allow(dead_code)]
    pub(in crate::dispatch) io: &'a fs::RuntimeIo,
    pub(in crate::dispatch) fs: &'a fs::FsState,
    pub(in crate::dispatch) cross: &'a (dyn NetCrossSubsystem + 'a),
}

pub(in crate::dispatch) trait MmExecutorReleaser {
    fn release_and_run(
        &mut self,
        dispatcher: &SyscallDispatcher,
        op: &mut dyn FnMut(),
    ) -> Result<(), super::outcome::DispatchError>;
}

impl<M: carrick_guest_mem::CurrentMmMemory> MmExecutorReleaser for super::SyscallCtx<'_, M> {
    fn release_and_run(
        &mut self,
        dispatcher: &SyscallDispatcher,
        op: &mut dyn FnMut(),
    ) -> Result<(), super::outcome::DispatchError> {
        let mut f = Some(op);
        dispatcher.with_current_mm_executor_released(self, || {
            if let Some(run) = f.take() {
                run();
            }
        })
    }
}

/// Cross-subsystem capabilities required during process operations.
pub(in crate::dispatch) trait ProcCrossSubsystem: Send + Sync {
    fn cred_snapshot(&self) -> Arc<crate::kernel::Credentials>;
    fn identity_pid(&self) -> u32;
    fn getpid(&self) -> super::DispatchOutcome;
    fn captured_file_table(&self) -> Arc<crate::kernel::FileTable>;
    fn open_file(&self, fd: i32) -> Option<OpenFile>;
    fn install_fd_with_status_flags(
        &self,
        description: super::OpenDescription,
        status_flags: u64,
        fd_flags: u64,
    ) -> super::DispatchOutcome;
    fn detach_fd_from_epolls(&self, fd: i32);
    fn close_open_file_and_free_pty(&self, open_file: &OpenFile);
    fn note_fd_closed(&self, fd: i32);
    fn resolve_at_path(&self, dirfd: u64, path: &str) -> Result<String, carrick_abi::LinuxErrno>;
    fn layered_lstat(
        &self,
        path: &str,
    ) -> Result<crate::rootfs::RootFsMetadata, carrick_abi::LinuxErrno>;
    #[cfg(test)]
    fn drain_xsignals_process_directed(&self, context: &crate::kernel::KernelContext);
    fn hvpatch_exact_process_signal(
        &self,
        context: &crate::kernel::KernelContext,
        target_key: crate::kernel::TaskKey,
        signum: u64,
        siginfo: Option<crate::linux_abi::LinuxSiginfo>,
    ) -> super::DispatchOutcome;
    fn non_interrupting_signal_mask(
        &self,
        context: &crate::kernel::KernelContext,
        tid: crate::thread::ThreadId,
    ) -> carrick_abi::SigSet;
    fn has_deliverable_dispatch_pending_for_wait(
        &self,
        context: &crate::kernel::KernelContext,
        tid: crate::thread::ThreadId,
        mask: carrick_abi::WaitSigMask,
    ) -> bool;
    #[cfg(test)]
    fn host_fd_for_poll(&self, fd: i32) -> Option<super::HostFd>;
    #[cfg(test)]
    fn task_rlimits(&self) -> crate::kernel::RlimitSet;
    #[cfg(test)]
    fn guest_pid_is_live(&self, pid: i32) -> Option<bool>;
    fn with_current_mm_executor_released(
        &self,
        ctx: &mut dyn MmExecutorReleaser,
        op: &mut dyn FnMut(),
    ) -> Result<(), super::outcome::DispatchError>;
}

impl ProcCrossSubsystem for SyscallDispatcher {
    fn cred_snapshot(&self) -> Arc<crate::kernel::Credentials> {
        self.cred_snapshot()
    }
    fn identity_pid(&self) -> u32 {
        self.identity_pid()
    }
    fn getpid(&self) -> super::DispatchOutcome {
        self.getpid()
    }
    fn captured_file_table(&self) -> Arc<crate::kernel::FileTable> {
        self.captured_file_table()
    }
    fn open_file(&self, fd: i32) -> Option<OpenFile> {
        self.open_file(fd)
    }
    fn install_fd_with_status_flags(
        &self,
        description: super::OpenDescription,
        status_flags: u64,
        fd_flags: u64,
    ) -> super::DispatchOutcome {
        self.install_fd_with_status_flags(description, status_flags, fd_flags)
    }
    fn detach_fd_from_epolls(&self, fd: i32) {
        self.detach_fd_from_epolls(fd);
    }
    fn close_open_file_and_free_pty(&self, open_file: &OpenFile) {
        self.close_open_file_and_free_pty(open_file);
    }
    fn note_fd_closed(&self, fd: i32) {
        self.note_fd_closed(fd);
    }
    fn resolve_at_path(&self, dirfd: u64, path: &str) -> Result<String, carrick_abi::LinuxErrno> {
        self.resolve_at_path(dirfd, path)
    }
    fn layered_lstat(
        &self,
        path: &str,
    ) -> Result<crate::rootfs::RootFsMetadata, carrick_abi::LinuxErrno> {
        self.layered_lstat(path)
    }
    #[cfg(test)]
    fn drain_xsignals_process_directed(&self, context: &crate::kernel::KernelContext) {
        self.drain_xsignals_process_directed(context);
    }
    fn hvpatch_exact_process_signal(
        &self,
        context: &crate::kernel::KernelContext,
        target_key: crate::kernel::TaskKey,
        signum: u64,
        siginfo: Option<crate::linux_abi::LinuxSiginfo>,
    ) -> super::DispatchOutcome {
        self.hvpatch_exact_process_signal(context, target_key, signum, siginfo)
    }
    fn non_interrupting_signal_mask(
        &self,
        context: &crate::kernel::KernelContext,
        tid: crate::thread::ThreadId,
    ) -> carrick_abi::SigSet {
        self.non_interrupting_signal_mask(context, tid)
    }
    fn has_deliverable_dispatch_pending_for_wait(
        &self,
        context: &crate::kernel::KernelContext,
        tid: crate::thread::ThreadId,
        mask: carrick_abi::WaitSigMask,
    ) -> bool {
        self.has_deliverable_dispatch_pending_for_wait(context, tid, mask)
    }
    #[cfg(test)]
    fn host_fd_for_poll(&self, fd: i32) -> Option<super::HostFd> {
        self.host_fd_for_poll(fd)
    }
    #[cfg(test)]
    fn task_rlimits(&self) -> crate::kernel::RlimitSet {
        self.task_rlimits()
    }
    #[cfg(test)]
    fn guest_pid_is_live(&self, pid: i32) -> Option<bool> {
        self.guest_pid_is_live(pid)
    }
    fn with_current_mm_executor_released(
        &self,
        ctx: &mut dyn MmExecutorReleaser,
        op: &mut dyn FnMut(),
    ) -> Result<(), super::outcome::DispatchError> {
        ctx.release_and_run(self, op)
    }
}

/// Subsystem view for process operations.
pub struct ProcView<'a> {
    pub(in crate::dispatch) proc: &'a Mutex<proc::ProcState>,
    pub(in crate::dispatch) seccomp: &'a crate::seccomp::SeccompState,
    pub(in crate::dispatch) page_geometry: crate::page_profile::PageGeometry,
    pub(in crate::dispatch) cross: &'a (dyn ProcCrossSubsystem + 'a),
}

/// Cross-subsystem capabilities required during signal operations.
pub(in crate::dispatch) trait SignalCrossSubsystem: Send + Sync {
    fn cred_snapshot(&self) -> Arc<crate::kernel::Credentials>;
    fn identity_pid(&self) -> u32;
    #[cfg(test)]
    fn capture_one_task_context(
        &self,
    ) -> Result<crate::kernel::KernelContext, crate::kernel::KernelError>;
    fn open_file(&self, fd: i32) -> Option<OpenFile>;
    fn install_fd_with_status_flags(
        &self,
        description: super::OpenDescription,
        status_flags: u64,
        fd_flags: u64,
    ) -> super::DispatchOutcome;
    fn effective_resource_limit(&self, resource: u64) -> carrick_abi::LinuxRlimit;
    fn stop_for_ptrace_signal(&self, signum: i32) -> bool;
    fn request_signal_pump(&self);
}

impl SignalCrossSubsystem for SyscallDispatcher {
    fn cred_snapshot(&self) -> Arc<crate::kernel::Credentials> {
        self.cred_snapshot()
    }
    fn identity_pid(&self) -> u32 {
        self.identity_pid()
    }
    #[cfg(test)]
    fn capture_one_task_context(
        &self,
    ) -> Result<crate::kernel::KernelContext, crate::kernel::KernelError> {
        self.capture_one_task_context()
    }
    fn open_file(&self, fd: i32) -> Option<OpenFile> {
        self.open_file(fd)
    }
    fn install_fd_with_status_flags(
        &self,
        description: super::OpenDescription,
        status_flags: u64,
        fd_flags: u64,
    ) -> super::DispatchOutcome {
        self.install_fd_with_status_flags(description, status_flags, fd_flags)
    }
    fn effective_resource_limit(&self, resource: u64) -> carrick_abi::LinuxRlimit {
        self.effective_resource_limit(resource)
    }
    fn stop_for_ptrace_signal(&self, signum: i32) -> bool {
        crate::exec_helpers::stop_for_ptrace_signal(self, signum)
    }
    fn request_signal_pump(&self) {
        self.request_signal_pump();
    }
}

/// Subsystem view for signal operations.
pub struct SignalView<'a> {
    #[allow(dead_code)]
    pub(in crate::dispatch) kernel_binding: &'a RwLock<crate::kernel::KernelTaskBinding>,
    #[allow(dead_code)]
    pub(in crate::dispatch) signal_pump_requested: &'a std::sync::atomic::AtomicBool,
    #[allow(dead_code)]
    pub(in crate::dispatch) async_signal_wake_owner: AsyncSignalWakeOwner,
    pub(in crate::dispatch) cross: &'a (dyn SignalCrossSubsystem + 'a),
}

pub(in crate::dispatch) trait IpcCrossSubsystem {
    fn cred_snapshot(&self) -> Arc<crate::kernel::Credentials>;
    fn identity_pid(&self) -> u32;
    fn hvpatch_process(&self) -> Option<crate::hvpatch::ProcessContext>;
    fn is_forked_guest_process(&self) -> bool;
    fn begin_host_alias_dispatch<'permit>(
        &self,
        permit: &'permit crate::dispatch::mm_mutation::HostAliasPermit<'_>,
    ) -> crate::dispatch::HostAliasDispatchGuard<'permit>;
    fn guest_vma_overlaps(&self, va: u64, len: u64) -> bool;
    fn begin_conditional_vma_dispatch<'permit>(
        &self,
        permit: &'permit crate::dispatch::mm_mutation::HostAliasPermit<'_>,
    ) -> crate::dispatch::HostAliasDispatchGuard<'permit>;
    fn remove_mapping_metadata(&self, addr: u64, len: u64);
    fn mark_vma_dispatch(&self, guard: &mut crate::dispatch::HostAliasDispatchGuard<'_>);
    fn has_deliverable_dispatch_pending_for_wait(
        &self,
        context: &crate::kernel::KernelContext,
        tid: crate::thread::ThreadId,
        mask: carrick_abi::WaitSigMask,
    ) -> bool;
    fn captured_file_table(&self) -> Arc<crate::kernel::FileTable>;
    fn open_file(&self, fd: i32) -> Option<OpenFile>;
    fn install_fd_at_or_above(&self, min_fd: i32, file: OpenFile) -> Result<i32, OpenFile>;
    fn fd_is_netlink(&self, fd: i32) -> bool;
    fn enqueue_netlink_message(
        &self,
        fd: i32,
        message: &[u8],
    ) -> Result<(), carrick_abi::LinuxErrno>;
    fn record_pending_siginfo(
        &self,
        context: &crate::kernel::KernelContext,
        tid: crate::thread::ThreadId,
        signo: i32,
        info: carrick_abi::LinuxSiginfo,
    );
    fn mark_signal_pending(
        &self,
        context: &crate::kernel::KernelContext,
        tid: crate::thread::ThreadId,
        signo: i32,
    );
}

impl IpcCrossSubsystem for SyscallDispatcher {
    fn cred_snapshot(&self) -> Arc<crate::kernel::Credentials> {
        self.cred_snapshot()
    }
    fn identity_pid(&self) -> u32 {
        self.identity_pid()
    }
    fn hvpatch_process(&self) -> Option<crate::hvpatch::ProcessContext> {
        self.hvpatch_process()
    }
    fn is_forked_guest_process(&self) -> bool {
        self.is_forked_guest_process()
    }
    fn begin_host_alias_dispatch<'permit>(
        &self,
        permit: &'permit crate::dispatch::mm_mutation::HostAliasPermit<'_>,
    ) -> crate::dispatch::HostAliasDispatchGuard<'permit> {
        self.begin_host_alias_dispatch(permit)
    }
    fn guest_vma_overlaps(&self, va: u64, len: u64) -> bool {
        self.guest_vma_overlaps(va, len)
    }
    fn begin_conditional_vma_dispatch<'permit>(
        &self,
        permit: &'permit crate::dispatch::mm_mutation::HostAliasPermit<'_>,
    ) -> crate::dispatch::HostAliasDispatchGuard<'permit> {
        self.begin_conditional_vma_dispatch(permit)
    }
    fn remove_mapping_metadata(&self, addr: u64, len: u64) {
        self.remove_mapping_metadata(addr, len);
    }
    fn mark_vma_dispatch(&self, guard: &mut crate::dispatch::HostAliasDispatchGuard<'_>) {
        self.mark_vma_dispatch(guard);
    }
    fn has_deliverable_dispatch_pending_for_wait(
        &self,
        context: &crate::kernel::KernelContext,
        tid: crate::thread::ThreadId,
        mask: carrick_abi::WaitSigMask,
    ) -> bool {
        self.has_deliverable_dispatch_pending_for_wait(context, tid, mask)
    }
    fn captured_file_table(&self) -> Arc<crate::kernel::FileTable> {
        self.captured_file_table()
    }
    fn open_file(&self, fd: i32) -> Option<OpenFile> {
        self.open_file(fd)
    }
    fn install_fd_at_or_above(&self, min_fd: i32, file: OpenFile) -> Result<i32, OpenFile> {
        self.install_fd_at_or_above(min_fd, file)
    }
    fn fd_is_netlink(&self, fd: i32) -> bool {
        self.fd_is_netlink(fd)
    }
    fn enqueue_netlink_message(
        &self,
        fd: i32,
        message: &[u8],
    ) -> Result<(), carrick_abi::LinuxErrno> {
        self.enqueue_netlink_message(fd, message)
    }
    fn record_pending_siginfo(
        &self,
        context: &crate::kernel::KernelContext,
        tid: crate::thread::ThreadId,
        signo: i32,
        info: carrick_abi::LinuxSiginfo,
    ) {
        self.record_pending_siginfo(context, tid, signo, info);
    }
    fn mark_signal_pending(
        &self,
        context: &crate::kernel::KernelContext,
        tid: crate::thread::ThreadId,
        signo: i32,
    ) {
        self.mark_signal_pending(context, tid, signo);
    }
}

/// Subsystem view for IPC operations.
pub struct IpcView<'a> {
    pub(in crate::dispatch) sysv: &'a Arc<sysv::SysvIpcNamespace>,
    pub(in crate::dispatch) sysv_process: &'a Mutex<sysv::SysvProcessAttachments>,
    pub(in crate::dispatch) mqueue: &'a Arc<mqueue::MqueueRegistry>,
    #[allow(dead_code)]
    pub(in crate::dispatch) kernel_binding: &'a RwLock<crate::kernel::KernelTaskBinding>,
    pub(in crate::dispatch) page_geometry: crate::page_profile::PageGeometry,
    pub(in crate::dispatch) cross: &'a (dyn IpcCrossSubsystem + 'a),
}

impl<'a> IpcView<'a> {
    #[inline]
    pub(in crate::dispatch) fn cred_snapshot(&self) -> Arc<crate::kernel::Credentials> {
        self.cross.cred_snapshot()
    }

    #[inline]
    pub(in crate::dispatch) fn identity_pid(&self) -> u32 {
        self.cross.identity_pid()
    }

    #[inline]
    pub(crate) fn hvpatch_process(&self) -> Option<crate::hvpatch::ProcessContext> {
        self.cross.hvpatch_process()
    }

    #[inline]
    pub(crate) fn is_forked_guest_process(&self) -> bool {
        self.cross.is_forked_guest_process()
    }

    #[inline]
    pub(crate) fn begin_host_alias_dispatch<'permit>(
        &self,
        permit: &'permit crate::dispatch::mm_mutation::HostAliasPermit<'_>,
    ) -> crate::dispatch::HostAliasDispatchGuard<'permit> {
        self.cross.begin_host_alias_dispatch(permit)
    }

    #[inline]
    pub(crate) fn guest_vma_overlaps(&self, va: u64, len: u64) -> bool {
        self.cross.guest_vma_overlaps(va, len)
    }

    #[inline]
    pub(crate) fn begin_conditional_vma_dispatch<'permit>(
        &self,
        permit: &'permit crate::dispatch::mm_mutation::HostAliasPermit<'_>,
    ) -> crate::dispatch::HostAliasDispatchGuard<'permit> {
        self.cross.begin_conditional_vma_dispatch(permit)
    }

    #[inline]
    pub(crate) fn remove_mapping_metadata(&self, addr: u64, len: u64) {
        self.cross.remove_mapping_metadata(addr, len);
    }

    #[inline]
    pub(crate) fn mark_vma_dispatch(
        &self,
        guard: &mut crate::dispatch::HostAliasDispatchGuard<'_>,
    ) {
        self.cross.mark_vma_dispatch(guard);
    }

    #[inline]
    pub(crate) fn has_deliverable_dispatch_pending_for_wait(
        &self,
        context: &crate::kernel::KernelContext,
        tid: crate::thread::ThreadId,
        mask: carrick_abi::WaitSigMask,
    ) -> bool {
        self.cross
            .has_deliverable_dispatch_pending_for_wait(context, tid, mask)
    }

    #[inline]
    pub(super) fn linux_page_size(&self) -> u64 {
        self.page_geometry.linux_page_size
    }

    #[inline]
    pub(in crate::dispatch) fn captured_file_table(&self) -> Arc<crate::kernel::FileTable> {
        self.cross.captured_file_table()
    }

    #[inline]
    pub(in crate::dispatch) fn open_file(&self, fd: i32) -> Option<OpenFile> {
        self.cross.open_file(fd)
    }

    #[inline]
    pub(in crate::dispatch) fn install_fd_at_or_above(
        &self,
        min_fd: i32,
        file: OpenFile,
    ) -> Result<i32, OpenFile> {
        self.cross.install_fd_at_or_above(min_fd, file)
    }

    #[inline]
    pub(in crate::dispatch) fn fd_is_netlink(&self, fd: i32) -> bool {
        self.cross.fd_is_netlink(fd)
    }

    #[inline]
    pub(in crate::dispatch) fn enqueue_netlink_message(
        &self,
        fd: i32,
        message: &[u8],
    ) -> Result<(), carrick_abi::LinuxErrno> {
        self.cross.enqueue_netlink_message(fd, message)
    }

    #[inline]
    pub(in crate::dispatch) fn record_pending_siginfo(
        &self,
        context: &crate::kernel::KernelContext,
        tid: crate::thread::ThreadId,
        signo: i32,
        info: carrick_abi::LinuxSiginfo,
    ) {
        self.cross.record_pending_siginfo(context, tid, signo, info);
    }

    #[inline]
    pub(in crate::dispatch) fn mark_signal_pending(
        &self,
        context: &crate::kernel::KernelContext,
        tid: crate::thread::ThreadId,
        signo: i32,
    ) {
        self.cross.mark_signal_pending(context, tid, signo);
    }
}

/// Cross-subsystem dependencies required by memory operations.
pub(in crate::dispatch) trait MemCrossSubsystem {
    fn open_file(&self, fd: i32) -> Option<OpenFile>;
    fn fd_is_valid(&self, fd: i32) -> bool;
    fn io_uring_description(&self, fd: i32) -> Option<Arc<crate::kernel::FileDescription>>;
    fn cred_snapshot(&self) -> Arc<crate::kernel::Credentials>;
    fn identity_pid(&self) -> u32;
    fn effective_resource_limit(&self, resource: u64) -> carrick_abi::LinuxRlimit;
    fn note_sysv_remap_file_pages(
        &self,
        addr: u64,
        end: u64,
    ) -> Result<bool, carrick_abi::LinuxErrno>;
    fn begin_host_alias_dispatch<'permit>(
        &self,
        permit: &'permit crate::dispatch::mm_mutation::HostAliasPermit<'_>,
    ) -> crate::dispatch::HostAliasDispatchGuard<'permit>;
    fn begin_conditional_vma_dispatch<'permit>(
        &self,
        permit: &'permit crate::dispatch::mm_mutation::HostAliasPermit<'_>,
    ) -> crate::dispatch::HostAliasDispatchGuard<'permit>;
    fn mark_vma_dispatch(&self, guard: &mut crate::dispatch::HostAliasDispatchGuard<'_>);
    fn owns_host_alias_dispatch(&self, guard: &crate::dispatch::HostAliasDispatchGuard<'_>)
    -> bool;
    fn io_uring_setup(
        &self,
        call: &mut dyn FnMut(&SyscallDispatcher) -> super::DispatchOutcome,
    ) -> super::DispatchOutcome;
    fn io_uring_enter(
        &self,
        call: &mut dyn FnMut(&SyscallDispatcher) -> super::DispatchOutcome,
    ) -> super::DispatchOutcome;
    fn captured_mm(&self) -> Arc<crate::kernel::Mm>;
}

impl MemCrossSubsystem for SyscallDispatcher {
    fn open_file(&self, fd: i32) -> Option<OpenFile> {
        self.open_file(fd)
    }
    fn fd_is_valid(&self, fd: i32) -> bool {
        self.fd_is_valid(fd)
    }
    fn io_uring_description(&self, fd: i32) -> Option<Arc<crate::kernel::FileDescription>> {
        self.io_uring_description(fd)
    }
    fn cred_snapshot(&self) -> Arc<crate::kernel::Credentials> {
        self.cred_snapshot()
    }
    fn identity_pid(&self) -> u32 {
        self.identity_pid()
    }
    fn effective_resource_limit(&self, resource: u64) -> carrick_abi::LinuxRlimit {
        self.effective_resource_limit(resource)
    }
    fn note_sysv_remap_file_pages(
        &self,
        addr: u64,
        end: u64,
    ) -> Result<bool, carrick_abi::LinuxErrno> {
        self.note_sysv_remap_file_pages(addr, end)
    }
    fn begin_host_alias_dispatch<'permit>(
        &self,
        permit: &'permit crate::dispatch::mm_mutation::HostAliasPermit<'_>,
    ) -> crate::dispatch::HostAliasDispatchGuard<'permit> {
        self.begin_host_alias_dispatch(permit)
    }
    fn begin_conditional_vma_dispatch<'permit>(
        &self,
        permit: &'permit crate::dispatch::mm_mutation::HostAliasPermit<'_>,
    ) -> crate::dispatch::HostAliasDispatchGuard<'permit> {
        self.begin_conditional_vma_dispatch(permit)
    }
    fn mark_vma_dispatch(&self, guard: &mut crate::dispatch::HostAliasDispatchGuard<'_>) {
        self.mark_vma_dispatch(guard);
    }
    fn owns_host_alias_dispatch(
        &self,
        guard: &crate::dispatch::HostAliasDispatchGuard<'_>,
    ) -> bool {
        self.owns_host_alias_dispatch(guard)
    }
    fn io_uring_setup(
        &self,
        call: &mut dyn FnMut(&SyscallDispatcher) -> super::DispatchOutcome,
    ) -> super::DispatchOutcome {
        call(self)
    }
    fn io_uring_enter(
        &self,
        call: &mut dyn FnMut(&SyscallDispatcher) -> super::DispatchOutcome,
    ) -> super::DispatchOutcome {
        call(self)
    }
    fn captured_mm(&self) -> Arc<crate::kernel::Mm> {
        self.captured_mm()
    }
}

/// Subsystem view for memory operations.
pub struct MemView<'a> {
    pub(in crate::dispatch) mm_binding: &'a Arc<DispatchMmBinding>,
    pub(in crate::dispatch) page_geometry: crate::page_profile::PageGeometry,
    pub(in crate::dispatch) proc: &'a Mutex<proc::ProcState>,
    pub(in crate::dispatch) fs: &'a fs::FsState,
    pub(in crate::dispatch) cross: &'a (dyn MemCrossSubsystem + 'a),
}

impl<'a> MemView<'a> {
    #[inline]
    pub(crate) fn mem(&self) -> arc_swap::Guard<Arc<DispatchMmAuthority>> {
        self.mm_binding.current.load()
    }

    #[inline]
    pub(crate) fn mm_authority(&self) -> Arc<DispatchMmAuthority> {
        self.mm_binding.current.load_full()
    }

    #[inline]
    pub(crate) fn linux_page_size(&self) -> u64 {
        self.page_geometry.linux_page_size
    }

    #[inline]
    pub(in crate::dispatch) fn open_file(&self, fd: i32) -> Option<OpenFile> {
        self.cross.open_file(fd)
    }

    #[inline]
    pub(in crate::dispatch) fn fd_is_valid(&self, fd: i32) -> bool {
        self.cross.fd_is_valid(fd)
    }

    #[inline]
    pub(in crate::dispatch) fn io_uring_description(
        &self,
        fd: i32,
    ) -> Option<Arc<crate::kernel::FileDescription>> {
        self.cross.io_uring_description(fd)
    }

    #[inline]
    pub(super) fn captured_mm(&self) -> Arc<crate::kernel::Mm> {
        self.cross.captured_mm()
    }

    #[inline]
    pub(in crate::dispatch) fn cred_snapshot(&self) -> Arc<crate::kernel::Credentials> {
        self.cross.cred_snapshot()
    }

    #[inline]
    pub(in crate::dispatch) fn identity_pid(&self) -> u32 {
        self.cross.identity_pid()
    }

    #[inline]
    pub(super) fn effective_resource_limit(&self, resource: u64) -> carrick_abi::LinuxRlimit {
        self.cross.effective_resource_limit(resource)
    }

    #[inline]
    pub(crate) fn note_sysv_remap_file_pages(
        &self,
        addr: u64,
        end: u64,
    ) -> Result<bool, carrick_abi::LinuxErrno> {
        self.cross.note_sysv_remap_file_pages(addr, end)
    }

    #[inline]
    pub(in crate::dispatch) fn begin_host_alias_dispatch<'permit>(
        &self,
        permit: &'permit crate::dispatch::mm_mutation::HostAliasPermit<'_>,
    ) -> crate::dispatch::HostAliasDispatchGuard<'permit> {
        self.cross.begin_host_alias_dispatch(permit)
    }

    #[inline]
    pub(in crate::dispatch) fn begin_conditional_vma_dispatch<'permit>(
        &self,
        permit: &'permit crate::dispatch::mm_mutation::HostAliasPermit<'_>,
    ) -> crate::dispatch::HostAliasDispatchGuard<'permit> {
        self.cross.begin_conditional_vma_dispatch(permit)
    }

    #[inline]
    pub(in crate::dispatch) fn mark_vma_dispatch(
        &self,
        guard: &mut crate::dispatch::HostAliasDispatchGuard<'_>,
    ) {
        self.cross.mark_vma_dispatch(guard);
    }

    #[inline]
    pub(super) fn owns_host_alias_dispatch(
        &self,
        guard: &crate::dispatch::HostAliasDispatchGuard<'_>,
    ) -> bool {
        self.cross.owns_host_alias_dispatch(guard)
    }

    #[cfg(test)]
    #[inline]
    pub(crate) fn mm_mutation_coordinator(&self) -> Arc<mm_mutation::MmMutationCoordinator> {
        Arc::clone(&self.mm_authority().mutation_coordinator)
    }

    #[cfg(test)]
    #[inline]
    pub(crate) fn begin_vma_dispatch<'permit>(
        &self,
        permit: &'permit crate::dispatch::mm_mutation::HostAliasPermit<'_>,
    ) -> crate::dispatch::HostAliasDispatchGuard<'permit> {
        self.mm_binding.begin_dispatch(permit, true)
    }

    #[cfg(test)]
    #[inline]
    pub(crate) fn with_vma_dispatch_for_test<T>(
        &self,
        use_guard: impl FnOnce(crate::dispatch::HostAliasDispatchGuard<'_>) -> T,
    ) -> T {
        mm_mutation::test_support::with_permit(self.mm_mutation_coordinator(), |permit| {
            use_guard(self.begin_vma_dispatch(permit))
        })
    }

    #[inline]
    pub(in crate::dispatch) fn io_uring_setup_impl<M: super::CurrentMmMemory>(
        &self,
        memory: &mut M,
        entries: u32,
        params_ptr: u64,
    ) -> super::DispatchOutcome {
        self.cross.io_uring_setup(&mut |dispatcher| {
            dispatcher.io_uring_setup_impl(memory, entries, params_ptr)
        })
    }

    #[inline]
    pub(in crate::dispatch) fn io_uring_enter_impl<M: super::CurrentMmMemory>(
        &self,
        memory: &mut M,
        fd: i32,
        to_submit: u32,
        flags: u32,
        argp: u64,
        argsz: u64,
    ) -> super::DispatchOutcome {
        self.cross.io_uring_enter(&mut |dispatcher| {
            dispatcher.io_uring_enter_impl(memory, fd, to_submit, flags, argp, argsz)
        })
    }
}

impl SyscallDispatcher {
    #[inline]
    pub fn fs_view(&self) -> FsView<'_> {
        FsView {
            fs: &self.fs,
            file_authority: &self.file_authority,
            io: &self.io,
            mm_binding: &self.mm_binding,
            proc: &self.proc,
            kernel_binding: &self.kernel_binding,
            network: &self.network,
            page_geometry: self.page_geometry,
            sysv: Some(&self.sysv),
            exec_host_fs_fallback: self.exec_host_fs_fallback,
            cross: self,
        }
    }

    #[inline]
    pub fn net_view(&self) -> NetView<'_> {
        NetView {
            network: &self.network,
            file_authority: &self.file_authority,
            kernel_binding: &self.kernel_binding,
            io: &self.io,
            fs: &self.fs,
            cross: self,
        }
    }

    #[inline]
    pub fn proc_view(&self) -> ProcView<'_> {
        ProcView {
            proc: &self.proc,
            seccomp: &self.seccomp,
            page_geometry: self.page_geometry,
            cross: self,
        }
    }

    #[inline]
    pub fn signal_view(&self) -> SignalView<'_> {
        SignalView {
            kernel_binding: &self.kernel_binding,
            signal_pump_requested: &self.signal_pump_requested,
            async_signal_wake_owner: self.async_signal_wake_owner,
            cross: self,
        }
    }

    #[inline]
    pub fn ipc_view(&self) -> IpcView<'_> {
        IpcView {
            sysv: &self.sysv,
            sysv_process: &self.sysv_process,
            mqueue: &self.mqueue,
            kernel_binding: &self.kernel_binding,
            page_geometry: self.page_geometry,
            cross: self,
        }
    }

    #[inline]
    pub fn mem_view(&self) -> MemView<'_> {
        MemView {
            mm_binding: &self.mm_binding,
            page_geometry: self.page_geometry,
            proc: &self.proc,
            fs: &self.fs,
            cross: self,
        }
    }
}
