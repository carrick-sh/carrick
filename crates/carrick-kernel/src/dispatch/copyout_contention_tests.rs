//! Dispatcher/owner integration without a VM. No refusal is injected: a live
//! sibling owns the production MM editor on another host thread. The adapter
//! below replaces only HVC transport, driving the real portal selection,
//! PREPARE, COMMIT and CANCEL against real descriptors and mmap-backed bytes.
//! It intentionally supports only the single-page record used by this witness.

use super::*;
use carrick_abi::{LinuxCloneFlags, syscall::nr};
use carrick_el1::fault::{NoopCowResolver, NoopPreparedResolver};
use carrick_el1_abi::{
    El1MmHandle, PortalPreparedPermit, PortalRetainedData, PortalTransferRequest,
    PortalTransferSlot, PortalWaitCause,
};
use carrick_el1_linux::mm_portal::{
    MmError, MmPortal, TransferIntent, prepare_transfer, serve_transfer,
    test_support::{NoPin, ROOT, Region, Tables, VA, admit_notified, nodes, residency},
};
use carrick_guest_mem::{
    CurrentMmMemory, GuestMemory, GuestWriteRange, MemoryError, MemoryPrepareError,
    PreparedGuestWrite, UserMemoryVenue,
};
use carrick_host::host_mapping::{HostMappingKind, OwnedHostMapping};
use carrick_mmu_core::aarch64::descriptor_txn::CallerInvalidatesAsid;
use std::cell::Cell;
use std::num::NonZeroU64;
use std::sync::mpsc;
use std::time::Duration;

struct PortalMemory<'a> {
    portal: &'a MmPortal<'a, NoPin>,
    tables: &'a Tables,
    backing: &'a OwnedHostMapping,
    handle: El1MmHandle,
    prepares: Cell<usize>,
    commits: Cell<usize>,
}

impl PortalMemory<'_> {
    fn fault(address: u64, length: usize) -> MemoryPrepareError {
        MemoryPrepareError::Fault(MemoryError::OutOfBounds { address, length })
    }

    fn prepare_record(
        &self,
        ranges: &[GuestWriteRange],
        intent: TransferIntent,
    ) -> Result<PortalPermit<'_, '_>, MemoryPrepareError> {
        assert_eq!(ranges.len(), 1, "single-record transport fixture");
        self.prepares.set(self.prepares.get() + 1);
        let range = ranges[0];
        let fault = || Self::fault(range.address().raw(), range.len());
        let map_error = |error| match error {
            MmError::Wait(wait) => MemoryPrepareError::OwnerWait(wait),
            other => panic!("unexpected production owner refusal: {other:?}"),
        };
        let transfer = self
            .portal
            .begin(
                self.handle,
                carrick_el1_linux::mm_portal::GuestVa::new(range.address().raw()),
                range.len() as u64,
                intent,
                0,
            )
            .map_err(map_error)?;
        let words = self.tables.live(&CallerInvalidatesAsid);
        let chunk = match self
            .portal
            .select(
                &transfer,
                &words,
                carrick_core::mm::transaction::SelectionVenues {
                    prepared: &mut NoopPreparedResolver,
                    cow: &mut NoopCowResolver,
                    residency: &residency(),
                    slot: 0,
                },
            )
            .map_err(map_error)?
        {
            carrick_core::mm::transaction::TransferStep::Selected(chunk) => chunk,
            _ => panic!("resident writable record must select or return an exact wait"),
        };
        assert_eq!(chunk.len, range.len() as u64);
        // This fixture retains the mmap owner for the complete permit lifetime.
        // The portal authenticates the selected frame and exact request again.
        let retained = PortalRetainedData {
            record: NonZeroU64::new(1).unwrap(),
            vm_generation: NonZeroU64::new(1).unwrap(),
            owner: None,
        };
        let request = chunk.request(intent, retained).map_err(|_| fault())?;
        let permit = prepare_transfer(self.portal, request, &words, 0)
            .map_err(map_error)?
            .expect("unchanged exact selection");
        Ok(PortalPermit {
            memory: self,
            request,
            permit: Some(permit),
        })
    }
}

struct PortalPermit<'a, 'owner> {
    memory: &'a PortalMemory<'owner>,
    request: PortalTransferRequest,
    permit: Option<PortalPreparedPermit>,
}

impl PreparedGuestWrite for PortalPermit<'_, '_> {
    fn commit(mut self: Box<Self>, outputs: &[&[u8]]) {
        assert_eq!(outputs.len(), 1);
        let bytes = outputs[0];
        assert_eq!(bytes.len() as u64, self.request.range.len());
        let wire = PortalTransferSlot::new();
        let mut ticket = wire
            .submit_commit(
                self.request,
                self.permit.take().unwrap(),
                bytes.len() as u64,
            )
            .unwrap();
        serve_transfer(
            self.memory.portal,
            wire.claim().unwrap(),
            &self.memory.tables.live(&CallerInvalidatesAsid),
            0,
            || {
                assert!(ticket.copy_requested(|authorization| {
                    let request = authorization.request();
                    assert_eq!(request, self.request);
                    let offset = (request.range.address() - VA) as usize;
                    assert_eq!(
                        request.selected.ipa,
                        self.memory.backing.as_ptr() as u64 + offset as u64
                    );
                    assert!(offset + bytes.len() <= self.memory.backing.len());
                    // SAFETY: the real owner authorized this exact write;
                    // the retained mapping outlives the permit. Only this
                    // transport thread accesses these data bytes.
                    unsafe {
                        std::ptr::copy_nonoverlapping(
                            bytes.as_ptr(),
                            self.memory.backing.as_ptr().add(offset),
                            bytes.len(),
                        );
                    }
                    self.memory.commits.set(self.memory.commits.get() + 1);
                    true
                }));
            },
        )
        .unwrap();
        let completion = ticket.take_completion().unwrap();
        assert_eq!(completion.completed, bytes.len() as u64);
        assert_eq!(completion.errno, 0);
    }
}

impl Drop for PortalPermit<'_, '_> {
    fn drop(&mut self) {
        if let Some(permit) = self.permit.take() {
            self.memory
                .portal
                .cancel_prepared(permit, self.request, 0)
                .unwrap();
        }
    }
}

impl GuestMemory for PortalMemory<'_> {
    fn user_memory_venue(&self) -> UserMemoryVenue {
        UserMemoryVenue::Owner
    }

    fn prepare_write(
        &mut self,
        ranges: &[GuestWriteRange],
    ) -> Result<Box<dyn PreparedGuestWrite + '_>, MemoryPrepareError> {
        self.prepare_record(ranges, TransferIntent::UserWrite)
            .map(|permit| Box::new(permit) as Box<dyn PreparedGuestWrite>)
    }

    fn read_bytes_raw(&self, address: u64, length: usize) -> Result<Vec<u8>, MemoryError> {
        let fault = || MemoryError::OutOfBounds { address, length };
        if address < VA
            || address
                .checked_add(length as u64)
                .is_none_or(|end| end > VA + 4096)
        {
            return Err(fault());
        }
        let range = GuestWriteRange::new(carrick_guest_mem::GuestVa::new(address), length).unwrap();
        let mut permit = self
            .prepare_record(&[range], TransferIntent::UserRead)
            .map_err(|error| match error {
                MemoryPrepareError::OwnerWait(wait) => {
                    MemoryError::ReadSuspended(Box::new(carrick_guest_mem::MemoryReadSuspension {
                        wait: carrick_guest_mem::MemoryReadWait::Owner(wait),
                        continuation: carrick_guest_mem::OwnedReadContinuation::new(()),
                    }))
                }
                _ => fault(),
            })?;
        let wire = PortalTransferSlot::new();
        let mut ticket = wire
            .submit_commit(permit.request, permit.permit.take().unwrap(), length as u64)
            .unwrap();
        let mut bytes = Vec::new();
        serve_transfer(
            self.portal,
            wire.claim().unwrap(),
            &self.tables.live(&CallerInvalidatesAsid),
            0,
            || {
                assert!(ticket.copy_requested(|authorization| {
                    let request = authorization.request();
                    assert_eq!(request, permit.request);
                    let offset = (address - VA) as usize;
                    assert_eq!(
                        request.selected.ipa,
                        self.backing.as_ptr() as u64 + offset as u64
                    );
                    // SAFETY: the production permit authorizes this exact read of the retained mapping.
                    bytes = unsafe {
                        std::slice::from_raw_parts(self.backing.as_ptr().add(offset), length)
                    }
                    .to_vec();
                    true
                }));
            },
        )
        .unwrap();
        assert_eq!(ticket.take_completion().unwrap().completed, length as u64);
        Ok(bytes)
    }

    fn write_bytes_raw(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        let range =
            GuestWriteRange::new(carrick_guest_mem::GuestVa::new(address), bytes.len()).unwrap();
        match self.prepare_record(&[range], TransferIntent::UserWrite) {
            Ok(permit) => {
                Box::new(permit).commit(&[bytes]);
                Ok(())
            }
            Err(MemoryPrepareError::OwnerWait(wait)) => Err(MemoryError::OwnerWait(wait)),
            Err(other) => panic!("unexpected record refusal: {other:?}"),
        }
    }
}
impl CurrentMmMemory for PortalMemory<'_> {}

#[test]
fn pipe2_copyout_waits_for_live_sibling_editor_and_commits_once() {
    let mut dispatcher = SyscallDispatcher::new();
    let root = dispatcher.capture_one_task_context().unwrap();
    let sibling = root
        .kernel()
        .clone_thread(
            &root,
            crate::kernel::ClonePlan::from_flags(
                LinuxCloneFlags::VM | LinuxCloneFlags::SIGHAND | LinuxCloneFlags::THREAD,
            )
            .unwrap(),
            carrick_hal::ThreadId::synthetic_for_tests(71_101),
            None,
        )
        .unwrap();
    let root = root
        .kernel()
        .context(root.task().key().id, root.thread().key().tid)
        .unwrap();
    assert_ne!(root.thread().key(), sibling.thread().key());
    assert_eq!(root.shared().mm().id(), sibling.shared().mm().id());
    assert!(root.exact_thread_is_live() && sibling.exact_thread_is_live());

    let region = Region::new();
    let zone = region.zone();
    let mm = admit_notified(&region, root.shared().mm().id().raw(), ROOT, 1, 0);
    let view = nodes(&region);
    let portal = MmPortal::new(
        NonZeroU64::new(711).unwrap(),
        region.table(),
        &zone.spaces,
        &view,
    )
    .with_zone(zone)
    .unwrap();
    let handle = portal.admitted_handle(mm, 0).unwrap();
    let backing = OwnedHostMapping::map_shared_anon(4096, HostMappingKind::PrivateAnon).unwrap();
    let tables = Tables::new(ROOT, backing.as_ptr() as u64, 1);
    let mut memory = PortalMemory {
        portal: &portal,
        tables: &tables,
        backing: &backing,
        handle,
        prepares: Cell::new(0),
        commits: Cell::new(0),
    };
    let reporter = crate::compat::CompatReporter::default();
    let request = SyscallRequest::new(nr::PIPE2.raw(), SyscallArgs::from([VA, 0, 0, 0, 0, 0]));
    let (entered_tx, entered_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    let (refused, observed, released) = std::thread::scope(|scope| {
        let sibling = &sibling;
        let peer = scope.spawn(move || {
            assert!(sibling.exact_thread_is_live());
            let access = carrick_el1_linux::sched::object_wait::space_access(
                zone,
                carrick_sched_core::SlotId::new(1),
            );
            let editor = access
                .try_begin_edit(
                    zone.spaces.find(sibling.shared().mm().id().raw()).unwrap(),
                    mm.raw(),
                    NonZeroU64::new(2).unwrap(),
                )
                .unwrap();
            // Hold the sibling's real editor admission at the copyout
            // boundary without sleeps or injected refusals.
            entered_tx.send(()).unwrap();
            release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            drop(editor);
        });
        entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let observed = portal
            .observe_wait(handle, PortalWaitCause::Editor)
            .unwrap()
            .unwrap();
        let refused = dispatcher
            .dispatch(&root, request, &mut memory, &reporter)
            .unwrap();
        // Always release/join before asserting, including on the red revision.
        release_tx.send(()).unwrap();
        peer.join().unwrap();
        let released = portal
            .observe_wait(handle, PortalWaitCause::Editor)
            .unwrap()
            .unwrap();
        (refused, observed, released)
    });
    assert_eq!(
        refused,
        DispatchOutcome::OwnerMemoryWait {
            wait: observed,
            committed: 0
        },
        "a live sibling's editor must suspend the syscall, never return errno 14"
    );
    assert_ne!(
        observed, released,
        "editor release advances the exact wait source"
    );
    assert_eq!(memory.prepares.get(), 1);
    assert_eq!(memory.commits.get(), 0);
    assert!(dispatcher.open_file(3).is_none() && dispatcher.open_file(4).is_none());
    // SAFETY: retained mmap, no peer byte accesses, exactly eight live bytes.
    assert_eq!(
        unsafe { std::slice::from_raw_parts(backing.as_ptr(), 8) },
        [0; 8]
    );
    assert_eq!(
        dispatcher
            .dispatch(&root, request, &mut memory, &reporter)
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(memory.prepares.get(), 2);
    assert_eq!(memory.commits.get(), 1);
    // SAFETY: the completed owner copy released its only writer.
    let output = unsafe { std::slice::from_raw_parts(backing.as_ptr(), 8) };
    assert_eq!(&output[..4], &3i32.to_ne_bytes());
    assert_eq!(&output[4..], &4i32.to_ne_bytes());
    assert!(dispatcher.open_file(3).is_some() && dispatcher.open_file(4).is_some());
    assert!(
        dispatcher.open_file(5).is_none(),
        "exactly one pair installed"
    );
}

#[test]
fn newfstatat_path_copyin_waits_for_live_sibling_editor_and_bad_path_faults() {
    stat_path_copyin(nr::NEWFSTATAT.raw());
}

#[test]
fn statx_path_copyin_waits_for_live_sibling_editor_and_bad_path_faults() {
    stat_path_copyin(nr::STATX.raw());
}

#[test]
fn x86_stat_paths_copyin_wait_for_live_sibling_editor() {
    for nr in [
        nr::CARRICK_PRIVATE_X86_STAT,
        nr::CARRICK_PRIVATE_X86_LSTAT,
        nr::CARRICK_PRIVATE_X86_NEWFSTATAT,
    ] {
        stat_path_copyin(nr.raw());
    }
}

fn stat_path_copyin(nr: u64) {
    let mut dispatcher = SyscallDispatcher::new();
    let root = dispatcher.capture_one_task_context().unwrap();
    let sibling = root
        .kernel()
        .clone_thread(
            &root,
            crate::kernel::ClonePlan::from_flags(
                LinuxCloneFlags::VM | LinuxCloneFlags::SIGHAND | LinuxCloneFlags::THREAD,
            )
            .unwrap(),
            carrick_hal::ThreadId::synthetic_for_tests(71_101),
            None,
        )
        .unwrap();
    let root = root
        .kernel()
        .context(root.task().key().id, root.thread().key().tid)
        .unwrap();
    assert_ne!(root.thread().key(), sibling.thread().key());
    assert_eq!(root.shared().mm().id(), sibling.shared().mm().id());
    assert!(root.exact_thread_is_live() && sibling.exact_thread_is_live());

    let region = Region::new();
    let zone = region.zone();
    let mm = admit_notified(&region, root.shared().mm().id().raw(), ROOT, 1, 0);
    let view = nodes(&region);
    let portal = MmPortal::new(
        NonZeroU64::new(711).unwrap(),
        region.table(),
        &zone.spaces,
        &view,
    )
    .with_zone(zone)
    .unwrap();
    let handle = portal.admitted_handle(mm, 0).unwrap();
    let backing = OwnedHostMapping::map_shared_anon(4096, HostMappingKind::PrivateAnon).unwrap();
    let tables = Tables::new(ROOT, backing.as_ptr() as u64, 1);
    let mut memory = PortalMemory {
        portal: &portal,
        tables: &tables,
        backing: &backing,
        handle,
        prepares: Cell::new(0),
        commits: Cell::new(0),
    };
    let reporter = crate::compat::CompatReporter::default();
    // SAFETY: this thread exclusively owns the retained fixture bytes.
    unsafe {
        std::ptr::copy_nonoverlapping(
            c"/dev/null".to_bytes_with_nul().as_ptr(),
            backing.as_ptr(),
            10,
        )
    };
    let simple_path =
        nr == nr::CARRICK_PRIVATE_X86_STAT.raw() || nr == nr::CARRICK_PRIVATE_X86_LSTAT.raw();
    let args = if simple_path {
        [VA, VA + 512, 0, 0, 0, 0]
    } else if nr != nr::STATX.raw() {
        [carrick_abi::LINUX_AT_FDCWD, VA, VA + 512, 0, 0, 0]
    } else {
        [carrick_abi::LINUX_AT_FDCWD, VA, 0, 0x7ff, VA + 512, 0]
    };
    let request = SyscallRequest::new(nr, SyscallArgs::from(args));
    let (entered_tx, entered_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    let (refused, observed, released) = std::thread::scope(|scope| {
        let sibling = &sibling;
        let peer = scope.spawn(move || {
            assert!(sibling.exact_thread_is_live());
            let access = carrick_el1_linux::sched::object_wait::space_access(
                zone,
                carrick_sched_core::SlotId::new(1),
            );
            let editor = access
                .try_begin_edit(
                    zone.spaces.find(sibling.shared().mm().id().raw()).unwrap(),
                    mm.raw(),
                    NonZeroU64::new(2).unwrap(),
                )
                .unwrap();
            // Hold the sibling's real editor admission at the copyout
            // boundary without sleeps or injected refusals.
            entered_tx.send(()).unwrap();
            release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            drop(editor);
        });
        entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let observed = portal
            .observe_wait(handle, PortalWaitCause::Editor)
            .unwrap()
            .unwrap();
        let refused = dispatcher
            .dispatch(&root, request, &mut memory, &reporter)
            .unwrap();
        // Always release/join before asserting, including on the red revision.
        release_tx.send(()).unwrap();
        peer.join().unwrap();
        let released = portal
            .observe_wait(handle, PortalWaitCause::Editor)
            .unwrap()
            .unwrap();
        (refused, observed, released)
    });
    assert_eq!(
        refused,
        DispatchOutcome::OwnerMemoryWait {
            wait: observed,
            committed: 0
        },
        "a live sibling's editor must suspend the syscall, never return errno 14"
    );
    assert_ne!(
        observed, released,
        "editor release advances the exact wait source"
    );
    assert_eq!(
        memory.commits.get(),
        0,
        "pathname refusal must precede output"
    );
    assert_eq!(
        dispatcher
            .dispatch(&root, request, &mut memory, &reporter)
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(memory.commits.get(), 1);
    let mut bad_args = args;
    bad_args[usize::from(!simple_path)] = VA + 8192;
    assert_eq!(
        dispatcher
            .dispatch(
                &root,
                SyscallRequest::new(nr, SyscallArgs::from(bad_args)),
                &mut memory,
                &reporter
            )
            .unwrap(),
        DispatchOutcome::errno(carrick_abi::LINUX_EFAULT)
    );
    assert_eq!(memory.commits.get(), 1);
}

/// Close the real owner gate after the vector has been copied in, so this
/// exercises pipe payload copyout rather than failing during iovec intake.
struct GateAfterIovec<'a> {
    memory: PortalMemory<'a>,
    close_after: Cell<Option<u64>>,
}
struct GateAfterCommit<'a> {
    permit: Box<dyn PreparedGuestWrite + 'a>,
    spaces: &'a carrick_sched_core::AddressSpaces,
    mm: u64,
    address: u64,
    close_after: &'a Cell<Option<u64>>,
}
impl PreparedGuestWrite for GateAfterCommit<'_> {
    fn commit(self: Box<Self>, outputs: &[&[u8]]) {
        self.permit.commit(outputs);
        if self.close_after.get() == Some(self.address) {
            self.close_after.set(None);
            self.spaces.raise(self.spaces.find(self.mm).unwrap());
        }
    }
}
impl GuestMemory for GateAfterIovec<'_> {
    fn user_memory_venue(&self) -> UserMemoryVenue {
        UserMemoryVenue::Owner
    }
    fn prepare_write(
        &mut self,
        ranges: &[GuestWriteRange],
    ) -> Result<Box<dyn PreparedGuestWrite + '_>, MemoryPrepareError> {
        let spaces = self.memory.portal.spaces;
        let mm = self.memory.handle.mm().raw();
        let permit = self.memory.prepare_write(ranges)?;
        Ok(Box::new(GateAfterCommit {
            permit,
            spaces,
            mm,
            address: ranges[0].address().raw(),
            close_after: &self.close_after,
        }))
    }
    fn read_bytes_raw(&self, address: u64, length: usize) -> Result<Vec<u8>, MemoryError> {
        let bytes = self.memory.read_bytes_raw(address, length)?;
        if self.close_after.get() == Some(address) {
            self.close_after.set(None);
            let spaces = self.memory.portal.spaces;
            spaces.raise(spaces.find(self.memory.handle.mm().raw()).unwrap());
        }
        Ok(bytes)
    }
    fn write_bytes_raw(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        self.memory.write_bytes_raw(address, bytes)?;
        if self.close_after.get() == Some(address) {
            self.close_after.set(None);
            let spaces = self.memory.portal.spaces;
            spaces.raise(spaces.find(self.memory.handle.mm().raw()).unwrap());
        }
        Ok(())
    }
}
impl CurrentMmMemory for GateAfterIovec<'_> {}

#[test]
fn readv_pipe_copyout_waits_for_live_sibling_gate_and_delivers_exact_bytes() {
    readv_pipe_gate(false, false);
}

#[test]
fn readv_pipe_later_gate_retains_cursor_and_description_after_fd_reuse() {
    readv_pipe_gate(true, false);
}

#[test]
fn readv_pipe_gate_then_empty_source_keeps_operation_through_readiness() {
    readv_pipe_gate(false, true);
}

fn readv_pipe_gate(later: bool, drained: bool) {
    let mut dispatcher = SyscallDispatcher::new();
    let root = dispatcher.capture_one_task_context().unwrap();
    let sibling = root
        .kernel()
        .clone_thread(
            &root,
            crate::kernel::ClonePlan::from_flags(
                LinuxCloneFlags::VM
                    | LinuxCloneFlags::SIGHAND
                    | LinuxCloneFlags::THREAD
                    | LinuxCloneFlags::FILES,
            )
            .unwrap(),
            carrick_hal::ThreadId::synthetic_for_tests(71_102),
            None,
        )
        .unwrap();
    let root = root
        .kernel()
        .context(root.task().key().id, root.thread().key().tid)
        .unwrap();
    assert!(root.exact_thread_is_live() && sibling.exact_thread_is_live());
    assert_ne!(root.thread().key(), sibling.thread().key());
    let region = Region::new();
    let zone = region.zone();
    let mm = admit_notified(&region, root.shared().mm().id().raw(), ROOT, 1, 0);
    let view = nodes(&region);
    let portal = MmPortal::new(
        NonZeroU64::new(711).unwrap(),
        region.table(),
        &zone.spaces,
        &view,
    )
    .with_zone(zone)
    .unwrap();
    let handle = portal.admitted_handle(mm, 0).unwrap();
    let backing = OwnedHostMapping::map_shared_anon(4096, HostMappingKind::PrivateAnon).unwrap();
    let tables = Tables::new(ROOT, backing.as_ptr() as u64, 1);
    let mut memory = GateAfterIovec {
        memory: PortalMemory {
            portal: &portal,
            tables: &tables,
            backing: &backing,
            handle,
            prepares: Cell::new(0),
            commits: Cell::new(0),
        },
        close_after: Cell::new(None),
    };
    let reporter = crate::compat::CompatReporter::default();
    let call = |number, args| SyscallRequest::new(number, SyscallArgs::from(args));
    assert_eq!(
        dispatcher
            .dispatch(
                &root,
                call(nr::PIPE2.raw(), [VA, 0, 0, 0, 0, 0]),
                &mut memory,
                &reporter
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    let pair = memory.read_bytes(VA, 8).unwrap();
    let fd = i32::from_ne_bytes(pair[..4].try_into().unwrap());
    let open = dispatcher.open_file(fd).unwrap();
    let pipe = match &*crate::kernel::FileDescription::read_for_io(&open.description).unwrap() {
        OpenDescription::PipeReader { pipe, .. } => Arc::clone(pipe),
        _ => panic!("pipe reader"),
    };
    assert_eq!(pipe.write_bytes(b"abcdefgh"), Ok(8));
    let mut iovec = Vec::new();
    iovec.extend_from_slice(&(VA + 256).to_ne_bytes());
    iovec.extend_from_slice(&(if later { 4u64 } else { 8u64 }).to_ne_bytes());
    if later {
        iovec.extend_from_slice(&(VA + 512).to_ne_bytes());
        iovec.extend_from_slice(&4u64.to_ne_bytes());
    }
    memory.write_bytes(VA + 64, &iovec).unwrap();
    memory
        .close_after
        .set(Some(if later { VA + 256 } else { VA + 64 }));
    let request = call(
        nr::READV.raw(),
        [fd as u64, VA + 64, if later { 2 } else { 1 }, 0, 0, 0],
    );
    let outcome = dispatcher
        .dispatch(&root, request, &mut memory, &reporter)
        .unwrap();
    let observed = portal
        .observe_wait(handle, PortalWaitCause::Gate)
        .unwrap()
        .unwrap();
    // Release before assertions, including on the red revision.
    carrick_el1_linux::sched::object_wait::space_access(zone, carrick_sched_core::SlotId::new(1))
        .lower(zone.spaces.find(mm.raw()).unwrap());
    assert_ne!(
        observed,
        portal
            .observe_wait(handle, PortalWaitCause::Gate)
            .unwrap()
            .unwrap()
    );
    assert!(
        !matches!(outcome, DispatchOutcome::Errno { .. }),
        "valid copyout must suspend, not return EFAULT: {outcome:?}"
    );
    assert_eq!(pipe.buffered_bytes(), if later { 4 } else { 8 });
    let DispatchOutcome::PipeReadSuspended(pending) = outcome else {
        panic!("pipe operation must retain its endpoint: {outcome:?}");
    };
    assert_eq!(
        pending.wait(),
        &carrick_guest_mem::MemoryReadWait::Owner(observed)
    );
    if drained {
        assert_eq!(pipe.read_with(8, |bytes| bytes.len()), Ok(8));
    }
    if later || drained {
        if later {
            assert_eq!(memory.read_bytes(VA + 256, 4).unwrap(), b"abcd");
        }
        assert_eq!(
            dispatcher
                .dispatch(
                    &sibling,
                    call(nr::CLOSE.raw(), [fd as u64, 0, 0, 0, 0, 0]),
                    &mut memory,
                    &reporter
                )
                .unwrap(),
            DispatchOutcome::Returned { value: 0 }
        );
        assert_eq!(
            dispatcher
                .dispatch(
                    &sibling,
                    call(nr::PIPE2.raw(), [VA + 32, 0, 0, 0, 0, 0]),
                    &mut memory,
                    &reporter
                )
                .unwrap(),
            DispatchOutcome::Returned { value: 0 }
        );
        assert_eq!(memory.read_bytes(VA + 32, 4).unwrap(), fd.to_ne_bytes());
        // The resumed operation must neither reread the vector nor resolve
        // this numeric descriptor, both of which now name different inputs.
        memory.write_bytes(VA + 64, &[0; 32]).unwrap();
    }
    let pending = if drained {
        use crate::kernel::continuation::{
            BlockedContinuation, ContinuationCapture, ContinuationEvent, RestartClass,
            fold_continuation_completion, test_support::publish,
        };
        let blocked = pending.resume(&root, &mut memory).unwrap();
        assert!(
            matches!(blocked, DispatchOutcome::BlockingFdWait { .. }),
            "the exact read must survive source exhaustion: {blocked:?}"
        );
        let generation = publish(&root, 0x898);
        let capture = ContinuationCapture::new(
            &root,
            generation,
            request,
            RestartClass::for_syscall(nr::READV.raw()),
        )
        .unwrap();
        let mut continuation =
            BlockedContinuation::from_dispatch_outcome(blocked, capture).unwrap();
        let service = crate::kernel::continuation::CarrierWaitService::new(Arc::new(
            crate::kernel::Scheduler::new(Arc::clone(root.kernel())),
        ));
        let mut registration = service.prepare_registration(&continuation);
        service.enroll(&mut registration).unwrap();
        let token = registration.wake_token();
        continuation.attach_registration(registration).unwrap();
        // Readiness completes against the captured pipe despite fd reuse and
        // mutated iovecs. It never reruns the numeric syscall arguments.
        assert_eq!(pipe.write_bytes(b"abcdefgh"), Ok(8));
        struct WakeThread(std::thread::Thread);
        impl std::task::Wake for WakeThread {
            fn wake(self: Arc<Self>) {
                self.0.unpark();
            }
            fn wake_by_ref(self: &Arc<Self>) {
                self.0.unpark();
            }
        }
        use std::future::Future;
        let waker = std::task::Waker::from(Arc::new(WakeThread(std::thread::current())));
        let mut cx = std::task::Context::from_waker(&waker);
        let mut future = std::pin::pin!(service.event(token));
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let event = loop {
            if let std::task::Poll::Ready(event) = future.as_mut().poll(&mut cx) {
                break Some(event.unwrap());
            }
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                break None;
            }
            std::thread::park_timeout(remaining);
        };
        if event.is_none() {
            let _ = continuation
                .cancel(crate::kernel::continuation::CancellationCause::ServiceShutdown);
            panic!("captured pipe readiness lost its producer subscription");
        }
        let event = event.unwrap();
        assert_eq!(event, ContinuationEvent::Ready);
        let result = continuation.resume(event, &root).unwrap();
        let outcome = fold_continuation_completion(
            result.completion,
            &dispatcher,
            &root,
            &mut memory,
            (root.shared().mm().id(), root.shared().mm().id().raw()),
        )
        .unwrap()
        .unwrap();
        assert_eq!(outcome, DispatchOutcome::Returned { value: 8 });
        assert_eq!(memory.read_bytes(VA + 256, 8).unwrap(), b"abcdefgh");
        assert_eq!(pipe.buffered_bytes(), 0);
        return;
    } else {
        pending
    };
    let before_resume = memory.memory.prepares.get();
    let (result, budget) = super::budget_meter::measure(|| pending.resume(&root, &mut memory));
    assert_eq!(result.unwrap(), DispatchOutcome::Returned { value: 8 });
    assert_eq!(
        budget.table_lookups, 0,
        "resume never resolves a reused numeric fd"
    );
    assert_eq!(
        budget.host_reads + budget.host_writes,
        0,
        "guest pipe transfer stays in the shared owner"
    );
    assert_eq!(
        memory.memory.prepares.get() - before_resume,
        1,
        "only the refused output is prepared again"
    );
    let output = if later {
        [
            memory.read_bytes(VA + 256, 4).unwrap(),
            memory.read_bytes(VA + 512, 4).unwrap(),
        ]
        .concat()
    } else {
        memory.read_bytes(VA + 256, 8).unwrap()
    };
    assert_eq!(output, b"abcdefgh");
    assert_eq!(pipe.buffered_bytes(), 0);
}
