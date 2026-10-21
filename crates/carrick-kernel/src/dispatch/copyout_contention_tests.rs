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
                TransferIntent::UserWrite,
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
        let request = chunk
            .request(TransferIntent::UserWrite, retained)
            .map_err(|_| fault())?;
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
        self.prepare_record(ranges)
            .map(|permit| Box::new(permit) as Box<dyn PreparedGuestWrite>)
    }

    fn read_bytes_raw(&self, _address: u64, _length: usize) -> Result<Vec<u8>, MemoryError> {
        Err(MemoryError::Unsupported)
    }

    fn write_bytes_raw(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        let range =
            GuestWriteRange::new(carrick_guest_mem::GuestVa::new(address), bytes.len()).unwrap();
        match self.prepare_record(&[range]) {
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
        DispatchOutcome::PreparedCopyoutWait {
            wait: Box::new(DispatchOutcome::OwnerMemoryWait {
                wait: observed,
                committed: 0,
            }),
            restart: super::PreparedCopyoutRestart::NoIntr,
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
