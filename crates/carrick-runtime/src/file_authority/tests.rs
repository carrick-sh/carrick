use std::io::{Seek as _, Write as _};
use std::os::fd::{AsRawFd, FromRawFd as _, OwnedFd};
use std::sync::Arc;

use carrick_kernel::domains::{HostPid, ProcessGeneration};

use super::*;

#[derive(Clone)]
struct Harness {
    transport: Arc<dyn FileAuthorityTransport>,
    ipc: Option<IpcFileAuthority>,
    epoch: AuthorityEpoch,
    client: ClientIdentity,
    next_request: u64,
    revision: Revision,
}

impl Harness {
    fn new() -> Self {
        let epoch = AuthorityEpoch::for_run(7).expect("authority epoch");
        let transport = DirectFileAuthority::for_run(FileAuthorityCore::for_run(epoch));
        Self::with_transport(epoch, Arc::new(transport), None)
    }

    fn new_ipc() -> Self {
        let epoch = AuthorityEpoch::for_run(8).expect("authority epoch");
        let transport = IpcFileAuthority::for_model_tests(FileAuthorityCore::for_run(epoch))
            .expect("IPC authority");
        Self::with_transport(epoch, Arc::new(transport.clone()), Some(transport))
    }

    fn with_transport(
        epoch: AuthorityEpoch,
        transport: Arc<dyn FileAuthorityTransport>,
        ipc: Option<IpcFileAuthority>,
    ) -> Self {
        let client = client(1, 1001, 1);
        let mut harness = Self {
            transport,
            ipc,
            epoch,
            client,
            next_request: 1,
            revision: Revision::ZERO,
        };
        assert!(matches!(
            harness.send(Command::RegisterClient, ObjectGeneration::INITIAL),
            Outcome::ClientRegistered
        ));
        harness
    }

    fn peer(&self, id: u64, host_pid: u32, generation: u32) -> Self {
        let mut peer = Self {
            transport: self.transport.clone(),
            ipc: self.ipc.clone(),
            epoch: self.epoch,
            client: client(id, host_pid, generation),
            next_request: 1,
            revision: self.revision,
        };
        assert!(matches!(
            peer.send(Command::RegisterClient, ObjectGeneration::INITIAL),
            Outcome::ClientRegistered
        ));
        peer
    }

    fn request(&mut self, command: Command, expected: ObjectGeneration) -> Request {
        let request = Request {
            epoch: self.epoch,
            client: self.client,
            request_id: RequestId::from_client_sequence(self.next_request).expect("request id"),
            expected_generation: expected,
            command,
        };
        self.next_request += 1;
        request
    }

    fn transact(
        &mut self,
        request: Request,
        capabilities: Vec<OwnedFd>,
    ) -> Result<AuthorityReply, AuthorityFatal> {
        let reply = self.transport.transact(AuthorityCall {
            request,
            capabilities,
        })?;
        self.revision = reply.response.authority_revision;
        Ok(reply)
    }

    fn execute(&mut self, request: Request) -> Result<Response, AuthorityFatal> {
        let response = self.transport.execute(request)?;
        self.revision = response.authority_revision;
        Ok(response)
    }

    fn send(&mut self, command: Command, expected: ObjectGeneration) -> Outcome {
        let request = self.request(command, expected);
        self.execute(request).expect("authority request").outcome
    }

    fn create_table(&mut self) -> FileTableId {
        match self.send(Command::CreateTable, ObjectGeneration::INITIAL) {
            Outcome::TableCreated { table, .. } => table,
            other => panic!("unexpected create-table outcome: {other:?}"),
        }
    }

    fn create_vfs_file(&mut self, path: &str, contents: &[u8]) -> VfsObjectId {
        match self.send(
            Command::CreateVfsFile {
                path: CanonicalPath::absolute(path).expect("canonical path"),
                mode: 0o644,
                contents: contents.to_vec(),
            },
            ObjectGeneration::INITIAL,
        ) {
            Outcome::VfsObjectCreated { object, .. } => object,
            other => panic!("unexpected VFS create outcome: {other:?}"),
        }
    }

    fn open_vfs(
        &mut self,
        table: FileTableId,
        object: VfsObjectId,
        minimum: i32,
        cloexec: bool,
    ) -> (FileSlotNumber, FileDescriptionId) {
        self.open_vfs_with_mode(table, object, minimum, cloexec, AccessMode::ReadWrite)
    }

    fn open_vfs_with_mode(
        &mut self,
        table: FileTableId,
        object: VfsObjectId,
        minimum: i32,
        cloexec: bool,
        access_mode: AccessMode,
    ) -> (FileSlotNumber, FileDescriptionId) {
        let descriptor_flags = if cloexec {
            DescriptorFlags::CLOSE_ON_EXEC
        } else {
            DescriptorFlags::NONE
        };
        match self.send(
            Command::OpenVfsAndInstall {
                table,
                object,
                object_generation: ObjectGeneration::INITIAL,
                minimum: fd(minimum),
                ceiling: NofileAllocationCeiling::from_captured_soft_limit(1024),
                descriptor_flags,
                access_mode,
                status_flags: StatusFlags::default(),
                path: None,
            },
            ObjectGeneration::INITIAL,
        ) {
            Outcome::Installed {
                fd, description, ..
            } => (fd, description),
            other => panic!("unexpected open outcome: {other:?}"),
        }
    }

    fn read(&mut self, table: FileTableId, fd: FileSlotNumber, maximum: u32) -> Vec<u8> {
        match self.send(
            Command::Read {
                table,
                fd,
                maximum: ByteCount::bounded(maximum).expect("bounded read"),
            },
            ObjectGeneration::INITIAL,
        ) {
            Outcome::Bytes { bytes, .. } => bytes,
            other => panic!("unexpected read outcome: {other:?}"),
        }
    }
}

fn client(id: u64, host_pid: u32, generation: u32) -> ClientIdentity {
    ClientIdentity::registered(
        ClientId::for_process_client(id).expect("client id"),
        HostPid::new(host_pid),
        ProcessGeneration::new(generation),
    )
    .expect("client identity")
}

fn fd(raw: i32) -> FileSlotNumber {
    FileSlotNumber::for_open_fd(raw).expect("fd")
}

fn transport_model_trace(mut harness: Harness) -> Vec<Outcome> {
    let mut outcomes = Vec::new();
    let table = match harness.send(Command::CreateTable, ObjectGeneration::INITIAL) {
        outcome @ Outcome::TableCreated { table, .. } => {
            outcomes.push(outcome);
            table
        }
        other => panic!("unexpected table outcome: {other:?}"),
    };
    let binding = FileAuthorityBinding {
        epoch: harness.epoch,
        client: harness.client,
        table,
        generation: ObjectGeneration::INITIAL,
    };
    assert_eq!(binding.table, table);
    assert_eq!(binding.client, harness.client);
    let object = match harness.send(
        Command::CreateVfsFile {
            path: CanonicalPath::absolute("/equivalence").expect("path"),
            mode: 0o640,
            contents: b"abc".to_vec(),
        },
        ObjectGeneration::INITIAL,
    ) {
        outcome @ Outcome::VfsObjectCreated { object, .. } => {
            outcomes.push(outcome);
            object
        }
        other => panic!("unexpected create outcome: {other:?}"),
    };
    let installed = harness.send(
        Command::OpenVfsAndInstall {
            table,
            object,
            object_generation: ObjectGeneration::INITIAL,
            minimum: fd(3),
            ceiling: NofileAllocationCeiling::from_captured_soft_limit(16),
            descriptor_flags: DescriptorFlags::NONE,
            access_mode: AccessMode::ReadWrite,
            status_flags: StatusFlags::default(),
            path: Some(CanonicalPath::absolute("/equivalence").expect("path")),
        },
        ObjectGeneration::INITIAL,
    );
    let (open_fd, description) = match installed {
        Outcome::Installed {
            fd, description, ..
        } => (fd, description),
        ref other => panic!("unexpected install outcome: {other:?}"),
    };
    outcomes.push(installed);
    outcomes.push(harness.send(
        Command::Write {
            table,
            fd: open_fd,
            bytes: b"XY".to_vec(),
        },
        ObjectGeneration::INITIAL,
    ));
    outcomes.push(harness.send(
        Command::Seek {
            table,
            fd: open_fd,
            offset: 0,
            whence: SeekWhence::Start,
        },
        ObjectGeneration::INITIAL,
    ));
    outcomes.push(harness.send(
        Command::Read {
            table,
            fd: open_fd,
            maximum: ByteCount::bounded(3).expect("bounded read"),
        },
        ObjectGeneration::INITIAL,
    ));
    outcomes.push(harness.send(
        Command::Dup {
            table,
            source: open_fd,
            minimum: fd(4),
            ceiling: NofileAllocationCeiling::from_captured_soft_limit(16),
            flags: DescriptorFlags::CLOSE_ON_EXEC,
        },
        ObjectGeneration::INITIAL,
    ));
    outcomes.push(harness.send(
        Command::InspectDescription { description },
        ObjectGeneration::INITIAL,
    ));
    outcomes.push(harness.send(
        Command::RenameVfs {
            from: CanonicalPath::absolute("/equivalence").expect("source"),
            to: CanonicalPath::absolute("/renamed").expect("target"),
        },
        ObjectGeneration::INITIAL,
    ));
    outcomes.push(harness.send(
        Command::UnlinkVfs {
            path: CanonicalPath::absolute("/renamed").expect("path"),
        },
        ObjectGeneration::INITIAL,
    ));
    outcomes.push(harness.send(
        Command::ExecSuccessor { source: table },
        ObjectGeneration::INITIAL,
    ));
    outcomes
}

fn normalize_trace_description_ids(trace: &mut [Outcome]) {
    let canonical = FileDescriptionId::from_registry_allocation(std::num::NonZeroU64::MIN);
    for outcome in trace {
        match outcome {
            Outcome::Installed { description, .. } | Outcome::Closed { description, .. } => {
                *description = canonical
            }
            Outcome::Slot(slot) => slot.description = canonical,
            Outcome::Description(description) => description.description = canonical,
            _ => {}
        }
    }
}

#[test]
fn direct_and_ipc_transports_produce_identical_model_trace() {
    let mut direct = transport_model_trace(Harness::new());
    let mut ipc = transport_model_trace(Harness::new_ipc());
    // Separate per-run cores allocate globally collision-free description IDs;
    // compare relational semantics rather than unrelated absolute identities.
    normalize_trace_description_ids(&mut direct);
    normalize_trace_description_ids(&mut ipc);
    assert_eq!(direct, ipc);
}

fn host_capability_lease_model(mut harness: Harness, disposition: CapabilityLeaseDisposition) {
    let table = harness.create_table();
    let mut file = tempfile::NamedTempFile::new().expect("temporary host file");
    file.write_all(b"host-bytes").expect("seed host file");
    file.as_file_mut()
        .seek(std::io::SeekFrom::Start(0))
        .expect("rewind");
    let owned: OwnedFd = file.into_file().into();
    let retry_owned = owned.try_clone().expect("duplicate adoption capability");
    let adopt_request = harness.request(
        Command::AdoptHostFileAndInstall {
            table,
            minimum: fd(3),
            ceiling: NofileAllocationCeiling::from_captured_soft_limit(16),
            descriptor_flags: DescriptorFlags::NONE,
            access_mode: AccessMode::ReadWrite,
            status_flags: StatusFlags::default(),
            writable: true,
            path: Some(CanonicalPath::absolute("/host-file").expect("path")),
        },
        ObjectGeneration::INITIAL,
    );
    let adopted = harness
        .transact(adopt_request.clone(), vec![owned])
        .expect("adopt host capability");
    assert!(adopted.capabilities.is_empty());
    let replayed_adoption = harness
        .transact(adopt_request, vec![retry_owned])
        .expect("replay host adoption");
    assert_eq!(replayed_adoption.response, adopted.response);
    assert!(replayed_adoption.capabilities.is_empty());
    let (open_fd, description) = match adopted.response.outcome {
        Outcome::Installed {
            fd, description, ..
        } => (fd, description),
        other => panic!("unexpected adopt outcome: {other:?}"),
    };
    assert_eq!(harness.read(table, open_fd, 4), b"host");

    let acquire_request = harness.request(
        Command::AcquireCapabilityLease {
            table,
            fd: open_fd,
            purpose: CapabilityLeasePurpose::MappingSource,
        },
        ObjectGeneration::INITIAL,
    );
    let first = harness
        .transact(acquire_request.clone(), Vec::new())
        .expect("acquire capability lease");
    let lease = match first.response.outcome {
        Outcome::CapabilityLeaseGranted {
            lease,
            description: leased,
            purpose: CapabilityLeasePurpose::MappingSource,
            ..
        } if leased == description => lease,
        other => panic!("unexpected lease outcome: {other:?}"),
    };
    assert_eq!(first.capabilities.len(), 1);
    let leased_fd = &first.capabilities[0];
    let flags = unsafe { libc::fcntl(leased_fd.as_raw_fd(), libc::F_GETFD) };
    assert!(flags >= 0 && flags & libc::FD_CLOEXEC != 0);
    let mut leased_bytes = [0_u8; 10];
    let read = unsafe {
        libc::pread(
            leased_fd.as_raw_fd(),
            leased_bytes.as_mut_ptr().cast(),
            leased_bytes.len(),
            0,
        )
    };
    assert_eq!(read, 10);
    assert_eq!(&leased_bytes, b"host-bytes");

    let replay = harness
        .transact(acquire_request, Vec::new())
        .expect("replay lease response");
    assert_eq!(replay.response, first.response);
    assert_eq!(replay.capabilities.len(), 1);
    assert_ne!(
        replay.capabilities[0].as_raw_fd(),
        first.capabilities[0].as_raw_fd()
    );

    assert!(matches!(
        harness.send(
            Command::Close { table, fd: open_fd },
            ObjectGeneration::INITIAL,
        ),
        Outcome::Closed {
            description_reclaimed: false,
            ..
        }
    ));
    assert!(matches!(
        harness.send(
            Command::InspectDescription { description },
            ObjectGeneration::INITIAL,
        ),
        Outcome::Description(DescriptionSnapshot {
            logical_slot_refs: 0,
            backing: DescriptionBackingSnapshot::HostFile { writable: true },
            ..
        })
    ));
    assert!(matches!(
        harness.send(
            Command::ReleaseCapabilityLease { lease, disposition },
            ObjectGeneration::INITIAL,
        ),
        Outcome::CapabilityLeaseReleased {
            description_reclaimed: true,
            object_reclaimed: false,
            ..
        }
    ));
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    assert_eq!(
        unsafe { libc::fstat(leased_fd.as_raw_fd(), stat.as_mut_ptr()) },
        0
    );
}

fn bounded_table_mutation_model(mut harness: Harness) {
    let table = harness.create_table();
    let mut descriptions = Vec::new();
    for (fd_raw, contents) in [(3, b"three".as_slice()), (4, b"four"), (5, b"five")] {
        match harness.send(
            Command::CreateSyntheticAndInstall {
                table,
                contents: contents.to_vec(),
                minimum: fd(fd_raw),
                ceiling: NofileAllocationCeiling::from_captured_soft_limit(fd_raw as u32 + 1),
                descriptor_flags: DescriptorFlags::NONE,
                access_mode: AccessMode::ReadWrite,
                status_flags: StatusFlags::default(),
                path: None,
            },
            ObjectGeneration::INITIAL,
        ) {
            Outcome::Installed { description, .. } => descriptions.push(description),
            other => panic!("unexpected install outcome: {other:?}"),
        }
    }
    assert!(matches!(
        harness.send(
            Command::SetDescriptorFlags {
                table,
                fd: fd(3),
                flags: DescriptorFlags::CLOSE_ON_EXEC,
            },
            ObjectGeneration::INITIAL,
        ),
        Outcome::DescriptorFlagsSet {
            flags: DescriptorFlags::CLOSE_ON_EXEC,
            ..
        }
    ));
    let next_after = match harness.send(
        Command::ListSlots {
            table,
            after: None,
            maximum: SlotPageLimit::bounded(2).expect("page limit"),
        },
        ObjectGeneration::INITIAL,
    ) {
        Outcome::SlotPage {
            slots, next_after, ..
        } => {
            assert_eq!(
                slots.iter().map(|slot| slot.fd).collect::<Vec<_>>(),
                vec![fd(3), fd(4)]
            );
            next_after
        }
        other => panic!("unexpected slot page: {other:?}"),
    };
    assert_eq!(next_after, Some(fd(4)));
    assert!(matches!(
        harness.send(
            Command::ListSlots {
                table,
                after: next_after,
                maximum: SlotPageLimit::bounded(2).expect("page limit"),
            },
            ObjectGeneration::INITIAL,
        ),
        Outcome::SlotPage { slots, next_after: None, .. }
            if slots.iter().map(|slot| slot.fd).collect::<Vec<_>>() == vec![fd(5)]
    ));

    assert!(matches!(
        harness.send(
            Command::ReplaceSlot {
                table,
                source: fd(3),
                target: fd(4),
                ceiling: NofileAllocationCeiling::from_captured_soft_limit(6),
                flags: DescriptorFlags::NONE,
                same_slot: SameSlotBehavior::Reject,
            },
            ObjectGeneration::INITIAL,
        ),
        Outcome::SlotReplaced {
            replaced_description: Some(replaced),
            description_reclaimed: true,
            ..
        } if replaced == descriptions[1]
    ));
    assert_eq!(
        harness.send(
            Command::InspectDescription {
                description: descriptions[1],
            },
            ObjectGeneration::INITIAL,
        ),
        Outcome::Rejected(AuthorityError::DescriptionNotFound)
    );
    let revision = harness.revision;
    assert!(matches!(
        harness.send(
            Command::ReplaceSlot {
                table,
                source: fd(3),
                target: fd(3),
                ceiling: NofileAllocationCeiling::from_captured_soft_limit(6),
                flags: DescriptorFlags::NONE,
                same_slot: SameSlotBehavior::ReturnUnchanged,
            },
            ObjectGeneration::INITIAL,
        ),
        Outcome::SlotReplaced {
            replaced_description: None,
            ..
        }
    ));
    assert_eq!(harness.revision, revision);
    assert_eq!(
        harness.send(
            Command::ReplaceSlot {
                table,
                source: fd(3),
                target: fd(3),
                ceiling: NofileAllocationCeiling::from_captured_soft_limit(6),
                flags: DescriptorFlags::NONE,
                same_slot: SameSlotBehavior::Reject,
            },
            ObjectGeneration::INITIAL,
        ),
        Outcome::Rejected(AuthorityError::SameSlotRejected)
    );
    assert_eq!(harness.revision, revision);
    assert!(matches!(
        harness.send(
            Command::MutateSlotRange {
                table,
                first: fd(3),
                last: fd(5),
                action: SlotRangeAction::SetCloseOnExec,
            },
            ObjectGeneration::INITIAL,
        ),
        Outcome::SlotRangeMutated { affected: 3, .. }
    ));
    assert!(matches!(
        harness.send(
            Command::MutateSlotRange {
                table,
                first: fd(4),
                last: fd(5),
                action: SlotRangeAction::Close,
            },
            ObjectGeneration::INITIAL,
        ),
        Outcome::SlotRangeMutated { affected: 2, .. }
    ));
    assert!(matches!(
        harness.send(
            Command::InspectDescription {
                description: descriptions[0],
            },
            ObjectGeneration::INITIAL,
        ),
        Outcome::Description(DescriptionSnapshot {
            logical_slot_refs: 1,
            ..
        })
    ));
}

fn epoll_model(mut harness: Harness) {
    let table = harness.create_table();
    let (epoll_fd, epoll_description) = match harness.send(
        Command::CreateEpollAndInstall {
            table,
            minimum: fd(3),
            ceiling: NofileAllocationCeiling::from_captured_soft_limit(16),
            descriptor_flags: DescriptorFlags::NONE,
        },
        ObjectGeneration::INITIAL,
    ) {
        Outcome::EpollCreated {
            fd, description, ..
        } => (fd, description),
        other => panic!("unexpected epoll creation: {other:?}"),
    };
    let (counter_fd, counter_description) = match harness.send(
        Command::CreateEventCounterAndInstall {
            table,
            initial: 0,
            semaphore: false,
            minimum: fd(4),
            ceiling: NofileAllocationCeiling::from_captured_soft_limit(16),
            descriptor_flags: DescriptorFlags::NONE,
            status_flags: StatusFlags::default(),
        },
        ObjectGeneration::INITIAL,
    ) {
        Outcome::EventCounterCreated {
            fd, description, ..
        } => (fd, description),
        other => panic!("unexpected event-counter creation: {other:?}"),
    };
    let registration = EpollRegistration {
        events: carrick_abi::LinuxEpollEvents::IN,
        data: EpollUserData::from_guest(0xfeed),
    };
    let host_plan = match harness.send(
        Command::EpollCtlAdd {
            table,
            epoll_fd,
            target_fd: counter_fd,
            registration,
        },
        ObjectGeneration::INITIAL,
    ) {
        Outcome::EpollInterestAdded { host_plan, .. } => host_plan,
        other => panic!("unexpected epoll ADD: {other:?}"),
    };
    assert!(matches!(
        harness.send(
            Command::EpollRevalidateHostPlan { plan: host_plan },
            ObjectGeneration::INITIAL,
        ),
        Outcome::EpollHostPlanValidated { valid: true, .. }
    ));
    let stale_plan = EpollHostPlan {
        plan_revision: Revision::from_wire(host_plan.plan_revision.raw() + 1),
        ..host_plan
    };
    assert!(matches!(
        harness.send(
            Command::EpollRevalidateHostPlan { plan: stale_plan },
            ObjectGeneration::INITIAL,
        ),
        Outcome::EpollHostPlanValidated { valid: false, .. }
    ));
    assert!(matches!(
        harness.send(
            Command::EpollCollect {
                table,
                epoll_fd,
                maximum: EpollEventLimit::bounded(4).expect("event limit"),
            },
            ObjectGeneration::INITIAL,
        ),
        Outcome::EpollEvents { events, .. } if events.is_empty()
    ));
    assert!(matches!(
        harness.send(
            Command::EventCounterWrite {
                table,
                fd: counter_fd,
                value: 1,
            },
            ObjectGeneration::INITIAL,
        ),
        Outcome::EventCounterWritten { counter: 1, .. }
    ));
    for _ in 0..2 {
        assert!(matches!(
            harness.send(
                Command::EpollCollect {
                    table,
                    epoll_fd,
                    maximum: EpollEventLimit::bounded(4).expect("event limit"),
                },
                ObjectGeneration::INITIAL,
            ),
            Outcome::EpollEvents { events, .. }
                if events == vec![EpollReadyEvent {
                    events: carrick_abi::LinuxEpollEvents::IN,
                    data: EpollUserData::from_guest(0xfeed),
                }]
        ));
    }

    let edge = EpollRegistration {
        events: carrick_abi::LinuxEpollEvents::IN | carrick_abi::LinuxEpollEvents::ET,
        data: EpollUserData::from_guest(0xed9e),
    };
    assert!(matches!(
        harness.send(
            Command::EpollCtlModify {
                table,
                epoll_fd,
                target_fd: counter_fd,
                registration: edge,
            },
            ObjectGeneration::INITIAL,
        ),
        Outcome::EpollInterestModified { .. }
    ));
    assert!(matches!(
        harness.send(
            Command::EpollCollect {
                table,
                epoll_fd,
                maximum: EpollEventLimit::bounded(4).expect("event limit"),
            },
            ObjectGeneration::INITIAL,
        ),
        Outcome::EpollEvents { events, .. } if events.len() == 1
    ));
    assert!(matches!(
        harness.send(
            Command::EpollCollect {
                table,
                epoll_fd,
                maximum: EpollEventLimit::bounded(4).expect("event limit"),
            },
            ObjectGeneration::INITIAL,
        ),
        Outcome::EpollEvents { events, .. } if events.is_empty()
    ));
    assert!(matches!(
        harness.send(
            Command::EventCounterRead {
                table,
                fd: counter_fd,
            },
            ObjectGeneration::INITIAL,
        ),
        Outcome::EventCounterRead { value: 1, .. }
    ));
    assert!(matches!(
        harness.send(
            Command::EventCounterWrite {
                table,
                fd: counter_fd,
                value: 2,
            },
            ObjectGeneration::INITIAL,
        ),
        Outcome::EventCounterWritten { counter: 2, .. }
    ));
    assert!(matches!(
        harness.send(
            Command::EpollCollect {
                table,
                epoll_fd,
                maximum: EpollEventLimit::bounded(4).expect("event limit"),
            },
            ObjectGeneration::INITIAL,
        ),
        Outcome::EpollEvents { events, .. } if events.len() == 1
    ));

    let oneshot = EpollRegistration {
        events: carrick_abi::LinuxEpollEvents::IN | carrick_abi::LinuxEpollEvents::ONESHOT,
        data: EpollUserData::from_guest(0x1),
    };
    assert!(matches!(
        harness.send(
            Command::EpollCtlModify {
                table,
                epoll_fd,
                target_fd: counter_fd,
                registration: oneshot,
            },
            ObjectGeneration::INITIAL,
        ),
        Outcome::EpollInterestModified { .. }
    ));
    assert!(matches!(
        harness.send(
            Command::EpollCollect {
                table,
                epoll_fd,
                maximum: EpollEventLimit::bounded(1).expect("event limit"),
            },
            ObjectGeneration::INITIAL,
        ),
        Outcome::EpollEvents { events, .. } if events.len() == 1
    ));
    assert!(matches!(
        harness.send(
            Command::EpollCollect {
                table,
                epoll_fd,
                maximum: EpollEventLimit::bounded(1).expect("event limit"),
            },
            ObjectGeneration::INITIAL,
        ),
        Outcome::EpollEvents { events, .. } if events.is_empty()
    ));

    let (nested_fd, _) = match harness.send(
        Command::CreateEpollAndInstall {
            table,
            minimum: fd(5),
            ceiling: NofileAllocationCeiling::from_captured_soft_limit(16),
            descriptor_flags: DescriptorFlags::NONE,
        },
        ObjectGeneration::INITIAL,
    ) {
        Outcome::EpollCreated {
            fd, description, ..
        } => (fd, description),
        other => panic!("unexpected nested epoll creation: {other:?}"),
    };
    assert!(matches!(
        harness.send(
            Command::EpollCtlAdd {
                table,
                epoll_fd,
                target_fd: nested_fd,
                registration,
            },
            ObjectGeneration::INITIAL,
        ),
        Outcome::EpollInterestAdded { .. }
    ));
    assert_eq!(
        harness.send(
            Command::EpollCtlAdd {
                table,
                epoll_fd: nested_fd,
                target_fd: epoll_fd,
                registration,
            },
            ObjectGeneration::INITIAL,
        ),
        Outcome::Rejected(AuthorityError::EpollLoop)
    );
    assert_eq!(
        harness.send(
            Command::EpollCtlAdd {
                table,
                epoll_fd,
                target_fd: epoll_fd,
                registration,
            },
            ObjectGeneration::INITIAL,
        ),
        Outcome::Rejected(AuthorityError::EpollLoop)
    );

    assert!(matches!(
        harness.send(
            Command::Close {
                table,
                fd: counter_fd,
            },
            ObjectGeneration::INITIAL,
        ),
        Outcome::Closed {
            description: closed,
            description_reclaimed: true,
            ..
        } if closed == counter_description
    ));
    assert!(matches!(
        harness.send(
            Command::InspectDescription {
                description: epoll_description,
            },
            ObjectGeneration::INITIAL,
        ),
        Outcome::Description(DescriptionSnapshot {
            backing: DescriptionBackingSnapshot::Epoll { interests: 1 },
            ..
        })
    ));
    assert!(matches!(
        harness.send(
            Command::Close {
                table,
                fd: nested_fd,
            },
            ObjectGeneration::INITIAL,
        ),
        Outcome::Closed {
            description_reclaimed: true,
            ..
        }
    ));
    assert!(matches!(
        harness.send(
            Command::InspectDescription {
                description: epoll_description,
            },
            ObjectGeneration::INITIAL,
        ),
        Outcome::Description(DescriptionSnapshot {
            backing: DescriptionBackingSnapshot::Epoll { interests: 0 },
            ..
        })
    ));
}

fn event_counter_saturation_model(mut harness: Harness) {
    let table = harness.create_table();
    let (epoll_fd, _) = match harness.send(
        Command::CreateEpollAndInstall {
            table,
            minimum: fd(3),
            ceiling: NofileAllocationCeiling::from_captured_soft_limit(16),
            descriptor_flags: DescriptorFlags::NONE,
        },
        ObjectGeneration::INITIAL,
    ) {
        Outcome::EpollCreated {
            fd, description, ..
        } => (fd, description),
        other => panic!("unexpected epoll create: {other:?}"),
    };
    let counter_fd = match harness.send(
        Command::CreateEventCounterAndInstall {
            table,
            initial: u64::MAX - 2,
            semaphore: false,
            minimum: fd(4),
            ceiling: NofileAllocationCeiling::from_captured_soft_limit(16),
            descriptor_flags: DescriptorFlags::NONE,
            status_flags: StatusFlags::default(),
        },
        ObjectGeneration::INITIAL,
    ) {
        Outcome::EventCounterCreated { fd, .. } => fd,
        other => panic!("unexpected counter create: {other:?}"),
    };
    assert!(matches!(
        harness.send(
            Command::EpollCtlAdd {
                table,
                epoll_fd,
                target_fd: counter_fd,
                registration: EpollRegistration {
                    events: carrick_abi::LinuxEpollEvents::OUT,
                    data: EpollUserData::default(),
                },
            },
            ObjectGeneration::INITIAL,
        ),
        Outcome::EpollInterestAdded { .. }
    ));
    assert!(matches!(
        harness.send(
            Command::EpollCollect {
                table,
                epoll_fd,
                maximum: EpollEventLimit::bounded(1).expect("limit"),
            },
            ObjectGeneration::INITIAL,
        ),
        Outcome::EpollEvents { events, .. }
            if events.first().is_some_and(|event| event.events.contains(carrick_abi::LinuxEpollEvents::OUT))
    ));
    assert!(matches!(
        harness.send(
            Command::EventCounterWrite {
                table,
                fd: counter_fd,
                value: 1,
            },
            ObjectGeneration::INITIAL,
        ),
        Outcome::EventCounterWritten { counter, .. } if counter == u64::MAX - 1
    ));
    assert!(matches!(
        harness.send(
            Command::EpollCollect {
                table,
                epoll_fd,
                maximum: EpollEventLimit::bounded(1).expect("limit"),
            },
            ObjectGeneration::INITIAL,
        ),
        Outcome::EpollEvents { events, .. } if events.is_empty()
    ));
    assert!(matches!(
        harness.send(
            Command::EventCounterWrite {
                table,
                fd: counter_fd,
                value: 0,
            },
            ObjectGeneration::INITIAL,
        ),
        Outcome::EventCounterWritten { counter, .. } if counter == u64::MAX - 1
    ));
    assert_eq!(
        harness.send(
            Command::EventCounterWrite {
                table,
                fd: counter_fd,
                value: 1,
            },
            ObjectGeneration::INITIAL,
        ),
        Outcome::Rejected(AuthorityError::WouldBlock)
    );
}

#[test]
fn direct_and_ipc_pipe_streams_preserve_shared_state_and_endpoint_lifetime() {
    for ipc in [false, true] {
        let mut harness = if ipc {
            Harness::new_ipc()
        } else {
            Harness::new()
        };
        let table = harness.create_table();
        let (pipe, read_fd, write_fd, write_description) = match harness.send(
            Command::CreatePipeAndInstall {
                table,
                minimum: fd(3),
                ceiling: NofileAllocationCeiling::from_captured_soft_limit(32),
                descriptor_flags: DescriptorFlags::NONE,
                status_flags: StatusFlags::from_linux_bits(0x800),
                capacity: PipeCapacity::bounded(8).expect("capacity"),
            },
            ObjectGeneration::INITIAL,
        ) {
            Outcome::PipeCreated {
                pipe,
                read_fd,
                write_fd,
                write_description,
                ..
            } => (pipe, read_fd, write_fd, write_description),
            other => panic!("unexpected pipe creation: {other:?}"),
        };
        assert!(matches!(
            harness.send(
                Command::Read {
                    table,
                    fd: read_fd,
                    maximum: ByteCount::bounded(8).expect("count"),
                },
                ObjectGeneration::INITIAL,
            ),
            Outcome::Rejected(AuthorityError::WouldBlock)
        ));
        assert!(matches!(
            harness.send(
                Command::Write {
                    table,
                    fd: write_fd,
                    bytes: b"abcdefghij".to_vec(),
                },
                ObjectGeneration::INITIAL,
            ),
            Outcome::StreamWritten { pipe: actual, count, .. }
                if actual == pipe && count.raw() == 8
        ));
        assert!(matches!(
            harness.send(
                Command::Write {
                    table,
                    fd: write_fd,
                    bytes: b"x".to_vec(),
                },
                ObjectGeneration::INITIAL,
            ),
            Outcome::Rejected(AuthorityError::WouldBlock)
        ));
        assert!(matches!(
            harness.send(
                Command::Read {
                    table,
                    fd: read_fd,
                    maximum: ByteCount::bounded(3).expect("count"),
                },
                ObjectGeneration::INITIAL,
            ),
            Outcome::StreamBytes { bytes, .. } if bytes == b"abc"
        ));
        assert!(matches!(
            harness.send(
                Command::SetPipeCapacity {
                    table,
                    fd: read_fd,
                    capacity: PipeCapacity::bounded(4).expect("capacity"),
                },
                ObjectGeneration::INITIAL,
            ),
            Outcome::Rejected(AuthorityError::InvalidPipeCapacity)
        ));
        assert!(matches!(
            harness.send(
                Command::Close { table, fd: read_fd },
                ObjectGeneration::INITIAL,
            ),
            Outcome::Closed { .. }
        ));
        assert!(matches!(
            harness.send(
                Command::Write {
                    table,
                    fd: write_fd,
                    bytes: b"x".to_vec(),
                },
                ObjectGeneration::INITIAL,
            ),
            Outcome::Rejected(AuthorityError::BrokenPipe)
        ));
        assert!(matches!(
            harness.send(
                Command::Close {
                    table,
                    fd: write_fd,
                },
                ObjectGeneration::INITIAL,
            ),
            Outcome::Closed {
                description: actual,
                description_reclaimed: true,
                ..
            } if actual == write_description
        ));
    }
}

#[test]
fn direct_and_ipc_signalfd_masks_are_authority_owned() {
    for ipc in [false, true] {
        let mut harness = if ipc {
            Harness::new_ipc()
        } else {
            Harness::new()
        };
        let table = harness.create_table();
        let initial = carrick_abi::SigSet::from_raw(0x12);
        let updated = carrick_abi::SigSet::from_raw(0x24);
        let (signal_fd, description) = match harness.send(
            Command::CreateSignalFdAndInstall {
                table,
                minimum: fd(3),
                ceiling: NofileAllocationCeiling::from_captured_soft_limit(16),
                descriptor_flags: DescriptorFlags::NONE,
                status_flags: StatusFlags::default(),
                mask: initial,
            },
            ObjectGeneration::INITIAL,
        ) {
            Outcome::SignalFdCreated {
                fd,
                description,
                mask,
                ..
            } if mask == initial => (fd, description),
            other => panic!("unexpected signalfd create: {other:?}"),
        };
        assert!(matches!(
            harness.send(
                Command::SetSignalFdMask {
                    table,
                    fd: signal_fd,
                    mask: updated,
                },
                ObjectGeneration::INITIAL,
            ),
            Outcome::SignalFdMaskSet { mask, .. } if mask == updated
        ));
        assert!(matches!(
            harness.send(
                Command::InspectDescription { description },
                ObjectGeneration::INITIAL,
            ),
            Outcome::Description(DescriptionSnapshot {
                backing: DescriptionBackingSnapshot::SignalFd { mask },
                ..
            }) if mask == updated
        ));
    }
}

#[test]
fn direct_and_ipc_timer_expiration_is_authority_owned() {
    for ipc in [false, true] {
        let mut harness = if ipc {
            Harness::new_ipc()
        } else {
            Harness::new()
        };
        let table = harness.create_table();
        let (timer_fd, description) = match harness.send(
            Command::CreateTimerAndInstall {
                table,
                minimum: fd(3),
                ceiling: NofileAllocationCeiling::from_captured_soft_limit(16),
                descriptor_flags: DescriptorFlags::NONE,
                status_flags: StatusFlags::default(),
            },
            ObjectGeneration::INITIAL,
        ) {
            Outcome::TimerCreated {
                fd, description, ..
            } => (fd, description),
            other => panic!("unexpected timer create: {other:?}"),
        };
        assert!(matches!(
            harness.send(
                Command::SetTimer {
                    table,
                    fd: timer_fd,
                    interval_ns: 10,
                    initial_ns: 20,
                },
                ObjectGeneration::INITIAL,
            ),
            Outcome::TimerSet { .. }
        ));
        assert!(matches!(
            harness.send(
                Command::ExpireTimer {
                    table,
                    fd: timer_fd,
                    expirations: 3,
                },
                ObjectGeneration::INITIAL,
            ),
            Outcome::TimerExpired { pending: 3, .. }
        ));
        assert_eq!(harness.read(table, timer_fd, 8), 3_u64.to_ne_bytes());
        assert!(matches!(
            harness.send(
                Command::Read {
                    table,
                    fd: timer_fd,
                    maximum: ByteCount::bounded(8).expect("count"),
                },
                ObjectGeneration::INITIAL,
            ),
            Outcome::Rejected(AuthorityError::WouldBlock)
        ));
        assert!(matches!(
            harness.send(
                Command::InspectDescription { description },
                ObjectGeneration::INITIAL,
            ),
            Outcome::Description(DescriptionSnapshot {
                backing: DescriptionBackingSnapshot::Timer {
                    interval_ns: 10,
                    initial_ns: 20,
                    pending: 0,
                },
                ..
            })
        ));
    }
}

#[test]
fn direct_and_ipc_event_counter_saturation_matches_linux() {
    event_counter_saturation_model(Harness::new());
    event_counter_saturation_model(Harness::new_ipc());
}

#[test]
fn direct_and_ipc_transports_match_epoll_model() {
    epoll_model(Harness::new());
    epoll_model(Harness::new_ipc());
}

fn epoll_lifecycle_model(mut parent: Harness) {
    let mut child = parent.peer(2, 1002, 1);
    let table = parent.create_table();
    let (epoll_fd, epoll_description) = match parent.send(
        Command::CreateEpollAndInstall {
            table,
            minimum: fd(3),
            ceiling: NofileAllocationCeiling::from_captured_soft_limit(16),
            descriptor_flags: DescriptorFlags::NONE,
        },
        ObjectGeneration::INITIAL,
    ) {
        Outcome::EpollCreated {
            fd, description, ..
        } => (fd, description),
        other => panic!("unexpected epoll create: {other:?}"),
    };
    let (counter_fd, counter_description) = match parent.send(
        Command::CreateEventCounterAndInstall {
            table,
            initial: 0,
            semaphore: false,
            minimum: fd(4),
            ceiling: NofileAllocationCeiling::from_captured_soft_limit(16),
            descriptor_flags: DescriptorFlags::NONE,
            status_flags: StatusFlags::default(),
        },
        ObjectGeneration::INITIAL,
    ) {
        Outcome::EventCounterCreated {
            fd, description, ..
        } => (fd, description),
        other => panic!("unexpected counter create: {other:?}"),
    };
    let child_table = match parent.send(
        Command::ForkCopy {
            source: table,
            owner: child.client,
        },
        ObjectGeneration::INITIAL,
    ) {
        Outcome::ForkCopied { table, .. } => table,
        other => panic!("unexpected fork copy: {other:?}"),
    };
    assert!(matches!(
        child.send(
            Command::EpollCtlAdd {
                table: child_table,
                epoll_fd,
                target_fd: counter_fd,
                registration: EpollRegistration {
                    events: carrick_abi::LinuxEpollEvents::IN,
                    data: EpollUserData::from_guest(0xc11d),
                },
            },
            ObjectGeneration::INITIAL,
        ),
        Outcome::EpollInterestAdded { .. }
    ));
    assert!(matches!(
        parent.send(
            Command::EventCounterWrite {
                table,
                fd: counter_fd,
                value: 1,
            },
            ObjectGeneration::INITIAL,
        ),
        Outcome::EventCounterWritten { .. }
    ));
    assert!(matches!(
        parent.send(
            Command::EpollCollect {
                table,
                epoll_fd,
                maximum: EpollEventLimit::bounded(1).expect("limit"),
            },
            ObjectGeneration::INITIAL,
        ),
        Outcome::EpollEvents { events, .. } if events.len() == 1
    ));
    assert!(matches!(
        parent.send(
            Command::Close {
                table,
                fd: counter_fd,
            },
            ObjectGeneration::INITIAL,
        ),
        Outcome::Closed {
            description_reclaimed: false,
            ..
        }
    ));
    assert!(matches!(
        child.send(
            Command::InspectDescription {
                description: epoll_description,
            },
            ObjectGeneration::INITIAL,
        ),
        Outcome::Description(DescriptionSnapshot {
            backing: DescriptionBackingSnapshot::Epoll { interests: 1 },
            ..
        })
    ));
    assert!(matches!(
        child.send(
            Command::Close {
                table: child_table,
                fd: counter_fd,
            },
            ObjectGeneration::INITIAL,
        ),
        Outcome::Closed {
            description: closed,
            description_reclaimed: true,
            ..
        } if closed == counter_description
    ));
    assert!(matches!(
        child.send(
            Command::InspectDescription {
                description: epoll_description,
            },
            ObjectGeneration::INITIAL,
        ),
        Outcome::Description(DescriptionSnapshot {
            backing: DescriptionBackingSnapshot::Epoll { interests: 0 },
            ..
        })
    ));
}

fn epoll_duplicate_registration_model(mut harness: Harness) {
    let table = harness.create_table();
    let epoll_fd = match harness.send(
        Command::CreateEpollAndInstall {
            table,
            minimum: fd(3),
            ceiling: NofileAllocationCeiling::from_captured_soft_limit(16),
            descriptor_flags: DescriptorFlags::NONE,
        },
        ObjectGeneration::INITIAL,
    ) {
        Outcome::EpollCreated { fd, .. } => fd,
        other => panic!("unexpected epoll create: {other:?}"),
    };
    let (counter_fd, counter_description) = match harness.send(
        Command::CreateEventCounterAndInstall {
            table,
            initial: 1,
            semaphore: false,
            minimum: fd(4),
            ceiling: NofileAllocationCeiling::from_captured_soft_limit(16),
            descriptor_flags: DescriptorFlags::NONE,
            status_flags: StatusFlags::default(),
        },
        ObjectGeneration::INITIAL,
    ) {
        Outcome::EventCounterCreated {
            fd, description, ..
        } => (fd, description),
        other => panic!("unexpected counter create: {other:?}"),
    };
    let duplicate_fd = match harness.send(
        Command::Dup {
            table,
            source: counter_fd,
            minimum: fd(5),
            ceiling: NofileAllocationCeiling::from_captured_soft_limit(16),
            flags: DescriptorFlags::NONE,
        },
        ObjectGeneration::INITIAL,
    ) {
        Outcome::Duplicated { fd, .. } => fd,
        other => panic!("unexpected dup: {other:?}"),
    };
    for (slot, data) in [(counter_fd, 1), (duplicate_fd, 2)] {
        assert!(matches!(
            harness.send(
                Command::EpollCtlAdd {
                    table,
                    epoll_fd,
                    target_fd: slot,
                    registration: EpollRegistration {
                        events: carrick_abi::LinuxEpollEvents::IN,
                        data: EpollUserData::from_guest(data),
                    },
                },
                ObjectGeneration::INITIAL,
            ),
            Outcome::EpollInterestAdded { .. }
        ));
    }
    assert!(matches!(
        harness.send(
            Command::EpollCollect {
                table,
                epoll_fd,
                maximum: EpollEventLimit::bounded(4).expect("limit"),
            },
            ObjectGeneration::INITIAL,
        ),
        Outcome::EpollEvents { events, .. }
            if events.iter().map(|event| event.data.raw()).collect::<Vec<_>>() == vec![1, 2]
    ));
    assert!(matches!(
        harness.send(
            Command::Close {
                table,
                fd: counter_fd,
            },
            ObjectGeneration::INITIAL,
        ),
        Outcome::Closed {
            description_reclaimed: false,
            ..
        }
    ));
    assert!(matches!(
        harness.send(
            Command::EpollCollect {
                table,
                epoll_fd,
                maximum: EpollEventLimit::bounded(4).expect("limit"),
            },
            ObjectGeneration::INITIAL,
        ),
        Outcome::EpollEvents { events, .. } if events.len() == 2
    ));
    assert!(matches!(
        harness.send(
            Command::Close {
                table,
                fd: duplicate_fd,
            },
            ObjectGeneration::INITIAL,
        ),
        Outcome::Closed {
            description: closed,
            description_reclaimed: true,
            ..
        } if closed == counter_description
    ));
    assert!(matches!(
        harness.send(
            Command::EpollCollect {
                table,
                epoll_fd,
                maximum: EpollEventLimit::bounded(4).expect("limit"),
            },
            ObjectGeneration::INITIAL,
        ),
        Outcome::EpollEvents { events, .. } if events.is_empty()
    ));
}

#[test]
fn direct_and_ipc_epoll_rejects_sixth_nesting_level() {
    for ipc in [false, true] {
        let mut harness = if ipc {
            Harness::new_ipc()
        } else {
            Harness::new()
        };
        let table = harness.create_table();
        let mut epolls = Vec::new();
        for minimum in 3..=9 {
            let epoll = match harness.send(
                Command::CreateEpollAndInstall {
                    table,
                    minimum: fd(minimum),
                    ceiling: NofileAllocationCeiling::from_captured_soft_limit(16),
                    descriptor_flags: DescriptorFlags::NONE,
                },
                ObjectGeneration::INITIAL,
            ) {
                Outcome::EpollCreated { fd, .. } => fd,
                other => panic!("unexpected epoll create: {other:?}"),
            };
            epolls.push(epoll);
        }
        for pair in epolls[1..].windows(2).rev() {
            assert!(matches!(
                harness.send(
                    Command::EpollCtlAdd {
                        table,
                        epoll_fd: pair[0],
                        target_fd: pair[1],
                        registration: EpollRegistration {
                            events: carrick_abi::LinuxEpollEvents::IN,
                            data: EpollUserData::default(),
                        },
                    },
                    ObjectGeneration::INITIAL,
                ),
                Outcome::EpollInterestAdded { .. }
            ));
        }
        assert!(matches!(
            harness.send(
                Command::EpollCtlAdd {
                    table,
                    epoll_fd: epolls[0],
                    target_fd: epolls[1],
                    registration: EpollRegistration {
                        events: carrick_abi::LinuxEpollEvents::IN,
                        data: EpollUserData::default(),
                    },
                },
                ObjectGeneration::INITIAL,
            ),
            Outcome::Rejected(AuthorityError::EpollLoop)
        ));
    }
}

#[test]
fn direct_and_ipc_epoll_allows_duplicate_descriptor_registrations() {
    epoll_duplicate_registration_model(Harness::new());
    epoll_duplicate_registration_model(Harness::new_ipc());
}

#[test]
fn direct_and_ipc_epoll_lifecycle_tracks_forked_tables() {
    epoll_lifecycle_model(Harness::new());
    epoll_lifecycle_model(Harness::new_ipc());
}

#[test]
fn direct_and_ipc_transports_match_bounded_table_mutations() {
    bounded_table_mutation_model(Harness::new());
    bounded_table_mutation_model(Harness::new_ipc());
}

#[test]
fn direct_and_ipc_host_streams_own_io_and_poll_capabilities() {
    for ipc in [false, true] {
        let mut harness = if ipc {
            Harness::new_ipc()
        } else {
            Harness::new()
        };
        let table = harness.create_table();
        let mut fds = [-1; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        for fd in fds {
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            assert!(flags >= 0);
            assert_eq!(
                unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) },
                0
            );
        }
        let reader = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        let writer = unsafe { OwnedFd::from_raw_fd(fds[1]) };
        let request = harness.request(
            Command::AdoptHostStreamAndInstall {
                table,
                minimum: fd(3),
                ceiling: NofileAllocationCeiling::from_captured_soft_limit(16),
                descriptor_flags: DescriptorFlags::NONE,
                access_mode: AccessMode::ReadOnly,
                status_flags: StatusFlags::default(),
                kind: HostStreamKind::Pipe {
                    end: PipeEnd::Reader,
                    bidirectional: false,
                },
                path: None,
            },
            ObjectGeneration::INITIAL,
        );
        let reply = harness
            .transact(request, vec![reader])
            .expect("adopt host stream");
        let (read_fd, description) = match reply.response.outcome {
            Outcome::HostStreamCreated {
                fd, description, ..
            } => (fd, description),
            other => panic!("unexpected host stream: {other:?}"),
        };
        assert_eq!(
            unsafe { libc::write(writer.as_raw_fd(), b"xy".as_ptr().cast(), 2) },
            2
        );
        assert_eq!(harness.read(table, read_fd, 2), b"xy");
        let poll_request = harness.request(
            Command::AcquireCapabilityLease {
                table,
                fd: read_fd,
                purpose: CapabilityLeasePurpose::PollSource,
            },
            ObjectGeneration::INITIAL,
        );
        let poll = harness
            .transact(poll_request, Vec::new())
            .expect("poll lease");
        assert_eq!(poll.capabilities.len(), 1);
        assert!(matches!(
            harness.send(
                Command::InspectDescription { description },
                ObjectGeneration::INITIAL,
            ),
            Outcome::Description(DescriptionSnapshot {
                backing: DescriptionBackingSnapshot::HostStream {
                    kind: HostStreamKind::Pipe {
                        end: PipeEnd::Reader,
                        bidirectional: false,
                    },
                },
                ..
            })
        ));
    }
}

#[test]
fn direct_and_ipc_io_uring_owns_both_backing_capabilities() {
    for ipc in [false, true] {
        let mut harness = if ipc {
            Harness::new_ipc()
        } else {
            Harness::new()
        };
        let table = harness.create_table();
        let data = tempfile::tempfile().expect("data file");
        data.set_len(4096).expect("size data");
        let lock = tempfile::tempfile().expect("lock file");
        lock.set_len(1).expect("size lock");
        let request = harness.request(
            Command::AdoptIoUringAndInstall {
                table,
                minimum: fd(3),
                ceiling: NofileAllocationCeiling::from_captured_soft_limit(16),
                descriptor_flags: DescriptorFlags::CLOSE_ON_EXEC,
                status_flags: StatusFlags::default(),
                entries: 8,
                data_length: 4096,
            },
            ObjectGeneration::INITIAL,
        );
        let reply = harness
            .transact(request, vec![lock.into(), data.into()])
            .expect("adopt ring");
        let (ring_fd, description) = match reply.response.outcome {
            Outcome::IoUringCreated {
                fd,
                description,
                entries: 8,
                data_length: 4096,
                ..
            } => (fd, description),
            other => panic!("unexpected ring creation: {other:?}"),
        };
        for purpose in [
            CapabilityLeasePurpose::IoUringData,
            CapabilityLeasePurpose::IoUringLock,
        ] {
            let request = harness.request(
                Command::AcquireCapabilityLease {
                    table,
                    fd: ring_fd,
                    purpose,
                },
                ObjectGeneration::INITIAL,
            );
            let lease = harness.transact(request, Vec::new()).expect("ring lease");
            assert_eq!(lease.capabilities.len(), 1);
        }
        assert!(matches!(
            harness.send(
                Command::InspectDescription { description },
                ObjectGeneration::INITIAL,
            ),
            Outcome::Description(DescriptionSnapshot {
                backing: DescriptionBackingSnapshot::IoUring {
                    entries: 8,
                    data_length: 4096,
                },
                ..
            })
        ));
    }
}

#[test]
fn direct_and_ipc_mapping_attachments_outlive_slots_and_split_on_unmap() {
    for ipc in [false, true] {
        let mut harness = if ipc {
            Harness::new_ipc()
        } else {
            Harness::new()
        };
        let table = harness.create_table();
        let file = tempfile::NamedTempFile::new().expect("temporary host file");
        let owned: OwnedFd = file.into_file().into();
        let adopt_request = harness.request(
            Command::AdoptHostFileAndInstall {
                table,
                minimum: fd(3),
                ceiling: NofileAllocationCeiling::from_captured_soft_limit(16),
                descriptor_flags: DescriptorFlags::NONE,
                access_mode: AccessMode::ReadWrite,
                status_flags: StatusFlags::default(),
                writable: true,
                path: None,
            },
            ObjectGeneration::INITIAL,
        );
        let adopted = harness
            .transact(adopt_request, vec![owned])
            .expect("adopt host file");
        let (open_fd, description) = match adopted.response.outcome {
            Outcome::Installed {
                fd, description, ..
            } => (fd, description),
            other => panic!("unexpected adoption: {other:?}"),
        };
        let lease_request = harness.request(
            Command::AcquireCapabilityLease {
                table,
                fd: open_fd,
                purpose: CapabilityLeasePurpose::MappingSource,
            },
            ObjectGeneration::INITIAL,
        );
        let lease_reply = harness
            .transact(lease_request, Vec::new())
            .expect("acquire mapping lease");
        let lease = match lease_reply.response.outcome {
            Outcome::CapabilityLeaseGranted { lease, .. } => lease,
            other => panic!("unexpected lease: {other:?}"),
        };
        assert_eq!(lease_reply.capabilities.len(), 1);
        let attachment = match harness.send(
            Command::FinalizeMappingLease {
                lease,
                disposition: MappingLeaseDisposition::Commit {
                    range: MappingRange::bounded(0x1000, 0x3000).expect("range"),
                },
            },
            ObjectGeneration::INITIAL,
        ) {
            Outcome::MappingLeaseFinalized {
                attachment: Some(attachment),
                ..
            } => attachment,
            other => panic!("unexpected mapping commit: {other:?}"),
        };
        let mut child = harness.peer(2, 1002, 1);
        let copied = match harness.send(
            Command::ForkCopyMappings {
                source_owner: harness.client,
                owner: child.client,
            },
            ObjectGeneration::INITIAL,
        ) {
            Outcome::MappingAttachmentsCopied { attachments, .. } => attachments,
            other => panic!("unexpected mapping copy: {other:?}"),
        };
        assert_eq!(copied.len(), 1);
        assert!(matches!(
            harness.send(
                Command::Close { table, fd: open_fd },
                ObjectGeneration::INITIAL,
            ),
            Outcome::Closed {
                description_reclaimed: false,
                ..
            }
        ));
        assert!(matches!(
            harness.send(
                Command::ReleaseMappingAttachment {
                    attachment,
                    release: MappingRelease::Range(
                        MappingRange::bounded(0x2000, 0x1000).expect("range"),
                    ),
                },
                ObjectGeneration::INITIAL,
            ),
            Outcome::MappingAttachmentReleased { remaining, .. }
                if remaining == vec![
                    MappingRange::bounded(0x1000, 0x1000).expect("range"),
                    MappingRange::bounded(0x3000, 0x1000).expect("range"),
                ]
        ));
        assert!(matches!(
            harness.send(
                Command::ReleaseMappingAttachment {
                    attachment,
                    release: MappingRelease::Whole,
                },
                ObjectGeneration::INITIAL,
            ),
            Outcome::MappingAttachmentReleased {
                description_reclaimed: false,
                object_reclaimed: false,
                ..
            }
        ));
        assert!(matches!(
            child.send(
                Command::ReleaseMappingAttachment {
                    attachment: copied[0],
                    release: MappingRelease::Whole,
                },
                ObjectGeneration::INITIAL,
            ),
            Outcome::MappingAttachmentReleased {
                description_reclaimed: true,
                ..
            }
        ));
        assert!(matches!(
            harness.send(
                Command::InspectDescription { description },
                ObjectGeneration::INITIAL,
            ),
            Outcome::Rejected(AuthorityError::DescriptionNotFound)
        ));
    }
}

#[test]
fn direct_and_ipc_transports_transfer_scoped_host_capability_leases() {
    host_capability_lease_model(Harness::new(), CapabilityLeaseDisposition::Commit);
    host_capability_lease_model(Harness::new_ipc(), CapabilityLeaseDisposition::Abort);
}

fn rejected_host_adoption_closes_transferred_capability(mut harness: Harness) {
    let table = harness.create_table();
    let directory = tempfile::tempdir().expect("temporary directory");
    let owned: OwnedFd = std::fs::File::open(directory.path())
        .expect("open directory")
        .into();
    let raw = owned.as_raw_fd();
    let request = harness.request(
        Command::AdoptHostFileAndInstall {
            table,
            minimum: fd(3),
            ceiling: NofileAllocationCeiling::from_captured_soft_limit(16),
            descriptor_flags: DescriptorFlags::NONE,
            access_mode: AccessMode::ReadOnly,
            status_flags: StatusFlags::default(),
            writable: false,
            path: None,
        },
        ObjectGeneration::INITIAL,
    );
    let reply = harness
        .transact(request, vec![owned])
        .expect("rejected adoption response");
    assert_eq!(
        reply.response.outcome,
        Outcome::Rejected(AuthorityError::HostBackingTypeMismatch)
    );
    assert!(reply.capabilities.is_empty());
    assert_eq!(unsafe { libc::fcntl(raw, libc::F_GETFD) }, -1);
}

#[test]
fn rejected_direct_and_ipc_adoptions_close_transferred_capabilities() {
    rejected_host_adoption_closes_transferred_capability(Harness::new());
    rejected_host_adoption_closes_transferred_capability(Harness::new_ipc());
}

fn client_exit_reclaims_owned_capability_leases(mut owner: Harness) {
    let mut observer = owner.peer(2, 1002, 1);
    let table = owner.create_table();
    let file = tempfile::tempfile().expect("temporary host file");
    let owned: OwnedFd = file.into();
    let request = owner.request(
        Command::AdoptHostFileAndInstall {
            table,
            minimum: fd(3),
            ceiling: NofileAllocationCeiling::from_captured_soft_limit(16),
            descriptor_flags: DescriptorFlags::NONE,
            access_mode: AccessMode::ReadOnly,
            status_flags: StatusFlags::default(),
            writable: false,
            path: None,
        },
        ObjectGeneration::INITIAL,
    );
    let reply = owner
        .transact(request, vec![owned])
        .expect("adopt host file");
    let (open_fd, description) = match reply.response.outcome {
        Outcome::Installed {
            fd, description, ..
        } => (fd, description),
        other => panic!("unexpected install outcome: {other:?}"),
    };
    let lease_request = owner.request(
        Command::AcquireCapabilityLease {
            table,
            fd: open_fd,
            purpose: CapabilityLeasePurpose::MappingSource,
        },
        ObjectGeneration::INITIAL,
    );
    let lease = match owner
        .transact(lease_request, Vec::new())
        .expect("lease")
        .response
        .outcome
    {
        Outcome::CapabilityLeaseGranted { lease, .. } => lease,
        other => panic!("unexpected lease outcome: {other:?}"),
    };
    assert_eq!(
        observer.send(
            Command::ReleaseCapabilityLease {
                lease,
                disposition: CapabilityLeaseDisposition::Abort,
            },
            ObjectGeneration::INITIAL,
        ),
        Outcome::Rejected(AuthorityError::CapabilityLeaseNotFound)
    );
    assert_eq!(
        owner.send(Command::ExitClient, ObjectGeneration::INITIAL),
        Outcome::ClientExited
    );
    assert_eq!(
        observer.send(
            Command::InspectDescription { description },
            ObjectGeneration::INITIAL,
        ),
        Outcome::Rejected(AuthorityError::DescriptionNotFound)
    );
}

#[test]
fn client_exit_reclaims_direct_and_ipc_capability_leases() {
    client_exit_reclaims_owned_capability_leases(Harness::new());
    client_exit_reclaims_owned_capability_leases(Harness::new_ipc());
}

#[test]
fn native_reexec_successor_endpoint_is_authenticated_and_cloexec() {
    let epoch = AuthorityEpoch::for_run(25).expect("epoch");
    let (transport, binding) =
        IpcFileAuthority::spawn_per_run(FileAuthorityCore::for_run(epoch), epoch)
            .expect("spawn per-run helper");
    let successor = transport
        .prepare_single_use_reexec_successor(0xfeed)
        .expect("prepare successor");
    assert_eq!(successor.nonce(), 0xfeed);
    for fd in [
        successor.socket_fd(),
        successor.process_lock_fd(),
        successor.lifetime_write_fd(),
    ] {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        assert!(flags >= 0 && flags & libc::FD_CLOEXEC != 0);
    }
    let successor = successor.adopt(0xfeed).expect("adopt successor");
    let request = Request {
        epoch,
        client: binding.client,
        request_id: RequestId::from_client_sequence(3).expect("request"),
        expected_generation: binding.generation,
        command: Command::ListSlots {
            table: binding.table,
            after: None,
            maximum: SlotPageLimit::bounded(1).expect("limit"),
        },
    };
    assert!(matches!(
        successor
            .execute(request)
            .expect("successor request")
            .outcome,
        Outcome::SlotPage { .. }
    ));
}

#[test]
fn inherited_helper_endpoint_serializes_cross_process_requests() {
    let epoch = AuthorityEpoch::for_run(24).expect("epoch");
    let (transport, binding) =
        IpcFileAuthority::spawn_per_run(FileAuthorityCore::for_run(epoch), epoch)
            .expect("spawn per-run helper");
    let shared = transport.clone();
    let child = unsafe { libc::fork() };
    assert!(child >= 0);
    if child == 0 {
        let request = Request {
            epoch,
            client: binding.client,
            request_id: RequestId::from_client_sequence(4).expect("request"),
            expected_generation: binding.generation,
            command: Command::ListSlots {
                table: binding.table,
                after: None,
                maximum: SlotPageLimit::bounded(1).expect("limit"),
            },
        };
        let ok = shared
            .execute(request)
            .is_ok_and(|response| matches!(response.outcome, Outcome::SlotPage { .. }));
        unsafe { libc::_exit(if ok { 0 } else { 1 }) };
    }
    let request = Request {
        epoch,
        client: binding.client,
        request_id: RequestId::from_client_sequence(3).expect("request"),
        expected_generation: binding.generation,
        command: Command::ListSlots {
            table: binding.table,
            after: None,
            maximum: SlotPageLimit::bounded(1).expect("limit"),
        },
    };
    assert!(matches!(
        transport.execute(request).expect("parent request").outcome,
        Outcome::SlotPage { .. }
    ));
    let mut status = 0;
    assert_eq!(unsafe { libc::waitpid(child, &raw mut status, 0) }, child);
    assert!(libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0);
}

#[test]
fn per_run_helper_bootstraps_authenticated_root_binding() {
    let epoch = AuthorityEpoch::for_run(23).expect("epoch");
    let (transport, binding) =
        IpcFileAuthority::spawn_per_run(FileAuthorityCore::for_run(epoch), epoch)
            .expect("spawn per-run helper");
    assert_eq!(binding.epoch, epoch);
    let request = Request {
        epoch,
        client: binding.client,
        request_id: RequestId::from_client_sequence(3).expect("request"),
        expected_generation: binding.generation,
        command: Command::ListSlots {
            table: binding.table,
            after: None,
            maximum: SlotPageLimit::bounded(1).expect("limit"),
        },
    };
    assert!(matches!(
        transport.execute(request).expect("list root table").outcome,
        Outcome::SlotPage { slots, .. } if slots.is_empty()
    ));
}

#[test]
fn ipc_authority_death_fails_closed() {
    let mut harness = Harness::new_ipc();
    harness
        .ipc
        .as_ref()
        .expect("IPC transport")
        .terminate_model_server();
    let request = harness.request(Command::CreateTable, ObjectGeneration::INITIAL);
    assert_eq!(
        harness.execute(request),
        Err(AuthorityFatal::TransportUnavailable)
    );
}

#[test]
fn authority_domains_round_trip_only_through_named_constructors() {
    let epoch = AuthorityEpoch::for_run(9).expect("epoch");
    let client_id = ClientId::for_process_client(10).expect("client");
    let request_id = RequestId::from_client_sequence(11).expect("request");
    let object = VfsObjectId::from_snapshot(12).expect("object");
    let generation = ObjectGeneration::from_snapshot(13).expect("generation");
    let descriptor_flags = DescriptorFlags::from_linux_bits(DescriptorFlags::CLOSE_ON_EXEC.raw())
        .expect("descriptor flags");
    let status_flags = StatusFlags::from_linux_bits(0x800);

    assert_eq!(epoch.raw(), 9);
    assert_eq!(client_id.raw(), 10);
    assert_eq!(request_id.raw(), 11);
    assert_eq!(object.raw(), 12);
    assert_eq!(generation.raw(), 13);
    assert!(descriptor_flags.close_on_exec());
    assert_eq!(status_flags.raw(), 0x800);
    assert_eq!(
        DescriptorFlags::from_linux_bits(2),
        Err(AuthorityError::InvalidDescriptorFlags)
    );

    let core = FileAuthorityCore::for_run(epoch);
    assert_eq!(core.epoch(), epoch);
    assert_eq!(core.revision().raw(), 0);
}

#[test]
fn direct_transport_replays_terminal_mutation_without_reapplying_it() {
    let mut harness = Harness::new();
    let request = harness.request(Command::CreateTable, ObjectGeneration::INITIAL);
    let first = harness.execute(request.clone()).expect("first request");
    let revision = harness.revision;
    let replay = harness.execute(request).expect("dedup replay");

    assert_eq!(first, replay);
    assert_eq!(harness.revision, revision);
}

#[test]
fn conflicting_duplicate_request_is_run_fatal() {
    let mut harness = Harness::new();
    let request = harness.request(Command::CreateTable, ObjectGeneration::INITIAL);
    harness.execute(request.clone()).expect("first request");
    let conflict = Request {
        command: Command::ExitClient,
        ..request
    };
    assert_eq!(
        harness.execute(conflict),
        Err(AuthorityFatal::RequestConflict)
    );
}

#[test]
fn fork_copies_slots_but_shares_authority_owned_offset_and_vfs_bytes() {
    let mut parent = Harness::new();
    let mut child = parent.peer(2, 1002, 1);
    let table = parent.create_table();
    let object = parent.create_vfs_file("/shared", b"abcdef");
    let (parent_fd, description) = parent.open_vfs(table, object, 3, false);
    let child_table = match parent.send(
        Command::ForkCopy {
            source: table,
            owner: child.client,
        },
        ObjectGeneration::INITIAL,
    ) {
        Outcome::ForkCopied { table, .. } => table,
        other => panic!("unexpected fork outcome: {other:?}"),
    };

    assert_eq!(parent.read(table, parent_fd, 3), b"abc");
    assert_eq!(child.read(child_table, parent_fd, 3), b"def");
    assert!(matches!(
        parent.send(
            Command::InspectDescription { description },
            ObjectGeneration::INITIAL,
        ),
        Outcome::Description(DescriptionSnapshot {
            logical_slot_refs: 2,
            offset,
            ..
        }) if offset.raw() == 6
    ));

    assert!(matches!(
        child.send(
            Command::Seek {
                table: child_table,
                fd: parent_fd,
                offset: -6,
                whence: SeekWhence::Current,
            },
            ObjectGeneration::INITIAL,
        ),
        Outcome::Seeked { .. }
    ));
    assert!(matches!(
        child.send(
            Command::Write {
                table: child_table,
                fd: parent_fd,
                bytes: b"XYZ".to_vec(),
            },
            ObjectGeneration::INITIAL,
        ),
        Outcome::Written { .. }
    ));
    assert!(matches!(
        parent.send(
            Command::Seek {
                table,
                fd: parent_fd,
                offset: -6,
                whence: SeekWhence::End,
            },
            ObjectGeneration::INITIAL,
        ),
        Outcome::Seeked { .. }
    ));
    assert_eq!(parent.read(table, parent_fd, 6), b"XYZdef");
}

#[test]
fn shared_table_uses_each_callers_process_domain_nofile_ceiling() {
    let mut first = Harness::new();
    let mut second = first.peer(2, 1102, 1);
    let table = first.create_table();
    assert!(matches!(
        first.send(
            Command::ShareTable {
                table,
                owner: second.client,
            },
            ObjectGeneration::INITIAL,
        ),
        Outcome::TableShared { .. }
    ));

    let rejected = first.send(
        Command::CreateSyntheticAndInstall {
            table,
            contents: b"first".to_vec(),
            minimum: fd(3),
            ceiling: NofileAllocationCeiling::from_captured_soft_limit(3),
            descriptor_flags: DescriptorFlags::NONE,
            access_mode: AccessMode::ReadWrite,
            status_flags: StatusFlags::default(),
            path: None,
        },
        ObjectGeneration::INITIAL,
    );
    assert_eq!(rejected, Outcome::Rejected(AuthorityError::NofileExceeded));

    let installed = second.send(
        Command::CreateSyntheticAndInstall {
            table,
            contents: b"second".to_vec(),
            minimum: fd(3),
            ceiling: NofileAllocationCeiling::from_captured_soft_limit(4),
            descriptor_flags: DescriptorFlags::NONE,
            access_mode: AccessMode::ReadWrite,
            status_flags: StatusFlags::default(),
            path: None,
        },
        ObjectGeneration::INITIAL,
    );
    assert!(matches!(installed, Outcome::Installed { fd: installed, .. } if installed == fd(3)));
    assert_eq!(first.read(table, fd(3), 6), b"second");
}

#[test]
fn dup_and_hardlink_preserve_distinct_slot_and_namespace_reference_domains() {
    let mut harness = Harness::new();
    let table = harness.create_table();
    let object = harness.create_vfs_file("/original", b"bytes");
    let (original_fd, description) = harness.open_vfs(table, object, 3, false);
    let duplicate_fd = match harness.send(
        Command::Dup {
            table,
            source: original_fd,
            minimum: fd(4),
            ceiling: NofileAllocationCeiling::from_captured_soft_limit(5),
            flags: DescriptorFlags::NONE,
        },
        ObjectGeneration::INITIAL,
    ) {
        Outcome::Duplicated { fd, .. } => fd,
        other => panic!("unexpected dup outcome: {other:?}"),
    };
    assert!(matches!(
        harness.send(
            Command::LinkVfs {
                object,
                path: CanonicalPath::absolute("/alias").expect("alias"),
            },
            ObjectGeneration::INITIAL,
        ),
        Outcome::VfsNamespaceChanged { object: linked, .. } if linked == object
    ));
    assert!(matches!(
        harness.send(
            Command::InspectDescription { description },
            ObjectGeneration::INITIAL,
        ),
        Outcome::Description(DescriptionSnapshot {
            logical_slot_refs: 2,
            ..
        })
    ));
    assert_eq!(harness.read(table, original_fd, 2), b"by");
    assert_eq!(harness.read(table, duplicate_fd, 3), b"tes");
    assert!(matches!(
        harness.send(
            Command::Seek {
                table,
                fd: original_fd,
                offset: 0,
                whence: SeekWhence::Start,
            },
            ObjectGeneration::INITIAL,
        ),
        Outcome::Seeked { .. }
    ));
    assert_eq!(harness.read(table, duplicate_fd, 5), b"bytes");
    assert!(matches!(
        harness.send(
            Command::ResolveVfs {
                path: CanonicalPath::absolute("/alias").expect("alias"),
            },
            ObjectGeneration::INITIAL,
        ),
        Outcome::VfsObjectResolved {
            object: resolved,
            mode: 0o644,
            ..
        } if resolved == object
    ));
}

#[test]
fn exec_successor_unshares_table_and_drops_only_cloexec_slots() {
    let mut harness = Harness::new();
    let table = harness.create_table();
    let keep = harness.create_vfs_file("/keep", b"keep");
    let drop = harness.create_vfs_file("/drop", b"drop");
    let (keep_fd, keep_description) = harness.open_vfs(table, keep, 3, false);
    let (drop_fd, drop_description) = harness.open_vfs(table, drop, 4, true);

    let successor = match harness.send(
        Command::ExecSuccessor { source: table },
        ObjectGeneration::INITIAL,
    ) {
        Outcome::ExecSucceeded {
            table,
            closed_on_exec,
            ..
        } => {
            assert_eq!(closed_on_exec, vec![drop_fd]);
            table
        }
        other => panic!("unexpected exec outcome: {other:?}"),
    };
    assert!(matches!(
        harness.send(
            Command::ResolveSlot {
                table: successor,
                fd: keep_fd,
            },
            ObjectGeneration::INITIAL,
        ),
        Outcome::Slot(_)
    ));
    assert_eq!(
        harness.send(
            Command::ResolveSlot {
                table: successor,
                fd: drop_fd,
            },
            ObjectGeneration::INITIAL,
        ),
        Outcome::Rejected(AuthorityError::SlotNotFound)
    );
    assert!(matches!(
        harness.send(
            Command::InspectDescription {
                description: keep_description,
            },
            ObjectGeneration::INITIAL,
        ),
        Outcome::Description(DescriptionSnapshot {
            logical_slot_refs: 1,
            ..
        })
    ));
    assert_eq!(
        harness.send(
            Command::InspectDescription {
                description: drop_description,
            },
            ObjectGeneration::INITIAL,
        ),
        Outcome::Rejected(AuthorityError::DescriptionNotFound)
    );
}

#[test]
fn exec_of_shared_table_leaves_other_sharers_cloexec_slots_reachable() {
    let mut harness = Harness::new();
    let mut peer = harness.peer(2, 1002, 1);
    let table = harness.create_table();
    let keep = harness.create_vfs_file("/shared-keep", b"keep");
    let drop = harness.create_vfs_file("/shared-drop", b"drop");
    let (keep_fd, keep_description) = harness.open_vfs(table, keep, 3, false);
    let (drop_fd, drop_description) = harness.open_vfs(table, drop, 4, true);
    assert!(matches!(
        harness.send(
            Command::ShareTable {
                table,
                owner: peer.client,
            },
            ObjectGeneration::INITIAL,
        ),
        Outcome::TableShared { .. }
    ));

    let successor = match harness.send(
        Command::ExecSuccessor { source: table },
        ObjectGeneration::INITIAL,
    ) {
        Outcome::ExecSucceeded { table, .. } => table,
        other => panic!("unexpected exec outcome: {other:?}"),
    };
    assert_eq!(
        harness.send(
            Command::ResolveSlot { table, fd: keep_fd },
            ObjectGeneration::INITIAL,
        ),
        Outcome::Rejected(AuthorityError::TableNotBound)
    );
    for fd in [keep_fd, drop_fd] {
        assert!(matches!(
            peer.send(
                Command::ResolveSlot { table, fd },
                ObjectGeneration::INITIAL,
            ),
            Outcome::Slot(_)
        ));
    }
    assert!(matches!(
        harness.send(
            Command::ResolveSlot {
                table: successor,
                fd: keep_fd,
            },
            ObjectGeneration::INITIAL,
        ),
        Outcome::Slot(_)
    ));
    assert_eq!(
        harness.send(
            Command::ResolveSlot {
                table: successor,
                fd: drop_fd,
            },
            ObjectGeneration::INITIAL,
        ),
        Outcome::Rejected(AuthorityError::SlotNotFound)
    );
    assert!(matches!(
        peer.send(
            Command::InspectDescription {
                description: keep_description,
            },
            ObjectGeneration::INITIAL,
        ),
        Outcome::Description(DescriptionSnapshot {
            logical_slot_refs: 2,
            ..
        })
    ));
    assert!(matches!(
        peer.send(
            Command::InspectDescription {
                description: drop_description,
            },
            ObjectGeneration::INITIAL,
        ),
        Outcome::Description(DescriptionSnapshot {
            logical_slot_refs: 1,
            ..
        })
    ));
}

#[test]
fn exiting_one_shared_table_client_preserves_slots_for_the_other() {
    let mut harness = Harness::new();
    let mut peer = harness.peer(2, 1002, 1);
    let table = harness.create_table();
    let object = harness.create_vfs_file("/exit-shared", b"payload");
    let (open_fd, description) = harness.open_vfs(table, object, 3, false);
    assert!(matches!(
        harness.send(
            Command::ShareTable {
                table,
                owner: peer.client,
            },
            ObjectGeneration::INITIAL,
        ),
        Outcome::TableShared { .. }
    ));
    assert_eq!(
        harness.send(Command::ExitClient, ObjectGeneration::INITIAL),
        Outcome::ClientExited
    );

    assert!(matches!(
        peer.send(
            Command::ResolveSlot { table, fd: open_fd },
            ObjectGeneration::INITIAL,
        ),
        Outcome::Slot(_)
    ));
    assert!(matches!(
        peer.send(
            Command::InspectDescription { description },
            ObjectGeneration::INITIAL,
        ),
        Outcome::Description(DescriptionSnapshot {
            logical_slot_refs: 1,
            ..
        })
    ));
    assert!(matches!(
        peer.send(
            Command::Close { table, fd: open_fd },
            ObjectGeneration::INITIAL,
        ),
        Outcome::Closed {
            description_reclaimed: true,
            ..
        }
    ));
}

#[test]
fn unlink_keeps_open_vfs_object_alive_until_last_description_closes() {
    let mut harness = Harness::new();
    let table = harness.create_table();
    let object = harness.create_vfs_file("/live", b"payload");
    let (open_fd, description) = harness.open_vfs(table, object, 3, false);

    assert!(matches!(
        harness.send(
            Command::UnlinkVfs {
                path: CanonicalPath::absolute("/live").expect("path"),
            },
            ObjectGeneration::INITIAL,
        ),
        Outcome::VfsNamespaceChanged {
            object_reclaimed: false,
            ..
        }
    ));
    assert_eq!(
        harness.send(
            Command::ResolveVfs {
                path: CanonicalPath::absolute("/live").expect("path"),
            },
            ObjectGeneration::INITIAL,
        ),
        Outcome::Rejected(AuthorityError::VfsNotFound)
    );
    assert_eq!(harness.read(table, open_fd, 7), b"payload");
    assert!(matches!(
        harness.send(
            Command::Close { table, fd: open_fd },
            ObjectGeneration::INITIAL,
        ),
        Outcome::Closed {
            description: closed,
            description_reclaimed: true,
            object_reclaimed: true,
            ..
        } if closed == description
    ));
}

#[test]
fn rename_replaces_namespace_target_without_destroying_open_target() {
    let mut harness = Harness::new();
    let table = harness.create_table();
    let source = harness.create_vfs_file("/source", b"source");
    let target = harness.create_vfs_file("/target", b"target");
    let (target_fd, _) = harness.open_vfs(table, target, 3, false);

    assert!(matches!(
        harness.send(
            Command::RenameVfs {
                from: CanonicalPath::absolute("/source").expect("source"),
                to: CanonicalPath::absolute("/target").expect("target"),
            },
            ObjectGeneration::INITIAL,
        ),
        Outcome::VfsNamespaceChanged { object, .. } if object == source
    ));
    assert_eq!(harness.read(table, target_fd, 6), b"target");
    assert!(matches!(
        harness.send(
            Command::ResolveVfs {
                path: CanonicalPath::absolute("/target").expect("target"),
            },
            ObjectGeneration::INITIAL,
        ),
        Outcome::VfsObjectResolved { object, .. } if object == source
    ));
}

#[test]
fn rename_between_hardlinks_to_the_same_object_is_a_noop() {
    let mut harness = Harness::new();
    let object = harness.create_vfs_file("/first-link", b"payload");
    assert!(matches!(
        harness.send(
            Command::LinkVfs {
                object,
                path: CanonicalPath::absolute("/second-link").expect("second link"),
            },
            ObjectGeneration::INITIAL,
        ),
        Outcome::VfsNamespaceChanged { .. }
    ));
    let revision = harness.revision;
    assert!(matches!(
        harness.send(
            Command::RenameVfs {
                from: CanonicalPath::absolute("/first-link").expect("first link"),
                to: CanonicalPath::absolute("/second-link").expect("second link"),
            },
            ObjectGeneration::INITIAL,
        ),
        Outcome::VfsNamespaceChanged {
            object: renamed,
            namespace_revision,
            object_reclaimed: false,
        } if renamed == object && namespace_revision == revision
    ));
    assert_eq!(harness.revision, revision);
    for path in ["/first-link", "/second-link"] {
        assert!(matches!(
            harness.send(
                Command::ResolveVfs {
                    path: CanonicalPath::absolute(path).expect("hard link"),
                },
                ObjectGeneration::INITIAL,
            ),
            Outcome::VfsObjectResolved { object: resolved, .. } if resolved == object
        ));
    }
}

#[test]
fn access_modes_reject_disallowed_io_without_publishing_a_revision() {
    let mut harness = Harness::new();
    let table = harness.create_table();
    let object = harness.create_vfs_file("/access", b"payload");
    let (read_only, _) = harness.open_vfs_with_mode(table, object, 3, false, AccessMode::ReadOnly);
    let (write_only, _) =
        harness.open_vfs_with_mode(table, object, 4, false, AccessMode::WriteOnly);
    let (path_only, _) = harness.open_vfs_with_mode(table, object, 5, false, AccessMode::PathOnly);
    let revision = harness.revision;

    assert_eq!(
        harness.send(
            Command::Write {
                table,
                fd: read_only,
                bytes: b"x".to_vec(),
            },
            ObjectGeneration::INITIAL,
        ),
        Outcome::Rejected(AuthorityError::NotWritable)
    );
    assert_eq!(
        harness.send(
            Command::Read {
                table,
                fd: write_only,
                maximum: ByteCount::bounded(1).expect("bounded read"),
            },
            ObjectGeneration::INITIAL,
        ),
        Outcome::Rejected(AuthorityError::NotReadable)
    );
    assert_eq!(
        harness.send(
            Command::Seek {
                table,
                fd: path_only,
                offset: 0,
                whence: SeekWhence::Start,
            },
            ObjectGeneration::INITIAL,
        ),
        Outcome::Rejected(AuthorityError::NotSeekable)
    );
    assert_eq!(harness.revision, revision);
}

#[test]
fn serialized_client_requests_replace_prior_dedup_entries() {
    let mut harness = Harness::new();
    let missing = CanonicalPath::absolute("/missing").expect("canonical path");
    for _ in 0..(super::core::MAX_TERMINAL_DEDUP_ENTRIES + 1) {
        assert_eq!(
            harness.send(
                Command::ResolveVfs {
                    path: missing.clone(),
                },
                ObjectGeneration::INITIAL,
            ),
            Outcome::Rejected(AuthorityError::VfsNotFound)
        );
    }

    let old = Request {
        epoch: harness.epoch,
        client: harness.client,
        request_id: RequestId::from_client_sequence(1).expect("old request id"),
        expected_generation: ObjectGeneration::INITIAL,
        command: Command::RegisterClient,
    };
    assert_eq!(harness.execute(old), Err(AuthorityFatal::RequestOutOfOrder));
}

#[test]
fn canonical_paths_reject_ambiguous_spellings() {
    for invalid in [
        "relative",
        "/trailing/",
        "/double//slash",
        "/dot/./name",
        "/up/../name",
    ] {
        assert_eq!(
            CanonicalPath::absolute(invalid),
            Err(AuthorityError::InvalidCanonicalPath)
        );
    }
    assert_eq!(CanonicalPath::absolute("/").expect("root").as_str(), "/");
}
