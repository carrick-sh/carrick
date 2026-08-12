use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::num::{NonZeroU32, NonZeroU64};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use carrick_abi::LinuxEpollEvents;

use crate::kernel::ObjectIdRegistry;

use super::backing::AuthorityBacking;
use super::epoll::{EpollState, ReadinessSnapshot};
use super::stream::PipeStreamState;
use super::types::{
    AccessMode, AuthorityCall, AuthorityEpoch, AuthorityError, AuthorityFatal, AuthorityReply,
    ByteCount, CanonicalPath, CapabilityLeaseDisposition, CapabilityLeaseId,
    CapabilityLeasePurpose, ClientId, ClientIdentity, Command, DescriptionSnapshot,
    DescriptorFlags, EpollEventLimit, EpollHostPlan, EpollHostPlanAction, EpollInterestKey,
    EpollRegistration, FileDescriptionId, FileOffset, FileSlotNumber, FileTableId, HostErrno,
    HostStreamKind, InterestGeneration, MappingAttachmentId, MappingLeaseDisposition, MappingRange,
    MappingRelease, NofileAllocationCeiling, ObjectGeneration, Outcome, PipeCapacity, PipeEnd,
    PipeId, Request, Response, Revision, SameSlotBehavior, SeekWhence, SlotPageLimit,
    SlotRangeAction, SlotSnapshot, StatusFlags, VfsObjectId,
};

pub(super) const MAX_TERMINAL_DEDUP_ENTRIES: usize = 8_192;

#[derive(Debug, Clone)]
struct FileSlotState {
    description: FileDescriptionId,
    description_generation: ObjectGeneration,
    flags: DescriptorFlags,
    path: Option<CanonicalPath>,
}

impl FileSlotState {
    fn snapshot(&self, fd: FileSlotNumber) -> SlotSnapshot {
        SlotSnapshot {
            fd,
            description: self.description,
            description_generation: self.description_generation,
            flags: self.flags,
            path: self.path.clone(),
        }
    }
}

#[derive(Debug)]
struct FileTableState {
    generation: ObjectGeneration,
    revision: Revision,
    slots: BTreeMap<FileSlotNumber, FileSlotState>,
    bindings: HashSet<ClientIdentity>,
}

#[derive(Debug)]
struct FileDescriptionState {
    generation: ObjectGeneration,
    revision: Revision,
    /// Reachable fd-table slots across every table, not transient operations,
    /// client bindings, namespace links, or Rust ownership handles.
    logical_slot_refs: u64,
    capability_lease_refs: u64,
    offset: FileOffset,
    access_mode: AccessMode,
    status_flags: StatusFlags,
    readiness: ReadinessSnapshot,
    backing: AuthorityBacking,
}

impl FileDescriptionState {
    fn snapshot(&self, description: FileDescriptionId) -> DescriptionSnapshot {
        DescriptionSnapshot {
            description,
            generation: self.generation,
            revision: self.revision,
            offset: self.offset,
            access_mode: self.access_mode,
            status_flags: self.status_flags,
            logical_slot_refs: self.logical_slot_refs,
            backing: self.backing.snapshot(),
        }
    }
}

#[derive(Debug)]
struct VfsObjectState {
    generation: ObjectGeneration,
    revision: Revision,
    mode: u32,
    contents: Vec<u8>,
    /// Namespace directory entries that name this object.
    namespace_links: u64,
    /// Open descriptions backed by this object. Dup/fork slots are counted in
    /// each description's `logical_slot_refs`, not again here.
    open_description_refs: u64,
}

#[derive(Debug, Clone)]
struct TerminalDedupEntry {
    request: Request,
    response: Response,
}

#[derive(Debug)]
struct CapabilityLeaseState {
    owner: ClientIdentity,
    description: FileDescriptionId,
    description_generation: ObjectGeneration,
    purpose: CapabilityLeasePurpose,
}

#[derive(Debug)]
struct MappingAttachmentState {
    owner: ClientIdentity,
    description: FileDescriptionId,
    ranges: Vec<MappingRange>,
}

/// One run's mutable file and writable-memory-VFS authority.
///
/// `execute` is the sole mutation boundary used by both direct and IPC
/// transports. It owns actual bytes and offsets, not a metadata mirror.
#[derive(Debug)]
pub(crate) struct FileAuthorityCore {
    epoch: AuthorityEpoch,
    ids: ObjectIdRegistry,
    next_vfs_object: u64,
    next_capability_lease: u64,
    next_mapping_attachment: u64,
    next_interest_generation: u32,
    next_pipe: u64,
    revision: Revision,
    namespace_revision: Revision,
    clients: HashMap<ClientId, ClientIdentity>,
    tables: BTreeMap<FileTableId, FileTableState>,
    descriptions: BTreeMap<FileDescriptionId, FileDescriptionState>,
    namespace: BTreeMap<CanonicalPath, VfsObjectId>,
    vfs_objects: BTreeMap<VfsObjectId, VfsObjectState>,
    capability_leases: BTreeMap<CapabilityLeaseId, CapabilityLeaseState>,
    mapping_attachments: BTreeMap<MappingAttachmentId, MappingAttachmentState>,
    epoll_watchers: BTreeMap<FileDescriptionId, BTreeSet<(FileDescriptionId, EpollInterestKey)>>,
    streams: BTreeMap<PipeId, PipeStreamState>,
    stream_revisions: BTreeMap<PipeId, Revision>,
    // Each authenticated client may have exactly one outstanding request. A
    // later request from that client therefore acknowledges the prior terminal
    // response and replaces this entry; a same-id retry replays it verbatim.
    dedup: HashMap<ClientIdentity, TerminalDedupEntry>,
}

impl FileAuthorityCore {
    pub(crate) fn for_run(epoch: AuthorityEpoch) -> Self {
        Self {
            epoch,
            ids: ObjectIdRegistry::new(),
            next_vfs_object: 1,
            next_capability_lease: 1,
            next_mapping_attachment: 1,
            next_interest_generation: 1,
            next_pipe: 1,
            revision: Revision::ZERO,
            namespace_revision: Revision::ZERO,
            clients: HashMap::new(),
            tables: BTreeMap::new(),
            descriptions: BTreeMap::new(),
            namespace: BTreeMap::new(),
            vfs_objects: BTreeMap::new(),
            capability_leases: BTreeMap::new(),
            mapping_attachments: BTreeMap::new(),
            epoll_watchers: BTreeMap::new(),
            streams: BTreeMap::new(),
            stream_revisions: BTreeMap::new(),
            dedup: HashMap::new(),
        }
    }

    pub(crate) const fn epoch(&self) -> AuthorityEpoch {
        self.epoch
    }

    pub(crate) const fn revision(&self) -> Revision {
        self.revision
    }

    pub(crate) fn execute_call(
        &mut self,
        mut call: AuthorityCall,
    ) -> Result<AuthorityReply, AuthorityFatal> {
        if call.capabilities.len() != expected_request_capabilities(&call.request.command) {
            return Err(AuthorityFatal::CapabilityMismatch);
        }
        for capability in &call.capabilities {
            ensure_cloexec(capability.as_raw_fd())?;
        }
        let response = self.execute_record(call.request, &mut call.capabilities)?;
        if !call.capabilities.is_empty() {
            return Err(AuthorityFatal::InvariantViolation(
                "fresh authority request left inbound capabilities unconsumed",
            ));
        }
        let capabilities = self.materialize_response_capabilities(&response)?;
        Ok(AuthorityReply {
            response,
            capabilities,
        })
    }

    fn materialize_response_capabilities(
        &self,
        response: &Response,
    ) -> Result<Vec<OwnedFd>, AuthorityFatal> {
        let Outcome::CapabilityLeaseGranted {
            lease,
            description,
            description_generation,
            purpose,
            ..
        } = &response.outcome
        else {
            return Ok(Vec::new());
        };
        let lease_state =
            self.capability_leases
                .get(lease)
                .ok_or(AuthorityFatal::InvariantViolation(
                    "terminal response referenced a missing lease",
                ))?;
        if lease_state.description != *description
            || lease_state.description_generation != *description_generation
            || lease_state.purpose != *purpose
        {
            return Err(AuthorityFatal::InvariantViolation(
                "terminal response disagreed with its capability lease",
            ));
        }
        let fd = self
            .descriptions
            .get(description)
            .and_then(|state| state.backing.host_fd(*purpose))
            .ok_or(AuthorityFatal::InvariantViolation(
                "capability lease lost its host descriptor backing",
            ))?;
        let duplicated = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
        if duplicated < 0 {
            return Err(AuthorityFatal::TransportUnavailable);
        }
        Ok(vec![unsafe { OwnedFd::from_raw_fd(duplicated) }])
    }

    fn execute_record(
        &mut self,
        request: Request,
        capabilities: &mut Vec<OwnedFd>,
    ) -> Result<Response, AuthorityFatal> {
        if request.epoch != self.epoch {
            capabilities.clear();
            return Ok(Response {
                request_id: request.request_id,
                authority_revision: self.revision,
                outcome: Outcome::Rejected(AuthorityError::StaleEpoch {
                    expected: self.epoch,
                    actual: request.epoch,
                }),
            });
        }
        if let Some(prior) = self.dedup.get(&request.client) {
            if prior.request.request_id == request.request_id {
                if prior.request == request {
                    capabilities.clear();
                    return Ok(prior.response.clone());
                }
                return Err(AuthorityFatal::RequestConflict);
            }
            if request.request_id < prior.request.request_id {
                return Err(AuthorityFatal::RequestOutOfOrder);
            }
        }
        let replaces_retired_generation = matches!(request.command, Command::RegisterClient)
            && self
                .dedup
                .keys()
                .any(|identity| identity.id == request.client.id);
        if !self.dedup.contains_key(&request.client)
            && !replaces_retired_generation
            && self.dedup.len() >= MAX_TERMINAL_DEDUP_ENTRIES
        {
            return Err(AuthorityFatal::DedupExhausted);
        }

        let outcome = match self.execute_fresh(&request, capabilities) {
            Ok(outcome) => outcome,
            Err(error) => Outcome::Rejected(error),
        };
        // Rejections and duplicate terminal requests must close any transferred
        // rights that the operation did not adopt.
        capabilities.clear();
        self.finish(request, outcome)
    }

    fn finish(&mut self, request: Request, outcome: Outcome) -> Result<Response, AuthorityFatal> {
        let response = Response {
            request_id: request.request_id,
            authority_revision: self.revision,
            outcome,
        };
        if matches!(request.command, Command::RegisterClient) {
            self.dedup
                .retain(|identity, _| identity.id != request.client.id);
        }
        self.dedup.insert(
            request.client,
            TerminalDedupEntry {
                request,
                response: response.clone(),
            },
        );
        Ok(response)
    }

    fn execute_fresh(
        &mut self,
        request: &Request,
        capabilities: &mut Vec<OwnedFd>,
    ) -> Result<Outcome, AuthorityError> {
        match &request.command {
            Command::RegisterClient => self.register_client(request),
            _ => {
                self.require_registered(request.client)?;
                match &request.command {
                    Command::RegisterClient => unreachable!(),
                    Command::ExitClient => self.exit_client(request.client),
                    Command::CreateTable => self.create_table(request.client),
                    Command::CreatePipeAndInstall {
                        table,
                        minimum,
                        ceiling,
                        descriptor_flags,
                        status_flags,
                        capacity,
                    } => self.create_pipe_and_install(
                        request.client,
                        *table,
                        request.expected_generation,
                        *minimum,
                        *ceiling,
                        *descriptor_flags,
                        *status_flags,
                        *capacity,
                    ),
                    Command::SetPipeCapacity {
                        table,
                        fd,
                        capacity,
                    } => self.set_pipe_capacity(
                        request.client,
                        *table,
                        request.expected_generation,
                        *fd,
                        *capacity,
                    ),
                    Command::CreateEpollAndInstall {
                        table,
                        minimum,
                        ceiling,
                        descriptor_flags,
                    } => self.create_epoll_and_install(
                        request.client,
                        *table,
                        request.expected_generation,
                        *minimum,
                        *ceiling,
                        *descriptor_flags,
                    ),
                    Command::CreateTimerAndInstall {
                        table,
                        minimum,
                        ceiling,
                        descriptor_flags,
                        status_flags,
                    } => self.create_timer_and_install(
                        request.client,
                        *table,
                        request.expected_generation,
                        *minimum,
                        *ceiling,
                        *descriptor_flags,
                        *status_flags,
                    ),
                    Command::SetTimer {
                        table,
                        fd,
                        interval_ns,
                        initial_ns,
                    } => self.set_timer(
                        request.client,
                        *table,
                        request.expected_generation,
                        *fd,
                        *interval_ns,
                        *initial_ns,
                    ),
                    Command::ExpireTimer {
                        table,
                        fd,
                        expirations,
                    } => self.expire_timer(
                        request.client,
                        *table,
                        request.expected_generation,
                        *fd,
                        *expirations,
                    ),
                    Command::CreateEventCounterAndInstall {
                        table,
                        initial,
                        semaphore,
                        minimum,
                        ceiling,
                        descriptor_flags,
                        status_flags,
                    } => self.create_event_counter_and_install(
                        request.client,
                        *table,
                        request.expected_generation,
                        *initial,
                        *semaphore,
                        *minimum,
                        *ceiling,
                        *descriptor_flags,
                        *status_flags,
                    ),
                    Command::CreateVfsFile {
                        path,
                        mode,
                        contents,
                    } => self.create_vfs_file(
                        path.clone(),
                        *mode,
                        contents.clone(),
                        request.expected_generation,
                    ),
                    Command::ResolveVfs { path } => self.resolve_vfs(path),
                    Command::LinkVfs { object, path } => {
                        self.link_vfs(*object, path.clone(), request.expected_generation)
                    }
                    Command::UnlinkVfs { path } => self.unlink_vfs(path),
                    Command::RenameVfs { from, to } => self.rename_vfs(from, to.clone()),
                    Command::OpenVfsAndInstall {
                        table,
                        object,
                        object_generation,
                        minimum,
                        ceiling,
                        descriptor_flags,
                        access_mode,
                        status_flags,
                        path,
                    } => self.open_vfs_and_install(
                        request.client,
                        *table,
                        request.expected_generation,
                        *object,
                        *object_generation,
                        *minimum,
                        *ceiling,
                        *descriptor_flags,
                        *access_mode,
                        *status_flags,
                        path.clone(),
                    ),
                    Command::CreateSyntheticAndInstall {
                        table,
                        contents,
                        minimum,
                        ceiling,
                        descriptor_flags,
                        access_mode,
                        status_flags,
                        path,
                    } => self.create_synthetic_and_install(
                        request.client,
                        *table,
                        request.expected_generation,
                        contents.clone(),
                        *minimum,
                        *ceiling,
                        *descriptor_flags,
                        *access_mode,
                        *status_flags,
                        path.clone(),
                    ),
                    Command::AdoptHostStreamAndInstall {
                        table,
                        minimum,
                        ceiling,
                        descriptor_flags,
                        access_mode,
                        status_flags,
                        kind,
                        path,
                    } => self.adopt_host_stream_and_install(
                        request.client,
                        *table,
                        request.expected_generation,
                        *minimum,
                        *ceiling,
                        *descriptor_flags,
                        *access_mode,
                        *status_flags,
                        *kind,
                        path.clone(),
                        capabilities,
                    ),
                    Command::AdoptIoUringAndInstall {
                        table,
                        minimum,
                        ceiling,
                        descriptor_flags,
                        status_flags,
                        entries,
                        data_length,
                    } => self.adopt_io_uring_and_install(
                        request.client,
                        *table,
                        request.expected_generation,
                        *minimum,
                        *ceiling,
                        *descriptor_flags,
                        *status_flags,
                        *entries,
                        *data_length,
                        capabilities,
                    ),
                    Command::AdoptHostFileAndInstall {
                        table,
                        minimum,
                        ceiling,
                        descriptor_flags,
                        access_mode,
                        status_flags,
                        writable,
                        path,
                    } => self.adopt_host_file_and_install(
                        request.client,
                        *table,
                        request.expected_generation,
                        *minimum,
                        *ceiling,
                        *descriptor_flags,
                        *access_mode,
                        *status_flags,
                        *writable,
                        path.clone(),
                        capabilities,
                    ),
                    Command::AcquireCapabilityLease { table, fd, purpose } => self
                        .acquire_capability_lease(
                            request.client,
                            *table,
                            request.expected_generation,
                            *fd,
                            *purpose,
                        ),
                    Command::ReleaseCapabilityLease { lease, disposition } => {
                        self.release_capability_lease(request.client, *lease, *disposition)
                    }
                    Command::FinalizeMappingLease { lease, disposition } => {
                        self.finalize_mapping_lease(request.client, *lease, *disposition)
                    }
                    Command::ReleaseMappingAttachment {
                        attachment,
                        release,
                    } => self.release_mapping_attachment(request.client, *attachment, *release),
                    Command::ResolveSlot { table, fd } => {
                        self.resolve_slot(request.client, *table, request.expected_generation, *fd)
                    }
                    Command::ListSlots {
                        table,
                        after,
                        maximum,
                    } => self.list_slots(
                        request.client,
                        *table,
                        request.expected_generation,
                        *after,
                        *maximum,
                    ),
                    Command::SetDescriptorFlags { table, fd, flags } => self.set_descriptor_flags(
                        request.client,
                        *table,
                        request.expected_generation,
                        *fd,
                        *flags,
                    ),
                    Command::ReplaceSlot {
                        table,
                        source,
                        target,
                        ceiling,
                        flags,
                        same_slot,
                    } => self.replace_slot(
                        request.client,
                        *table,
                        request.expected_generation,
                        *source,
                        *target,
                        *ceiling,
                        *flags,
                        *same_slot,
                    ),
                    Command::MutateSlotRange {
                        table,
                        first,
                        last,
                        action,
                    } => self.mutate_slot_range(
                        request.client,
                        *table,
                        request.expected_generation,
                        *first,
                        *last,
                        *action,
                    ),
                    Command::EpollCtlAdd {
                        table,
                        epoll_fd,
                        target_fd,
                        registration,
                    } => self.epoll_ctl_add(
                        request.client,
                        *table,
                        request.expected_generation,
                        *epoll_fd,
                        *target_fd,
                        *registration,
                    ),
                    Command::EpollCtlModify {
                        table,
                        epoll_fd,
                        target_fd,
                        registration,
                    } => self.epoll_ctl_modify(
                        request.client,
                        *table,
                        request.expected_generation,
                        *epoll_fd,
                        *target_fd,
                        *registration,
                    ),
                    Command::EpollCtlDelete {
                        table,
                        epoll_fd,
                        target_fd,
                    } => self.epoll_ctl_delete(
                        request.client,
                        *table,
                        request.expected_generation,
                        *epoll_fd,
                        *target_fd,
                    ),
                    Command::EpollRevalidateHostPlan { plan } => {
                        self.epoll_revalidate_host_plan(*plan)
                    }
                    Command::ObserveReadiness {
                        table,
                        fd,
                        ready,
                        read_available,
                    } => self.observe_readiness(
                        request.client,
                        *table,
                        request.expected_generation,
                        *fd,
                        *ready,
                        *read_available,
                    ),
                    Command::EpollCollect {
                        table,
                        epoll_fd,
                        maximum,
                    } => self.epoll_collect(
                        request.client,
                        *table,
                        request.expected_generation,
                        *epoll_fd,
                        *maximum,
                    ),
                    Command::EpollAcknowledgeIo {
                        table,
                        fd,
                        consumed,
                        read_available,
                        write_backpressured,
                    } => self.epoll_acknowledge_io(
                        request.client,
                        *table,
                        request.expected_generation,
                        *fd,
                        *consumed,
                        *read_available,
                        *write_backpressured,
                    ),
                    Command::EventCounterRead { table, fd } => self.event_counter_read(
                        request.client,
                        *table,
                        request.expected_generation,
                        *fd,
                    ),
                    Command::EventCounterWrite { table, fd, value } => self.event_counter_write(
                        request.client,
                        *table,
                        request.expected_generation,
                        *fd,
                        *value,
                    ),
                    Command::Read { table, fd, maximum } => self.read(
                        request.client,
                        *table,
                        request.expected_generation,
                        *fd,
                        *maximum,
                    ),
                    Command::Write { table, fd, bytes } => self.write(
                        request.client,
                        *table,
                        request.expected_generation,
                        *fd,
                        bytes,
                    ),
                    Command::Seek {
                        table,
                        fd,
                        offset,
                        whence,
                    } => self.seek(
                        request.client,
                        *table,
                        request.expected_generation,
                        *fd,
                        *offset,
                        *whence,
                    ),
                    Command::Close { table, fd } => {
                        self.close(request.client, *table, request.expected_generation, *fd)
                    }
                    Command::Dup {
                        table,
                        source,
                        minimum,
                        ceiling,
                        flags,
                    } => self.duplicate(
                        request.client,
                        *table,
                        request.expected_generation,
                        *source,
                        *minimum,
                        *ceiling,
                        *flags,
                    ),
                    Command::ForkCopy { source, owner } => {
                        self.fork_copy(request.client, *source, request.expected_generation, *owner)
                    }
                    Command::ForkCopyMappings {
                        source_owner,
                        owner,
                    } => self.fork_copy_mappings(request.client, *source_owner, *owner),
                    Command::ShareTable { table, owner } => self.share_table(
                        request.client,
                        *table,
                        request.expected_generation,
                        *owner,
                    ),
                    Command::ExecSuccessor { source } => {
                        self.exec_successor(request.client, *source, request.expected_generation)
                    }
                    Command::InspectDescription { description } => {
                        self.inspect_description(*description, request.expected_generation)
                    }
                }
            }
        }
    }

    fn register_client(&mut self, request: &Request) -> Result<Outcome, AuthorityError> {
        if request.expected_generation != ObjectGeneration::INITIAL {
            return Err(AuthorityError::StaleObjectGeneration);
        }
        match self.clients.get(&request.client.id) {
            Some(existing) if *existing == request.client => {
                Err(AuthorityError::ClientAlreadyRegistered)
            }
            Some(_) => Err(AuthorityError::StaleClientGeneration),
            None => {
                self.publish_mutation();
                self.clients.insert(request.client.id, request.client);
                Ok(Outcome::ClientRegistered)
            }
        }
    }

    fn require_registered(&self, identity: ClientIdentity) -> Result<(), AuthorityError> {
        match self.clients.get(&identity.id) {
            Some(current) if *current == identity => Ok(()),
            Some(_) => Err(AuthorityError::StaleClientGeneration),
            None => Err(AuthorityError::ClientNotRegistered),
        }
    }

    fn exit_client(&mut self, identity: ClientIdentity) -> Result<Outcome, AuthorityError> {
        let affected: Vec<FileTableId> = self
            .tables
            .iter()
            .filter_map(|(table_id, table)| table.bindings.contains(&identity).then_some(*table_id))
            .collect();
        let drop_tables: Vec<FileTableId> = affected
            .iter()
            .copied()
            .filter(|table_id| {
                self.tables
                    .get(table_id)
                    .is_some_and(|table| table.bindings.len() == 1)
            })
            .collect();
        let owned_leases: Vec<CapabilityLeaseId> = self
            .capability_leases
            .iter()
            .filter_map(|(lease, state)| (state.owner == identity).then_some(*lease))
            .collect();
        let owned_attachments: Vec<MappingAttachmentId> = self
            .mapping_attachments
            .iter()
            .filter_map(|(attachment, state)| (state.owner == identity).then_some(*attachment))
            .collect();
        let revision = self.publish_mutation();
        for table_id in &affected {
            let table = self.tables.get_mut(table_id).unwrap_or_else(|| {
                abort_fatal(AuthorityFatal::InvariantViolation(
                    "client exit lost an affected file table",
                ))
            });
            table.bindings.remove(&identity);
            table.revision = revision;
        }
        let mut released = Vec::new();
        for table_id in drop_tables {
            let table = self.tables.remove(&table_id).unwrap_or_else(|| {
                abort_fatal(AuthorityFatal::InvariantViolation(
                    "client exit lost an unbound file table",
                ))
            });
            released.extend(table.slots.into_values().map(|slot| slot.description));
        }
        for description in released {
            self.release_description_ref(description, revision);
        }
        for lease in owned_leases {
            let state = self.capability_leases.remove(&lease).unwrap_or_else(|| {
                abort_fatal(AuthorityFatal::InvariantViolation(
                    "client exit lost an owned capability lease",
                ))
            });
            self.release_capability_lease_ref(state.description, revision);
        }
        for attachment in owned_attachments {
            let state = self
                .mapping_attachments
                .remove(&attachment)
                .unwrap_or_else(|| {
                    abort_fatal(AuthorityFatal::InvariantViolation(
                        "client exit lost an owned mapping attachment",
                    ))
                });
            self.release_capability_lease_ref(state.description, revision);
        }
        self.clients.remove(&identity.id);
        Ok(Outcome::ClientExited)
    }

    fn create_table(&mut self, owner: ClientIdentity) -> Result<Outcome, AuthorityError> {
        let table = self.allocate_table();
        let revision = self.publish_mutation();
        self.tables.insert(
            table,
            FileTableState {
                generation: ObjectGeneration::INITIAL,
                revision,
                slots: BTreeMap::new(),
                bindings: HashSet::from([owner]),
            },
        );
        Ok(Outcome::TableCreated {
            table,
            generation: ObjectGeneration::INITIAL,
            revision,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn create_pipe_and_install(
        &mut self,
        client: ClientIdentity,
        table: FileTableId,
        table_generation: ObjectGeneration,
        minimum: FileSlotNumber,
        ceiling: NofileAllocationCeiling,
        descriptor_flags: DescriptorFlags,
        status_flags: StatusFlags,
        capacity: PipeCapacity,
    ) -> Result<Outcome, AuthorityError> {
        self.require_bound_table(client, table, table_generation)?;
        let (read_fd, write_fd) = self.allocate_pair(table, minimum, ceiling)?;
        let pipe = self.allocate_pipe();
        let read_description = self.allocate_description();
        let write_description = self.allocate_description();
        let revision = self.publish_mutation();
        self.streams.insert(pipe, PipeStreamState::new(capacity));
        self.stream_revisions.insert(pipe, revision);
        for (description, end, access_mode) in [
            (read_description, PipeEnd::Reader, AccessMode::ReadOnly),
            (write_description, PipeEnd::Writer, AccessMode::WriteOnly),
        ] {
            self.descriptions.insert(
                description,
                FileDescriptionState {
                    generation: ObjectGeneration::INITIAL,
                    revision,
                    logical_slot_refs: 1,
                    capability_lease_refs: 0,
                    offset: FileOffset::default(),
                    access_mode,
                    status_flags,
                    readiness: self.pipe_readiness(pipe, end),
                    backing: AuthorityBacking::PipeEnd { pipe, end },
                },
            );
        }
        let table_state = self.tables.get_mut(&table).unwrap_or_else(|| {
            abort_fatal(AuthorityFatal::InvariantViolation(
                "pipe creation lost its validated file table",
            ))
        });
        for (fd, description) in [(read_fd, read_description), (write_fd, write_description)] {
            table_state.slots.insert(
                fd,
                FileSlotState {
                    description,
                    description_generation: ObjectGeneration::INITIAL,
                    flags: descriptor_flags,
                    path: None,
                },
            );
        }
        table_state.revision = revision;
        Ok(Outcome::PipeCreated {
            table,
            pipe,
            read_fd,
            write_fd,
            read_description,
            write_description,
            generation: ObjectGeneration::INITIAL,
            table_revision: revision,
            stream_revision: revision,
        })
    }

    fn set_pipe_capacity(
        &mut self,
        client: ClientIdentity,
        table: FileTableId,
        expected: ObjectGeneration,
        fd: FileSlotNumber,
        capacity: PipeCapacity,
    ) -> Result<Outcome, AuthorityError> {
        let (pipe, _) = self.pipe_for_slot(client, table, expected, fd)?;
        self.streams
            .get(&pipe)
            .ok_or(AuthorityError::NotPipe)?
            .capacity();
        let mut prepared = self.streams.remove(&pipe).unwrap_or_else(|| {
            abort_fatal(AuthorityFatal::InvariantViolation(
                "pipe capacity mutation lost its stream",
            ))
        });
        let result = prepared.set_capacity(capacity);
        self.streams.insert(pipe, prepared);
        result?;
        let revision = self.publish_mutation();
        self.stream_revisions.insert(pipe, revision);
        self.refresh_pipe_descriptions(pipe, revision);
        Ok(Outcome::PipeCapacitySet {
            pipe,
            capacity,
            stream_revision: revision,
        })
    }

    fn create_epoll_and_install(
        &mut self,
        client: ClientIdentity,
        table: FileTableId,
        table_generation: ObjectGeneration,
        minimum: FileSlotNumber,
        ceiling: NofileAllocationCeiling,
        descriptor_flags: DescriptorFlags,
    ) -> Result<Outcome, AuthorityError> {
        self.require_bound_table(client, table, table_generation)?;
        let fd = self.allocate_lowest(table, minimum, ceiling)?;
        let description = self.allocate_description();
        let outcome = self.commit_new_description_install(
            table,
            fd,
            description,
            descriptor_flags,
            AccessMode::PathOnly,
            StatusFlags::default(),
            None,
            AuthorityBacking::Epoll(EpollState::default()),
            None,
        );
        let Outcome::Installed {
            table_revision,
            description_revision,
            ..
        } = outcome
        else {
            abort_fatal(AuthorityFatal::InvariantViolation(
                "epoll creation returned a non-install outcome",
            ));
        };
        Ok(Outcome::EpollCreated {
            table,
            fd,
            description,
            generation: ObjectGeneration::INITIAL,
            table_revision,
            description_revision,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn create_timer_and_install(
        &mut self,
        client: ClientIdentity,
        table: FileTableId,
        table_generation: ObjectGeneration,
        minimum: FileSlotNumber,
        ceiling: NofileAllocationCeiling,
        descriptor_flags: DescriptorFlags,
        status_flags: StatusFlags,
    ) -> Result<Outcome, AuthorityError> {
        self.require_bound_table(client, table, table_generation)?;
        let fd = self.allocate_lowest(table, minimum, ceiling)?;
        let description = self.allocate_description();
        let outcome = self.commit_new_description_install(
            table,
            fd,
            description,
            descriptor_flags,
            AccessMode::ReadOnly,
            status_flags,
            None,
            AuthorityBacking::Timer {
                interval_ns: 0,
                initial_ns: 0,
                pending: 0,
            },
            None,
        );
        let Outcome::Installed {
            table_revision,
            description_revision,
            ..
        } = outcome
        else {
            abort_fatal(AuthorityFatal::InvariantViolation(
                "timer install returned an unexpected outcome",
            ));
        };
        Ok(Outcome::TimerCreated {
            table,
            fd,
            description,
            generation: ObjectGeneration::INITIAL,
            table_revision,
            description_revision,
        })
    }

    fn set_timer(
        &mut self,
        client: ClientIdentity,
        table: FileTableId,
        expected: ObjectGeneration,
        fd: FileSlotNumber,
        interval_ns: u64,
        initial_ns: u64,
    ) -> Result<Outcome, AuthorityError> {
        let description = self.slot(client, table, expected, fd)?.description;
        let state = self
            .descriptions
            .get(&description)
            .ok_or(AuthorityError::DescriptionNotFound)?;
        if !matches!(state.backing, AuthorityBacking::Timer { .. }) {
            return Err(AuthorityError::NotTimer);
        }
        let revision = self.publish_mutation();
        let state = self.descriptions.get_mut(&description).unwrap_or_else(|| {
            abort_fatal(AuthorityFatal::InvariantViolation(
                "timer set lost its description",
            ))
        });
        state.backing = AuthorityBacking::Timer {
            interval_ns,
            initial_ns,
            pending: 0,
        };
        state.readiness = ReadinessSnapshot {
            ready: LinuxEpollEvents::empty(),
            read_available: 0,
        };
        state.revision = revision;
        Ok(Outcome::TimerSet {
            description,
            interval_ns,
            initial_ns,
            description_revision: revision,
        })
    }

    fn expire_timer(
        &mut self,
        client: ClientIdentity,
        table: FileTableId,
        expected: ObjectGeneration,
        fd: FileSlotNumber,
        expirations: u64,
    ) -> Result<Outcome, AuthorityError> {
        let description = self.slot(client, table, expected, fd)?.description;
        let pending = match self
            .descriptions
            .get(&description)
            .ok_or(AuthorityError::DescriptionNotFound)?
            .backing
        {
            AuthorityBacking::Timer { pending, .. } => {
                pending.checked_add(expirations).unwrap_or_else(|| {
                    abort_fatal(AuthorityFatal::InvariantViolation(
                        "timer expiration overflow",
                    ))
                })
            }
            _ => return Err(AuthorityError::NotTimer),
        };
        let revision = self.publish_mutation();
        let state = self.descriptions.get_mut(&description).unwrap_or_else(|| {
            abort_fatal(AuthorityFatal::InvariantViolation(
                "timer expiration lost its description",
            ))
        });
        let AuthorityBacking::Timer {
            pending: stored, ..
        } = &mut state.backing
        else {
            abort_fatal(AuthorityFatal::InvariantViolation("timer backing changed"));
        };
        *stored = pending;
        state.readiness = ReadinessSnapshot {
            ready: LinuxEpollEvents::IN,
            read_available: 8,
        };
        state.revision = revision;
        Ok(Outcome::TimerExpired {
            description,
            expirations,
            pending,
            description_revision: revision,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn create_event_counter_and_install(
        &mut self,
        client: ClientIdentity,
        table: FileTableId,
        table_generation: ObjectGeneration,
        initial: u64,
        semaphore: bool,
        minimum: FileSlotNumber,
        ceiling: NofileAllocationCeiling,
        descriptor_flags: DescriptorFlags,
        status_flags: StatusFlags,
    ) -> Result<Outcome, AuthorityError> {
        if initial == u64::MAX {
            return Err(AuthorityError::InvalidEventCounterValue);
        }
        self.require_bound_table(client, table, table_generation)?;
        let fd = self.allocate_lowest(table, minimum, ceiling)?;
        let description = self.allocate_description();
        let outcome = self.commit_new_description_install(
            table,
            fd,
            description,
            descriptor_flags,
            AccessMode::ReadWrite,
            status_flags,
            None,
            AuthorityBacking::EventCounter {
                counter: initial,
                semaphore,
            },
            None,
        );
        let Outcome::Installed {
            table_revision,
            description_revision,
            ..
        } = outcome
        else {
            abort_fatal(AuthorityFatal::InvariantViolation(
                "event-counter creation returned a non-install outcome",
            ));
        };
        let state = self.descriptions.get_mut(&description).unwrap_or_else(|| {
            abort_fatal(AuthorityFatal::InvariantViolation(
                "event-counter creation lost its description",
            ))
        });
        state.readiness = event_counter_readiness(initial);
        Ok(Outcome::EventCounterCreated {
            table,
            fd,
            description,
            generation: ObjectGeneration::INITIAL,
            table_revision,
            description_revision,
        })
    }

    fn create_vfs_file(
        &mut self,
        path: CanonicalPath,
        mode: u32,
        contents: Vec<u8>,
        expected: ObjectGeneration,
    ) -> Result<Outcome, AuthorityError> {
        self.require_initial(expected)?;
        if path.as_str() == "/" {
            return Err(AuthorityError::VfsRootMutation);
        }
        if self.namespace.contains_key(&path) {
            return Err(AuthorityError::VfsPathExists);
        }
        self.validate_payload(&contents)?;
        let object = self.allocate_vfs_object();
        let revision = self.publish_mutation();
        self.namespace_revision = revision;
        self.vfs_objects.insert(
            object,
            VfsObjectState {
                generation: ObjectGeneration::INITIAL,
                revision,
                mode: mode & 0o7777,
                contents,
                namespace_links: 1,
                open_description_refs: 0,
            },
        );
        self.namespace.insert(path, object);
        Ok(Outcome::VfsObjectCreated {
            object,
            namespace_revision: revision,
        })
    }

    fn resolve_vfs(&self, path: &CanonicalPath) -> Result<Outcome, AuthorityError> {
        let object = *self
            .namespace
            .get(path)
            .ok_or(AuthorityError::VfsNotFound)?;
        let state = self
            .vfs_objects
            .get(&object)
            .ok_or(AuthorityError::VfsNotFound)?;
        Ok(Outcome::VfsObjectResolved {
            object,
            mode: state.mode,
            object_revision: state.revision,
            namespace_revision: self.namespace_revision,
        })
    }

    fn link_vfs(
        &mut self,
        object: VfsObjectId,
        path: CanonicalPath,
        expected: ObjectGeneration,
    ) -> Result<Outcome, AuthorityError> {
        if path.as_str() == "/" {
            return Err(AuthorityError::VfsRootMutation);
        }
        if self.namespace.contains_key(&path) {
            return Err(AuthorityError::VfsPathExists);
        }
        let state = self
            .vfs_objects
            .get(&object)
            .ok_or(AuthorityError::VfsNotFound)?;
        self.check_generation(state.generation, expected)?;
        let namespace_links = state.namespace_links.checked_add(1).unwrap_or_else(|| {
            abort_fatal(AuthorityFatal::InvariantViolation(
                "VFS namespace link count overflow",
            ))
        });
        let revision = self.publish_mutation();
        let state = self.vfs_objects.get_mut(&object).unwrap_or_else(|| {
            abort_fatal(AuthorityFatal::InvariantViolation(
                "link lost its validated VFS object",
            ))
        });
        state.namespace_links = namespace_links;
        state.revision = revision;
        self.namespace.insert(path, object);
        self.namespace_revision = revision;
        Ok(Outcome::VfsNamespaceChanged {
            object,
            namespace_revision: revision,
            object_reclaimed: false,
        })
    }

    fn unlink_vfs(&mut self, path: &CanonicalPath) -> Result<Outcome, AuthorityError> {
        if path.as_str() == "/" {
            return Err(AuthorityError::VfsRootMutation);
        }
        let object = *self
            .namespace
            .get(path)
            .ok_or(AuthorityError::VfsNotFound)?;
        let namespace_links = self
            .vfs_objects
            .get(&object)
            .unwrap_or_else(|| {
                abort_fatal(AuthorityFatal::InvariantViolation(
                    "namespace entry referenced a missing VFS object",
                ))
            })
            .namespace_links
            .checked_sub(1)
            .unwrap_or_else(|| {
                abort_fatal(AuthorityFatal::InvariantViolation(
                    "VFS namespace link count underflow",
                ))
            });
        let revision = self.publish_mutation();
        self.namespace.remove(path);
        let state = self.vfs_objects.get_mut(&object).unwrap_or_else(|| {
            abort_fatal(AuthorityFatal::InvariantViolation(
                "unlink lost its validated VFS object",
            ))
        });
        state.namespace_links = namespace_links;
        state.revision = revision;
        self.namespace_revision = revision;
        let reclaimed = self.maybe_reclaim_vfs_object(object);
        Ok(Outcome::VfsNamespaceChanged {
            object,
            namespace_revision: revision,
            object_reclaimed: reclaimed,
        })
    }

    fn rename_vfs(
        &mut self,
        from: &CanonicalPath,
        to: CanonicalPath,
    ) -> Result<Outcome, AuthorityError> {
        if from.as_str() == "/" || to.as_str() == "/" {
            return Err(AuthorityError::VfsRootMutation);
        }
        let object = *self
            .namespace
            .get(from)
            .ok_or(AuthorityError::VfsNotFound)?;
        if *from == to {
            return Ok(Outcome::VfsNamespaceChanged {
                object,
                namespace_revision: self.namespace_revision,
                object_reclaimed: false,
            });
        }
        let replaced = self.namespace.get(&to).copied();
        if replaced == Some(object) {
            return Ok(Outcome::VfsNamespaceChanged {
                object,
                namespace_revision: self.namespace_revision,
                object_reclaimed: false,
            });
        }
        if !self.vfs_objects.contains_key(&object) {
            abort_fatal(AuthorityFatal::InvariantViolation(
                "rename source referenced a missing VFS object",
            ));
        }
        let replaced_links = replaced.map(|replaced| {
            self.vfs_objects
                .get(&replaced)
                .unwrap_or_else(|| {
                    abort_fatal(AuthorityFatal::InvariantViolation(
                        "rename target referenced a missing VFS object",
                    ))
                })
                .namespace_links
                .checked_sub(1)
                .unwrap_or_else(|| {
                    abort_fatal(AuthorityFatal::InvariantViolation(
                        "rename target link count underflow",
                    ))
                })
        });
        let revision = self.publish_mutation();
        // The source link moves; it is neither removed nor added, so its object
        // keeps the same namespace-link count.
        self.namespace.remove(from);
        self.namespace.insert(to, object);
        self.namespace_revision = revision;
        let state = self.vfs_objects.get_mut(&object).unwrap_or_else(|| {
            abort_fatal(AuthorityFatal::InvariantViolation(
                "rename lost its validated source VFS object",
            ))
        });
        state.revision = revision;
        if let Some(replaced) = replaced {
            let target = self.vfs_objects.get_mut(&replaced).unwrap_or_else(|| {
                abort_fatal(AuthorityFatal::InvariantViolation(
                    "rename lost its validated target VFS object",
                ))
            });
            target.namespace_links = replaced_links.unwrap_or_else(|| {
                abort_fatal(AuthorityFatal::InvariantViolation(
                    "rename omitted its prepared target link count",
                ))
            });
            target.revision = revision;
            self.maybe_reclaim_vfs_object(replaced);
        }
        Ok(Outcome::VfsNamespaceChanged {
            object,
            namespace_revision: revision,
            object_reclaimed: false,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn open_vfs_and_install(
        &mut self,
        client: ClientIdentity,
        table: FileTableId,
        table_generation: ObjectGeneration,
        object: VfsObjectId,
        object_generation: ObjectGeneration,
        minimum: FileSlotNumber,
        ceiling: NofileAllocationCeiling,
        descriptor_flags: DescriptorFlags,
        access_mode: AccessMode,
        status_flags: StatusFlags,
        path: Option<CanonicalPath>,
    ) -> Result<Outcome, AuthorityError> {
        self.require_bound_table(client, table, table_generation)?;
        let object_state = self
            .vfs_objects
            .get(&object)
            .ok_or(AuthorityError::VfsNotFound)?;
        self.check_generation(object_state.generation, object_generation)?;
        let open_description_refs = object_state
            .open_description_refs
            .checked_add(1)
            .unwrap_or_else(|| {
                abort_fatal(AuthorityFatal::InvariantViolation(
                    "VFS open-description reference overflow",
                ))
            });
        let fd = self.allocate_lowest(table, minimum, ceiling)?;
        let description = self.allocate_description();
        Ok(self.commit_new_description_install(
            table,
            fd,
            description,
            descriptor_flags,
            access_mode,
            status_flags,
            path,
            AuthorityBacking::Vfs { object },
            Some(open_description_refs),
        ))
    }

    #[allow(clippy::too_many_arguments)]
    fn create_synthetic_and_install(
        &mut self,
        client: ClientIdentity,
        table: FileTableId,
        table_generation: ObjectGeneration,
        contents: Vec<u8>,
        minimum: FileSlotNumber,
        ceiling: NofileAllocationCeiling,
        descriptor_flags: DescriptorFlags,
        access_mode: AccessMode,
        status_flags: StatusFlags,
        path: Option<CanonicalPath>,
    ) -> Result<Outcome, AuthorityError> {
        self.require_bound_table(client, table, table_generation)?;
        self.validate_payload(&contents)?;
        let fd = self.allocate_lowest(table, minimum, ceiling)?;
        let description = self.allocate_description();
        Ok(self.commit_new_description_install(
            table,
            fd,
            description,
            descriptor_flags,
            access_mode,
            status_flags,
            path,
            AuthorityBacking::Synthetic { contents },
            None,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    fn adopt_host_file_and_install(
        &mut self,
        client: ClientIdentity,
        table: FileTableId,
        table_generation: ObjectGeneration,
        minimum: FileSlotNumber,
        ceiling: NofileAllocationCeiling,
        descriptor_flags: DescriptorFlags,
        access_mode: AccessMode,
        status_flags: StatusFlags,
        writable: bool,
        path: Option<CanonicalPath>,
        capabilities: &mut Vec<OwnedFd>,
    ) -> Result<Outcome, AuthorityError> {
        self.require_bound_table(client, table, table_generation)?;
        if access_mode.writable() && !writable {
            return Err(AuthorityError::BackingReadOnly);
        }
        let host_fd = capabilities.first().unwrap_or_else(|| {
            abort_fatal(AuthorityFatal::InvariantViolation(
                "host-file adoption lost its validated descriptor",
            ))
        });
        validate_host_file(host_fd.as_raw_fd(), access_mode)?;
        let fd = self.allocate_lowest(table, minimum, ceiling)?;
        let description = self.allocate_description();
        let host_fd = capabilities.pop().unwrap_or_else(|| {
            abort_fatal(AuthorityFatal::InvariantViolation(
                "host-file adoption lost its prepared descriptor",
            ))
        });
        Ok(self.commit_new_description_install(
            table,
            fd,
            description,
            descriptor_flags,
            access_mode,
            status_flags,
            path,
            AuthorityBacking::Host {
                fd: host_fd,
                writable,
            },
            None,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    fn adopt_host_stream_and_install(
        &mut self,
        client: ClientIdentity,
        table: FileTableId,
        table_generation: ObjectGeneration,
        minimum: FileSlotNumber,
        ceiling: NofileAllocationCeiling,
        descriptor_flags: DescriptorFlags,
        access_mode: AccessMode,
        status_flags: StatusFlags,
        kind: HostStreamKind,
        path: Option<CanonicalPath>,
        capabilities: &mut Vec<OwnedFd>,
    ) -> Result<Outcome, AuthorityError> {
        self.require_bound_table(client, table, table_generation)?;
        let fd = self.allocate_lowest(table, minimum, ceiling)?;
        let host_fd = capabilities
            .pop()
            .ok_or(AuthorityError::HostBackingTypeMismatch)?;
        validate_host_stream(host_fd.as_raw_fd(), access_mode, kind)?;
        let description = self.allocate_description();
        let outcome = self.commit_new_description_install(
            table,
            fd,
            description,
            descriptor_flags,
            access_mode,
            status_flags,
            path,
            AuthorityBacking::HostStream { fd: host_fd, kind },
            None,
        );
        let Outcome::Installed {
            table_revision,
            description_revision,
            ..
        } = outcome
        else {
            abort_fatal(AuthorityFatal::InvariantViolation(
                "host stream install returned an unexpected outcome",
            ));
        };
        Ok(Outcome::HostStreamCreated {
            table,
            fd,
            description,
            generation: ObjectGeneration::INITIAL,
            kind,
            table_revision,
            description_revision,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn adopt_io_uring_and_install(
        &mut self,
        client: ClientIdentity,
        table: FileTableId,
        table_generation: ObjectGeneration,
        minimum: FileSlotNumber,
        ceiling: NofileAllocationCeiling,
        descriptor_flags: DescriptorFlags,
        status_flags: StatusFlags,
        entries: u32,
        data_length: u64,
        capabilities: &mut Vec<OwnedFd>,
    ) -> Result<Outcome, AuthorityError> {
        self.require_bound_table(client, table, table_generation)?;
        if entries == 0 || data_length == 0 {
            return Err(AuthorityError::InvalidMappingRange);
        }
        let fd = self.allocate_lowest(table, minimum, ceiling)?;
        let data_fd = capabilities
            .pop()
            .ok_or(AuthorityError::HostBackingTypeMismatch)?;
        let lock_fd = capabilities
            .pop()
            .ok_or(AuthorityError::HostBackingTypeMismatch)?;
        validate_regular_file_length(data_fd.as_raw_fd(), data_length)?;
        validate_regular_file_length(lock_fd.as_raw_fd(), 1)?;
        let description = self.allocate_description();
        let outcome = self.commit_new_description_install(
            table,
            fd,
            description,
            descriptor_flags,
            AccessMode::ReadWrite,
            status_flags,
            None,
            AuthorityBacking::IoUring {
                data_fd,
                lock_fd,
                entries,
                data_length,
            },
            None,
        );
        let Outcome::Installed {
            table_revision,
            description_revision,
            ..
        } = outcome
        else {
            abort_fatal(AuthorityFatal::InvariantViolation(
                "io_uring install returned an unexpected outcome",
            ));
        };
        Ok(Outcome::IoUringCreated {
            table,
            fd,
            description,
            generation: ObjectGeneration::INITIAL,
            entries,
            data_length,
            table_revision,
            description_revision,
        })
    }

    fn acquire_capability_lease(
        &mut self,
        client: ClientIdentity,
        table: FileTableId,
        expected: ObjectGeneration,
        fd: FileSlotNumber,
        purpose: CapabilityLeasePurpose,
    ) -> Result<Outcome, AuthorityError> {
        let slot = self.slot(client, table, expected, fd)?.clone();
        let state = self
            .descriptions
            .get(&slot.description)
            .ok_or(AuthorityError::DescriptionNotFound)?;
        if state.backing.host_fd(purpose).is_none() {
            return Err(AuthorityError::NotHostBacked);
        }
        let capability_lease_refs =
            state
                .capability_lease_refs
                .checked_add(1)
                .unwrap_or_else(|| {
                    abort_fatal(AuthorityFatal::InvariantViolation(
                        "capability lease reference overflow",
                    ))
                });
        let lease = self.allocate_capability_lease();
        let revision = self.publish_mutation();
        let state = self
            .descriptions
            .get_mut(&slot.description)
            .unwrap_or_else(|| {
                abort_fatal(AuthorityFatal::InvariantViolation(
                    "capability lease lost its validated description",
                ))
            });
        state.capability_lease_refs = capability_lease_refs;
        state.revision = revision;
        self.capability_leases.insert(
            lease,
            CapabilityLeaseState {
                owner: client,
                description: slot.description,
                description_generation: slot.description_generation,
                purpose,
            },
        );
        Ok(Outcome::CapabilityLeaseGranted {
            lease,
            description: slot.description,
            description_generation: slot.description_generation,
            purpose,
            revision,
        })
    }

    fn release_capability_lease(
        &mut self,
        client: ClientIdentity,
        lease: CapabilityLeaseId,
        disposition: CapabilityLeaseDisposition,
    ) -> Result<Outcome, AuthorityError> {
        let lease_state = self
            .capability_leases
            .get(&lease)
            .ok_or(AuthorityError::CapabilityLeaseNotFound)?;
        if lease_state.owner != client {
            return Err(AuthorityError::CapabilityLeaseNotFound);
        }
        let description = lease_state.description;
        let revision = self.publish_mutation();
        self.capability_leases.remove(&lease).unwrap_or_else(|| {
            abort_fatal(AuthorityFatal::InvariantViolation(
                "capability release lost its validated lease",
            ))
        });
        let (description_reclaimed, object_reclaimed) =
            self.release_capability_lease_ref(description, revision);
        Ok(Outcome::CapabilityLeaseReleased {
            lease,
            disposition,
            description_reclaimed,
            object_reclaimed,
            revision,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn finalize_mapping_lease(
        &mut self,
        client: ClientIdentity,
        lease: CapabilityLeaseId,
        disposition: MappingLeaseDisposition,
    ) -> Result<Outcome, AuthorityError> {
        let lease_state = self
            .capability_leases
            .get(&lease)
            .ok_or(AuthorityError::CapabilityLeaseNotFound)?;
        if lease_state.owner != client
            || lease_state.purpose != CapabilityLeasePurpose::MappingSource
        {
            return Err(AuthorityError::CapabilityLeaseNotFound);
        }
        let description = lease_state.description;
        let attachment = match disposition {
            MappingLeaseDisposition::Commit { .. } => Some(self.allocate_mapping_attachment()),
            MappingLeaseDisposition::Abort => None,
        };
        let revision = self.publish_mutation();
        self.capability_leases.remove(&lease).unwrap_or_else(|| {
            abort_fatal(AuthorityFatal::InvariantViolation(
                "mapping lease finalization lost its validated lease",
            ))
        });
        let (description_reclaimed, object_reclaimed) = match (attachment, disposition) {
            (Some(attachment), MappingLeaseDisposition::Commit { range }) => {
                self.mapping_attachments.insert(
                    attachment,
                    MappingAttachmentState {
                        owner: client,
                        description,
                        ranges: vec![range],
                    },
                );
                let state = self.descriptions.get_mut(&description).unwrap_or_else(|| {
                    abort_fatal(AuthorityFatal::InvariantViolation(
                        "mapping attachment lost its leased description",
                    ))
                });
                state.revision = revision;
                (false, false)
            }
            (None, MappingLeaseDisposition::Abort) => {
                self.release_capability_lease_ref(description, revision)
            }
            _ => abort_fatal(AuthorityFatal::InvariantViolation(
                "mapping lease disposition and attachment disagree",
            )),
        };
        Ok(Outcome::MappingLeaseFinalized {
            lease,
            attachment,
            description,
            disposition,
            description_reclaimed,
            object_reclaimed,
            revision,
        })
    }

    fn release_mapping_attachment(
        &mut self,
        client: ClientIdentity,
        attachment: MappingAttachmentId,
        release: MappingRelease,
    ) -> Result<Outcome, AuthorityError> {
        let state = self
            .mapping_attachments
            .get(&attachment)
            .ok_or(AuthorityError::MappingAttachmentNotFound)?;
        if state.owner != client {
            return Err(AuthorityError::MappingAttachmentNotFound);
        }
        let remaining = release_mapping_ranges(&state.ranges, release)?;
        let description = state.description;
        let revision = self.publish_mutation();
        if remaining.is_empty() {
            self.mapping_attachments
                .remove(&attachment)
                .unwrap_or_else(|| {
                    abort_fatal(AuthorityFatal::InvariantViolation(
                        "mapping release lost its validated attachment",
                    ))
                });
            let (description_reclaimed, object_reclaimed) =
                self.release_capability_lease_ref(description, revision);
            return Ok(Outcome::MappingAttachmentReleased {
                attachment,
                remaining,
                description_reclaimed,
                object_reclaimed,
                revision,
            });
        }
        let state = self
            .mapping_attachments
            .get_mut(&attachment)
            .unwrap_or_else(|| {
                abort_fatal(AuthorityFatal::InvariantViolation(
                    "partial mapping release lost its attachment",
                ))
            });
        state.ranges = remaining.clone();
        self.descriptions
            .get_mut(&description)
            .unwrap_or_else(|| {
                abort_fatal(AuthorityFatal::InvariantViolation(
                    "partial mapping release lost its description",
                ))
            })
            .revision = revision;
        Ok(Outcome::MappingAttachmentReleased {
            attachment,
            remaining,
            description_reclaimed: false,
            object_reclaimed: false,
            revision,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn commit_new_description_install(
        &mut self,
        table: FileTableId,
        fd: FileSlotNumber,
        description: FileDescriptionId,
        descriptor_flags: DescriptorFlags,
        access_mode: AccessMode,
        status_flags: StatusFlags,
        path: Option<CanonicalPath>,
        backing: AuthorityBacking,
        open_description_refs: Option<u64>,
    ) -> Outcome {
        let object = backing.vfs_object();
        let revision = self.publish_mutation();
        if let Some(object) = object {
            let state = self.vfs_objects.get_mut(&object).unwrap_or_else(|| {
                abort_fatal(AuthorityFatal::InvariantViolation(
                    "install lost its validated VFS object",
                ))
            });
            state.open_description_refs = open_description_refs.unwrap_or_else(|| {
                abort_fatal(AuthorityFatal::InvariantViolation(
                    "VFS install omitted its prepared reference count",
                ))
            });
            state.revision = revision;
        } else if open_description_refs.is_some() {
            abort_fatal(AuthorityFatal::InvariantViolation(
                "non-VFS install carried a VFS reference count",
            ));
        }
        self.descriptions.insert(
            description,
            FileDescriptionState {
                generation: ObjectGeneration::INITIAL,
                revision,
                logical_slot_refs: 1,
                capability_lease_refs: 0,
                offset: FileOffset::default(),
                access_mode,
                status_flags,
                readiness: ReadinessSnapshot {
                    ready: LinuxEpollEvents::empty(),
                    read_available: 0,
                },
                backing,
            },
        );
        let table_state = self.tables.get_mut(&table).unwrap_or_else(|| {
            abort_fatal(AuthorityFatal::InvariantViolation(
                "install lost its validated file table",
            ))
        });
        table_state.slots.insert(
            fd,
            FileSlotState {
                description,
                description_generation: ObjectGeneration::INITIAL,
                flags: descriptor_flags,
                path,
            },
        );
        table_state.revision = revision;
        Outcome::Installed {
            table,
            fd,
            description,
            description_generation: ObjectGeneration::INITIAL,
            table_revision: revision,
            description_revision: revision,
        }
    }

    fn resolve_slot(
        &self,
        client: ClientIdentity,
        table: FileTableId,
        expected: ObjectGeneration,
        fd: FileSlotNumber,
    ) -> Result<Outcome, AuthorityError> {
        let table = self.bound_table(client, table, expected)?;
        let slot = table.slots.get(&fd).ok_or(AuthorityError::SlotNotFound)?;
        Ok(Outcome::Slot(slot.snapshot(fd)))
    }

    fn list_slots(
        &self,
        client: ClientIdentity,
        table: FileTableId,
        expected: ObjectGeneration,
        after: Option<FileSlotNumber>,
        maximum: SlotPageLimit,
    ) -> Result<Outcome, AuthorityError> {
        let state = self.bound_table(client, table, expected)?;
        let maximum = usize::from(maximum.raw());
        let mut slots: Vec<SlotSnapshot> = state
            .slots
            .iter()
            .filter(|(fd, _)| after.is_none_or(|after| **fd > after))
            .take(maximum + 1)
            .map(|(fd, slot)| slot.snapshot(*fd))
            .collect();
        let has_more = slots.len() > maximum;
        if has_more {
            slots.pop();
        }
        let next_after = has_more.then(|| slots.last().map(|slot| slot.fd)).flatten();
        Ok(Outcome::SlotPage {
            table,
            slots,
            next_after,
            table_revision: state.revision,
        })
    }

    fn set_descriptor_flags(
        &mut self,
        client: ClientIdentity,
        table: FileTableId,
        expected: ObjectGeneration,
        fd: FileSlotNumber,
        flags: DescriptorFlags,
    ) -> Result<Outcome, AuthorityError> {
        self.slot(client, table, expected, fd)?;
        let revision = self.publish_mutation();
        let table_state = self.tables.get_mut(&table).unwrap_or_else(|| {
            abort_fatal(AuthorityFatal::InvariantViolation(
                "descriptor-flag mutation lost its validated table",
            ))
        });
        let slot = table_state.slots.get_mut(&fd).unwrap_or_else(|| {
            abort_fatal(AuthorityFatal::InvariantViolation(
                "descriptor-flag mutation lost its validated slot",
            ))
        });
        slot.flags = flags;
        table_state.revision = revision;
        Ok(Outcome::DescriptorFlagsSet {
            table,
            fd,
            flags,
            table_revision: revision,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn replace_slot(
        &mut self,
        client: ClientIdentity,
        table: FileTableId,
        expected: ObjectGeneration,
        source: FileSlotNumber,
        target: FileSlotNumber,
        ceiling: NofileAllocationCeiling,
        flags: DescriptorFlags,
        same_slot: SameSlotBehavior,
    ) -> Result<Outcome, AuthorityError> {
        let source_slot = self.slot(client, table, expected, source)?.clone();
        let target_raw = u32::try_from(target.raw()).map_err(|_| AuthorityError::NofileExceeded)?;
        if target_raw >= ceiling.raw() {
            return Err(AuthorityError::NofileExceeded);
        }
        let table_state = self.bound_table(client, table, expected)?;
        if source == target {
            if same_slot == SameSlotBehavior::Reject {
                return Err(AuthorityError::SameSlotRejected);
            }
            return Ok(Outcome::SlotReplaced {
                table,
                source,
                target,
                replaced_description: None,
                description_reclaimed: false,
                object_reclaimed: false,
                table_revision: table_state.revision,
            });
        }
        let replaced = table_state.slots.get(&target).cloned();
        let needs_ref_increment = replaced
            .as_ref()
            .is_none_or(|slot| slot.description != source_slot.description);
        let source_refs = needs_ref_increment.then(|| {
            self.descriptions
                .get(&source_slot.description)
                .unwrap_or_else(|| {
                    abort_fatal(AuthorityFatal::InvariantViolation(
                        "source slot referenced a missing description",
                    ))
                })
                .logical_slot_refs
                .checked_add(1)
                .unwrap_or_else(|| {
                    abort_fatal(AuthorityFatal::InvariantViolation(
                        "slot replacement reference overflow",
                    ))
                })
        });
        let revision = self.publish_mutation();
        let table_state = self.tables.get_mut(&table).unwrap_or_else(|| {
            abort_fatal(AuthorityFatal::InvariantViolation(
                "slot replacement lost its validated table",
            ))
        });
        table_state.slots.insert(
            target,
            FileSlotState {
                flags,
                ..source_slot.clone()
            },
        );
        table_state.revision = revision;
        if let Some(source_refs) = source_refs {
            let description = self
                .descriptions
                .get_mut(&source_slot.description)
                .unwrap_or_else(|| {
                    abort_fatal(AuthorityFatal::InvariantViolation(
                        "slot replacement lost its source description",
                    ))
                });
            description.logical_slot_refs = source_refs;
            description.revision = revision;
        }
        let (description_reclaimed, object_reclaimed) = replaced
            .as_ref()
            .filter(|slot| slot.description != source_slot.description)
            .map_or((false, false), |slot| {
                self.release_description_ref(slot.description, revision)
            });
        Ok(Outcome::SlotReplaced {
            table,
            source,
            target,
            replaced_description: replaced.map(|slot| slot.description),
            description_reclaimed,
            object_reclaimed,
            table_revision: revision,
        })
    }

    fn mutate_slot_range(
        &mut self,
        client: ClientIdentity,
        table: FileTableId,
        expected: ObjectGeneration,
        first: FileSlotNumber,
        last: FileSlotNumber,
        action: SlotRangeAction,
    ) -> Result<Outcome, AuthorityError> {
        if first > last {
            return Err(AuthorityError::InvalidSlotRange);
        }
        let state = self.bound_table(client, table, expected)?;
        let fds: Vec<FileSlotNumber> = state.slots.range(first..=last).map(|(fd, _)| *fd).collect();
        let affected = u32::try_from(fds.len()).unwrap_or_else(|_| {
            abort_fatal(AuthorityFatal::InvariantViolation(
                "slot range population exceeded u32",
            ))
        });
        if fds.is_empty() {
            return Ok(Outcome::SlotRangeMutated {
                table,
                action,
                affected,
                table_revision: state.revision,
            });
        }
        let revision = self.publish_mutation();
        let mut released = Vec::new();
        let table_state = self.tables.get_mut(&table).unwrap_or_else(|| {
            abort_fatal(AuthorityFatal::InvariantViolation(
                "slot range mutation lost its validated table",
            ))
        });
        match action {
            SlotRangeAction::Close => {
                for fd in fds {
                    let slot = table_state.slots.remove(&fd).unwrap_or_else(|| {
                        abort_fatal(AuthorityFatal::InvariantViolation(
                            "slot range close lost a validated slot",
                        ))
                    });
                    released.push(slot.description);
                }
            }
            SlotRangeAction::SetCloseOnExec => {
                for fd in fds {
                    let slot = table_state.slots.get_mut(&fd).unwrap_or_else(|| {
                        abort_fatal(AuthorityFatal::InvariantViolation(
                            "slot range flag mutation lost a validated slot",
                        ))
                    });
                    slot.flags = slot.flags.with_close_on_exec();
                }
            }
        }
        table_state.revision = revision;
        for description in released {
            self.release_description_ref(description, revision);
        }
        Ok(Outcome::SlotRangeMutated {
            table,
            action,
            affected,
            table_revision: revision,
        })
    }

    fn epoll_ctl_add(
        &mut self,
        client: ClientIdentity,
        table: FileTableId,
        expected: ObjectGeneration,
        epoll_fd: FileSlotNumber,
        target_fd: FileSlotNumber,
        registration: EpollRegistration,
    ) -> Result<Outcome, AuthorityError> {
        let (epoll_description, key) =
            self.epoll_interest_key(client, table, expected, epoll_fd, target_fd)?;
        if self.epoll_state(epoll_description)?.contains(key) {
            return Err(AuthorityError::EpollInterestExists);
        }
        if epoll_description == key.target_description
            || self.epoll_path_reaches(key.target_description, epoll_description, 1)
        {
            return Err(AuthorityError::EpollLoop);
        }
        let generation = self.allocate_interest_generation();
        let revision = self.publish_mutation();
        let state = self.epoll_state_mut(epoll_description).unwrap_or_else(|_| {
            abort_fatal(AuthorityFatal::InvariantViolation(
                "epoll ADD lost its validated instance",
            ))
        });
        state.add(key, registration, generation);
        let description = self
            .descriptions
            .get_mut(&epoll_description)
            .unwrap_or_else(|| {
                abort_fatal(AuthorityFatal::InvariantViolation(
                    "epoll ADD lost its description",
                ))
            });
        description.revision = revision;
        self.epoll_watchers
            .entry(key.target_description)
            .or_default()
            .insert((epoll_description, key));
        Ok(Outcome::EpollInterestAdded {
            key,
            generation,
            description_revision: revision,
            host_plan: EpollHostPlan {
                epoll_description,
                target_description: key.target_description,
                registered_slot: key.registered_slot,
                generation,
                action: EpollHostPlanAction::RegisterOrModify,
                events: registration.events,
                plan_revision: revision,
            },
        })
    }

    fn epoll_ctl_modify(
        &mut self,
        client: ClientIdentity,
        table: FileTableId,
        expected: ObjectGeneration,
        epoll_fd: FileSlotNumber,
        target_fd: FileSlotNumber,
        registration: EpollRegistration,
    ) -> Result<Outcome, AuthorityError> {
        let (epoll_description, key) =
            self.epoll_interest_key(client, table, expected, epoll_fd, target_fd)?;
        if !self.epoll_state(epoll_description)?.contains(key) {
            return Err(AuthorityError::EpollInterestNotFound);
        }
        let revision = self.publish_mutation();
        let state = self.epoll_state_mut(epoll_description).unwrap_or_else(|_| {
            abort_fatal(AuthorityFatal::InvariantViolation(
                "epoll MOD lost its validated instance",
            ))
        });
        let generation = state.modify(key, registration).unwrap_or_else(|| {
            abort_fatal(AuthorityFatal::InvariantViolation(
                "epoll MOD lost its validated interest",
            ))
        });
        self.descriptions
            .get_mut(&epoll_description)
            .unwrap_or_else(|| {
                abort_fatal(AuthorityFatal::InvariantViolation(
                    "epoll MOD lost its description",
                ))
            })
            .revision = revision;
        Ok(Outcome::EpollInterestModified {
            key,
            generation,
            description_revision: revision,
            host_plan: EpollHostPlan {
                epoll_description,
                target_description: key.target_description,
                registered_slot: key.registered_slot,
                generation,
                action: EpollHostPlanAction::RegisterOrModify,
                events: registration.events,
                plan_revision: revision,
            },
        })
    }

    fn epoll_ctl_delete(
        &mut self,
        client: ClientIdentity,
        table: FileTableId,
        expected: ObjectGeneration,
        epoll_fd: FileSlotNumber,
        target_fd: FileSlotNumber,
    ) -> Result<Outcome, AuthorityError> {
        let (epoll_description, key) =
            self.epoll_interest_key(client, table, expected, epoll_fd, target_fd)?;
        if !self.epoll_state(epoll_description)?.contains(key) {
            return Err(AuthorityError::EpollInterestNotFound);
        }
        let revision = self.publish_mutation();
        let removed = self
            .epoll_state_mut(epoll_description)
            .unwrap_or_else(|_| {
                abort_fatal(AuthorityFatal::InvariantViolation(
                    "epoll DEL lost its validated instance",
                ))
            })
            .delete(key)
            .unwrap_or_else(|| {
                abort_fatal(AuthorityFatal::InvariantViolation(
                    "epoll DEL lost its validated interest",
                ))
            });
        self.descriptions
            .get_mut(&epoll_description)
            .unwrap_or_else(|| {
                abort_fatal(AuthorityFatal::InvariantViolation(
                    "epoll DEL lost its description",
                ))
            })
            .revision = revision;
        if let Some(watchers) = self.epoll_watchers.get_mut(&key.target_description) {
            watchers.remove(&(epoll_description, key));
            if watchers.is_empty() {
                self.epoll_watchers.remove(&key.target_description);
            }
        }
        Ok(Outcome::EpollInterestDeleted {
            key,
            description_revision: revision,
            host_plan: EpollHostPlan {
                epoll_description,
                target_description: key.target_description,
                registered_slot: key.registered_slot,
                generation: removed.generation,
                action: EpollHostPlanAction::Delete,
                events: LinuxEpollEvents::empty(),
                plan_revision: revision,
            },
        })
    }

    fn epoll_revalidate_host_plan(&self, plan: EpollHostPlan) -> Result<Outcome, AuthorityError> {
        let current_revision = self
            .descriptions
            .get(&plan.epoll_description)
            .ok_or(AuthorityError::DescriptionNotFound)?
            .revision;
        let current = self
            .epoll_state(plan.epoll_description)?
            .interest(EpollInterestKey {
                registered_slot: plan.registered_slot,
                target_description: plan.target_description,
            });
        let valid = match plan.action {
            EpollHostPlanAction::RegisterOrModify => current.is_some_and(|interest| {
                interest.generation == plan.generation
                    && interest.registration.events == plan.events
                    && current_revision == plan.plan_revision
            }),
            EpollHostPlanAction::Delete => {
                current.is_none() && current_revision == plan.plan_revision
            }
        };
        Ok(Outcome::EpollHostPlanValidated {
            valid,
            current_revision,
        })
    }

    fn observe_readiness(
        &mut self,
        client: ClientIdentity,
        table: FileTableId,
        expected: ObjectGeneration,
        fd: FileSlotNumber,
        ready: LinuxEpollEvents,
        read_available: u64,
    ) -> Result<Outcome, AuthorityError> {
        let description = self.slot(client, table, expected, fd)?.description;
        let state = self
            .descriptions
            .get(&description)
            .ok_or(AuthorityError::DescriptionNotFound)?;
        if !is_epollable(&state.backing) {
            return Err(AuthorityError::NotEpollable);
        }
        let revision = self.publish_mutation();
        let state = self.descriptions.get_mut(&description).unwrap_or_else(|| {
            abort_fatal(AuthorityFatal::InvariantViolation(
                "readiness observation lost its description",
            ))
        });
        state.readiness = ReadinessSnapshot {
            ready,
            read_available,
        };
        state.revision = revision;
        Ok(Outcome::ReadinessObserved {
            description,
            description_revision: revision,
        })
    }

    fn epoll_collect(
        &mut self,
        client: ClientIdentity,
        table: FileTableId,
        expected: ObjectGeneration,
        epoll_fd: FileSlotNumber,
        maximum: EpollEventLimit,
    ) -> Result<Outcome, AuthorityError> {
        let epoll_description = self.slot(client, table, expected, epoll_fd)?.description;
        let current = self.epoll_state(epoll_description)?.clone();
        let readiness: BTreeMap<FileDescriptionId, ReadinessSnapshot> = current
            .target_descriptions()
            .filter_map(|description| {
                self.descriptions
                    .get(&description)
                    .map(|state| (description, state.readiness))
            })
            .collect();
        let mut prepared = current.clone();
        let events = prepared.collect(&readiness, maximum);
        let changed = prepared != current;
        let revision = if changed {
            self.publish_mutation()
        } else {
            self.descriptions
                .get(&epoll_description)
                .ok_or(AuthorityError::DescriptionNotFound)?
                .revision
        };
        if changed {
            let description = self
                .descriptions
                .get_mut(&epoll_description)
                .unwrap_or_else(|| {
                    abort_fatal(AuthorityFatal::InvariantViolation(
                        "epoll collect lost its description",
                    ))
                });
            let AuthorityBacking::Epoll(state) = &mut description.backing else {
                abort_fatal(AuthorityFatal::InvariantViolation(
                    "epoll collect backing changed after preparation",
                ));
            };
            *state = prepared;
            description.revision = revision;
        }
        Ok(Outcome::EpollEvents {
            events,
            description_revision: revision,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn epoll_acknowledge_io(
        &mut self,
        client: ClientIdentity,
        table: FileTableId,
        expected: ObjectGeneration,
        fd: FileSlotNumber,
        consumed: LinuxEpollEvents,
        read_available: u64,
        write_backpressured: bool,
    ) -> Result<Outcome, AuthorityError> {
        let description = self.slot(client, table, expected, fd)?.description;
        self.descriptions
            .get(&description)
            .ok_or(AuthorityError::DescriptionNotFound)?;
        let epolls: Vec<FileDescriptionId> = self
            .epoll_watchers
            .get(&description)
            .into_iter()
            .flat_map(|watchers| watchers.iter().map(|(epoll, _)| *epoll))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        for epoll in &epolls {
            self.epoll_state(*epoll)?;
        }
        let revision = self.publish_mutation();
        for epoll in epolls {
            let state = self.epoll_state_mut(epoll).unwrap_or_else(|_| {
                abort_fatal(AuthorityFatal::InvariantViolation(
                    "epoll I/O acknowledgement lost a watcher",
                ))
            });
            if state.acknowledge_io(description, consumed, read_available, write_backpressured) {
                self.descriptions
                    .get_mut(&epoll)
                    .unwrap_or_else(|| {
                        abort_fatal(AuthorityFatal::InvariantViolation(
                            "epoll I/O acknowledgement lost a description",
                        ))
                    })
                    .revision = revision;
            }
        }
        let target = self.descriptions.get_mut(&description).unwrap_or_else(|| {
            abort_fatal(AuthorityFatal::InvariantViolation(
                "epoll I/O acknowledgement lost its target",
            ))
        });
        target.readiness.read_available = read_available;
        target.revision = revision;
        Ok(Outcome::EpollIoAcknowledged {
            description,
            description_revision: revision,
        })
    }

    fn event_counter_read(
        &mut self,
        client: ClientIdentity,
        table: FileTableId,
        expected: ObjectGeneration,
        fd: FileSlotNumber,
    ) -> Result<Outcome, AuthorityError> {
        let description = self.slot(client, table, expected, fd)?.description;
        let state = self
            .descriptions
            .get(&description)
            .ok_or(AuthorityError::DescriptionNotFound)?;
        let AuthorityBacking::EventCounter { counter, semaphore } = &state.backing else {
            return Err(AuthorityError::NotEventCounter);
        };
        if *counter == 0 {
            return Err(AuthorityError::WouldBlock);
        }
        let value = if *semaphore { 1 } else { *counter };
        let next = if *semaphore { counter - 1 } else { 0 };
        let revision = self.publish_mutation();
        let state = self.descriptions.get_mut(&description).unwrap_or_else(|| {
            abort_fatal(AuthorityFatal::InvariantViolation(
                "event-counter read lost its description",
            ))
        });
        let AuthorityBacking::EventCounter { counter, .. } = &mut state.backing else {
            abort_fatal(AuthorityFatal::InvariantViolation(
                "event-counter read backing changed after preparation",
            ));
        };
        *counter = next;
        let readiness = event_counter_readiness(next);
        state.readiness = readiness;
        state.revision = revision;
        self.acknowledge_epolls_without_publish(
            description,
            LinuxEpollEvents::IN,
            readiness.read_available,
            false,
            revision,
        );
        Ok(Outcome::EventCounterRead {
            value,
            description_revision: revision,
        })
    }

    fn event_counter_write(
        &mut self,
        client: ClientIdentity,
        table: FileTableId,
        expected: ObjectGeneration,
        fd: FileSlotNumber,
        value: u64,
    ) -> Result<Outcome, AuthorityError> {
        if value == u64::MAX {
            return Err(AuthorityError::InvalidEventCounterValue);
        }
        let description = self.slot(client, table, expected, fd)?.description;
        let state = self
            .descriptions
            .get(&description)
            .ok_or(AuthorityError::DescriptionNotFound)?;
        let AuthorityBacking::EventCounter { counter, .. } = &state.backing else {
            return Err(AuthorityError::NotEventCounter);
        };
        let next = counter
            .checked_add(value)
            .filter(|next| *next < u64::MAX)
            .ok_or(AuthorityError::WouldBlock)?;
        let revision = self.publish_mutation();
        let state = self.descriptions.get_mut(&description).unwrap_or_else(|| {
            abort_fatal(AuthorityFatal::InvariantViolation(
                "event-counter write lost its description",
            ))
        });
        let AuthorityBacking::EventCounter { counter, .. } = &mut state.backing else {
            abort_fatal(AuthorityFatal::InvariantViolation(
                "event-counter write backing changed after preparation",
            ));
        };
        *counter = next;
        state.readiness = event_counter_readiness(next);
        state.revision = revision;
        Ok(Outcome::EventCounterWritten {
            value,
            counter: next,
            description_revision: revision,
        })
    }

    fn epoll_interest_key(
        &self,
        client: ClientIdentity,
        table: FileTableId,
        expected: ObjectGeneration,
        epoll_fd: FileSlotNumber,
        target_fd: FileSlotNumber,
    ) -> Result<(FileDescriptionId, EpollInterestKey), AuthorityError> {
        let epoll_description = self.slot(client, table, expected, epoll_fd)?.description;
        self.epoll_state(epoll_description)?;
        let target_description = self.slot(client, table, expected, target_fd)?.description;
        let target = self
            .descriptions
            .get(&target_description)
            .ok_or(AuthorityError::DescriptionNotFound)?;
        if !is_epollable(&target.backing) {
            return Err(AuthorityError::NotEpollable);
        }
        Ok((
            epoll_description,
            EpollInterestKey {
                registered_slot: target_fd,
                target_description,
            },
        ))
    }

    fn epoll_state(&self, description: FileDescriptionId) -> Result<&EpollState, AuthorityError> {
        let state = self
            .descriptions
            .get(&description)
            .ok_or(AuthorityError::DescriptionNotFound)?;
        match &state.backing {
            AuthorityBacking::Epoll(epoll) => Ok(epoll),
            _ => Err(AuthorityError::NotEpoll),
        }
    }

    fn epoll_state_mut(
        &mut self,
        description: FileDescriptionId,
    ) -> Result<&mut EpollState, AuthorityError> {
        let state = self
            .descriptions
            .get_mut(&description)
            .ok_or(AuthorityError::DescriptionNotFound)?;
        match &mut state.backing {
            AuthorityBacking::Epoll(epoll) => Ok(epoll),
            _ => Err(AuthorityError::NotEpoll),
        }
    }

    fn epoll_path_reaches(
        &self,
        current: FileDescriptionId,
        goal: FileDescriptionId,
        depth: usize,
    ) -> bool {
        if current == goal {
            return true;
        }
        let Ok(state) = self.epoll_state(current) else {
            return false;
        };
        if depth >= 5 {
            return state.target_descriptions().next().is_some();
        }
        state
            .target_descriptions()
            .any(|target| self.epoll_path_reaches(target, goal, depth + 1))
    }

    fn acknowledge_epolls_without_publish(
        &mut self,
        description: FileDescriptionId,
        consumed: LinuxEpollEvents,
        read_available: u64,
        write_backpressured: bool,
        revision: Revision,
    ) {
        let epolls: BTreeSet<FileDescriptionId> = self
            .epoll_watchers
            .get(&description)
            .into_iter()
            .flat_map(|watchers| watchers.iter().map(|(epoll, _)| *epoll))
            .collect();
        for epoll in epolls {
            let changed = self
                .epoll_state_mut(epoll)
                .unwrap_or_else(|_| {
                    abort_fatal(AuthorityFatal::InvariantViolation(
                        "epoll acknowledgement lost an indexed watcher",
                    ))
                })
                .acknowledge_io(description, consumed, read_available, write_backpressured);
            if changed {
                self.descriptions
                    .get_mut(&epoll)
                    .unwrap_or_else(|| {
                        abort_fatal(AuthorityFatal::InvariantViolation(
                            "epoll acknowledgement lost an indexed description",
                        ))
                    })
                    .revision = revision;
            }
        }
    }

    fn read_pipe_description(
        &mut self,
        description: FileDescriptionId,
        maximum: ByteCount,
    ) -> Result<Outcome, AuthorityError> {
        let (pipe, end) = self.pipe_for_description(description)?;
        if end != PipeEnd::Reader {
            return Err(AuthorityError::NotReadable);
        }
        let bytes = self
            .streams
            .get_mut(&pipe)
            .ok_or(AuthorityError::NotPipe)?
            .read(usize::try_from(maximum.raw()).map_err(|_| AuthorityError::PayloadTooLarge)?)?;
        let revision = self.publish_mutation();
        self.stream_revisions.insert(pipe, revision);
        self.refresh_pipe_descriptions(pipe, revision);
        self.acknowledge_epolls_without_publish(
            description,
            LinuxEpollEvents::IN,
            self.descriptions
                .get(&description)
                .map_or(0, |state| state.readiness.read_available),
            false,
            revision,
        );
        Ok(Outcome::StreamBytes {
            pipe,
            bytes,
            description_revision: revision,
            stream_revision: revision,
        })
    }

    fn write_pipe_description(
        &mut self,
        description: FileDescriptionId,
        bytes: &[u8],
    ) -> Result<Outcome, AuthorityError> {
        self.validate_payload(bytes)?;
        let (pipe, end) = self.pipe_for_description(description)?;
        if end != PipeEnd::Writer {
            return Err(AuthorityError::NotWritable);
        }
        let written = self
            .streams
            .get_mut(&pipe)
            .ok_or(AuthorityError::NotPipe)?
            .write(bytes)?;
        let count = ByteCount::bounded(
            u32::try_from(written).map_err(|_| AuthorityError::PayloadTooLarge)?,
        )?;
        let revision = self.publish_mutation();
        self.stream_revisions.insert(pipe, revision);
        self.refresh_pipe_descriptions(pipe, revision);
        Ok(Outcome::StreamWritten {
            pipe,
            count,
            description_revision: revision,
            stream_revision: revision,
        })
    }

    fn read_timer_description(
        &mut self,
        description: FileDescriptionId,
        maximum: ByteCount,
    ) -> Result<Outcome, AuthorityError> {
        if maximum.raw() < 8 {
            return Err(AuthorityError::InvalidOffset);
        }
        let pending = match self
            .descriptions
            .get(&description)
            .ok_or(AuthorityError::DescriptionNotFound)?
            .backing
        {
            AuthorityBacking::Timer { pending, .. } if pending > 0 => pending,
            AuthorityBacking::Timer { .. } => return Err(AuthorityError::WouldBlock),
            _ => return Err(AuthorityError::NotTimer),
        };
        let revision = self.publish_mutation();
        let state = self.descriptions.get_mut(&description).unwrap_or_else(|| {
            abort_fatal(AuthorityFatal::InvariantViolation(
                "timer read lost its description",
            ))
        });
        let AuthorityBacking::Timer {
            pending: stored, ..
        } = &mut state.backing
        else {
            abort_fatal(AuthorityFatal::InvariantViolation("timer backing changed"));
        };
        *stored = 0;
        state.readiness = ReadinessSnapshot {
            ready: LinuxEpollEvents::empty(),
            read_available: 0,
        };
        state.revision = revision;
        Ok(Outcome::Bytes {
            bytes: pending.to_ne_bytes().to_vec(),
            offset: state.offset,
            description_revision: revision,
        })
    }

    fn read_host_stream_description(
        &mut self,
        description: FileDescriptionId,
        maximum: ByteCount,
    ) -> Result<Outcome, AuthorityError> {
        let fd = match &self
            .descriptions
            .get(&description)
            .ok_or(AuthorityError::DescriptionNotFound)?
            .backing
        {
            AuthorityBacking::HostStream { fd, .. } => fd.as_raw_fd(),
            _ => return Err(AuthorityError::WrongOperationFamily),
        };
        let mut bytes = vec![0; usize::try_from(maximum.raw()).unwrap_or(usize::MAX)];
        let read = unsafe { libc::read(fd, bytes.as_mut_ptr().cast(), bytes.len()) };
        if read < 0 {
            let error = HostErrno::last();
            if error.raw() == libc::EAGAIN {
                return Err(AuthorityError::WouldBlock);
            }
            return Err(AuthorityError::HostIo(error));
        }
        bytes.truncate(usize::try_from(read).map_err(|_| AuthorityError::InvalidOffset)?);
        let revision = self.publish_mutation();
        let state = self.descriptions.get_mut(&description).unwrap_or_else(|| {
            abort_fatal(AuthorityFatal::InvariantViolation(
                "host-stream read lost its description",
            ))
        });
        state.revision = revision;
        Ok(Outcome::Bytes {
            bytes,
            offset: state.offset,
            description_revision: revision,
        })
    }

    fn write_host_stream_description(
        &mut self,
        description: FileDescriptionId,
        bytes: &[u8],
    ) -> Result<Outcome, AuthorityError> {
        self.validate_payload(bytes)?;
        let fd = match &self
            .descriptions
            .get(&description)
            .ok_or(AuthorityError::DescriptionNotFound)?
            .backing
        {
            AuthorityBacking::HostStream { fd, .. } => fd.as_raw_fd(),
            _ => return Err(AuthorityError::WrongOperationFamily),
        };
        let written = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
        if written < 0 {
            let error = HostErrno::last();
            if error.raw() == libc::EAGAIN {
                return Err(AuthorityError::WouldBlock);
            }
            return Err(AuthorityError::HostIo(error));
        }
        let count = ByteCount::bounded(
            u32::try_from(written).map_err(|_| AuthorityError::PayloadTooLarge)?,
        )?;
        let revision = self.publish_mutation();
        let state = self.descriptions.get_mut(&description).unwrap_or_else(|| {
            abort_fatal(AuthorityFatal::InvariantViolation(
                "host-stream write lost its description",
            ))
        });
        state.revision = revision;
        Ok(Outcome::Written {
            count,
            offset: state.offset,
            description_revision: revision,
            object_revision: None,
        })
    }

    fn pipe_for_slot(
        &self,
        client: ClientIdentity,
        table: FileTableId,
        expected: ObjectGeneration,
        fd: FileSlotNumber,
    ) -> Result<(PipeId, PipeEnd), AuthorityError> {
        let description = self.slot(client, table, expected, fd)?.description;
        self.pipe_for_description(description)
    }

    fn pipe_for_description(
        &self,
        description: FileDescriptionId,
    ) -> Result<(PipeId, PipeEnd), AuthorityError> {
        let state = self
            .descriptions
            .get(&description)
            .ok_or(AuthorityError::DescriptionNotFound)?;
        match state.backing {
            AuthorityBacking::PipeEnd { pipe, end } => Ok((pipe, end)),
            _ => Err(AuthorityError::NotPipe),
        }
    }

    fn pipe_readiness(&self, pipe: PipeId, end: PipeEnd) -> ReadinessSnapshot {
        let stream = self.streams.get(&pipe).unwrap_or_else(|| {
            abort_fatal(AuthorityFatal::InvariantViolation(
                "pipe description referenced a missing stream",
            ))
        });
        ReadinessSnapshot {
            ready: stream.readiness(end),
            read_available: if end == PipeEnd::Reader {
                stream.readable_bytes()
            } else {
                0
            },
        }
    }

    fn refresh_pipe_descriptions(&mut self, pipe: PipeId, revision: Revision) {
        let updates: Vec<(FileDescriptionId, PipeEnd, ReadinessSnapshot)> = self
            .descriptions
            .iter()
            .filter_map(|(description, state)| match state.backing {
                AuthorityBacking::PipeEnd { pipe: current, end } if current == pipe => {
                    Some((*description, end, self.pipe_readiness(pipe, end)))
                }
                _ => None,
            })
            .collect();
        for (description, _, readiness) in updates {
            let state = self.descriptions.get_mut(&description).unwrap_or_else(|| {
                abort_fatal(AuthorityFatal::InvariantViolation(
                    "pipe readiness refresh lost a description",
                ))
            });
            state.readiness = readiness;
            state.revision = revision;
        }
    }

    fn read(
        &mut self,
        client: ClientIdentity,
        table: FileTableId,
        expected: ObjectGeneration,
        fd: FileSlotNumber,
        maximum: ByteCount,
    ) -> Result<Outcome, AuthorityError> {
        let slot = self.slot(client, table, expected, fd)?.clone();
        let description = self
            .descriptions
            .get(&slot.description)
            .ok_or(AuthorityError::DescriptionNotFound)?;
        if !description.access_mode.readable() {
            return Err(AuthorityError::NotReadable);
        }
        if matches!(description.backing, AuthorityBacking::PipeEnd { .. }) {
            return self.read_pipe_description(slot.description, maximum);
        }
        if matches!(description.backing, AuthorityBacking::HostStream { .. }) {
            return self.read_host_stream_description(slot.description, maximum);
        }
        if matches!(description.backing, AuthorityBacking::Timer { .. }) {
            return self.read_timer_description(slot.description, maximum);
        }
        let offset = description.offset;
        let start = usize::try_from(offset.raw()).map_err(|_| AuthorityError::InvalidOffset)?;
        let maximum =
            usize::try_from(maximum.raw()).map_err(|_| AuthorityError::PayloadTooLarge)?;
        let bytes: Vec<u8> = match &description.backing {
            AuthorityBacking::Vfs { object } => {
                let object = self
                    .vfs_objects
                    .get(object)
                    .ok_or(AuthorityError::VfsNotFound)?;
                object.contents[start.min(object.contents.len())..]
                    .iter()
                    .take(maximum)
                    .copied()
                    .collect()
            }
            AuthorityBacking::Synthetic { contents } => contents[start.min(contents.len())..]
                .iter()
                .take(maximum)
                .copied()
                .collect(),
            AuthorityBacking::Host { fd, .. } => {
                let mut bytes = vec![0; maximum];
                let read = unsafe {
                    libc::pread(
                        fd.as_raw_fd(),
                        bytes.as_mut_ptr().cast(),
                        bytes.len(),
                        libc::off_t::try_from(offset.raw())
                            .map_err(|_| AuthorityError::InvalidOffset)?,
                    )
                };
                if read < 0 {
                    return Err(AuthorityError::HostIo(super::HostErrno::last()));
                }
                bytes.truncate(usize::try_from(read).map_err(|_| AuthorityError::InvalidOffset)?);
                bytes
            }
            AuthorityBacking::Epoll(_)
            | AuthorityBacking::EventCounter { .. }
            | AuthorityBacking::PipeEnd { .. }
            | AuthorityBacking::IoUring { .. }
            | AuthorityBacking::HostStream { .. }
            | AuthorityBacking::Timer { .. } => {
                return Err(AuthorityError::WrongOperationFamily);
            }
        };
        let next = offset
            .raw()
            .checked_add(u64::try_from(bytes.len()).map_err(|_| AuthorityError::InvalidOffset)?)
            .ok_or(AuthorityError::InvalidOffset)?;
        let revision = self.publish_mutation();
        let description = self
            .descriptions
            .get_mut(&slot.description)
            .unwrap_or_else(|| {
                abort_fatal(AuthorityFatal::InvariantViolation(
                    "read lost its validated description",
                ))
            });
        description.offset = FileOffset::from_start(next);
        description.revision = revision;
        Ok(Outcome::Bytes {
            bytes,
            offset: description.offset,
            description_revision: revision,
        })
    }

    fn write(
        &mut self,
        client: ClientIdentity,
        table: FileTableId,
        expected: ObjectGeneration,
        fd: FileSlotNumber,
        bytes: &[u8],
    ) -> Result<Outcome, AuthorityError> {
        self.validate_payload(bytes)?;
        let slot = self.slot(client, table, expected, fd)?.clone();
        let description = self
            .descriptions
            .get(&slot.description)
            .ok_or(AuthorityError::DescriptionNotFound)?;
        if !description.access_mode.writable() {
            return Err(AuthorityError::NotWritable);
        }
        if matches!(description.backing, AuthorityBacking::PipeEnd { .. }) {
            return self.write_pipe_description(slot.description, bytes);
        }
        if matches!(description.backing, AuthorityBacking::HostStream { .. }) {
            return self.write_host_stream_description(slot.description, bytes);
        }
        let start =
            usize::try_from(description.offset.raw()).map_err(|_| AuthorityError::InvalidOffset)?;
        let object = description.backing.vfs_object();
        if object.is_some_and(|object| !self.vfs_objects.contains_key(&object)) {
            abort_fatal(AuthorityFatal::InvariantViolation(
                "write description referenced a missing VFS object",
            ));
        }
        let written = match &description.backing {
            AuthorityBacking::Host { fd, writable } => {
                if !writable {
                    return Err(AuthorityError::BackingReadOnly);
                }
                let written = unsafe {
                    libc::pwrite(
                        fd.as_raw_fd(),
                        bytes.as_ptr().cast(),
                        bytes.len(),
                        libc::off_t::try_from(description.offset.raw())
                            .map_err(|_| AuthorityError::InvalidOffset)?,
                    )
                };
                if written < 0 {
                    return Err(AuthorityError::HostIo(super::HostErrno::last()));
                }
                usize::try_from(written).map_err(|_| AuthorityError::InvalidOffset)?
            }
            AuthorityBacking::Synthetic { .. } | AuthorityBacking::Vfs { .. } => bytes.len(),
            AuthorityBacking::Epoll(_)
            | AuthorityBacking::EventCounter { .. }
            | AuthorityBacking::PipeEnd { .. }
            | AuthorityBacking::IoUring { .. }
            | AuthorityBacking::HostStream { .. }
            | AuthorityBacking::Timer { .. } => {
                return Err(AuthorityError::WrongOperationFamily);
            }
        };
        let count = ByteCount::bounded(
            u32::try_from(written).map_err(|_| AuthorityError::PayloadTooLarge)?,
        )?;
        let end = start
            .checked_add(written)
            .ok_or(AuthorityError::InvalidOffset)?;
        let end_offset = u64::try_from(end).map_err(|_| AuthorityError::InvalidOffset)?;
        let revision = self.publish_mutation();
        match object {
            Some(object) => {
                let state = self.vfs_objects.get_mut(&object).unwrap_or_else(|| {
                    abort_fatal(AuthorityFatal::InvariantViolation(
                        "write lost its validated VFS object",
                    ))
                });
                if state.contents.len() < end {
                    state.contents.resize(end, 0);
                }
                state.contents[start..end].copy_from_slice(&bytes[..written]);
                state.revision = revision;
            }
            None => match &mut self
                .descriptions
                .get_mut(&slot.description)
                .unwrap_or_else(|| {
                    abort_fatal(AuthorityFatal::InvariantViolation(
                        "write lost its validated description backing",
                    ))
                })
                .backing
            {
                AuthorityBacking::Synthetic { contents } => {
                    if contents.len() < end {
                        contents.resize(end, 0);
                    }
                    contents[start..end].copy_from_slice(&bytes[..written]);
                }
                AuthorityBacking::Host { .. } => {}
                AuthorityBacking::Vfs { .. } => unreachable!(),
                AuthorityBacking::Epoll(_)
                | AuthorityBacking::EventCounter { .. }
                | AuthorityBacking::PipeEnd { .. }
                | AuthorityBacking::IoUring { .. }
                | AuthorityBacking::HostStream { .. }
                | AuthorityBacking::Timer { .. } => {
                    abort_fatal(AuthorityFatal::InvariantViolation(
                        "generic write reached a typed-operation backing",
                    ));
                }
            },
        }
        let description = self
            .descriptions
            .get_mut(&slot.description)
            .unwrap_or_else(|| {
                abort_fatal(AuthorityFatal::InvariantViolation(
                    "write lost its validated description",
                ))
            });
        description.offset = FileOffset::from_start(end_offset);
        description.revision = revision;
        Ok(Outcome::Written {
            count,
            offset: description.offset,
            description_revision: revision,
            object_revision: object.map(|_| revision),
        })
    }

    fn seek(
        &mut self,
        client: ClientIdentity,
        table: FileTableId,
        expected: ObjectGeneration,
        fd: FileSlotNumber,
        offset: i64,
        whence: SeekWhence,
    ) -> Result<Outcome, AuthorityError> {
        let slot = self.slot(client, table, expected, fd)?.clone();
        let description = self
            .descriptions
            .get(&slot.description)
            .ok_or(AuthorityError::DescriptionNotFound)?;
        if !description.access_mode.seekable() {
            return Err(AuthorityError::NotSeekable);
        }
        let base = match whence {
            SeekWhence::Start => 0,
            SeekWhence::Current => i64::try_from(description.offset.raw())
                .map_err(|_| AuthorityError::InvalidOffset)?,
            SeekWhence::End => i64::try_from(self.backing_len(&description.backing)?)
                .map_err(|_| AuthorityError::InvalidOffset)?,
        };
        let next = base
            .checked_add(offset)
            .filter(|next| *next >= 0)
            .ok_or(AuthorityError::InvalidOffset)?;
        let next = u64::try_from(next).map_err(|_| AuthorityError::InvalidOffset)?;
        let revision = self.publish_mutation();
        let description = self
            .descriptions
            .get_mut(&slot.description)
            .unwrap_or_else(|| {
                abort_fatal(AuthorityFatal::InvariantViolation(
                    "seek lost its validated description",
                ))
            });
        description.offset = FileOffset::from_start(next);
        description.revision = revision;
        Ok(Outcome::Seeked {
            offset: description.offset,
            description_revision: revision,
        })
    }

    fn close(
        &mut self,
        client: ClientIdentity,
        table: FileTableId,
        expected: ObjectGeneration,
        fd: FileSlotNumber,
    ) -> Result<Outcome, AuthorityError> {
        self.require_bound_table(client, table, expected)?;
        let slot = self
            .tables
            .get(&table)
            .and_then(|table| table.slots.get(&fd))
            .cloned()
            .ok_or(AuthorityError::SlotNotFound)?;
        let revision = self.publish_mutation();
        let table_state = self.tables.get_mut(&table).unwrap_or_else(|| {
            abort_fatal(AuthorityFatal::InvariantViolation(
                "close lost its validated file table",
            ))
        });
        table_state.slots.remove(&fd);
        table_state.revision = revision;
        let (description_reclaimed, object_reclaimed) =
            self.release_description_ref(slot.description, revision);
        Ok(Outcome::Closed {
            description: slot.description,
            description_reclaimed,
            object_reclaimed,
            table_revision: revision,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn duplicate(
        &mut self,
        client: ClientIdentity,
        table: FileTableId,
        expected: ObjectGeneration,
        source: FileSlotNumber,
        minimum: FileSlotNumber,
        ceiling: NofileAllocationCeiling,
        flags: DescriptorFlags,
    ) -> Result<Outcome, AuthorityError> {
        let source_slot = self.slot(client, table, expected, source)?.clone();
        let description = self
            .descriptions
            .get(&source_slot.description)
            .ok_or(AuthorityError::DescriptionNotFound)?;
        let logical_slot_refs = description
            .logical_slot_refs
            .checked_add(1)
            .unwrap_or_else(|| {
                abort_fatal(AuthorityFatal::InvariantViolation(
                    "logical slot reference overflow during dup",
                ))
            });
        let fd = self.allocate_lowest(table, minimum, ceiling)?;
        let revision = self.publish_mutation();
        let table_state = self.tables.get_mut(&table).unwrap_or_else(|| {
            abort_fatal(AuthorityFatal::InvariantViolation(
                "dup lost its validated file table",
            ))
        });
        table_state.slots.insert(
            fd,
            FileSlotState {
                flags,
                ..source_slot.clone()
            },
        );
        table_state.revision = revision;
        let description = self
            .descriptions
            .get_mut(&source_slot.description)
            .unwrap_or_else(|| {
                abort_fatal(AuthorityFatal::InvariantViolation(
                    "dup lost its validated source description",
                ))
            });
        description.logical_slot_refs = logical_slot_refs;
        description.revision = revision;
        Ok(Outcome::Duplicated {
            source,
            fd,
            table_revision: revision,
        })
    }

    fn fork_copy(
        &mut self,
        client: ClientIdentity,
        source: FileTableId,
        expected: ObjectGeneration,
        owner: ClientIdentity,
    ) -> Result<Outcome, AuthorityError> {
        self.require_registered(owner)?;
        let source_state = self.bound_table(client, source, expected)?;
        let slots = source_state.slots.clone();
        let prepared_refs = self.prepare_ref_increments(&slots);
        let table = self.allocate_table();
        let revision = self.publish_mutation();
        for (description_id, logical_slot_refs) in prepared_refs {
            let description = self
                .descriptions
                .get_mut(&description_id)
                .unwrap_or_else(|| {
                    abort_fatal(AuthorityFatal::InvariantViolation(
                        "fork lost its validated description",
                    ))
                });
            description.logical_slot_refs = logical_slot_refs;
            description.revision = revision;
        }
        self.tables.insert(
            table,
            FileTableState {
                generation: ObjectGeneration::INITIAL,
                revision,
                slots,
                bindings: HashSet::from([owner]),
            },
        );
        Ok(Outcome::ForkCopied {
            source,
            table,
            generation: ObjectGeneration::INITIAL,
            revision,
        })
    }

    fn fork_copy_mappings(
        &mut self,
        client: ClientIdentity,
        source_owner: ClientIdentity,
        owner: ClientIdentity,
    ) -> Result<Outcome, AuthorityError> {
        if client != source_owner {
            return Err(AuthorityError::StaleClientGeneration);
        }
        self.require_registered(owner)?;
        let source: Vec<(FileDescriptionId, Vec<MappingRange>)> = self
            .mapping_attachments
            .values()
            .filter_map(|state| {
                (state.owner == source_owner).then_some((state.description, state.ranges.clone()))
            })
            .collect();
        let mut prepared_refs = HashMap::new();
        for (description, _) in &source {
            let count = prepared_refs.entry(*description).or_insert_with(|| {
                self.descriptions
                    .get(description)
                    .unwrap_or_else(|| {
                        abort_fatal(AuthorityFatal::InvariantViolation(
                            "mapping copy referenced a missing description",
                        ))
                    })
                    .capability_lease_refs
            });
            *count = count.checked_add(1).unwrap_or_else(|| {
                abort_fatal(AuthorityFatal::InvariantViolation(
                    "mapping copy reference overflow",
                ))
            });
        }
        let attachments: Vec<MappingAttachmentId> = (0..source.len())
            .map(|_| self.allocate_mapping_attachment())
            .collect();
        let revision = self.publish_mutation();
        for (description, refs) in prepared_refs {
            let state = self.descriptions.get_mut(&description).unwrap_or_else(|| {
                abort_fatal(AuthorityFatal::InvariantViolation(
                    "mapping copy lost its description",
                ))
            });
            state.capability_lease_refs = refs;
            state.revision = revision;
        }
        for (attachment, (description, ranges)) in attachments.iter().copied().zip(source) {
            self.mapping_attachments.insert(
                attachment,
                MappingAttachmentState {
                    owner,
                    description,
                    ranges,
                },
            );
        }
        Ok(Outcome::MappingAttachmentsCopied {
            source_owner,
            owner,
            attachments,
            revision,
        })
    }

    fn share_table(
        &mut self,
        client: ClientIdentity,
        table: FileTableId,
        expected: ObjectGeneration,
        owner: ClientIdentity,
    ) -> Result<Outcome, AuthorityError> {
        self.require_registered(owner)?;
        self.require_bound_table(client, table, expected)?;
        let revision = self.publish_mutation();
        let state = self.tables.get_mut(&table).unwrap_or_else(|| {
            abort_fatal(AuthorityFatal::InvariantViolation(
                "table share lost its validated file table",
            ))
        });
        state.bindings.insert(owner);
        state.revision = revision;
        Ok(Outcome::TableShared { table, revision })
    }

    fn exec_successor(
        &mut self,
        client: ClientIdentity,
        source: FileTableId,
        expected: ObjectGeneration,
    ) -> Result<Outcome, AuthorityError> {
        let source_state = self.bound_table(client, source, expected)?;
        let surviving: BTreeMap<_, _> = source_state
            .slots
            .iter()
            .filter(|(_, slot)| !slot.flags.close_on_exec())
            .map(|(fd, slot)| (*fd, slot.clone()))
            .collect();
        let closed_on_exec = source_state
            .slots
            .iter()
            .filter_map(|(fd, slot)| slot.flags.close_on_exec().then_some(*fd))
            .collect();
        let source_slots = source_state.slots.clone();
        let source_becomes_unbound = source_state.bindings.len() == 1;
        let prepared_refs = self.prepare_ref_increments(&surviving);
        let table = self.allocate_table();
        let revision = self.publish_mutation();
        for (description_id, logical_slot_refs) in prepared_refs {
            let description = self
                .descriptions
                .get_mut(&description_id)
                .unwrap_or_else(|| {
                    abort_fatal(AuthorityFatal::InvariantViolation(
                        "exec lost its validated surviving description",
                    ))
                });
            description.logical_slot_refs = logical_slot_refs;
            description.revision = revision;
        }
        if source_becomes_unbound {
            self.tables.remove(&source).unwrap_or_else(|| {
                abort_fatal(AuthorityFatal::InvariantViolation(
                    "exec lost its source file table",
                ))
            });
            for slot in source_slots.values() {
                self.release_description_ref(slot.description, revision);
            }
        } else {
            let source_state = self.tables.get_mut(&source).unwrap_or_else(|| {
                abort_fatal(AuthorityFatal::InvariantViolation(
                    "exec lost its shared source file table",
                ))
            });
            source_state.bindings.remove(&client);
            source_state.revision = revision;
        }
        self.tables.insert(
            table,
            FileTableState {
                generation: ObjectGeneration::INITIAL,
                revision,
                slots: surviving,
                bindings: HashSet::from([client]),
            },
        );
        Ok(Outcome::ExecSucceeded {
            source,
            table,
            generation: ObjectGeneration::INITIAL,
            closed_on_exec,
            revision,
        })
    }

    fn inspect_description(
        &self,
        description: FileDescriptionId,
        expected: ObjectGeneration,
    ) -> Result<Outcome, AuthorityError> {
        let state = self
            .descriptions
            .get(&description)
            .ok_or(AuthorityError::DescriptionNotFound)?;
        self.check_generation(state.generation, expected)?;
        Ok(Outcome::Description(state.snapshot(description)))
    }

    fn slot(
        &self,
        client: ClientIdentity,
        table: FileTableId,
        expected: ObjectGeneration,
        fd: FileSlotNumber,
    ) -> Result<&FileSlotState, AuthorityError> {
        self.bound_table(client, table, expected)?
            .slots
            .get(&fd)
            .ok_or(AuthorityError::SlotNotFound)
    }

    fn bound_table(
        &self,
        client: ClientIdentity,
        table: FileTableId,
        expected: ObjectGeneration,
    ) -> Result<&FileTableState, AuthorityError> {
        let state = self
            .tables
            .get(&table)
            .ok_or(AuthorityError::TableNotFound)?;
        self.check_generation(state.generation, expected)?;
        if !state.bindings.contains(&client) {
            return Err(AuthorityError::TableNotBound);
        }
        Ok(state)
    }

    fn require_bound_table(
        &self,
        client: ClientIdentity,
        table: FileTableId,
        expected: ObjectGeneration,
    ) -> Result<(), AuthorityError> {
        self.bound_table(client, table, expected).map(|_| ())
    }

    fn allocate_pair(
        &self,
        table: FileTableId,
        minimum: FileSlotNumber,
        ceiling: NofileAllocationCeiling,
    ) -> Result<(FileSlotNumber, FileSlotNumber), AuthorityError> {
        let first = self.allocate_lowest(table, minimum, ceiling)?;
        let next_raw = first
            .raw()
            .checked_add(1)
            .ok_or(AuthorityError::PairAllocationFailed)?;
        let next = FileSlotNumber::for_open_fd(next_raw)
            .map_err(|_| AuthorityError::PairAllocationFailed)?;
        let second = self.allocate_lowest(table, next, ceiling)?;
        if second == first {
            return Err(AuthorityError::PairAllocationFailed);
        }
        Ok((first, second))
    }

    fn allocate_lowest(
        &self,
        table: FileTableId,
        minimum: FileSlotNumber,
        ceiling: NofileAllocationCeiling,
    ) -> Result<FileSlotNumber, AuthorityError> {
        let state = self
            .tables
            .get(&table)
            .ok_or(AuthorityError::TableNotFound)?;
        let ceiling = i32::try_from(ceiling.raw()).unwrap_or(i32::MAX);
        let mut raw = minimum.raw();
        while raw < ceiling {
            let fd =
                FileSlotNumber::for_open_fd(raw).map_err(|_| AuthorityError::NofileExceeded)?;
            if !state.slots.contains_key(&fd) {
                return Ok(fd);
            }
            raw = raw.checked_add(1).ok_or(AuthorityError::NofileExceeded)?;
        }
        Err(AuthorityError::NofileExceeded)
    }

    fn prepare_ref_increments(
        &self,
        slots: &BTreeMap<FileSlotNumber, FileSlotState>,
    ) -> HashMap<FileDescriptionId, u64> {
        let mut increments: HashMap<FileDescriptionId, u64> = HashMap::new();
        for slot in slots.values() {
            let count = increments.entry(slot.description).or_default();
            *count = count.checked_add(1).unwrap_or_else(|| {
                abort_fatal(AuthorityFatal::InvariantViolation(
                    "fork/exec reference increment overflow",
                ))
            });
        }
        increments
            .into_iter()
            .map(|(description, increment)| {
                let logical_slot_refs = self
                    .descriptions
                    .get(&description)
                    .unwrap_or_else(|| {
                        abort_fatal(AuthorityFatal::InvariantViolation(
                            "table slot referenced a missing description",
                        ))
                    })
                    .logical_slot_refs
                    .checked_add(increment)
                    .unwrap_or_else(|| {
                        abort_fatal(AuthorityFatal::InvariantViolation(
                            "logical slot reference overflow during lifecycle preparation",
                        ))
                    });
                (description, logical_slot_refs)
            })
            .collect()
    }

    fn release_description_ref(
        &mut self,
        description: FileDescriptionId,
        revision: Revision,
    ) -> (bool, bool) {
        let state = self.descriptions.get_mut(&description).unwrap_or_else(|| {
            abort_fatal(AuthorityFatal::InvariantViolation(
                "slot referenced a missing description",
            ))
        });
        state.logical_slot_refs = state.logical_slot_refs.checked_sub(1).unwrap_or_else(|| {
            abort_fatal(AuthorityFatal::InvariantViolation(
                "logical slot reference underflow",
            ))
        });
        state.revision = revision;
        self.reclaim_description_if_unreferenced(description, revision)
    }

    fn release_capability_lease_ref(
        &mut self,
        description: FileDescriptionId,
        revision: Revision,
    ) -> (bool, bool) {
        let state = self.descriptions.get_mut(&description).unwrap_or_else(|| {
            abort_fatal(AuthorityFatal::InvariantViolation(
                "capability lease referenced a missing description",
            ))
        });
        state.capability_lease_refs =
            state
                .capability_lease_refs
                .checked_sub(1)
                .unwrap_or_else(|| {
                    abort_fatal(AuthorityFatal::InvariantViolation(
                        "capability lease reference underflow",
                    ))
                });
        state.revision = revision;
        self.reclaim_description_if_unreferenced(description, revision)
    }

    fn reclaim_description_if_unreferenced(
        &mut self,
        description: FileDescriptionId,
        revision: Revision,
    ) -> (bool, bool) {
        let reclaim = self
            .descriptions
            .get(&description)
            .is_some_and(|state| state.logical_slot_refs == 0 && state.capability_lease_refs == 0);
        if !reclaim {
            return (false, false);
        }
        self.detach_reclaimed_description_from_epolls(description, revision);
        let pipe_end = self
            .descriptions
            .get(&description)
            .and_then(|state| match state.backing {
                AuthorityBacking::PipeEnd { pipe, end } => Some((pipe, end)),
                _ => None,
            });
        if let Some((pipe, end)) = pipe_end {
            let stream = self.streams.get_mut(&pipe).unwrap_or_else(|| {
                abort_fatal(AuthorityFatal::InvariantViolation(
                    "reclaimed pipe description referenced a missing stream",
                ))
            });
            stream.release(end);
        }
        let state = self.descriptions.remove(&description).unwrap_or_else(|| {
            abort_fatal(AuthorityFatal::InvariantViolation(
                "reclaim lost its unreferenced description",
            ))
        });
        if let Some((pipe, _)) = pipe_end {
            if self
                .streams
                .get(&pipe)
                .is_some_and(PipeStreamState::is_unreferenced)
            {
                self.streams.remove(&pipe);
                self.stream_revisions.remove(&pipe);
            } else {
                self.stream_revisions.insert(pipe, revision);
                self.refresh_pipe_descriptions(pipe, revision);
            }
        }
        let Some(object) = state.backing.vfs_object() else {
            return (true, false);
        };
        let object_state = self.vfs_objects.get_mut(&object).unwrap_or_else(|| {
            abort_fatal(AuthorityFatal::InvariantViolation(
                "VFS description referenced a missing object",
            ))
        });
        object_state.revision = revision;
        object_state.open_description_refs = object_state
            .open_description_refs
            .checked_sub(1)
            .unwrap_or_else(|| {
                abort_fatal(AuthorityFatal::InvariantViolation(
                    "VFS open-description reference underflow",
                ))
            });
        (true, self.maybe_reclaim_vfs_object(object))
    }

    fn detach_reclaimed_description_from_epolls(
        &mut self,
        description: FileDescriptionId,
        revision: Revision,
    ) {
        if let Some(watchers) = self.epoll_watchers.remove(&description) {
            let epolls: BTreeSet<FileDescriptionId> =
                watchers.iter().map(|(epoll, _)| *epoll).collect();
            for (epoll, key) in watchers {
                let state = self.epoll_state_mut(epoll).unwrap_or_else(|_| {
                    abort_fatal(AuthorityFatal::InvariantViolation(
                        "reverse epoll index referenced a missing instance",
                    ))
                });
                if state.delete(key).is_none() {
                    abort_fatal(AuthorityFatal::InvariantViolation(
                        "reverse epoll index referenced a missing interest",
                    ));
                }
            }
            for epoll in epolls {
                self.descriptions
                    .get_mut(&epoll)
                    .unwrap_or_else(|| {
                        abort_fatal(AuthorityFatal::InvariantViolation(
                            "epoll auto-detach lost an instance description",
                        ))
                    })
                    .revision = revision;
            }
        }
        let epoll_keys: Vec<EpollInterestKey> = self
            .epoll_state(description)
            .map(|state| state.keys().collect())
            .unwrap_or_default();
        for key in epoll_keys {
            if let Some(watchers) = self.epoll_watchers.get_mut(&key.target_description) {
                watchers.remove(&(description, key));
                if watchers.is_empty() {
                    self.epoll_watchers.remove(&key.target_description);
                }
            }
        }
    }

    fn maybe_reclaim_vfs_object(&mut self, object: VfsObjectId) -> bool {
        let reclaim = self
            .vfs_objects
            .get(&object)
            .is_some_and(|state| state.namespace_links == 0 && state.open_description_refs == 0);
        if reclaim {
            self.vfs_objects.remove(&object);
        }
        reclaim
    }

    fn backing_len(&self, backing: &AuthorityBacking) -> Result<u64, AuthorityError> {
        match backing {
            AuthorityBacking::Synthetic { contents } => {
                u64::try_from(contents.len()).map_err(|_| AuthorityError::InvalidOffset)
            }
            AuthorityBacking::Vfs { object } => self
                .vfs_objects
                .get(object)
                .ok_or(AuthorityError::VfsNotFound)
                .and_then(|state| {
                    u64::try_from(state.contents.len()).map_err(|_| AuthorityError::InvalidOffset)
                }),
            AuthorityBacking::Host { fd, .. } => {
                // This is an authority-side metadata attempt, not client MM or
                // guest-memory work. It stays bounded to one nonblocking fstat.
                let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
                if unsafe { libc::fstat(fd.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
                    return Err(AuthorityError::HostIo(super::HostErrno::last()));
                }
                let stat = unsafe { stat.assume_init() };
                u64::try_from(stat.st_size).map_err(|_| AuthorityError::InvalidOffset)
            }
            AuthorityBacking::Epoll(_)
            | AuthorityBacking::EventCounter { .. }
            | AuthorityBacking::PipeEnd { .. }
            | AuthorityBacking::IoUring { .. }
            | AuthorityBacking::HostStream { .. }
            | AuthorityBacking::Timer { .. } => Err(AuthorityError::NotSeekable),
        }
    }

    fn check_generation(
        &self,
        actual: ObjectGeneration,
        expected: ObjectGeneration,
    ) -> Result<(), AuthorityError> {
        if actual == expected {
            Ok(())
        } else {
            Err(AuthorityError::StaleObjectGeneration)
        }
    }

    fn require_initial(&self, expected: ObjectGeneration) -> Result<(), AuthorityError> {
        self.check_generation(ObjectGeneration::INITIAL, expected)
    }

    fn validate_payload(&self, bytes: &[u8]) -> Result<(), AuthorityError> {
        let len = u32::try_from(bytes.len()).map_err(|_| AuthorityError::PayloadTooLarge)?;
        ByteCount::bounded(len).map(|_| ())
    }

    fn allocate_table(&self) -> FileTableId {
        self.ids
            .file_table_id()
            .unwrap_or_else(|_| abort_fatal(AuthorityFatal::IdentityExhausted))
    }

    fn allocate_description(&self) -> FileDescriptionId {
        self.ids
            .file_description_id()
            .unwrap_or_else(|_| abort_fatal(AuthorityFatal::IdentityExhausted))
    }

    fn allocate_pipe(&mut self) -> PipeId {
        let raw = NonZeroU64::new(self.next_pipe)
            .unwrap_or_else(|| abort_fatal(AuthorityFatal::IdentityExhausted));
        self.next_pipe = self
            .next_pipe
            .checked_add(1)
            .unwrap_or_else(|| abort_fatal(AuthorityFatal::IdentityExhausted));
        PipeId::from_authority_allocation(raw)
    }

    fn allocate_interest_generation(&mut self) -> InterestGeneration {
        let raw = NonZeroU32::new(self.next_interest_generation)
            .unwrap_or_else(|| abort_fatal(AuthorityFatal::IdentityExhausted));
        self.next_interest_generation = self
            .next_interest_generation
            .checked_add(1)
            .unwrap_or_else(|| abort_fatal(AuthorityFatal::IdentityExhausted));
        InterestGeneration::from_authority_allocation(raw)
    }

    fn allocate_mapping_attachment(&mut self) -> MappingAttachmentId {
        let raw = NonZeroU64::new(self.next_mapping_attachment)
            .unwrap_or_else(|| abort_fatal(AuthorityFatal::IdentityExhausted));
        self.next_mapping_attachment = self
            .next_mapping_attachment
            .checked_add(1)
            .unwrap_or_else(|| abort_fatal(AuthorityFatal::IdentityExhausted));
        MappingAttachmentId::from_authority_allocation(raw)
    }

    fn allocate_capability_lease(&mut self) -> CapabilityLeaseId {
        let raw = NonZeroU64::new(self.next_capability_lease)
            .unwrap_or_else(|| abort_fatal(AuthorityFatal::IdentityExhausted));
        self.next_capability_lease = self
            .next_capability_lease
            .checked_add(1)
            .unwrap_or_else(|| abort_fatal(AuthorityFatal::IdentityExhausted));
        CapabilityLeaseId::from_authority_allocation(raw)
    }

    fn allocate_vfs_object(&mut self) -> VfsObjectId {
        let raw = NonZeroU64::new(self.next_vfs_object)
            .unwrap_or_else(|| abort_fatal(AuthorityFatal::IdentityExhausted));
        self.next_vfs_object = self
            .next_vfs_object
            .checked_add(1)
            .unwrap_or_else(|| abort_fatal(AuthorityFatal::IdentityExhausted));
        VfsObjectId::from_authority_allocation(raw)
    }

    fn publish_mutation(&mut self) -> Revision {
        let next = self
            .revision
            .next()
            .unwrap_or_else(|error| abort_fatal(error));
        self.revision = next;
        next
    }
}

fn event_counter_readiness(counter: u64) -> ReadinessSnapshot {
    // eventfd(2): the stored maximum is UINT64_MAX-1 and POLLOUT means
    // at least an increment of one can succeed. Therefore only that exact
    // saturated value suppresses write readiness; a write of zero is valid.
    let mut ready = LinuxEpollEvents::OUT;
    if counter > 0 {
        ready |= LinuxEpollEvents::IN;
    }
    if counter == u64::MAX - 1 {
        ready.remove(LinuxEpollEvents::OUT);
    }
    ReadinessSnapshot {
        ready,
        read_available: u64::from(counter > 0) * 8,
    }
}

fn is_epollable(backing: &AuthorityBacking) -> bool {
    matches!(
        backing,
        AuthorityBacking::Epoll(_)
            | AuthorityBacking::EventCounter { .. }
            | AuthorityBacking::PipeEnd { .. }
    )
}

fn release_mapping_ranges(
    ranges: &[MappingRange],
    release: MappingRelease,
) -> Result<Vec<MappingRange>, AuthorityError> {
    if matches!(release, MappingRelease::Whole) {
        return Ok(Vec::new());
    }
    let MappingRelease::Range(release) = release else {
        return Ok(Vec::new());
    };
    let release_end = release
        .start()
        .checked_add(release.length())
        .ok_or(AuthorityError::InvalidMappingRange)?;
    let mut overlapped = false;
    let mut remaining = Vec::with_capacity(ranges.len().saturating_add(1));
    for range in ranges {
        let range_end = range
            .start()
            .checked_add(range.length())
            .ok_or(AuthorityError::InvalidMappingRange)?;
        let overlap_start = range.start().max(release.start());
        let overlap_end = range_end.min(release_end);
        if overlap_start >= overlap_end {
            remaining.push(*range);
            continue;
        }
        overlapped = true;
        if range.start() < overlap_start {
            remaining.push(MappingRange::bounded(
                range.start(),
                overlap_start - range.start(),
            )?);
        }
        if overlap_end < range_end {
            remaining.push(MappingRange::bounded(overlap_end, range_end - overlap_end)?);
        }
    }
    if !overlapped {
        return Err(AuthorityError::MappingReleaseOutsideAttachment);
    }
    Ok(remaining)
}

fn expected_request_capabilities(command: &Command) -> usize {
    match command {
        Command::AdoptHostFileAndInstall { .. } | Command::AdoptHostStreamAndInstall { .. } => 1,
        Command::AdoptIoUringAndInstall { .. } => 2,
        _ => 0,
    }
}

fn validate_host_stream(
    fd: i32,
    access_mode: AccessMode,
    kind: HostStreamKind,
) -> Result<(), AuthorityError> {
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut stat) } != 0 {
        return Err(AuthorityError::HostIo(HostErrno::last()));
    }
    let host_kind = stat.st_mode & libc::S_IFMT;
    let kind_matches = match kind {
        HostStreamKind::Pipe { .. } => host_kind == libc::S_IFIFO,
        HostStreamKind::Pty(_) | HostStreamKind::CharacterDevice => host_kind == libc::S_IFCHR,
        HostStreamKind::Socket { .. } => host_kind == libc::S_IFSOCK,
    };
    if !kind_matches {
        return Err(AuthorityError::HostBackingTypeMismatch);
    }
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(AuthorityError::HostIo(HostErrno::last()));
    }
    let host_access = flags & libc::O_ACCMODE;
    if (access_mode.readable() && host_access == libc::O_WRONLY)
        || (access_mode.writable() && host_access == libc::O_RDONLY)
    {
        return Err(AuthorityError::HostAccessMismatch);
    }
    Ok(())
}

fn validate_regular_file_length(fd: i32, minimum: u64) -> Result<(), AuthorityError> {
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut stat) } != 0 {
        return Err(AuthorityError::HostIo(HostErrno::last()));
    }
    if stat.st_mode & libc::S_IFMT != libc::S_IFREG
        || stat.st_size < 0
        || u64::try_from(stat.st_size).map_or(true, |length| length < minimum)
    {
        return Err(AuthorityError::HostBackingTypeMismatch);
    }
    Ok(())
}

fn validate_host_file(fd: i32, access_mode: AccessMode) -> Result<(), AuthorityError> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } != 0 {
        return Err(AuthorityError::HostIo(super::HostErrno::last()));
    }
    let stat = unsafe { stat.assume_init() };
    if stat.st_mode & libc::S_IFMT != libc::S_IFREG {
        return Err(AuthorityError::HostBackingTypeMismatch);
    }
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(AuthorityError::HostIo(super::HostErrno::last()));
    }
    let actual = flags & libc::O_ACCMODE;
    let matches = match access_mode {
        AccessMode::ReadOnly => actual == libc::O_RDONLY || actual == libc::O_RDWR,
        AccessMode::WriteOnly => actual == libc::O_WRONLY || actual == libc::O_RDWR,
        AccessMode::ReadWrite => actual == libc::O_RDWR,
        AccessMode::PathOnly => true,
    };
    if !matches {
        return Err(AuthorityError::HostAccessMismatch);
    }
    Ok(())
}

fn ensure_cloexec(fd: i32) -> Result<(), AuthorityFatal> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
        return Err(AuthorityFatal::TransportUnavailable);
    }
    Ok(())
}

fn abort_fatal(error: AuthorityFatal) -> ! {
    tracing::error!(%error, "FileAuthority encountered a run-fatal invariant");
    std::process::abort();
}
