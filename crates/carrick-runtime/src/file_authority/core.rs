use std::collections::{BTreeMap, HashMap, HashSet};
use std::num::NonZeroU64;

use crate::kernel::ObjectIdRegistry;

use super::backing::AuthorityBacking;
use super::types::{
    AccessMode, AuthorityEpoch, AuthorityError, AuthorityFatal, ByteCount, CanonicalPath, ClientId,
    ClientIdentity, Command, DescriptionSnapshot, DescriptorFlags, FileDescriptionId, FileOffset,
    FileSlotNumber, FileTableId, NofileAllocationCeiling, ObjectGeneration, Outcome, Request,
    Response, Revision, SeekWhence, SlotSnapshot, StatusFlags, VfsObjectId,
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
    offset: FileOffset,
    access_mode: AccessMode,
    status_flags: StatusFlags,
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

/// One run's mutable file and writable-memory-VFS authority.
///
/// `execute` is the sole mutation boundary used by both direct and IPC
/// transports. It owns actual bytes and offsets, not a metadata mirror.
#[derive(Debug)]
pub(crate) struct FileAuthorityCore {
    epoch: AuthorityEpoch,
    ids: ObjectIdRegistry,
    next_vfs_object: u64,
    revision: Revision,
    namespace_revision: Revision,
    clients: HashMap<ClientId, ClientIdentity>,
    tables: BTreeMap<FileTableId, FileTableState>,
    descriptions: BTreeMap<FileDescriptionId, FileDescriptionState>,
    namespace: BTreeMap<CanonicalPath, VfsObjectId>,
    vfs_objects: BTreeMap<VfsObjectId, VfsObjectState>,
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
            revision: Revision::ZERO,
            namespace_revision: Revision::ZERO,
            clients: HashMap::new(),
            tables: BTreeMap::new(),
            descriptions: BTreeMap::new(),
            namespace: BTreeMap::new(),
            vfs_objects: BTreeMap::new(),
            dedup: HashMap::new(),
        }
    }

    pub(crate) const fn epoch(&self) -> AuthorityEpoch {
        self.epoch
    }

    pub(crate) const fn revision(&self) -> Revision {
        self.revision
    }

    pub(crate) fn execute(&mut self, request: Request) -> Result<Response, AuthorityFatal> {
        if request.epoch != self.epoch {
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

        let outcome = match self.execute_fresh(&request) {
            Ok(outcome) => outcome,
            Err(error) => Outcome::Rejected(error),
        };
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

    fn execute_fresh(&mut self, request: &Request) -> Result<Outcome, AuthorityError> {
        match &request.command {
            Command::RegisterClient => self.register_client(request),
            _ => {
                self.require_registered(request.client)?;
                match &request.command {
                    Command::RegisterClient => unreachable!(),
                    Command::ExitClient => self.exit_client(request.client),
                    Command::CreateTable => self.create_table(request.client),
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
                    Command::ResolveSlot { table, fd } => {
                        self.resolve_slot(request.client, *table, request.expected_generation, *fd)
                    }
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
            AuthorityBacking::VfsFile { object },
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
            AuthorityBacking::SyntheticFile { contents },
            None,
        ))
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
                offset: FileOffset::default(),
                access_mode,
                status_flags,
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
        let offset = description.offset;
        let start = usize::try_from(offset.raw()).map_err(|_| AuthorityError::InvalidOffset)?;
        let maximum =
            usize::try_from(maximum.raw()).map_err(|_| AuthorityError::PayloadTooLarge)?;
        let bytes: Vec<u8> = match self
            .descriptions
            .get(&slot.description)
            .ok_or(AuthorityError::DescriptionNotFound)?
            .backing
            .vfs_object()
        {
            Some(object) => {
                let object = self
                    .vfs_objects
                    .get(&object)
                    .ok_or(AuthorityError::VfsNotFound)?;
                object.contents[start.min(object.contents.len())..]
                    .iter()
                    .take(maximum)
                    .copied()
                    .collect()
            }
            None => match &self
                .descriptions
                .get(&slot.description)
                .ok_or(AuthorityError::DescriptionNotFound)?
                .backing
            {
                AuthorityBacking::SyntheticFile { contents } => contents
                    [start.min(contents.len())..]
                    .iter()
                    .take(maximum)
                    .copied()
                    .collect(),
                AuthorityBacking::VfsFile { .. } => unreachable!(),
            },
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
        let count = ByteCount::bounded(
            u32::try_from(bytes.len()).map_err(|_| AuthorityError::PayloadTooLarge)?,
        )?;
        let slot = self.slot(client, table, expected, fd)?.clone();
        let description = self
            .descriptions
            .get(&slot.description)
            .ok_or(AuthorityError::DescriptionNotFound)?;
        if !description.access_mode.writable() {
            return Err(AuthorityError::NotWritable);
        }
        let start =
            usize::try_from(description.offset.raw()).map_err(|_| AuthorityError::InvalidOffset)?;
        let end = start
            .checked_add(bytes.len())
            .ok_or(AuthorityError::InvalidOffset)?;
        let object = description.backing.vfs_object();
        if object.is_some_and(|object| !self.vfs_objects.contains_key(&object)) {
            abort_fatal(AuthorityFatal::InvariantViolation(
                "write description referenced a missing VFS object",
            ));
        }
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
                state.contents[start..end].copy_from_slice(bytes);
                state.revision = revision;
            }
            None => match &mut self
                .descriptions
                .get_mut(&slot.description)
                .unwrap_or_else(|| {
                    abort_fatal(AuthorityFatal::InvariantViolation(
                        "write lost its validated synthetic description",
                    ))
                })
                .backing
            {
                AuthorityBacking::SyntheticFile { contents } => {
                    if contents.len() < end {
                        contents.resize(end, 0);
                    }
                    contents[start..end].copy_from_slice(bytes);
                }
                AuthorityBacking::VfsFile { .. } => unreachable!(),
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
        if state.logical_slot_refs != 0 {
            state.revision = revision;
            return (false, false);
        }
        let state = self.descriptions.remove(&description).unwrap_or_else(|| {
            abort_fatal(AuthorityFatal::InvariantViolation(
                "reclaim lost its zero-reference description",
            ))
        });
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
            AuthorityBacking::SyntheticFile { contents } => {
                u64::try_from(contents.len()).map_err(|_| AuthorityError::InvalidOffset)
            }
            AuthorityBacking::VfsFile { object } => self
                .vfs_objects
                .get(object)
                .ok_or(AuthorityError::VfsNotFound)
                .and_then(|state| {
                    u64::try_from(state.contents.len()).map_err(|_| AuthorityError::InvalidOffset)
                }),
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

fn abort_fatal(error: AuthorityFatal) -> ! {
    tracing::error!(%error, "FileAuthority encountered a run-fatal invariant");
    std::process::abort();
}
