//! Production file-table publication into the shared IPC authority.
use super::*;
use crate::el1_ipc::{AdmissionError, HostDescription, HostIpc, HostTable};
use carrick_el1_abi::ipc::{IpcBacking, fd};
use carrick_el1_abi::ipc_tables::IpcTableMap;

/// The host slot map and stdio markers serialize publication. This binding
/// owns only their shared projection; pipe/eventfd descriptions and flags
/// already use the same OFD authority in both venues.
pub(super) struct Binding {
    table: HostTable,
    owner: Arc<HostIpc>,
    map: &'static IpcTableMap,
    file_table: FileTableId,
    stdio: Vec<HostDescription>,
    explicit_stdio: [bool; 3],
    closed_stdio: [bool; 3],
    stdio_cloexec: [bool; 3],
}

impl std::fmt::Debug for Binding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IpcFileTable")
            .field("table", &self.table)
            .finish_non_exhaustive()
    }
}

impl Binding {
    fn new(
        owner: Arc<HostIpc>,
        map: &'static IpcTableMap,
        file_table: FileTableId,
        slots: &FileSlotMap,
        closed_stdio: [bool; 3],
        stdio_cloexec: [bool; 3],
    ) -> Result<Self, AdmissionError> {
        let capacity = slots.keys().copied().max().unwrap_or(2).max(2) as usize + 1;
        let table = HostTable::create(
            Arc::clone(&owner),
            i32::MAX as usize + 1,
            capacity.next_power_of_two(),
        )?;
        let mut binding = Self {
            table,
            owner,
            map,
            file_table,
            stdio: Vec::with_capacity(3),
            explicit_stdio: [false; 3],
            closed_stdio,
            stdio_cloexec,
        };
        for number in 0..3 {
            let token = binding
                .owner
                .retain_host_resource(Box::new((file_table, fd::Fd(number))))?;
            let backing = IpcBacking::Host(token).encode();
            let description = match binding.owner.admit_description(fd::Description::new(
                backing,
                fd::AccessMode::ReadWrite,
                fd::StatusFlags::default(),
            )) {
                Ok(description) => description,
                Err(error) => {
                    binding.owner.release(backing).unwrap_or_else(|_| {
                        carrick_fatal!("ipc::table", "stdio admission rollback failed")
                    });
                    return Err(error);
                }
            };
            binding.stdio.push(description);
        }
        for (&number, slot) in slots.iter() {
            binding.sync_slot(number, Some(slot))?;
        }
        for number in 0..3 {
            binding.sync_stdio(number)?;
        }
        // No guest can observe a partial namespace. Publish only after every
        // real descriptor and implicit host stream has been represented.
        map.publish(file_table.raw(), binding.table.id().to_raw())
            .map_err(|_| AdmissionError::NoMemory)?;
        Ok(binding)
    }

    fn close(&self, number: i32) -> Result<(), AdmissionError> {
        match self.table.close(fd::Fd(number)) {
            Ok(())
            | Err(AdmissionError::Shared(carrick_el1_abi::ipc::IpcError::Fd(fd::Error::BadFd))) => {
                Ok(())
            }
            Err(error) => Err(error),
        }
    }

    fn sync_stdio(&self, number: usize) -> Result<(), AdmissionError> {
        if self.explicit_stdio[number] {
            return Ok(());
        }
        if self.closed_stdio[number] {
            self.close(number as i32)
        } else {
            self.table.replace(
                fd::Fd(number as i32),
                &self.stdio[number].flags(),
                self.stdio_cloexec[number],
            )
        }
    }

    fn sync_slot(&mut self, number: i32, slot: Option<&FileSlot>) -> Result<(), AdmissionError> {
        if number < 0 {
            return Err(fd::Error::BadFd.into());
        }
        if number < 3 {
            self.explicit_stdio[number as usize] = slot.is_some();
        }
        if let Some(slot) = slot {
            // Geometric growth: repeated adjacent opens do not copy the whole
            // descriptor extent at each insertion.
            self.table
                .ensure_capacity((number as usize + 1).next_power_of_two())?;
            self.table.replace_slot(fd::Fd(number), slot)
        } else if number < 3 {
            self.sync_stdio(number as usize)
        } else {
            self.close(number)
        }
    }
}

impl Drop for Binding {
    fn drop(&mut self) {
        // Withdraw before the owned table invalidates its generation. Already
        // admitted operations keep their own pins through teardown.
        self.map.withdraw(self.file_table.raw());
    }
}

impl FileTable {
    /// Admit the complete namespace once, then maintain it at mutation sites.
    /// A resource refusal forwards this table to the host without retrying an
    /// O(n) admission on every syscall. A new fork/exec namespace can re-admit.
    pub fn publish_ipc(
        &self,
        owner: Arc<HostIpc>,
        map: &'static IpcTableMap,
    ) -> Result<(), AdmissionError> {
        if !self.functional_refs_active() {
            return Err(fd::Error::StaleTable.into());
        }
        {
            let ipc = self.ipc.lock();
            if let Some(binding) = &*ipc {
                return match binding {
                    Ok(binding)
                        if Arc::ptr_eq(&owner, &binding.owner)
                            && core::ptr::eq(map, binding.map) =>
                    {
                        Ok(())
                    }
                    Ok(_) => Err(fd::Error::StaleTable.into()),
                    Err(error) => Err(*error),
                };
            }
        }
        let _mutation = self
            .functional_gate
            .acquire_mutation()
            .ok_or(fd::Error::StaleTable)?;
        let slots = self.open_files.read();
        // Global lock order: open files, stdio flags, closed stdio, IPC binding.
        let cloexec = self.stdio_cloexec.lock();
        let closed = self.closed_stdio.lock();
        let mut ipc = self.ipc.lock();
        if let Some(binding) = &*ipc {
            return match binding {
                Ok(binding)
                    if Arc::ptr_eq(&owner, &binding.owner) && core::ptr::eq(map, binding.map) =>
                {
                    Ok(())
                }
                Ok(_) => Err(fd::Error::StaleTable.into()),
                Err(error) => Err(*error),
            };
        }
        let admitted = Binding::new(owner, map, self.id, &slots, *closed, *cloexec);
        let result = admitted.as_ref().map(|_| ()).map_err(|error| *error);
        *ipc = Some(admitted);
        result
    }

    pub(super) fn sync_ipc_slot(&self, number: i32, slot: Option<&FileSlot>) {
        let mut ipc = self.ipc.lock();
        if let Some(Ok(binding)) = &mut *ipc
            && let Err(error) = binding.sync_slot(number, slot)
        {
            // Drop invalidates the whole shared namespace before the host
            // mutation becomes visible; a stale guest TableId forwards.
            *ipc = Some(Err(error));
        }
    }

    pub(super) fn retire_ipc(&self) {
        let old = self.ipc.lock().replace(Err(fd::Error::StaleTable.into()));
        drop(old);
    }
}

#[derive(Clone, Copy)]
pub(super) enum StdioField {
    Closed,
    Cloexec,
}

pub struct FileTableStdioGuard<'a> {
    guard: MutexGuard<'a, [bool; 3]>,
    _mutation: FileTableMutationLease,
    table: &'a FileTable,
    field: StdioField,
    before: [bool; 3],
}
impl Deref for FileTableStdioGuard<'_> {
    type Target = [bool; 3];
    fn deref(&self) -> &Self::Target {
        &self.guard
    }
}
impl DerefMut for FileTableStdioGuard<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.guard
    }
}
impl Drop for FileTableStdioGuard<'_> {
    fn drop(&mut self) {
        self.table.revision.publish();
        if *self.guard == self.before {
            return;
        }
        // Do not acquire open_files here: callers may already hold its guard.
        // explicit_stdio is updated under that guard and this same IPC mutex.
        let mut ipc = self.table.ipc.lock();
        if let Some(Ok(binding)) = &mut *ipc {
            match self.field {
                StdioField::Closed => binding.closed_stdio = *self.guard,
                StdioField::Cloexec => binding.stdio_cloexec = *self.guard,
            }
            for number in 0..3 {
                if let Err(error) = binding.sync_stdio(number) {
                    *ipc = Some(Err(error));
                    break;
                }
            }
        }
    }
}

impl FileTable {
    pub(super) fn stdio_guard(&self, field: StdioField) -> FileTableStdioGuard<'_> {
        let mutation = self.mutation_lease();
        let guard = match field {
            StdioField::Closed => self.closed_stdio.lock(),
            StdioField::Cloexec => self.stdio_cloexec.lock(),
        };
        let before = *guard;
        FileTableStdioGuard {
            guard,
            _mutation: mutation,
            table: self,
            field,
            before,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::ids::ObjectIdRegistry;
    use carrick_el1_abi::ipc::{IpcBacking, fd};

    fn map() -> &'static IpcTableMap {
        // SAFETY: the map consists of zero-initialized atomics, lives for this
        // test process, and is accessed only through its synchronized API.
        unsafe {
            &*std::alloc::alloc_zeroed(std::alloc::Layout::new::<IpcTableMap>())
                .cast::<IpcTableMap>()
        }
    }

    // No host fd, fork, environment mutation or global counter: VM-free
    // authority witnesses run in the parallel kernel partition.
    #[test]
    fn red_until_step3_m1_one_table_writer() {
        let ids = ObjectIdRegistry::new();
        let owner = Arc::new(HostIpc::new(1 << 20).unwrap());
        let map = map();
        let parent = FileTable::new(ids.file_table_id().unwrap());
        let description = Arc::new(FileDescription::regular(ids.file_description_id().unwrap()));
        description.retain_fd_ref();
        parent.install(FileSlotNumber::for_open_fd(3).unwrap(), description, false);
        parent.publish_ipc(Arc::clone(&owner), map).unwrap();
        let peer = FileTable::for_fork_copy(ids.file_table_id().unwrap(), &parent);
        peer.publish_ipc(Arc::clone(&owner), map).unwrap();
        let region = owner.region();
        let authority = region.fd(crate::el1_zone::HostLockWait);
        let shared = fd::TableId::from_raw(map.lookup(parent.id().raw()).unwrap());
        let peer_id = fd::TableId::from_raw(map.lookup(peer.id().raw()).unwrap());
        authority.setfd(shared, fd::Fd(3), true).unwrap();
        assert_eq!(authority.getfd(peer_id, fd::Fd(3)), Ok(false));
        let host_flag = parent.read_open_files().get(&3).unwrap().fd_flags != 0;
        let result = if host_flag {
            Ok(())
        } else {
            Err("host slot flags diverge from shared authority")
        };
        assert_eq!(
            result.expect_err("flips at M1 cutover"),
            "host slot flags diverge from shared authority"
        );
    }

    #[test]
    fn red_until_step3_m1_no_host_slot_selection() {
        let ids = ObjectIdRegistry::new();
        let owner = Arc::new(HostIpc::new(1 << 20).unwrap());
        let map = map();
        let parent = Arc::new(FileTable::new(ids.file_table_id().unwrap()));
        parent.publish_ipc(Arc::clone(&owner), map).unwrap();
        let peer = FileTable::for_fork_copy(ids.file_table_id().unwrap(), &parent);
        peer.publish_ipc(Arc::clone(&owner), map).unwrap();
        let region = owner.region();
        let authority = region.fd(crate::el1_zone::HostLockWait);
        let shared = fd::TableId::from_raw(map.lookup(parent.id().raw()).unwrap());
        // Bare stdio is present only as implicit markers in the host map.
        assert_eq!(parent.slot_count(), 0);
        for number in 0..3 {
            assert!(authority.get(shared, fd::Fd(number)).is_ok());
        }
        authority.close(shared, fd::Fd(0)).unwrap();
        // The one authority's lowest free slot is now 0. Host selection still
        // considers implicit stdio open and chooses 3, even with a live peer.
        let selected = parent.reserve_slot_at_or_above(0, 64).unwrap();
        let result = if selected.fd() == 0 {
            Ok(())
        } else {
            Err("host selector ignores shared fd zero hole")
        };
        assert_eq!(
            result.expect_err("flips at M1 cutover"),
            "host selector ignores shared fd zero hole"
        );
    }

    #[test]
    fn serial_host_el1_ipc_file_table_fork_exec_and_refusal() {
        let ids = ObjectIdRegistry::new();
        let owner = Arc::new(HostIpc::new(1 << 16).unwrap());
        let map = map();
        let parent = FileTable::new(ids.file_table_id().unwrap());
        let description = Arc::new(FileDescription::regular(ids.file_description_id().unwrap()));
        description.retain_fd_ref();
        parent.install(
            FileSlotNumber::for_open_fd(3).unwrap(),
            Arc::clone(&description),
            true,
        );
        parent.lock_stdio_cloexec()[1] = true;
        parent.publish_ipc(Arc::clone(&owner), map).unwrap();
        let child = FileTable::for_fork_copy(ids.file_table_id().unwrap(), &parent);
        child.publish_ipc(Arc::clone(&owner), map).unwrap();
        let exec = FileTable::for_exec(ids.file_table_id().unwrap(), &child);
        exec.publish_ipc(Arc::clone(&owner), map).unwrap();
        let region = owner.region();
        let authority = region.fd(crate::el1_zone::HostLockWait);
        let parent_id = fd::TableId::from_raw(map.lookup(parent.id().raw()).unwrap());
        let child_id = fd::TableId::from_raw(map.lookup(child.id().raw()).unwrap());
        let exec_id = fd::TableId::from_raw(map.lookup(exec.id().raw()).unwrap());
        assert_eq!(
            authority.get(parent_id, fd::Fd(3)).unwrap(),
            authority.get(child_id, fd::Fd(3)).unwrap()
        );
        assert_eq!(authority.get(exec_id, fd::Fd(3)), Err(fd::Error::BadFd));
        assert_eq!(authority.get(exec_id, fd::Fd(1)), Err(fd::Error::BadFd));
        assert!(authority.get(parent_id, fd::Fd(1)).is_ok());
        let (operation, _) = authority.pin(parent_id, fd::Fd(3)).unwrap();
        // The host namespace survives shared storage exhaustion. No partial
        // projection remains available to guest reads after the mutation.
        description.retain_fd_ref();
        parent.install(
            FileSlotNumber::for_open_fd(1_000_000).unwrap(),
            Arc::clone(&description),
            false,
        );
        assert!(map.lookup(parent.id().raw()).is_none());
        assert_eq!(
            authority.get(parent_id, fd::Fd(3)),
            Err(fd::Error::StaleTable)
        );
        assert_eq!(parent.slot_count(), 2);
        assert!(authority.pinned(&operation).is_ok());
        assert!(parent.publish_ipc(Arc::clone(&owner), map).is_err());
        assert!(map.lookup(child.id().raw()).is_some());
        assert!(authority.unpin(operation).unwrap().is_none());
        let child_key = child.id();
        drop(child);
        assert!(map.lookup(child_key.raw()).is_none());
        assert_eq!(
            authority.get(child_id, fd::Fd(3)),
            Err(fd::Error::StaleTable)
        );
    }

    #[test]
    fn serial_host_el1_ipc_file_table_publishes_mutations_and_functional_retirement() {
        let ids = ObjectIdRegistry::new();
        let owner = Arc::new(HostIpc::new(1 << 20).unwrap());
        let map = map();
        let table = FileTable::new(ids.file_table_id().unwrap());
        let original = Arc::new(FileDescription::regular(ids.file_description_id().unwrap()));
        original.retain_fd_ref();
        table.install(
            FileSlotNumber::for_open_fd(3).unwrap(),
            Arc::clone(&original),
            false,
        );
        table
            .publish_ipc(Arc::clone(&owner), map)
            .expect("publish complete live FileTable");
        let shared = fd::TableId::from_raw(map.lookup(table.id().raw()).expect("live namespace"));
        let region = owner.region();
        let authority = region.fd(crate::el1_zone::HostLockWait);
        for number in 0..4 {
            assert!(matches!(
                IpcBacking::decode(authority.get(shared, fd::Fd(number)).unwrap().backing),
                Some(IpcBacking::Host(_))
            ));
        }
        assert_eq!(authority.get(shared, fd::Fd(4)), Err(fd::Error::BadFd));
        let (operation, before) = authority.pin(shared, fd::Fd(3)).unwrap();
        let replacement = Arc::new(FileDescription::regular(ids.file_description_id().unwrap()));
        replacement.retain_fd_ref();
        let old = table
            .install(
                FileSlotNumber::for_open_fd(3).unwrap(),
                Arc::clone(&replacement),
                true,
            )
            .unwrap();
        old.description.release_fd_ref();
        assert_ne!(
            authority.get(shared, fd::Fd(3)).unwrap().backing,
            before.backing
        );
        assert_eq!(authority.getfd(shared, fd::Fd(3)), Ok(true));
        assert_eq!(authority.holds(&operation), Ok((0, 1)));
        table.write_open_files().get_mut(&3).unwrap().fd_flags = 0;
        assert_eq!(authority.getfd(shared, fd::Fd(3)), Ok(false));
        // High-number admission must grow storage and keep the same table ID.
        replacement.retain_fd_ref();
        table
            .write_open_files()
            .insert(63, FileSlot::new(Arc::clone(&replacement), 0));
        assert_eq!(
            authority.get(shared, fd::Fd(63)).unwrap(),
            authority.get(shared, fd::Fd(3)).unwrap()
        );
        table.lock_closed_stdio()[0] = true;
        assert_eq!(authority.get(shared, fd::Fd(0)), Err(fd::Error::BadFd));
        table.lock_closed_stdio()[0] = false;
        table.lock_stdio_cloexec()[0] = true;
        assert_eq!(authority.getfd(shared, fd::Fd(0)), Ok(true));
        let removed = table.write_open_files().remove(&63).unwrap();
        removed.description.release_fd_ref();
        assert_eq!(authority.get(shared, fd::Fd(63)), Err(fd::Error::BadFd));
        // A diagnostic reference remains, but no new operation can enter.
        for (_, slot) in table.drain_functional_refs() {
            slot.description.release_fd_ref();
        }
        assert!(map.lookup(table.id().raw()).is_none());
        assert_eq!(authority.get(shared, fd::Fd(3)), Err(fd::Error::StaleTable));
        assert!(table.publish_ipc(Arc::clone(&owner), map).is_err());
        let retired = authority.unpin(operation).unwrap().unwrap();
        owner.release(retired.backing).unwrap();
    }
}
