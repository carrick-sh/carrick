//! Production file-table publication into the shared IPC authority.
use super::*;
use crate::el1_ipc::{AdmissionError, HostDescription, HostIpc, HostTable};
use carrick_el1_abi::ipc::{IpcBacking, fd};
use carrick_el1_abi::ipc_tables::IpcTableMap;

/// The host slot map and stdio markers serialize publication. This binding
/// owns only their shared projection; pipe/eventfd descriptions and flags
/// already use the same OFD authority in both venues.
pub(super) struct Binding {
    reservations: HashMap<i32, (u64, crate::el1_ipc::HostSlotReservation)>,
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
        reserved_slots: &HashMap<i32, u64>,
        closed_stdio: [bool; 3],
        stdio_cloexec: [bool; 3],
    ) -> Result<Self, AdmissionError> {
        let max_slot = slots
            .keys()
            .chain(reserved_slots.keys())
            .copied()
            .max()
            .unwrap_or(2)
            .max(2) as usize;
        let capacity = max_slot + 1;
        let table = HostTable::create(
            Arc::clone(&owner),
            i32::MAX as usize + 1,
            capacity.next_power_of_two(),
        )?;
        let mut binding = Self {
            reservations: HashMap::new(),
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
            binding.install_slot(number, slot)?;
        }
        for (number, &closed) in closed_stdio.iter().enumerate() {
            binding.set_stdio_closed(number, closed)?;
        }
        for (&fd, &reservation_id) in reserved_slots.iter() {
            let claim = binding.table.reserve_exact(fd::Fd(fd))?;
            binding.reservations.insert(fd, (reservation_id, claim));
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

    fn install_slot(&mut self, number: i32, slot: &FileSlot) -> Result<(), AdmissionError> {
        if number < 0 {
            return Err(fd::Error::BadFd.into());
        }
        if number < 3 {
            self.explicit_stdio[number as usize] = true;
            self.closed_stdio[number as usize] = false;
        }
        // Geometric growth: repeated adjacent opens do not copy the whole
        // descriptor extent at each insertion.
        self.table
            .ensure_capacity((number as usize + 1).next_power_of_two())?;
        self.table.replace_slot(fd::Fd(number), slot)
    }

    fn remove_slot(&mut self, number: i32) -> Result<(), AdmissionError> {
        if number < 0 {
            return Err(fd::Error::BadFd.into());
        }
        if number < 3 {
            self.explicit_stdio[number as usize] = false;
            self.closed_stdio[number as usize] = true;
        }
        self.close(number)
    }

    fn set_cloexec(&self, number: i32, cloexec: bool) -> Result<(), AdmissionError> {
        if number < 0 {
            return Err(fd::Error::BadFd.into());
        }
        self.owner
            .region()
            .fd(crate::el1_zone::HostLockWait)
            .setfd(self.table.id(), fd::Fd(number), cloexec)
            .map_err(Into::into)
    }

    fn set_stdio_closed(&mut self, number: usize, closed: bool) -> Result<(), AdmissionError> {
        self.closed_stdio[number] = closed;
        if self.explicit_stdio[number] {
            return Ok(());
        }
        if closed {
            self.close(number as i32)
        } else {
            self.table.replace(
                fd::Fd(number as i32),
                &self.stdio[number].flags(),
                self.stdio_cloexec[number],
            )
        }
    }

    fn set_stdio_cloexec(&mut self, number: usize, cloexec: bool) -> Result<(), AdmissionError> {
        self.stdio_cloexec[number] = cloexec;
        if self.explicit_stdio[number] || self.closed_stdio[number] {
            return Ok(());
        }
        self.set_cloexec(number as i32, cloexec)
    }

    fn reserve_min(
        &mut self,
        min_fd: i32,
        limit: i32,
        reservation_id: u64,
    ) -> Result<i32, crate::linux_abi::LinuxErrno> {
        if min_fd >= limit {
            return Err(crate::linux_abi::LINUX_EMFILE);
        }
        let claim = self
            .table
            .reserve_min(fd::Fd(min_fd.max(0)))
            .map_err(AdmissionError::reservation_errno)?;
        let fd = claim.fd().ok_or(crate::linux_abi::LINUX_EBADF)?.0;
        if fd >= limit {
            drop(claim);
            return Err(crate::linux_abi::LINUX_EMFILE);
        }
        self.reservations.insert(fd, (reservation_id, claim));
        Ok(fd)
    }

    fn reserve_exact(
        &mut self,
        fd: i32,
        reservation_id: u64,
    ) -> Result<(), crate::linux_abi::LinuxErrno> {
        let claim = self
            .table
            .reserve_exact(fd::Fd(fd))
            .map_err(AdmissionError::reservation_errno)?;
        self.reservations.insert(fd, (reservation_id, claim));
        Ok(())
    }

    fn take_reservation(
        &mut self,
        fd: i32,
        reservation_id: u64,
    ) -> Option<crate::el1_ipc::HostSlotReservation> {
        if self
            .reservations
            .get(&fd)
            .is_some_and(|(id, _)| *id == reservation_id)
        {
            self.reservations.remove(&fd).map(|(_, claim)| claim)
        } else {
            None
        }
    }

    fn commit_reservation(
        &mut self,
        fd: i32,
        reservation_id: u64,
        slot: &FileSlot,
    ) -> Result<(), AdmissionError> {
        if let Some(mut claim) = self.take_reservation(fd, reservation_id) {
            let description = slot.description.ipc_description(&self.owner)?;
            claim.commit(&description, slot.close_on_exec())?;
            if (0..3).contains(&fd) {
                self.explicit_stdio[fd as usize] = true;
                self.closed_stdio[fd as usize] = false;
            }
            Ok(())
        } else {
            self.install_slot(fd, slot)
        }
    }

    fn get_fd_flags(&self, number: i32) -> Option<Result<u64, crate::linux_abi::LinuxErrno>> {
        if number < 0 {
            return Some(Err(crate::linux_abi::LINUX_EBADF));
        }
        let region = self.owner.region();
        let authority = region.fd(crate::el1_zone::HostLockWait);
        match authority.getfd(self.table.id(), fd::Fd(number)) {
            Ok(true) => Some(Ok(crate::linux_abi::LINUX_FD_CLOEXEC)),
            Ok(false) => Some(Ok(0)),
            Err(fd::Error::BadFd) => Some(Err(crate::linux_abi::LINUX_EBADF)),
            Err(_) => None,
        }
    }

    fn refresh_flags(&self, slots: &mut FileSlotMap) {
        let region = self.owner.region();
        let authority = region.fd(crate::el1_zone::HostLockWait);
        for (&fd, slot) in slots.iter_mut() {
            if let Ok(cloexec) = authority.getfd(self.table.id(), fd::Fd(fd)) {
                if cloexec {
                    slot.fd_flags |= crate::linux_abi::LINUX_FD_CLOEXEC;
                } else {
                    slot.fd_flags &= !crate::linux_abi::LINUX_FD_CLOEXEC;
                }
            }
        }
    }

    fn refresh_stdio(&mut self) {
        let region = self.owner.region();
        let authority = region.fd(crate::el1_zone::HostLockWait);
        for number in 0..3 {
            if self.explicit_stdio[number] {
                continue;
            }
            match authority.getfd(self.table.id(), fd::Fd(number as i32)) {
                Ok(cloexec) => {
                    self.closed_stdio[number] = false;
                    self.stdio_cloexec[number] = cloexec;
                }
                Err(fd::Error::BadFd) => {
                    self.closed_stdio[number] = true;
                    self.stdio_cloexec[number] = false;
                }
                Err(_) => {}
            }
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
        // Global lock order: open files, reserved slots, stdio flags, closed stdio, IPC binding.
        let reserved = self.lock_reserved_slots();
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
        let admitted = Binding::new(owner, map, self.id, &slots, &reserved, *closed, *cloexec);
        let result = admitted.as_ref().map(|_| ()).map_err(|error| *error);
        *ipc = Some(admitted);
        result
    }

    pub(super) fn reserve_ipc_min(
        &self,
        min_fd: i32,
        limit: i32,
        reservation_id: u64,
    ) -> Option<Result<i32, crate::linux_abi::LinuxErrno>> {
        let mut ipc = self.ipc.lock();
        let Some(Ok(binding)) = &mut *ipc else {
            return None;
        };
        Some(binding.reserve_min(min_fd, limit, reservation_id))
    }

    pub(super) fn reserve_ipc_exact(
        &self,
        fd: i32,
        reservation_id: u64,
    ) -> Result<(), crate::linux_abi::LinuxErrno> {
        let mut ipc = self.ipc.lock();
        if let Some(Ok(binding)) = &mut *ipc {
            binding.reserve_exact(fd, reservation_id)?;
        }
        Ok(())
    }

    pub(super) fn cancel_ipc_reservation(&self, fd: i32, reservation_id: u64) {
        let claim = self
            .ipc
            .lock()
            .as_mut()
            .and_then(|binding| binding.as_mut().ok())
            .and_then(|binding| binding.take_reservation(fd, reservation_id));
        drop(claim);
    }

    pub(super) fn commit_ipc_reservation(&self, fd: i32, reservation_id: u64, slot: &FileSlot) {
        let mut ipc = self.ipc.lock();
        if let Some(Ok(binding)) = &mut *ipc
            && let Err(error) = binding.commit_reservation(fd, reservation_id, slot)
        {
            *ipc = Some(Err(error));
        }
    }

    pub(super) fn install_ipc_slot(&self, number: i32, slot: &FileSlot) {
        let mut ipc = self.ipc.lock();
        if let Some(Ok(binding)) = &mut *ipc
            && let Err(error) = binding.install_slot(number, slot)
        {
            // Drop invalidates the whole shared namespace before the host
            // mutation becomes visible; a stale guest TableId forwards.
            *ipc = Some(Err(error));
        }
    }

    pub(super) fn remove_ipc_slot(&self, number: i32) {
        let mut ipc = self.ipc.lock();
        if let Some(Ok(binding)) = &mut *ipc
            && let Err(error) = binding.remove_slot(number)
        {
            *ipc = Some(Err(error));
        }
    }

    pub(super) fn set_ipc_cloexec(&self, number: i32, cloexec: bool) {
        let mut ipc = self.ipc.lock();
        if let Some(Ok(binding)) = &mut *ipc
            && let Err(error) = binding.set_cloexec(number, cloexec)
        {
            *ipc = Some(Err(error));
        }
    }

    pub(crate) fn ipc_fd_flags(
        &self,
        number: i32,
    ) -> Option<Result<u64, crate::linux_abi::LinuxErrno>> {
        let ipc = self.ipc.lock();
        let Some(Ok(binding)) = &*ipc else {
            return None;
        };
        binding.get_fd_flags(number)
    }

    pub(super) fn reconcile_copy_from_ipc(
        &self,
        slots: &mut FileSlotMap,
        stdio_cloexec: &mut [bool; 3],
        closed_stdio: &mut [bool; 3],
    ) {
        let mut ipc = self.ipc.lock();
        if let Some(Ok(binding)) = &mut *ipc {
            binding.refresh_flags(slots);
            binding.refresh_stdio();
            *stdio_cloexec = binding.stdio_cloexec;
            *closed_stdio = binding.closed_stdio;
        }
    }

    pub(super) fn retire_ipc(&self) {
        let old = self.ipc.lock().replace(Err(fd::Error::StaleTable.into()));
        drop(old);
    }
}

#[derive(::core::clone::Clone, ::core::marker::Copy)]
pub(super) enum StdioField {
    Closed,
    Cloexec,
}

pub struct FileTableStdioGuard<'a> {
    guard: MutexGuard<'a, [bool; 3]>,
    _mutation: FileTableMutationCustody<'a>,
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
            for number in 0..3 {
                if self.guard[number] == self.before[number] {
                    continue;
                }
                let result = match self.field {
                    StdioField::Closed => binding.set_stdio_closed(number, self.guard[number]),
                    StdioField::Cloexec => binding.set_stdio_cloexec(number, self.guard[number]),
                };
                if let Err(error) = result {
                    *ipc = Some(Err(error));
                    break;
                }
            }
        }
    }
}

impl FileTable {
    pub(super) fn stdio_guard<'a>(
        &'a self,
        field: StdioField,
        mutation: Option<&'a FileTableMutationLease>,
    ) -> FileTableStdioGuard<'a> {
        let mutation = mutation.map_or_else(
            || FileTableMutationCustody::Owned(self.mutation_lease()),
            FileTableMutationCustody::Borrowed,
        );
        let mut guard = match field {
            StdioField::Closed => self.closed_stdio.lock(),
            StdioField::Cloexec => self.stdio_cloexec.lock(),
        };
        if let Some(Ok(binding)) = &mut *self.ipc.lock() {
            binding.refresh_stdio();
            *guard = match field {
                StdioField::Closed => binding.closed_stdio,
                StdioField::Cloexec => binding.stdio_cloexec,
            };
        }
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
    fn one_table_writer() {
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
        let fd3 = FileSlotNumber::for_open_fd(3).unwrap();
        assert_eq!(peer.slot(fd3).unwrap().fd_flags, 0);
        assert_eq!(
            parent.ipc_fd_flags(3),
            Some(Ok(crate::linux_abi::LINUX_FD_CLOEXEC))
        );
        let host_flag = parent.slot(fd3).unwrap().fd_flags != 0;
        assert!(host_flag, "host slot flags diverge from shared authority");
    }

    #[test]
    fn no_host_slot_selection() {
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
        let selected = parent.reserve_slot_at_or_above(0, 64).unwrap();
        assert_eq!(
            selected.fd(),
            0,
            "host selector ignores shared fd zero hole"
        );
    }

    #[test]
    fn ipc_reservation_commit_refuses_a_stale_occupied_host_slot() {
        let ids = ObjectIdRegistry::new();
        let owner = Arc::new(HostIpc::new(1 << 20).unwrap());
        let map = map();
        let table = Arc::new(FileTable::new(ids.file_table_id().unwrap()));
        let old = Arc::new(FileDescription::regular(ids.file_description_id().unwrap()));
        old.retain_fd_ref();
        table.install(
            FileSlotNumber::for_open_fd(3).unwrap(),
            Arc::clone(&old),
            false,
        );
        table.publish_ipc(Arc::clone(&owner), map).unwrap();

        let shared = fd::TableId::from_raw(map.lookup(table.id().raw()).unwrap());
        owner
            .region()
            .fd(crate::el1_zone::HostLockWait)
            .close(shared, fd::Fd(3))
            .unwrap();
        let reservation = table.reserve_slot_at_or_above(0, 64).unwrap();
        assert_eq!(reservation.fd(), 3);
        let replacement = Arc::new(FileDescription::regular(ids.file_description_id().unwrap()));
        assert_eq!(
            reservation.commit(FileSlot::new(Arc::clone(&replacement), 0)),
            Err(crate::linux_abi::LINUX_EBUSY)
        );
        assert!(Arc::ptr_eq(
            &table
                .slot(FileSlotNumber::for_open_fd(3).unwrap())
                .unwrap()
                .description(),
            &old
        ));
        assert_eq!(old.fd_ref_count(), 1);
        assert_eq!(replacement.fd_ref_count(), 0);
        assert!(!table.is_slot_reserved(3));
    }

    #[test]
    fn epoll_detach_reservation_propagates_shared_claim_conflict() {
        let ids = ObjectIdRegistry::new();
        let owner = Arc::new(HostIpc::new(1 << 20).unwrap());
        let table = Arc::new(FileTable::new(ids.file_table_id().unwrap()));
        table.publish_ipc(owner, map()).unwrap();
        let first = table.reserve_exact_target(7, 64).unwrap();

        assert!(matches!(
            table.reserve_slot_for_epoll_detach(7),
            Err(crate::linux_abi::LINUX_EBUSY)
        ));
        assert_eq!(
            table.lock_reserved_slots().get(&7).copied(),
            Some(first.reservation_id())
        );
    }

    #[test]
    fn serial_host_el1_ipc_file_table_fork_exec_and_refusal() {
        let ids = ObjectIdRegistry::new();
        let owner = Arc::new(HostIpc::new(1 << 16).unwrap());
        let map = map();
        let (kernel, context) = crate::kernel::Kernel::bootstrap_root(
            crate::kernel::RootBootstrap::for_reference_model(
                9120,
                carrick_hal::ThreadId::synthetic_for_tests(9120),
                "ipc exec".into(),
            )
            .unwrap(),
        )
        .unwrap();
        let parent = context.resources().files();
        let description = Arc::new(FileDescription::regular(ids.file_description_id().unwrap()));
        description.retain_fd_ref();
        parent.install(
            FileSlotNumber::for_open_fd(3).unwrap(),
            Arc::clone(&description),
            true,
        );
        parent.lock_stdio_cloexec()[1] = true;
        parent.publish_ipc(Arc::clone(&owner), map).unwrap();
        let child_context = kernel
            .fork_task(
                &context,
                crate::kernel::ClonePlan::from_flags(carrick_abi::LinuxCloneFlags::empty())
                    .unwrap(),
                carrick_hal::ThreadId::synthetic_for_tests(9121),
                "ipc child".into(),
                None,
            )
            .unwrap();
        let child = child_context.resources().files();
        child.publish_ipc(Arc::clone(&owner), map).unwrap();
        let region = owner.region();
        let authority = region.fd(crate::el1_zone::HostLockWait);
        let parent_id = fd::TableId::from_raw(map.lookup(parent.id().raw()).unwrap());
        let child_id = fd::TableId::from_raw(map.lookup(child.id().raw()).unwrap());
        assert_eq!(
            authority.get(parent_id, fd::Fd(3)).unwrap(),
            authority.get(child_id, fd::Fd(3)).unwrap()
        );
        let prepared = kernel.prepare_exec(&child_context, None).unwrap();
        let committed = kernel.commit_exec(prepared, None).unwrap();
        let exec = committed.resources().files();
        exec.publish_ipc(Arc::clone(&owner), map).unwrap();
        let exec_id = fd::TableId::from_raw(map.lookup(exec.id().raw()).unwrap());
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
        assert!(map.lookup(child.id().raw()).is_none());
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
        table.write_open_files(None).get_mut(&3).unwrap().fd_flags = 0;
        assert_eq!(authority.getfd(shared, fd::Fd(3)), Ok(false));
        // High-number admission must grow storage and keep the same table ID.
        replacement.retain_fd_ref();
        table
            .write_open_files(None)
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
        let removed = table.write_open_files(None).remove(&63).unwrap();
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
