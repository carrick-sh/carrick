//! Owned shared-table lifecycle. Backing release always follows unlocking.

use std::sync::Arc;

use super::{AdmissionError, HostDescriptionFlags, HostDescriptionState, HostIpc};
use crate::el1_zone::HostLockWait;
use carrick_el1_abi::ipc::{IPC_MAX_OFDS, fd};

enum PhysicalRelease {
    Description(fd::Description),
    RetiredTables,
    Reservation(fd::reservation::SlotReservation),
}

impl AdmissionError {
    /// Linux errors for numeric reservation admission/settlement. A busy
    /// target is an ordinary dup/open race (EBUSY), never object-creation
    /// corruption. Storage requests must be handled before reaching dispatch.
    pub fn reservation_errno(self) -> carrick_abi::LinuxErrno {
        use carrick_abi::{
            LINUX_EBADF, LINUX_EBUSY, LINUX_EINVAL, LINUX_EMFILE, LINUX_ENFILE, LINUX_ENOMEM,
        };
        use carrick_el1_abi::ipc::IpcError;
        match self {
            Self::Shared(IpcError::Fd(fd::Error::Busy)) => LINUX_EBUSY,
            Self::Shared(IpcError::Fd(fd::Error::BadFd)) => LINUX_EBADF,
            Self::Shared(IpcError::Fd(fd::Error::InvalidArgument)) => LINUX_EINVAL,
            Self::Shared(IpcError::Fd(fd::Error::TooManyFiles)) => LINUX_EMFILE,
            Self::NoMemory | Self::Shared(IpcError::Fd(fd::Error::NoMemory)) => LINUX_ENOMEM,
            Self::Shared(IpcError::ZoneLimit) => LINUX_ENFILE,
            error => super::CreateError::from_admission(error).errno(),
        }
    }
}

impl HostIpc {
    pub(crate) fn service_retired_tables(&self) {
        HostTable::release(self, PhysicalRelease::RetiredTables);
    }
}

#[derive(Debug)]
pub struct HostTable {
    owner: Arc<HostIpc>,
    id: fd::TableId,
    capacity: usize,
}

/// An in-flight host operation owns one shared numeric claim. Dropping it
/// cancels admission; table retirement also revokes its exact incarnation.
#[must_use]
#[derive(Debug)]
pub struct HostSlotReservation {
    owner: Arc<HostIpc>,
    claim: Option<fd::reservation::SlotReservation>,
}

impl HostSlotReservation {
    pub fn fd(&self) -> Option<fd::Fd> {
        self.claim
            .as_ref()
            .map(fd::reservation::SlotReservation::fd)
    }

    /// Refusal preserves custody for retry or cancellation. Success retains
    /// the source pin and transfers any displaced physical release outside the
    /// table lock, using the same owner as ordinary close and table teardown.
    pub fn commit(
        &mut self,
        description: &HostDescriptionFlags,
        cloexec: bool,
    ) -> Result<(), AdmissionError> {
        if !Arc::ptr_eq(&self.owner, &description.owner) {
            return Err(fd::Error::StalePin.into());
        }
        let retired = {
            let state = description.state.lock();
            let HostDescriptionState::Live(pin) = &*state else {
                return Err(fd::Error::StalePin.into());
            };
            let claim = self.claim.take().ok_or(fd::Error::InvalidArgument)?;
            match self
                .owner
                .region()
                .fd(HostLockWait)
                .commit_reservation(claim, pin, cloexec)
            {
                Ok(retired) => retired,
                Err(refused) => {
                    let error = refused.error();
                    self.claim = Some(refused.into_reservation());
                    return Err(error.into());
                }
            }
        };
        if let Some(retired) = retired {
            HostTable::release(&self.owner, PhysicalRelease::Description(retired));
        }
        Ok(())
    }
}

impl Drop for HostSlotReservation {
    fn drop(&mut self) {
        if let Some(claim) = self.claim.take() {
            HostTable::release(&self.owner, PhysicalRelease::Reservation(claim));
        }
    }
}

impl HostTable {
    pub fn create(
        owner: Arc<HostIpc>,
        limit: usize,
        capacity: usize,
    ) -> Result<Self, AdmissionError> {
        let id = owner.create_table(limit, capacity)?;
        Ok(Self {
            owner,
            id,
            capacity,
        })
    }

    /// Select through the shared bitmap, growing its storage before retrying.
    pub fn reserve_min(&mut self, min: fd::Fd) -> Result<HostSlotReservation, AdmissionError> {
        self.reserve(|authority, id| authority.reserve_min(id, min))
    }

    pub fn reserve_exact(&mut self, target: fd::Fd) -> Result<HostSlotReservation, AdmissionError> {
        self.reserve(|authority, id| authority.reserve_exact(id, target))
    }

    fn reserve(
        &mut self,
        operation: impl Fn(
            &carrick_el1_abi::ipc::IpcFdAuthority<'_, HostLockWait>,
            fd::TableId,
        ) -> Result<fd::reservation::SlotReservation, fd::Error>,
    ) -> Result<HostSlotReservation, AdmissionError> {
        loop {
            let region = self.owner.region();
            match operation(&region.fd(HostLockWait), self.id) {
                Ok(claim) => {
                    return Ok(HostSlotReservation {
                        owner: Arc::clone(&self.owner),
                        claim: Some(claim),
                    });
                }
                Err(fd::Error::NeedsBacking { descriptors }) => {
                    self.ensure_capacity(descriptors.next_power_of_two())?
                }
                Err(error) => return Err(error.into()),
            }
        }
    }

    pub fn id(&self) -> fd::TableId {
        self.id
    }

    /// Admit the exact FileSlot description, including host-only forwarding
    /// records. Callers must already retain the slot's functional reference.
    pub fn replace_slot(
        &self,
        target: fd::Fd,
        slot: &crate::kernel::FileSlot,
    ) -> Result<(), AdmissionError> {
        let description = slot.description.ipc_description(&self.owner)?;
        self.replace(target, &description, slot.close_on_exec())
    }

    /// Caller serializes host admission; growing storage preserves identity.
    pub fn ensure_capacity(&mut self, capacity: usize) -> Result<(), AdmissionError> {
        if capacity > self.capacity {
            self.owner.ensure_capacity(self.id, capacity)?;
            self.capacity = capacity;
        }
        Ok(())
    }

    pub fn fork(&self) -> Result<Self, AdmissionError> {
        let id = self
            .owner
            .region()
            .fork_descriptors(self.id, &HostLockWait, |_| Ok(()))?;
        Ok(Self {
            owner: Arc::clone(&self.owner),
            id,
            capacity: self.capacity,
        })
    }

    /// Publish a new slot or replace its exact prior description atomically.
    /// Foreign or retired pins fail before changing the target.
    pub fn replace(
        &self,
        target: fd::Fd,
        description: &HostDescriptionFlags,
        cloexec: bool,
    ) -> Result<(), AdmissionError> {
        let retired = {
            let state = description.state.lock();
            let HostDescriptionState::Live(pin) = &*state else {
                return Err(fd::Error::StalePin.into());
            };
            self.owner
                .region()
                .fd(HostLockWait)
                .replace_pin(self.id, target, pin, cloexec)?
        };
        if let Some(retired) = retired {
            Self::release(&self.owner, PhysicalRelease::Description(retired));
        }
        Ok(())
    }

    pub fn close(&self, target: fd::Fd) -> Result<(), AdmissionError> {
        if let Some(retired) = self
            .owner
            .region()
            .fd(HostLockWait)
            .close(self.id, target)?
        {
            Self::release(&self.owner, PhysicalRelease::Description(retired));
        }
        Ok(())
    }

    pub fn exec(&self) -> Result<(), AdmissionError> {
        // At most one final hold per slot, and no more than the zone holds;
        // reserve before entering the core so callbacks never allocate there.
        let mut retired = Vec::with_capacity(self.capacity.min(IPC_MAX_OFDS));
        self.owner
            .region()
            .fd(HostLockWait)
            .exec(self.id, |d| retired.push(d))?;
        for description in retired {
            Self::release(&self.owner, PhysicalRelease::Description(description));
        }
        Ok(())
    }

    fn release(owner: &HostIpc, release: PhysicalRelease) {
        // The table's physical-release owner also settles ring-retired tables.
        // Both paths run after namespace locks and share the same corruption
        // policy; an ordinary admission refusal never reaches this owner.
        let result = match release {
            PhysicalRelease::Description(description) => owner
                .release(description.backing)
                .map(|_| ())
                .map_err(AdmissionError::from),
            PhysicalRelease::RetiredTables => owner.drain_retired_tables().map(|_| ()),
            PhysicalRelease::Reservation(claim) => {
                match owner.region().fd(HostLockWait).cancel_reservation(claim) {
                    Ok(()) => Ok(()),
                    Err(refused) if refused.error() == fd::Error::StaleTable => Ok(()),
                    Err(refused) => Err(refused.error().into()),
                }
            }
        };
        result.unwrap_or_else(|_| {
            carrick_fatal::carrick_fatal!("ipc::table", "invalid retired descriptor resource")
        });
    }
}

impl Drop for HostTable {
    fn drop(&mut self) {
        let mut retired = Vec::with_capacity(self.capacity.min(IPC_MAX_OFDS));
        self.owner
            .region()
            .fd(HostLockWait)
            .destroy_table(self.id, |d| retired.push(d))
            .map_err(AdmissionError::from)
            .and_then(|extent| self.owner.reclaim_descriptors(extent))
            .unwrap_or_else(|_| {
                carrick_fatal::carrick_fatal!("ipc::table", "invalid owned table retirement")
            });
        for description in retired {
            Self::release(&self.owner, PhysicalRelease::Description(description));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use carrick_el1_abi::ipc::{IpcBacking, pipe::EventMode};

    #[test]
    fn serial_host_el1_ipc_reservations_cancel_commit_and_retire_once() {
        let owner = Arc::new(HostIpc::new(1 << 20).unwrap());
        let mut parent = HostTable::create(owner.clone(), 64, 4).unwrap();
        let mut peer = parent.fork().unwrap();
        let claim = parent.reserve_min(fd::Fd(0)).unwrap();
        assert_eq!(claim.fd(), Some(fd::Fd(0)));
        let busy = parent.reserve_exact(fd::Fd(0)).unwrap_err();
        assert_eq!(busy.reservation_errno().get(), 16);
        let second = parent.reserve_min(fd::Fd(0)).unwrap();
        assert_eq!(second.fd(), Some(fd::Fd(1)));
        let peer_claim = peer.reserve_min(fd::Fd(0)).unwrap();
        assert_eq!(peer_claim.fd(), Some(fd::Fd(0)));
        drop(claim);
        let mut replacement = parent.reserve_min(fd::Fd(0)).unwrap();
        assert_eq!(replacement.fd(), Some(fd::Fd(0)));
        // Growth preserves the other pending claim; dropped reservations free
        // their exact slot even after backing has moved.
        drop(parent.reserve_exact(fd::Fd(32)).unwrap());
        drop(second);
        assert_eq!(parent.reserve_min(fd::Fd(1)).unwrap().fd(), Some(fd::Fd(1)));
        let token = owner.retain_host_resource(Box::new(42_u32)).unwrap();
        let description = owner
            .admit_description(fd::Description::new(
                IpcBacking::Host(token).encode(),
                fd::AccessMode::ReadWrite,
                fd::StatusFlags::default(),
            ))
            .unwrap();
        let flags = description.flags();
        replacement.commit(&flags, true).unwrap();
        assert_eq!(replacement.fd(), None);
        assert!(replacement.commit(&flags, false).is_err(), "consumed once");
        drop((description, flags, replacement));
        assert_eq!(owner.retained_host_resources(), 1);
        drop(parent);
        assert_eq!(owner.retained_host_resources(), 0);
        drop(peer);
        drop(peer_claim); // retirement already revoked this exact table
        assert_eq!(owner.retained_host_resources(), 0);
    }

    #[test]
    fn serial_host_el1_ipc_owned_table_releases_resources_after_unlocking() {
        struct Reenter {
            owner: std::sync::Weak<HostIpc>,
            table: fd::TableId,
            observed: Arc<parking_lot::Mutex<Option<fd::Error>>>,
        }
        impl Drop for Reenter {
            fn drop(&mut self) {
                let owner = self.owner.upgrade().unwrap();
                *self.observed.lock() = owner
                    .region()
                    .fd(fd::BoundedSpin(0))
                    .get(self.table, fd::Fd(0))
                    .err();
            }
        }
        let owner = Arc::new(HostIpc::new(16384).unwrap());
        let table = HostTable::create(Arc::clone(&owner), 64, 4).unwrap();
        let observed = Arc::new(parking_lot::Mutex::new(None));
        let install = |cloexec| {
            let token = owner
                .retain_host_resource(Box::new(Reenter {
                    owner: Arc::downgrade(&owner),
                    table: table.id(),
                    observed: Arc::clone(&observed),
                }))
                .unwrap();
            let description = owner
                .admit_description(fd::Description::new(
                    IpcBacking::Host(token).encode(),
                    fd::AccessMode::ReadWrite,
                    fd::StatusFlags::default(),
                ))
                .unwrap();
            table
                .replace(fd::Fd(0), &description.flags(), cloexec)
                .unwrap();
        };
        install(true);
        table.exec().unwrap();
        assert_eq!(*observed.lock(), Some(fd::Error::BadFd));
        install(false);
        drop(table);
        assert_eq!(*observed.lock(), Some(fd::Error::StaleTable));
    }

    #[test]
    fn serial_host_el1_ipc_owned_tables_reclaim_extent_and_identity_capacity() {
        let owner = Arc::new(HostIpc::new(1 << 16).unwrap());
        for capacity in [0, i32::MAX as usize + 1] {
            assert!(matches!(
                owner.create_table(64, capacity),
                Err(AdmissionError::NoMemory)
            ));
            assert_eq!(owner.region().descriptor_allocations(), 0);
        }
        for _ in 0..carrick_el1_abi::ipc::IPC_FD_TABLES + 1 {
            let mut parent = HostTable::create(Arc::clone(&owner), 64, 4).unwrap();
            let child = parent.fork().unwrap();
            let third = HostTable::create(Arc::clone(&owner), 64, 4).unwrap();
            // The three live tables own distinct extents. In particular,
            // successful fork must not reclaim its consumed (zeroed) token,
            // because pool offset zero may still belong to the parent.
            assert_eq!(owner.region().descriptor_allocations(), 3);
            parent.ensure_capacity(64).unwrap();
            assert_eq!(owner.region().descriptor_allocations(), 3);
            drop((parent, child, third));
            assert_eq!(owner.region().descriptor_allocations(), 0);
        }
    }

    #[test]
    fn serial_host_el1_ipc_owned_table_fork_replace_exec_and_retire() {
        let owner = Arc::new(HostIpc::new(1 << 20).unwrap());
        let object = owner.create_eventfd(7, EventMode::Counter).unwrap();
        let original = owner
            .admit_description(fd::Description::new(
                IpcBacking::EventFd { object }.encode(),
                fd::AccessMode::ReadWrite,
                fd::StatusFlags::default(),
            ))
            .unwrap();
        let table = HostTable::create(Arc::clone(&owner), 64, 4).unwrap();
        table.replace(fd::Fd(0), &original.flags(), true).unwrap();
        let child = table.fork().unwrap();
        let region = owner.region();
        let authority = region.fd(HostLockWait);
        let (operation, _) = authority.pin(table.id(), fd::Fd(0)).unwrap();
        drop(original);
        let successor_object = owner.create_eventfd(9, EventMode::Counter).unwrap();
        let successor = owner
            .admit_description(fd::Description::new(
                IpcBacking::EventFd {
                    object: successor_object,
                }
                .encode(),
                fd::AccessMode::ReadWrite,
                fd::StatusFlags::default(),
            ))
            .unwrap();
        table.replace(fd::Fd(0), &successor.flags(), false).unwrap();
        assert_eq!(
            authority.get(child.id(), fd::Fd(0)).unwrap().backing,
            IpcBacking::EventFd { object }.encode()
        );
        child.exec().unwrap();
        assert_eq!(authority.holds(&operation).unwrap(), (0, 1));
        let child_id = child.id();
        drop(child);
        assert_eq!(
            authority.get(child_id, fd::Fd(0)),
            Err(fd::Error::StaleTable),
            "dropping an owned table must invalidate its generation"
        );
        drop(table);
        drop(successor);
        assert!(region.lock(successor_object, &HostLockWait).is_err());
        assert_eq!(
            region
                .lock(object, &HostLockWait)
                .unwrap()
                .eventfd()
                .unwrap()
                .try_read()
                .result,
            Ok(7)
        );
        let final_description = authority.unpin(operation).unwrap().unwrap();
        owner.release(final_description.backing).unwrap();
        assert!(region.lock(object, &HostLockWait).is_err());
    }
}
