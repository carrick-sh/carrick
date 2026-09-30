//! Owned shared-table lifecycle. Backing release always follows unlocking.

use std::sync::Arc;

use super::{AdmissionError, HostDescriptionFlags, HostDescriptionState, HostIpc};
use crate::el1_zone::HostLockWait;
use carrick_el1_abi::ipc::{IPC_MAX_OFDS, fd};

#[derive(Debug)]
pub struct HostTable {
    owner: Arc<HostIpc>,
    id: fd::TableId,
    capacity: usize,
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
        let mut storage = self.owner.provision_descriptors(self.capacity)?;
        let result = self
            .owner
            .region()
            .fd(HostLockWait)
            .fork(self.id, &mut storage);
        if result.is_err() {
            self.owner.reclaim_descriptors(storage);
        }
        let id = result?;
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
            self.release(retired);
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
            self.release(retired);
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
            self.release(description);
        }
        Ok(())
    }

    fn release(&self, description: fd::Description) {
        self.owner.release(description.backing).unwrap_or_else(|_| {
            carrick_fatal::carrick_fatal!("ipc::table", "invalid retired description backing")
        });
    }
}

impl Drop for HostTable {
    fn drop(&mut self) {
        let mut retired = Vec::with_capacity(self.capacity.min(IPC_MAX_OFDS));
        let extent = self
            .owner
            .region()
            .fd(HostLockWait)
            .destroy_table(self.id, |d| retired.push(d))
            .unwrap_or_else(|_| {
                carrick_fatal::carrick_fatal!("ipc::table", "invalid owned table retirement")
            });
        self.owner.reclaim_descriptors(extent);
        for description in retired {
            self.release(description);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use carrick_el1_abi::ipc::{IpcBacking, pipe::EventMode};

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
        for _ in 0..carrick_el1_abi::ipc::IPC_FD_TABLES + 1 {
            let mut parent = HostTable::create(Arc::clone(&owner), 64, 4).unwrap();
            let child = parent.fork().unwrap();
            let third = HostTable::create(Arc::clone(&owner), 64, 4).unwrap();
            // The three live tables own distinct extents. In particular,
            // successful fork must not reclaim its consumed (zeroed) token,
            // because pool offset zero may still belong to the parent.
            assert_eq!(owner.descriptors.lock().allocated.len(), 3);
            parent.ensure_capacity(64).unwrap();
            assert_eq!(owner.descriptors.lock().allocated.len(), 3);
            drop((parent, child, third));
            assert!(owner.descriptors.lock().allocated.is_empty());
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
