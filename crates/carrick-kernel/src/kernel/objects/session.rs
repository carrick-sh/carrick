//! Process group and session identity objects in the kernel graph.
//!
//! Linux processes belong to a process group, which in turn belongs to a session.
//! Carrick tracks process group and session leadership with typed claims minted
//! against an [`IdRegistry`], maintaining monotonic object generations so reuse
//! of numeric PGIDs never aliases live kernel graph relationships.

use std::sync::atomic::Ordering;

use carrick_fatal::carrick_fatal;

use crate::kernel::ids::{ProcessGroupId, SessionId};
use crate::kernel::registry::{IdRegistry, ProcessGroupClaim, SessionClaim};

use super::{NEXT_PROCESS_GROUP_GENERATION, ObjectGraphError};

#[derive(Debug)]
pub struct ProcessGroup {
    id: ProcessGroupId,
    session: SessionId,
    generation: u64,
    _claim: ProcessGroupClaim,
}

impl ProcessGroup {
    pub fn new(
        id: ProcessGroupId,
        session: SessionId,
        registry: &IdRegistry,
        claim: ProcessGroupClaim,
    ) -> Result<Self, ObjectGraphError> {
        if claim.raw() != id.raw() || !claim.belongs_to(registry) {
            return Err(ObjectGraphError::ProcessGroupClaimMismatch);
        }
        let generation = NEXT_PROCESS_GROUP_GENERATION.fetch_add(1, Ordering::Relaxed);
        if generation == 0 || generation == u64::MAX {
            carrick_fatal!(
                "kernel::process_group_generation",
                "monotone process-group generation exhausted"
            );
        }
        Ok(Self {
            id,
            session,
            generation,
            _claim: claim,
        })
    }

    pub const fn id(&self) -> ProcessGroupId {
        self.id
    }

    pub const fn session(&self) -> SessionId {
        self.session
    }

    /// Monotonic object generation. Unlike the numeric PGID, this never follows
    /// a later process group that reuses the same id.
    pub(crate) const fn generation(&self) -> u64 {
        self.generation
    }
}

#[derive(Debug)]
pub struct Session {
    id: SessionId,
    _claim: SessionClaim,
}

impl Session {
    pub fn new(
        id: SessionId,
        registry: &IdRegistry,
        claim: SessionClaim,
    ) -> Result<Self, ObjectGraphError> {
        if claim.raw() != id.raw() || !claim.belongs_to(registry) {
            return Err(ObjectGraphError::SessionClaimMismatch);
        }
        Ok(Self { id, _claim: claim })
    }

    pub const fn id(&self) -> SessionId {
        self.id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_claim_from_another_registry_is_rejected() {
        let owner = IdRegistry::new();
        let foreign = IdRegistry::new();
        let (owner_task, owner_reservation) = owner.reserve_task().expect("owner task");
        let owner_task_claim = owner_reservation.commit();
        let (foreign_task, foreign_reservation) = foreign.reserve_task().expect("foreign task");
        let foreign_task_claim = foreign_reservation.commit();
        assert_eq!(owner_task.raw(), foreign_task.raw());
        let group = ProcessGroupId::from_leader(owner_task);
        let session = SessionId::from_leader(owner_task);
        let foreign_claim = foreign
            .claim_process_group(ProcessGroupId::from_leader(foreign_task))
            .expect("foreign group claim");

        assert!(matches!(
            ProcessGroup::new(group, session, &owner, foreign_claim),
            Err(ObjectGraphError::ProcessGroupClaimMismatch)
        ));
        drop(owner_task_claim);
        drop(foreign_task_claim);
    }

    #[test]
    fn group_and_session_objects_hold_typed_namespace_claims() {
        let ids = IdRegistry::new();
        let (task_id, task_reservation) = ids.reserve_task().expect("task reservation");
        let task_claim = task_reservation.commit();
        let group_id = ProcessGroupId::from_leader(task_id);
        let session_id = SessionId::from_leader(task_id);
        let group_claim = ids.claim_process_group(group_id).expect("group claim");
        let session_claim = ids.claim_session(session_id).expect("session claim");
        let group =
            ProcessGroup::new(group_id, session_id, &ids, group_claim).expect("group object");
        let session = Session::new(session_id, &ids, session_claim).expect("session object");

        drop(task_claim);
        assert!(ids.is_reserved_number(task_id.raw()));
        drop(group);
        assert!(ids.is_reserved_number(task_id.raw()));
        drop(session);
        assert!(!ids.is_reserved_number(task_id.raw()));
    }
}
