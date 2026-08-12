use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(test)]
use carrick_kernel::domains::{HostPid, ProcessGeneration};

use super::{
    AuthorityEpoch, AuthorityFatal, Command, FileAuthorityBinding, FileAuthorityCore,
    FileAuthorityTransport, ObjectGeneration, Outcome, Request, RequestId, Response, SlotPageLimit,
};
#[cfg(test)]
use super::{ClientId, ClientIdentity};

#[cfg(not(test))]
type RunTransport = super::IpcFileAuthority;
#[cfg(test)]
type RunTransport = super::DirectFileAuthority;

/// The one authenticated FileAuthority endpoint retained by a dispatcher run.
///
/// The helper and root table are live before any guest host fork. Syscall
/// families are attached to this root incrementally; until a family is cut
/// over, this object owns no guest-visible backing from that family.
pub(crate) struct FileAuthorityRun {
    transport: RunTransport,
    binding: FileAuthorityBinding,
    next_request: AtomicU64,
}

impl std::fmt::Debug for FileAuthorityRun {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FileAuthorityRun")
            .field("binding", &self.binding)
            .finish_non_exhaustive()
    }
}

impl FileAuthorityRun {
    /// Start the process-real helper in production. Unit tests use the same
    /// core and request surface directly so ordinary dispatcher fixtures do not
    /// fork helper processes.
    pub(crate) fn launch() -> Result<Arc<Self>, AuthorityFatal> {
        let epoch = run_epoch()?;
        #[cfg(not(test))]
        let (transport, binding) =
            super::IpcFileAuthority::spawn_per_run(FileAuthorityCore::for_run(epoch), epoch)?;
        #[cfg(test)]
        let (transport, binding) = direct_root(epoch)?;

        let authority = Arc::new(Self {
            transport,
            binding,
            // Root registration and root-table creation consumed requests 1-2.
            next_request: AtomicU64::new(3),
        });
        let health = authority.execute(
            Command::ListSlots {
                table: binding.table,
                after: None,
                maximum: SlotPageLimit::bounded(1)
                    .map_err(|_| AuthorityFatal::InvariantViolation("invalid root health bound"))?,
            },
            binding.generation,
        )?;
        if !matches!(health.outcome, Outcome::SlotPage { ref slots, .. } if slots.is_empty()) {
            return Err(AuthorityFatal::InvariantViolation(
                "FileAuthority root health check was not empty",
            ));
        }
        Ok(authority)
    }

    pub(crate) const fn binding(&self) -> FileAuthorityBinding {
        self.binding
    }

    fn execute(
        &self,
        command: Command,
        expected_generation: ObjectGeneration,
    ) -> Result<Response, AuthorityFatal> {
        let sequence = self
            .next_request
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1)
            })
            .map_err(|_| AuthorityFatal::IdentityExhausted)?;
        let request_id = RequestId::from_client_sequence(sequence)
            .map_err(|_| AuthorityFatal::IdentityExhausted)?;
        self.transport.execute(Request {
            epoch: self.binding.epoch,
            client: self.binding.client,
            request_id,
            expected_generation,
            command,
        })
    }
}

fn run_epoch() -> Result<AuthorityEpoch, AuthorityFatal> {
    #[cfg(not(test))]
    let raw = {
        let mut bytes = [0_u8; 8];
        getrandom::fill(&mut bytes).map_err(|_| AuthorityFatal::TransportUnavailable)?;
        // Setting one bit makes the typed epoch nonzero without introducing a
        // retry or a fallback identity source.
        u64::from_le_bytes(bytes) | 1
    };
    #[cfg(test)]
    let raw = 1;
    AuthorityEpoch::for_run(raw).map_err(|_| AuthorityFatal::IdentityExhausted)
}

#[cfg(test)]
fn direct_root(
    epoch: AuthorityEpoch,
) -> Result<(RunTransport, FileAuthorityBinding), AuthorityFatal> {
    let transport = super::DirectFileAuthority::for_run(FileAuthorityCore::for_run(epoch));
    let client = ClientIdentity::registered(
        ClientId::for_process_client(1).map_err(|_| AuthorityFatal::IdentityExhausted)?,
        HostPid::new(std::process::id()),
        ProcessGeneration::new(1),
    )
    .map_err(|_| AuthorityFatal::IdentityExhausted)?;
    let registered = transport.execute(Request {
        epoch,
        client,
        request_id: RequestId::from_client_sequence(1)
            .map_err(|_| AuthorityFatal::IdentityExhausted)?,
        expected_generation: ObjectGeneration::INITIAL,
        command: Command::RegisterClient,
    })?;
    if !matches!(registered.outcome, Outcome::ClientRegistered) {
        return Err(AuthorityFatal::InvariantViolation(
            "direct root registration was rejected",
        ));
    }
    let created = transport.execute(Request {
        epoch,
        client,
        request_id: RequestId::from_client_sequence(2)
            .map_err(|_| AuthorityFatal::IdentityExhausted)?,
        expected_generation: ObjectGeneration::INITIAL,
        command: Command::CreateTable,
    })?;
    let Outcome::TableCreated {
        table, generation, ..
    } = created.outcome
    else {
        return Err(AuthorityFatal::InvariantViolation(
            "direct root table creation was rejected",
        ));
    };
    Ok((
        transport,
        FileAuthorityBinding {
            epoch,
            client,
            table,
            generation,
        },
    ))
}
