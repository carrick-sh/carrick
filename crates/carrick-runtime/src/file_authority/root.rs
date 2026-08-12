use std::sync::Arc;

use parking_lot::Mutex;

#[cfg(test)]
use carrick_kernel::domains::{HostPid, ProcessGeneration};

use super::{
    AuthorityEpoch, AuthorityFatal, Command, FileAuthorityBinding, FileAuthorityCore,
    FileAuthorityTransport, ObjectGeneration, Outcome, Request, RequestId, Response, SlotPageLimit,
};
#[cfg(test)]
use super::{ClientId, ClientIdentity};

/// The one authenticated FileAuthority endpoint retained by a dispatcher run.
///
/// The helper and root table are live before any guest host fork. Syscall
/// families are attached to this root incrementally; until a family is cut
/// over, this object owns no guest-visible backing from that family.
pub(crate) struct FileAuthorityRun {
    transport: Arc<dyn FileAuthorityTransport>,
    binding: FileAuthorityBinding,
    next_request: Mutex<u64>,
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
        let (transport, binding) = {
            let (transport, binding) =
                super::IpcFileAuthority::spawn_per_run(FileAuthorityCore::for_run(epoch), epoch)?;
            (
                Arc::new(transport) as Arc<dyn FileAuthorityTransport>,
                binding,
            )
        };
        #[cfg(test)]
        let (transport, binding) = {
            let (transport, binding) = direct_root(epoch)?;
            (
                Arc::new(transport) as Arc<dyn FileAuthorityTransport>,
                binding,
            )
        };

        // Root registration and root-table creation consumed requests 1-2.
        let authority = Self::with_transport(transport, binding, 3);
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

    fn with_transport(
        transport: Arc<dyn FileAuthorityTransport>,
        binding: FileAuthorityBinding,
        next_request: u64,
    ) -> Arc<Self> {
        Arc::new(Self {
            transport,
            binding,
            next_request: Mutex::new(next_request),
        })
    }

    pub(crate) const fn binding(&self) -> FileAuthorityBinding {
        self.binding
    }

    fn execute(
        &self,
        command: Command,
        expected_generation: ObjectGeneration,
    ) -> Result<Response, AuthorityFatal> {
        // Allocation and the complete round trip are one critical section. An
        // atomic counter lets request N+1 reach the authority while N is still
        // in flight, which the core rejects as `RequestOutOfOrder` — and an
        // authority rejection terminates the run, so this is not recoverable.
        // The guard is a client transport lock, never a kernel-object lock, so
        // holding it across the round trip does not enter the object lock order.
        let mut next_request = self.next_request.lock();
        let sequence = *next_request;
        // Consume the sequence before the round trip: there is no retry path, so
        // an identity must never be reused after a request is issued.
        *next_request = sequence
            .checked_add(1)
            .ok_or(AuthorityFatal::IdentityExhausted)?;
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
) -> Result<(super::DirectFileAuthority, FileAuthorityBinding), AuthorityFatal> {
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

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use super::super::{AuthorityCall, AuthorityReply};
    use super::*;

    /// Transport that reports the peak number of same-client requests observed
    /// inside one round trip.
    struct OverlapProbe {
        inner: super::super::DirectFileAuthority,
        in_flight: AtomicUsize,
        peak_in_flight: AtomicUsize,
        arrivals: AtomicUsize,
    }

    impl OverlapProbe {
        fn wrapping(inner: super::super::DirectFileAuthority) -> Arc<Self> {
            Arc::new(Self {
                inner,
                in_flight: AtomicUsize::new(0),
                peak_in_flight: AtomicUsize::new(0),
                arrivals: AtomicUsize::new(0),
            })
        }
    }

    impl FileAuthorityTransport for OverlapProbe {
        fn transact(&self, call: AuthorityCall) -> Result<AuthorityReply, AuthorityFatal> {
            let depth = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            self.peak_in_flight.fetch_max(depth, Ordering::SeqCst);
            // Hold the first arrival open. A second caller can only be seen here
            // if allocation and the round trip are not one critical section.
            if self.arrivals.fetch_add(1, Ordering::SeqCst) == 0 {
                std::thread::sleep(Duration::from_millis(250));
            }
            let reply = self.inner.transact(call);
            self.in_flight.fetch_sub(1, Ordering::SeqCst);
            reply
        }
    }

    /// K3 task #41 contract: per-client request allocation and the complete
    /// transport round trip are one serialized critical section, so request N+1
    /// cannot overtake N.
    #[test]
    fn same_client_requests_cannot_overtake_an_in_flight_round_trip() {
        let epoch = AuthorityEpoch::for_run(11).expect("authority epoch");
        let (inner, binding) = direct_root(epoch).expect("direct root");
        let probe = OverlapProbe::wrapping(inner);
        let run = FileAuthorityRun::with_transport(probe.clone(), binding, 3);

        let health = move || Command::ListSlots {
            table: binding.table,
            after: None,
            maximum: SlotPageLimit::bounded(1).expect("root health bound"),
        };

        let first = {
            let run = Arc::clone(&run);
            std::thread::spawn(move || run.execute(health(), binding.generation))
        };
        let second = {
            let run = Arc::clone(&run);
            std::thread::spawn(move || run.execute(health(), binding.generation))
        };

        first.join().expect("first thread").expect("first request");
        second
            .join()
            .expect("second thread")
            .expect("second request");

        assert_eq!(
            probe.arrivals.load(Ordering::SeqCst),
            2,
            "both requests must reach the transport"
        );
        assert_eq!(
            probe.peak_in_flight.load(Ordering::SeqCst),
            1,
            "a same-client request reached the authority while another was in flight"
        );
    }
}
