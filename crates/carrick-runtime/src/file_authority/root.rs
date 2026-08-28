use std::sync::Arc;

use parking_lot::Mutex;

use carrick_kernel::domains::{HostPid, ProcessGeneration};

use super::{
    AuthorityEpoch, AuthorityFatal, Command, DirectFileAuthority, FileAuthorityBinding,
    FileAuthorityCore, FileAuthorityTransport, ObjectGeneration, Outcome, Request, RequestId,
    Response,
};
use super::{ClientId, ClientIdentity};

/// The one authenticated FileAuthority endpoint retained by a dispatcher run.
///
/// The in-carrier core and root table are live before any guest task starts.
/// Syscall families are attached to this root incrementally; until a family is
/// cut over, this object owns no guest-visible backing from that family.
pub(crate) struct FileAuthorityRun {
    transport: Arc<dyn FileAuthorityTransport>,
    direct: Arc<DirectFileAuthority>,
    #[allow(
        dead_code,
        reason = "retained for exact-root authentication in the in-carrier dispatch cutover"
    )]
    root_table: std::sync::Weak<crate::kernel::FileTable>,
    binding: FileAuthorityBinding,
    #[allow(
        dead_code,
        reason = "retained for serialized client request allocation in the in-carrier cutover"
    )]
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
    /// Start the per-run, in-carrier file authority.
    pub(crate) fn launch(
        root_table: Arc<crate::kernel::FileTable>,
    ) -> Result<Arc<Self>, AuthorityFatal> {
        let epoch = run_epoch()?;
        let (direct_raw, binding) = direct_root(epoch, &root_table)?;
        let direct = Arc::new(direct_raw);
        let transport = Arc::clone(&direct) as Arc<dyn FileAuthorityTransport>;
        let authority =
            Self::with_transports(transport, direct, Arc::downgrade(&root_table), binding, 2);
        Ok(authority)
    }

    fn with_transports(
        transport: Arc<dyn FileAuthorityTransport>,
        direct: Arc<DirectFileAuthority>,
        root_table: std::sync::Weak<crate::kernel::FileTable>,
        binding: FileAuthorityBinding,
        next_request: u64,
    ) -> Arc<Self> {
        Arc::new(Self {
            transport,
            direct,
            root_table,
            binding,
            next_request: Mutex::new(next_request),
        })
    }

    pub(crate) const fn binding(&self) -> FileAuthorityBinding {
        self.binding
    }

    #[allow(
        dead_code,
        reason = "retained for the in-carrier canonical dispatch cutover"
    )]
    pub(crate) fn transport(&self) -> &Arc<DirectFileAuthority> {
        &self.direct
    }

    #[cfg(test)]
    #[allow(dead_code, reason = "retained for exact-root authentication in test")]
    pub(crate) fn root_table(&self) -> Option<Arc<crate::kernel::FileTable>> {
        self.root_table.upgrade()
    }

    #[cfg(test)]
    pub(crate) fn model_table_count_for_test(&self) -> usize {
        self.direct.model_table_count()
    }

    #[cfg(test)]
    pub(crate) fn model_description_count_for_test(&self) -> usize {
        self.direct.model_description_count()
    }

    #[allow(
        dead_code,
        reason = "retained for ordinary model commands in the in-carrier cutover"
    )]
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

fn direct_root(
    epoch: AuthorityEpoch,
    root_table: &Arc<crate::kernel::FileTable>,
) -> Result<(DirectFileAuthority, FileAuthorityBinding), AuthorityFatal> {
    let transport = DirectFileAuthority::for_run(FileAuthorityCore::for_run(epoch));
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
    Ok((
        transport,
        FileAuthorityBinding {
            epoch,
            client,
            table: root_table.id(),
            generation: ObjectGeneration::INITIAL,
        },
    ))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use super::super::{AuthorityCall, AuthorityReply};
    use super::*;
    use crate::kernel::{FileSlotNumber, FileTable, ObjectIdRegistry};

    /// Transport that reports the peak number of same-client requests observed
    /// inside one round trip.
    struct OverlapProbe {
        inner: Arc<DirectFileAuthority>,
        in_flight: AtomicUsize,
        peak_in_flight: AtomicUsize,
        arrivals: AtomicUsize,
    }

    impl OverlapProbe {
        fn wrapping(inner: Arc<DirectFileAuthority>) -> Arc<Self> {
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
        let ids = ObjectIdRegistry::new();
        let table = Arc::new(FileTable::new(ids.file_table_id().expect("table id")));
        let (inner, binding) = direct_root(epoch, &table).expect("direct root");
        let direct = Arc::new(inner);
        let probe = OverlapProbe::wrapping(Arc::clone(&direct));
        let run = FileAuthorityRun::with_transports(
            probe.clone(),
            direct,
            Arc::downgrade(&table),
            binding,
            2,
        );

        let table_id = binding.table;
        let command = move || Command::ResolveSlot {
            table: table_id,
            fd: FileSlotNumber::for_open_fd(3).expect("fd"),
        };

        let first = {
            let run = Arc::clone(&run);
            let cmd = command();
            std::thread::spawn(move || run.execute(cmd, binding.generation))
        };
        let second = {
            let run = Arc::clone(&run);
            let cmd = command();
            std::thread::spawn(move || run.execute(cmd, binding.generation))
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

    #[test]
    fn launch_creates_in_carrier_authority() {
        let ids = ObjectIdRegistry::new();
        let table = Arc::new(FileTable::new(ids.file_table_id().expect("table id")));
        let authority = FileAuthorityRun::launch(table).expect("launch in-carrier authority");
        let binding = authority.binding();
        assert_eq!(binding.client.id.raw(), 1);
        assert_eq!(binding.generation, ObjectGeneration::INITIAL);
    }

    #[test]
    fn file_authority_has_no_host_helper_process_path() {
        let production_root = include_str!("root.rs")
            .split("#[cfg(test)]\nmod tests")
            .next()
            .expect("production FileAuthority root source");
        let module_surface = include_str!("mod.rs");
        for retired in [
            concat!("Detached", "Helper"),
            concat!("CARRICK_FILE_AUTHORITY_", "HELPER"),
            concat!("Ipc", "FileAuthority"),
            concat!("spawn_", "per_run"),
        ] {
            assert!(
                !production_root.contains(retired) && !module_surface.contains(retired),
                "FileAuthority retained retired host-helper authority `{retired}`"
            );
        }
    }
}
