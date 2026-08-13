//! Live kernel debug protocol: a bounded, versioned, uid-authenticated Unix
//! socket that serves one coherent [`KernelSnapshotV1`] projection per
//! connection.
//!
//! This is the K1 "observability is a kernel ABI" surface. The reader never
//! sees a host pointer, never sees a partially collected snapshot, and cannot
//! be made to wait on a wedged guest: every stage is deadline-bounded and
//! fails closed with a named error.
//!
//! [`KernelSnapshotV1`]: super::snapshot::KernelSnapshotV1

pub mod client;
pub mod dto;
pub mod endpoint;
pub mod server;
pub mod wire;

pub use client::{ClientError, fetch, fetch_at};
pub use dto::{
    KERNEL_DEBUG_REQUEST_SCHEMA, KERNEL_DEBUG_RESPONSE_SCHEMA, KernelDebugDtoError,
    KernelDebugRequest, KernelDebugSnapshot, KernelDebugTable, UnknownTable,
};
pub use endpoint::{DebugEndpoint, EndpointError};
pub use server::{KernelDebugServer, ServerError};
pub use wire::{DEADLINE, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, WireError};

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::Arc;

    use super::*;
    use crate::kernel::core::Kernel;

    /// Minimal `MmBackend` so a snapshot can complete. A root built with
    /// `for_reference_model` has NO mm backend, and the snapshot then fails
    /// closed with "authority unavailable for Mms" — correct behaviour, but it
    /// tests the refusal path rather than the served path.
    #[derive(Debug)]
    struct StubMmBackend;

    impl crate::kernel::MmBackend for StubMmBackend {
        fn snapshot(
            &self,
            _deadline: std::time::Instant,
        ) -> Result<crate::kernel::MmBackendSnapshot, crate::kernel::SnapshotError> {
            let root = crate::kernel::Stage1Root::for_aarch64_4k(carrick_guest_mem::Gpa(0x1000))
                .expect("aligned stage-1 root");
            let asid = crate::kernel::Asid::from_registry_allocation(
                std::num::NonZeroU16::new(1).expect("nonzero test ASID"),
            );
            Ok(crate::kernel::MmBackendSnapshot {
                revision: 1,
                binding: crate::kernel::MmBinding {
                    asid,
                    stage1_root: root,
                    ttbr0: crate::kernel::Ttbr0::for_aarch64(asid, root),
                },
                vmas: vec![crate::kernel::VmaSummary {
                    start: carrick_guest_mem::GuestVa(0x1000),
                    end: carrick_guest_mem::GuestVa(0x2000),
                }],
                vma_revision: None,
                mapping_ids: Vec::new(),
                frame_inventory_revision: None,
            })
        }

        fn revision(&self) -> u64 {
            1
        }
    }

    /// Build a Kernel with a root task, the same way the other kernel tests do.
    fn kernel_with_root() -> Arc<Kernel> {
        let bootstrap = crate::kernel::RootBootstrap::with_mm_backend(
            4242,
            carrick_hal::ThreadId::synthetic_for_tests(4242),
            Arc::new(StubMmBackend),
            "root".to_owned(),
        )
        .expect("root bootstrap input");
        let (kernel, _context) = Kernel::bootstrap_root(bootstrap).expect("root kernel");
        kernel
    }

    fn scoped_endpoint(run_id: &str) -> (tempfile::TempDir, DebugEndpoint) {
        super::endpoint::tests::scoped_endpoint(run_id)
    }

    #[test]
    fn a_live_server_serves_every_table_from_one_coherent_snapshot() {
        let (_temp, endpoint) = scoped_endpoint("k1-debug-all-tables");
        let kernel = kernel_with_root();
        let mut server =
            KernelDebugServer::start_at(Arc::clone(&kernel), endpoint.clone()).expect("server");

        let snapshot = fetch_at(&endpoint, None).expect("fetch snapshot");

        assert_eq!(snapshot.schema, KERNEL_DEBUG_RESPONSE_SCHEMA);
        assert_eq!(
            snapshot.present(),
            KernelDebugTable::ALL.into_iter().collect::<BTreeSet<_>>(),
            "an unfiltered request must carry every table"
        );
        assert!(
            snapshot
                .tasks
                .as_ref()
                .is_some_and(|tasks| !tasks.is_empty()),
            "a kernel with a root task must report at least one task"
        );
        server.shutdown();
    }

    #[test]
    fn a_filtered_request_carries_exactly_the_requested_tables() {
        let (_temp, endpoint) = scoped_endpoint("k1-debug-filtered");
        let kernel = kernel_with_root();
        let mut server =
            KernelDebugServer::start_at(Arc::clone(&kernel), endpoint.clone()).expect("server");

        let wanted = vec![KernelDebugTable::Task, KernelDebugTable::Thread];
        let snapshot = fetch_at(&endpoint, Some(wanted.clone())).expect("fetch filtered");

        assert_eq!(
            snapshot.present(),
            wanted.into_iter().collect::<BTreeSet<_>>(),
            "a filtered response must not carry unrequested tables"
        );
        assert!(
            snapshot.mms.is_none(),
            "an unrequested table must be absent, not empty"
        );
        server.shutdown();
    }

    #[test]
    fn the_client_reports_a_named_error_when_no_run_is_listening() {
        let (_temp, endpoint) = scoped_endpoint("k1-debug-not-listening");
        let error = fetch_at(&endpoint, None).expect_err("no server is listening");
        assert!(
            matches!(error, ClientError::NotListening { .. }),
            "expected a named not-listening error, got {error:?}"
        );
    }

    #[test]
    fn a_second_server_cannot_steal_a_live_endpoint() {
        let (_temp, endpoint) = scoped_endpoint("k1-debug-exclusive");
        let kernel = kernel_with_root();
        let mut first =
            KernelDebugServer::start_at(Arc::clone(&kernel), endpoint.clone()).expect("server");

        let error = KernelDebugServer::start_at(Arc::clone(&kernel), endpoint.clone())
            .expect_err("a live endpoint must not be stolen");
        assert!(
            matches!(
                error,
                ServerError::Endpoint(EndpointError::OwnedByLiveProcess { .. })
            ),
            "expected live-owner refusal, got {error:?}"
        );
        first.shutdown();
    }

    #[test]
    fn shutdown_releases_the_socket() {
        let (_temp, endpoint) = scoped_endpoint("k1-debug-release");
        let kernel = kernel_with_root();
        let mut server =
            KernelDebugServer::start_at(Arc::clone(&kernel), endpoint.clone()).expect("server");
        assert!(endpoint.socket_path().exists(), "server must bind");
        server.shutdown();
        assert!(
            !endpoint.socket_path().exists(),
            "shutdown must unbind so a later run is not refused by a dead socket"
        );
    }

    #[test]
    fn validation_rejects_an_unknown_response_schema() {
        let mut snapshot = empty_snapshot();
        snapshot.schema = "carrick.kernel-debug-snapshot.v2".to_owned();
        let error = snapshot
            .validate(&BTreeSet::new())
            .expect_err("unknown schema must be refused");
        assert!(matches!(error, KernelDebugDtoError::UnknownSchema(_)));
    }

    #[test]
    fn validation_rejects_a_missing_requested_table() {
        let snapshot = empty_snapshot();
        let requested = [KernelDebugTable::Task].into_iter().collect();
        let error = snapshot
            .validate(&requested)
            .expect_err("a missing requested table must be refused");
        assert!(
            matches!(error, KernelDebugDtoError::MissingTable("task")),
            "got {error:?}"
        );
    }

    #[test]
    fn validation_rejects_a_duplicate_id() {
        let mut snapshot = empty_snapshot();
        let row = dto::DebugMmRow {
            id: 7,
            class: dto::DebugClass::Live,
            revision: 1,
            asid: 1,
            stage1_root_gpa: 0x1000,
            ttbr0: 0x1000,
            mapping_ids: Vec::new(),
            legacy_aio_context_count: 0,
            next_legacy_aio_context: 0,
        };
        snapshot.mms = Some(vec![row.clone(), row]);
        let requested = [KernelDebugTable::Mm].into_iter().collect();
        let error = snapshot
            .validate(&requested)
            .expect_err("a duplicate id must be refused");
        assert!(
            matches!(error, KernelDebugDtoError::DuplicateId { table: "mm", .. }),
            "got {error:?}"
        );
    }

    #[test]
    fn validation_rejects_a_broken_join() {
        let mut snapshot = empty_snapshot();
        snapshot.mms = Some(Vec::new());
        snapshot.vmas = Some(vec![dto::DebugVmaRow {
            mm: 99,
            start: 0,
            end: 0x1000,
        }]);
        let requested = [KernelDebugTable::Mm, KernelDebugTable::Vma]
            .into_iter()
            .collect();
        let error = snapshot
            .validate(&requested)
            .expect_err("a vma referencing an absent mm must be refused");
        assert!(
            matches!(
                error,
                KernelDebugDtoError::BrokenJoin {
                    from: "vma.mm",
                    to: "mm",
                    ..
                }
            ),
            "got {error:?}"
        );
    }

    #[test]
    fn validation_rejects_a_partial_frame() {
        let mut snapshot = empty_snapshot();
        snapshot.frames = Some(vec![dto::DebugFrameRow {
            frame: 1,
            length: 0x4000,
            mappings: vec![42],
        }]);
        snapshot.mappings = Some(Vec::new());
        let requested = [KernelDebugTable::Frame, KernelDebugTable::Mapping]
            .into_iter()
            .collect();
        let error = snapshot
            .validate(&requested)
            .expect_err("a frame listing an absent mapping must be refused");
        assert!(
            matches!(
                error,
                KernelDebugDtoError::PartialFrame {
                    frame: 1,
                    mapping: 42
                }
            ),
            "got {error:?}"
        );
    }

    #[test]
    fn unknown_table_names_are_rejected_by_name() {
        let error = KernelDebugTable::parse("taskz").expect_err("typo must be refused");
        assert_eq!(error.0, "taskz");
        assert_eq!(
            KernelDebugTable::parse("file-description").expect("known table"),
            KernelDebugTable::FileDescription
        );
    }

    fn empty_snapshot() -> KernelDebugSnapshot {
        KernelDebugSnapshot {
            schema: KERNEL_DEBUG_RESPONSE_SCHEMA.to_owned(),
            snapshot_schema_version: crate::kernel::snapshot::KERNEL_SNAPSHOT_V1_SCHEMA,
            registry_epoch: 0,
            tasks: None,
            zombies: None,
            threads: None,
            task_shared: None,
            thread_resources: None,
            mms: None,
            vmas: None,
            frames: None,
            mappings: None,
            file_tables: None,
            file_slots: None,
            file_descriptions: None,
            fs_contexts: None,
            credentials: None,
            process_groups: None,
            sessions: None,
            sighands: None,
            task_signals: None,
            thread_signals: None,
        }
    }
}
