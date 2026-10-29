//! VM-free tests for signed-harness failure evidence.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "common/diagnostics.rs"]
mod diagnostics;

#[cfg(test)]
mod tests {
    use super::diagnostics::*;
    use carrick_kernel::kernel::debug::{self, AbortReason, PostMortem};

    mod serial_host {
        use super::*;
        #[test]
        fn logging_child() {
            let Ok(root) = std::env::var("EMBED_LOG_TEST_ROOT") else {
                return;
            };
            install(std::path::Path::new(&root), "harness-run");
            // A second installation must retain the first subscriber and file.
            install(std::path::Path::new(&root), "harness-run");
            tracing::warn!("child warning retained");
            tracing::debug!("child debug disabled");
            if std::env::var_os("EMBED_LOG_TEST_PANIC").is_some() {
                panic!("forced harness failure");
            }
        }

        #[test]
        fn failure_replays_logs_and_success_stays_quiet() {
            for fail in [false, true] {
                let dir = tempfile::tempdir().unwrap();
                let mut child = std::process::Command::new(std::env::current_exe().unwrap());
                child
                    .args([
                        "--exact",
                        "tests::serial_host::logging_child",
                        "--nocapture",
                    ])
                    .env_remove("RUST_LOG")
                    .env("EMBED_LOG_TEST_ROOT", dir.path());
                if fail {
                    child.env("EMBED_LOG_TEST_PANIC", "1");
                }
                // Bound the subprocess as well as the debug RPCs.
                let output = tempfile::tempfile().unwrap();
                child
                    .stdout(output.try_clone().unwrap())
                    .stderr(output.try_clone().unwrap());
                let mut child = child.spawn().unwrap();
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
                let status = loop {
                    if let Some(status) = child.try_wait().unwrap() {
                        break status;
                    }
                    if std::time::Instant::now() >= deadline {
                        child.kill().unwrap();
                        panic!("logging child timed out");
                    }
                    std::thread::sleep(std::time::Duration::from_millis(10));
                };
                use std::io::{Read, Seek};
                let mut output = output;
                output.rewind().unwrap();
                let mut text = String::new();
                output.read_to_string(&mut text).unwrap();
                assert_eq!(status.success(), !fail, "{text}");
                assert_eq!(text.contains("child warning retained"), fail, "{text}");
                let logs = std::fs::read_dir(dir.path().join("target/embed-logs/harness-run"))
                    .unwrap()
                    .collect::<Result<Vec<_>, _>>()
                    .unwrap();
                assert_eq!(logs.len(), 1);
                let log = std::fs::read_to_string(logs[0].path()).unwrap();
                assert!(log.contains("child warning retained"));
                assert!(!log.contains("child debug disabled"));
            }
        }
    }

    #[test]
    fn warning_log_survives_without_a_vm_and_default_disables_debug() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("warnings.log");
        let dispatch = tracing::Dispatch::new(subscriber(
            std::fs::File::create(&path).unwrap(),
            filter(None),
        ));
        tracing::dispatcher::with_default(&dispatch, || {
            tracing::debug!("debug must stay disabled");
            tracing::info!("info must stay disabled");
            tracing::warn!(task = 42, "executor failed a claimed task");
            tracing::error!("error retained");
        });
        let log = std::fs::read_to_string(path).unwrap();
        assert!(log.contains("executor failed a claimed task"));
        assert!(log.contains("task=42"));
        assert!(log.contains("error retained"));
        assert!(!log.contains("must stay disabled"));
    }

    #[test]
    fn operator_filter_overrides_default() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("operator.log");
        tracing::subscriber::with_default(
            subscriber(std::fs::File::create(&path).unwrap(), filter(Some("debug"))),
            || tracing::debug!("operator requested debug"),
        );
        assert!(
            std::fs::read_to_string(path)
                .unwrap()
                .contains("operator requested debug")
        );
    }

    #[test]
    fn absent_runner_still_persists_explicitly_degraded_evidence() {
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("previously-missing");
        let run_id = format!("embed-no-runner-{}", std::process::id());
        carrick_kernel::event_ring::rec(1, 1017, 42, 7);
        let path = persist_watchdog(&run_id, &output).unwrap();
        let capture: PostMortem = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(capture.run_id.as_deref(), Some(run_id.as_str()));
        assert!(
            capture
                .truncated
                .iter()
                .any(|row| row.section == "debug_server")
        );
        assert!(output.join("event-ring.jsonl").is_file());
        assert!(output.join("event-ring-high-rate.jsonl").is_file());
    }

    struct Census;

    impl debug::PhysicalCaptureProvider for Census {
        fn capture(&self) -> debug::PhysicalCapture {
            debug::PhysicalCapture {
                zone_census: "test carrier census".to_owned(),
                vcpus: Vec::new(),
                host_threads: Vec::new(),
                unavailable: Vec::new(),
            }
        }
    }

    #[test]
    fn capture_is_persisted_without_the_runner_consuming_an_abort() {
        use carrick_kernel::kernel::{Kernel, RootBootstrap};
        let run_id = format!("embed-capture-{}", std::process::id());
        let bootstrap = RootBootstrap::for_reference_model(
            4242,
            carrick_hal::ThreadId::synthetic_for_tests(4242),
            "watchdog-capture".to_owned(),
        )
        .unwrap();
        let (kernel, _context) = Kernel::bootstrap_root(bootstrap).unwrap();
        let _server =
            debug::KernelDebugServer::install(kernel, &run_id, Some(std::sync::Arc::new(Census)))
                .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("watchdog");
        carrick_kernel::event_ring::rec(1, 1017, 42, 7);
        let path = persist_watchdog(&run_id, &output).unwrap();
        let capture: PostMortem = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        // The reference backend cannot snapshot its MM authority; the real
        // server must retain its degraded task graph alongside the census.
        assert!(capture.degraded_kernel.is_some(), "{capture:#?}");
        assert_eq!(capture.physical.unwrap().zone_census, "test carrier census");
        let ring = std::fs::read_to_string(output.join("event-ring.jsonl")).unwrap();
        assert!(
            ring.contains("1017"),
            "watchdog must preserve ring contents"
        );
        assert!(matches!(capture.reason, AbortReason::LiveCapture { .. }));
        assert!(output.join("event-ring.jsonl").is_file());
    }
}
