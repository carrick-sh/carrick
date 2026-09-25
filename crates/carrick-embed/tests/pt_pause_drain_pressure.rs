//! Signed binding for contracts `kernel.mm.pt-pause-drain-acknowledgement` and
//! `kernel.vcpu.kick-el0-boundary`. Signed lane only
//! (`just test-embed pt_pause_drain_pressure`).
//!
//! A Go test binary takes thousands of stage-1 page-table pauses (first-touch
//! faults, `mmap`/`munmap`/`mprotect`) while its sibling threads compute
//! between clock reads. A kick that lands inside Carrick's EL1 syscall vector
//! used to be lost — the re-armed "IRQ" asserted the masked FIQ line, into an
//! EL0 state with IRQs masked — and the drain's 500 ms deadline then killed the
//! guest with `fault page-table pause failed before mutation: TimedOut`. The
//! window widens with vCPU oversubscription, which in-process CPU burners do
//! not produce (three clean rounds per suite on the broken binary), so the
//! pressure here is what the gate runs: concurrent carriers of the same Go
//! suites, launched from the signed `target/release/carrick` as load only and
//! reaped by run id. On the broken binary the subject failed in roughly a
//! third of runs under that load. RED when a subject run fails or does not
//! pass; green when every round completes with the guest's own PASS.
mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use carrick_embed::{ContainerBuilder, ImageStore, PullPolicy};

const GO_IMAGE: &str = "localhost:5005/carrick-go-conformance:1.24";

/// Subject rounds per suite.
const ROUNDS: usize = 3;

/// Concurrent load carriers, as in `carrick-conformance --workers 4` plus the
/// subject: the shape that crashed go-testing and go-time on main.
const LOAD_CARRIERS: usize = 4;

/// The load rows: the four Go suites that crashed with the pause timeout.
const LOAD_ROWS: [(&str, &str); 4] = [
    ("/usr/local/go/src/time", "/conformance/time.test"),
    ("/usr/local/go/src/testing", "/conformance/testing.test"),
    ("/usr/local/go/src/os/signal", "/conformance/os_signal.test"),
    ("/usr/local/go/src/time", "/conformance/time.test"),
];

/// Concurrent carriers of the same Go suites, restarted until dropped. Their
/// own verdicts are not asserted: they exist to oversubscribe the host's
/// vCPU threads the way the conformance gate does.
struct LoadCarriers {
    stop: Arc<AtomicBool>,
    run_ids: Vec<String>,
    workers: Vec<std::thread::JoinHandle<()>>,
}

impl LoadCarriers {
    fn start() -> Self {
        let bin = common::repo_root().join("target/release/carrick");
        assert!(
            bin.exists(),
            "{} missing: `just test-embed` depends on `build`",
            bin.display()
        );
        let stop = Arc::new(AtomicBool::new(false));
        let mut run_ids = Vec::new();
        let mut workers = Vec::new();
        for (index, (workdir, binary)) in LOAD_ROWS.iter().take(LOAD_CARRIERS).enumerate() {
            let run_id = format!("{}-load{index}", common::run_id());
            run_ids.push(run_id.clone());
            let stop = Arc::clone(&stop);
            let bin = bin.clone();
            let (workdir, binary) = (workdir.to_string(), binary.to_string());
            workers.push(std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    let _ = std::process::Command::new(&bin)
                        .args([
                            "run",
                            "--pull",
                            "missing",
                            "-w",
                            &workdir,
                            GO_IMAGE,
                            &binary,
                            "-test.short",
                        ])
                        .env("CARRICK_RUN_ID", &run_id)
                        .stdin(std::process::Stdio::null())
                        .stdout(std::process::Stdio::null())
                        .stderr(std::process::Stdio::null())
                        .status();
                }
            }));
        }
        Self {
            stop,
            run_ids,
            workers,
        }
    }
}

impl Drop for LoadCarriers {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let kill_script = common::repo_root().join("scripts/sudo/kill.sh");
        for run_id in &self.run_ids {
            let _ = std::process::Command::new(&kill_script)
                .arg(run_id)
                .status();
        }
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
    }
}

// A failed subject round is the test's verdict; report the carrier error.
#[allow(clippy::panic)]
fn run_go_suite_under_load(workdir: &str, binary: &str, run: &str) {
    let _guest = common::guest_lock();
    let _load = LoadCarriers::start();
    for round in 0..ROUNDS {
        let result = ContainerBuilder::from_image(GO_IMAGE)
            .image_store(ImageStore::default_for_user())
            .pull_policy(PullPolicy::Missing)
            .workdir(workdir)
            .command([binary, "-test.short", "-test.run", run])
            .run_blocking()
            .unwrap_or_else(|error| {
                panic!(
                    "round {round}: {binary} carrier failed under concurrent carrier load: {error}"
                )
            });
        assert!(
            result.signal.is_none() && result.exit_code == 0,
            "round {round}: {binary} exit_code={} signal={:?}\nstderr tail: {}",
            result.exit_code,
            result.signal,
            String::from_utf8_lossy(&result.stderr[result.stderr.len().saturating_sub(2048)..])
        );
    }
}

#[test]
fn go_time_page_table_pauses_survive_carrier_load() {
    run_go_suite_under_load("/usr/local/go/src/time", "/conformance/time.test", "Test");
}

#[test]
fn go_testing_page_table_pauses_survive_carrier_load() {
    // `TestTBHelperParallel` fails identically under the Docker oracle
    // (baseline `go-testing`: carrick and docker both 161/162), so exclude the
    // `TestTB*` family to keep the guest's own verdict a clean PASS.
    run_go_suite_under_load(
        "/usr/local/go/src/testing",
        "/conformance/testing.test",
        "^Test([^T]|T[^B])",
    );
}
