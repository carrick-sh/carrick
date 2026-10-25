//! Shared helpers for carrick-embed's guest-running (signed) tests.
//!
//! These suites are run ONLY through `just test-embed` (scripts/test-signed.sh),
//! which signs the test executable with the hypervisor entitlement, exports
//! `CARRICK_RUN_ID`, and runs it under `RUST_TEST_THREADS=1`.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard};

use carrick_abi::{NsGid, NsUid};
use carrick_embed::{Carrier, ContainerBuilder, ContainerResult, EmbedError, InMemoryFileVfs};
use carrick_image::PullPolicy;

/// The canonical smoke image: the arm64 probe lane's image
/// (`crates/carrick-cli/tests/conformance.rs:209`, `ARM64.image`) and
/// AGENTS.md's default guest (frame pointers, so `carrick trace` can walk it).
pub const SMOKE_IMAGE: &str = "docker.io/library/ubuntu:24.04";

/// Qualify native exec stability on one signed executable identity. Every
/// round is mandatory; a panic stops the population at its first failure.
pub fn native_exec_three_rounds(name: &str, mut run: impl FnMut()) {
    for round in 1..=3 {
        println!("native-exec-round case={name} round={round} started");
        run();
        println!("native-exec-round case={name} round={round} passed");
    }
}

/// One fork/exit/fork/exec/wait composition on a native fork child: the
/// el1-sched fixture's `reused-slot-exec` mode forks a child that exits,
/// forks again into the retired slot and has that child `execve` a raw
/// no-libc successor, then waits for both. Shared by
/// `el1_fork_exec::native_child_exec_after_reusing_a_retired_slot` and the
/// `smoke_signed` target. The caller holds `guest_lock` and a watchdog and
/// passes the builder for [`SMOKE_IMAGE`]: implicit
/// (`ContainerBuilder::from_image`) or on an explicit carrier.
pub fn reused_slot_native_child_exec(builder: ContainerBuilder) {
    // Signed smoke for the fork/exit/exec composition. Numeric slot reuse is
    // deterministic only in the VM-free
    // `first_exec_after_fork_exit_reuses_the_slot_with_a_fresh_root_incarnation`
    // witness because the live allocator hashes the successor MM.
    // The successor is a raw no-libc image. A ring-owned native process has
    // no host task context, so libc/std startup (std's stdio ppoll) and the
    // CLI terminal are out of reach; its reply returns over in-zone pipes.
    const SUCCESSOR: &str = "carrick-linux-aarch64-read-then-write-via-stdio";
    let fixture_dir = repo_root().join("target/embed-fixtures");
    let successor_dir =
        repo_root().join("fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release");
    assert!(
        successor_dir.join(SUCCESSOR).is_file(),
        "missing {SUCCESSOR}; run scripts/build-linux-fixtures.sh first"
    );
    let result = run_or_fail(
        builder
            .pull_policy(PullPolicy::Missing)
            .mount_readonly(fixture_dir.to_string_lossy(), "/opt/carrick")
            .mount_readonly(successor_dir.to_string_lossy(), "/p")
            .command([
                "/opt/carrick/el1-sched-aarch64".to_owned(),
                "reused-slot-exec".to_owned(),
                format!("/p/{SUCCESSOR}"),
            ])
            .run_blocking(),
    );
    assert!(
        result.success(),
        "exit {} signal {:?} stdout {:?} stderr {:?}",
        result.exit_code,
        result.signal,
        result.stdout_utf8(),
        result.stderr_utf8()
    );
    assert_eq!(result.stdout_utf8(), "reused-slot-exec ok\n");
}

static GUEST_LOCK: Mutex<()> = Mutex::new(());

/// Serialize guest-running tests inside one process: HVF allows one VM per
/// process, and the Inherit case redirects the process's own fd 1. The recipe
/// sets `RUST_TEST_THREADS=1`; this is the in-file belt for a filtered run.
pub fn guest_lock() -> MutexGuard<'static, ()> {
    GUEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The repository root (`crates/carrick-embed` is two levels down).
pub fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("carrick-embed lives under crates/carrick-embed")
        .to_path_buf()
}

/// A builder for the immutable, locally-built raw-syscall interceptor probe.
/// The fixture bytes are mounted executable through Carrick's public VFS seam;
/// no mutable image content participates in this proof.
pub fn interceptor_probe_builder(mode: &str) -> ContainerBuilder {
    ContainerBuilder::from_image(SMOKE_IMAGE)
        .pull_policy(PullPolicy::Missing)
        .command(["/opt/carrick/interceptor-probe", mode])
        .vfs_mount("/opt/carrick", Box::new(interceptor_probe_vfs(None)))
}

pub fn interceptor_probe_vfs(marker: Option<&[u8]>) -> InMemoryFileVfs {
    let fixture = repo_root().join("target/embed-fixtures/interceptor-probe-aarch64");
    let bytes = std::fs::read(&fixture).unwrap_or_else(|error| {
        panic!(
            "read {}: {error}; scripts/test-signed.sh must build the fixture first",
            fixture.display()
        )
    });
    let vfs = InMemoryFileVfs::new();
    vfs.add_file_with_metadata(
        "/opt/carrick/interceptor-probe",
        bytes,
        0o755,
        NsUid::ROOT,
        NsGid::ROOT,
        0,
    )
    .expect("install executable interceptor probe");
    if let Some(marker) = marker {
        // VfsMounts deliberately passes the canonical absolute guest path to
        // mounted filesystems (proc/sys/dev use the same convention).
        vfs.add_file("/opt/carrick/marker", marker)
            .expect("install topology marker");
    }
    vfs
}

/// The static zone-readers fixture (`fixtures/embed-zone-readers`), mounted
/// executable at `/opt/carrick/zone-readers`.
pub fn zone_readers_vfs() -> InMemoryFileVfs {
    let fixture = repo_root().join("target/embed-fixtures/zone-readers-aarch64");
    let bytes = std::fs::read(&fixture).unwrap_or_else(|error| {
        panic!(
            "read {}: {error}; scripts/test-signed.sh must build the fixture first",
            fixture.display()
        )
    });
    let vfs = InMemoryFileVfs::new();
    vfs.add_file_with_metadata(
        "/opt/carrick/zone-readers",
        bytes,
        0o755,
        NsUid::ROOT,
        NsGid::ROOT,
        0,
    )
    .expect("install executable zone-readers fixture");
    vfs
}

/// The static icache-reuse fixture (`fixtures/embed-icache-reuse`), mounted
/// executable at `/opt/carrick/icache-reuse`.
pub fn icache_reuse_vfs() -> InMemoryFileVfs {
    let fixture = repo_root().join("target/embed-fixtures/icache-reuse-aarch64");
    let bytes = std::fs::read(&fixture).unwrap_or_else(|error| {
        panic!(
            "read {}: {error}; scripts/test-signed.sh must build the fixture first",
            fixture.display()
        )
    });
    let vfs = InMemoryFileVfs::new();
    vfs.add_file_with_metadata(
        "/opt/carrick/icache-reuse",
        bytes,
        0o755,
        NsUid::ROOT,
        NsGid::ROOT,
        0,
    )
    .expect("install executable icache-reuse fixture");
    vfs
}

/// The static host-copyout fixture (`fixtures/embed-copyout`), mounted
/// executable at `/opt/carrick/copyout`.
pub fn copyout_vfs() -> InMemoryFileVfs {
    let fixture = repo_root().join("target/embed-fixtures/copyout-aarch64");
    let bytes = std::fs::read(&fixture).unwrap_or_else(|error| {
        panic!(
            "read {}: {error}; scripts/test-signed.sh must build the fixture first",
            fixture.display()
        )
    });
    let vfs = InMemoryFileVfs::new();
    vfs.add_file_with_metadata(
        "/opt/carrick/copyout",
        bytes,
        0o755,
        NsUid::ROOT,
        NsGid::ROOT,
        0,
    )
    .expect("install executable copyout fixture");
    vfs
}

/// Where the static el1-sched fixture (`fixtures/embed-el1-sched`) is mounted.
pub const EL1_SCHED_FIXTURE: &str = "/opt/carrick/el1-sched";

/// The static el1-sched fixture, mounted executable at `/opt/carrick`.
pub fn el1_sched_vfs() -> InMemoryFileVfs {
    let fixture = repo_root().join("target/embed-fixtures/el1-sched-aarch64");
    let bytes = std::fs::read(&fixture).unwrap_or_else(|error| {
        panic!(
            "read {}: {error}; scripts/test-signed.sh must build the fixture first \
             (scripts/build-embed-el1-sched.sh)",
            fixture.display()
        )
    });
    let vfs = InMemoryFileVfs::new();
    vfs.add_file_with_metadata(EL1_SCHED_FIXTURE, bytes, 0o755, NsUid::ROOT, NsGid::ROOT, 0)
        .expect("install executable el1-sched fixture");
    vfs
}

/// An explicit carrier (one VM serving every container built from it), or a
/// loud failure: HV_DENIED is never a skip, and a prior carrier still retiring
/// is waited for, bounded.
pub fn carrier_or_fail() -> Carrier {
    for _ in 0..50 {
        match Carrier::new() {
            Ok(carrier) => return carrier,
            Err(EmbedError::Entitlement) => panic!(
                "HV_DENIED (0xfae94007): run through scripts/test-signed.sh; \
                 a bare cargo test cannot boot a guest"
            ),
            Err(EmbedError::CarrierAlreadyActive) => {
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            Err(error) => panic!("carrier initialization failed: {error}"),
        }
    }
    panic!("carrier initialization timed out waiting for a prior carrier to retire");
}

/// Unwrap a container run, turning `EmbedError::Entitlement` into a loud,
/// actionable FAILURE. Never a skip: an unsigned test executable is a broken
/// gate, not an absent one.
pub fn run_or_fail(outcome: Result<ContainerResult, EmbedError>) -> ContainerResult {
    match outcome {
        Ok(result) => result,
        Err(EmbedError::Entitlement) => panic!(
            "HV_DENIED (0xfae94007): this test executable lacks \
             com.apple.security.hypervisor. Run it through `just test-embed` \
             (scripts/test-signed.sh signs it); a bare `cargo test -p carrick-embed` \
             can never boot a guest."
        ),
        Err(err) => panic!("container run failed: {err}"),
    }
}

/// The run id `scripts/test-signed.sh` exported. Every guest this process
/// launches is titled `carrick:<run-id>:`, and the CLI-parity test derives
/// `<run-id>-cli` for the child it spawns, so `scripts/sudo/kill.sh` can reap
/// exactly this run. Fail closed: without the stamp nothing can clean up.
pub fn run_id() -> String {
    std::env::var("CARRICK_RUN_ID")
        .ok()
        .filter(|id| !id.is_empty())
        .expect(
            "CARRICK_RUN_ID must be set: scripts/test-signed.sh exports it so \
             scripts/sudo/kill.sh can reap this run's guests",
        )
}

/// Bound a guest run: if the run outlives `timeout`, reap this run id with
/// `scripts/sudo/kill.sh`, so a hang is a test failure rather than a wedge.
pub struct Watchdog {
    done: std::sync::Arc<std::sync::atomic::AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl Watchdog {
    pub fn start(timeout: std::time::Duration) -> Self {
        let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let done_clone = done.clone();
        let run_id = run_id();
        let handle = std::thread::spawn(move || {
            let start = std::time::Instant::now();
            while start.elapsed() < timeout {
                if done_clone.load(std::sync::atomic::Ordering::Relaxed) {
                    return;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            if !done_clone.load(std::sync::atomic::Ordering::Relaxed) {
                eprintln!(
                    "WATCHDOG: timeout ({timeout:?}) exceeded for CARRICK_RUN_ID={run_id}; reaping with scripts/sudo/kill.sh"
                );
                // The in-guest scheduler's state is the post-mortem of a
                // wedge in a carrier that schedules threads at EL1.
                if let Some(zone) = carrick_el1_abi::zone_tables() {
                    let mut census = String::new();
                    let _ = zone.write_census(&mut census);
                    // The object each parked record waits on, and its state:
                    // a lost write leaves the object empty; a lost wake
                    // leaves it readable with the waiter still linked.
                    if let Some(region) =
                        carrick_el1_abi::ipc_window_host().and_then(|window| window.attach().ok())
                    {
                        let _ =
                            carrick_el1_abi::ipc::write_ipc_wait_census(zone, &region, &mut census);
                        // Host-side waiters hold no zone record: the objects
                        // they subscribe to, what each is owed, and the owed
                        // index a host boundary would drain.
                        let _ = region.write_host_wake_census(&mut census);
                    }
                    // The flags through which EL1 announces owed host work.
                    let _ = carrick_el1_abi::write_current_task_census(&mut census);
                    // Root lock words distinguish a missing producer from an
                    // EL1 critical section that left its image while held.
                    let _ = carrick_runtime::write_reservation_root_census(&mut census);
                    eprintln!("WATCHDOG zone census:\n{census}");
                }
                // The abort's post-mortem names every blocked thread's
                // continuation and whether the wait service still holds it
                // (never woken) or published its wake (woken, never run).
                // Persist it for every watchdog wedge, not only when an
                // operator remembered CARRICK_POSTMORTEM_DIR.
                let post_mortem_dir = carrick_kernel::kernel::debug::PostMortem::configured_dir()
                    .unwrap_or_else(|| {
                        let dir = repo_root().join("target/embed-post-mortem").join(&run_id);
                        carrick_kernel::kernel::debug::PostMortem::install_dir(dir.clone());
                        dir
                    });
                eprintln!(
                    "WATCHDOG post-mortem directory: {}",
                    post_mortem_dir.display()
                );
                // The kernel graph's view of the wedge: the runner answers a
                // latched abort with a post-mortem (written under
                // CARRICK_POSTMORTEM_DIR when set) before the reap.
                carrick_kernel::kernel::debug::request_abort(
                    carrick_kernel::kernel::debug::AbortReason::DebugRequest {
                        run_id: run_id.clone(),
                    },
                );
                std::thread::sleep(std::time::Duration::from_secs(8));
                let kill_script = repo_root().join("scripts/sudo/kill.sh");
                let _ = std::process::Command::new(kill_script)
                    .arg(&run_id)
                    .status();
            }
        });
        Self {
            done,
            handle: Some(handle),
        }
    }

    pub fn disarm(mut self) {
        self.done.store(true, std::sync::atomic::Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

impl Drop for Watchdog {
    fn drop(&mut self) {
        self.done.store(true, std::sync::atomic::Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}
