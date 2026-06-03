//! Run a base64-injected probe under carrick and under Docker, returning the
//! guest's combined stdout+stderr. Mirrors conformance.rs's run_*_probe path
//! (PROBE_SNIPPET stdin injection, per-sample CARRICK_RUN_ID, deadline watcher,
//! scoped cleanup) with perf-specific CPU normalization. SERIAL ONLY: callers
//! must run carrick and docker for the same sample non-concurrently.
use std::io::Write;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

const PROBE_SNIPPET: &str = "base64 -d > /tmp/p && chmod +x /tmp/p && /tmp/p";
const SAMPLE_DEADLINE: Duration = Duration::from_secs(60);
const PLATFORM: &str = "linux/arm64";
pub const IMAGE: &str = "docker.io/library/ubuntu:24.04";
/// `nproc` both engines must report for a normalized sample.
pub const CPU_PIN: u32 = 4;

static SEQ: AtomicU64 = AtomicU64::new(0);

/// Per-sample run id, stamped into the carrick guest title for scoped cleanup.
pub fn perf_run_id() -> String {
    format!(
        "cr-perf-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    )
}

fn scoped_kill_guests(repo_root: &Path, run_id: &str) {
    let _ = Command::new("sudo")
        .arg("-n")
        .arg(repo_root.join("scripts/sudo/kill.sh"))
        .arg(run_id)
        .output();
}

fn normalize(s: &str) -> String {
    s.lines()
        .filter(|l| !l.contains("case-insensitive; defaulting") && !l.contains("Pass `--fs host`"))
        .map(|l| l.trim_end())
        .collect::<Vec<_>>()
        .join("\n")
        .trim_end()
        .to_string()
}

/// Drain a child with a wall-clock deadline; on timeout SIGKILL the process
/// group and scoped-reap any escaped carrick guests. Returns combined output.
fn drain_with_deadline(child: std::process::Child, repo_root: &Path, run_id: &str) -> String {
    let pid = child.id() as i32;
    let done = Arc::new(AtomicBool::new(false));
    let watcher = {
        let done = Arc::clone(&done);
        let repo_root = repo_root.to_path_buf();
        let run_id = run_id.to_string();
        std::thread::spawn(move || {
            let start = Instant::now();
            while !done.load(Ordering::Relaxed) {
                if start.elapsed() > SAMPLE_DEADLINE {
                    unsafe { libc::kill(-pid, libc::SIGKILL) };
                    scoped_kill_guests(&repo_root, &run_id);
                    return true;
                }
                std::thread::sleep(Duration::from_millis(200));
            }
            false
        })
    };
    let out = child.wait_with_output().expect("wait child");
    done.store(true, Ordering::Relaxed);
    if watcher.join().unwrap_or(false) {
        return format!("<TIMEOUT after {}s>", SAMPLE_DEADLINE.as_secs());
    }
    let mut combined = String::from_utf8_lossy(&out.stdout).into_owned();
    combined.push_str(&String::from_utf8_lossy(&out.stderr));
    normalize(&combined)
}

fn feed_stdin(child: &mut std::process::Child, bytes: &[u8]) {
    let mut stdin = child.stdin.take().expect("stdin");
    let bytes = bytes.to_vec();
    std::thread::spawn(move || {
        let _ = stdin.write_all(&bytes);
    });
}

/// Guest mount point for the bind-mount disk cases.
const GUEST_MOUNT: &str = "/mnt";

/// Shell snippet that exports BENCH_DIR before exec'ing the base64-injected
/// probe — env-forwarding into the guest isn't relied on, so the probe reads
/// its target dir from the shell it inherits.
fn mounted_snippet() -> String {
    format!("export BENCH_DIR={GUEST_MOUNT}; {PROBE_SNIPPET}")
}

/// `-v` spec mounting the gitignored internal-SSD scratch dir at GUEST_MOUNT.
fn scratch_mount_spec(repo_root: &Path) -> String {
    format!("{}/.bench-scratch:{GUEST_MOUNT}", repo_root.display())
}

/// Run `probe_b64` under carrick (cold lane: a fresh `carrick run`), with
/// CARRICK_EXPOSED_CPUS=CPU_PIN. When `mount`, bind-mounts `.bench-scratch` at
/// /mnt (`-v`, needs `--fs host`) and points the probe at it via BENCH_DIR.
/// `repo_root` is the workspace root; `run_id` is reaped on timeout.
pub fn run_carrick(
    bin: &PathBuf,
    repo_root: &Path,
    run_id: &str,
    probe_b64: &[u8],
    mount: bool,
) -> String {
    let snippet = if mount {
        mounted_snippet()
    } else {
        PROBE_SNIPPET.to_string()
    };
    let mut args: Vec<String> = vec![
        "run".into(),
        "--platform".into(),
        PLATFORM.into(),
        "--raw".into(),
        "--fs".into(),
        "host".into(),
    ];
    if mount {
        args.push("-v".into());
        args.push(scratch_mount_spec(repo_root));
    }
    args.push(IMAGE.into());
    args.push("/bin/sh".into());
    args.push("-c".into());
    args.push(snippet);
    let mut child = Command::new(bin)
        .args(&args)
        .env("CARRICK_RUN_ID", run_id)
        .env("CARRICK_EXPOSED_CPUS", CPU_PIN.to_string())
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .process_group(0)
        .spawn()
        .expect("spawn carrick");
    feed_stdin(&mut child, probe_b64);
    drain_with_deadline(child, repo_root, run_id)
}

/// Run the NATIVE macOS build of a probe directly — no carrick, no Docker, no
/// VM (the host ceiling, the third "macos" engine). `native_bin` is the
/// aarch64-apple-darwin binary from the bench-native crate; it self-times and
/// prints the same key=value output as the guest probes. No base64/stdin
/// injection, no run-id, no cleanup — it is just a host process.
pub fn run_native(native_bin: &Path, bench_dir: Option<&str>) -> String {
    let mut cmd = Command::new(native_bin);
    cmd.stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    if let Some(d) = bench_dir {
        cmd.env("BENCH_DIR", d);
    }
    let out = match cmd.output() {
        Ok(o) => o,
        Err(e) => return format!("<native spawn failed: {e}>"),
    };
    let mut combined = String::from_utf8_lossy(&out.stdout).into_owned();
    combined.push_str(&String::from_utf8_lossy(&out.stderr));
    normalize(&combined)
}

/// Run `probe_b64` under Docker, pinned to 4 CPUs via --cpuset-cpus so `nproc`
/// inside the container is 4 (CFS --cpus would NOT change nproc).
pub fn run_docker(repo_root: &Path, run_id: &str, probe_b64: &[u8], mount: bool) -> String {
    let snippet = if mount {
        mounted_snippet()
    } else {
        PROBE_SNIPPET.to_string()
    };
    let mut args: Vec<String> = vec![
        "run".into(),
        "-i".into(),
        "--rm".into(),
        "--platform".into(),
        PLATFORM.into(),
        "--cpuset-cpus".into(),
        "0-3".into(),
    ];
    if mount {
        args.push("-v".into());
        args.push(scratch_mount_spec(repo_root));
    }
    args.push(IMAGE.into());
    args.push("/bin/sh".into());
    args.push("-c".into());
    args.push(snippet);
    let mut child = Command::new("docker")
        .args(&args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        // Own process group so the deadline watcher's kill(-pid) can reach the
        // docker CLI on timeout (without this, kill(-pid) hits a nonexistent
        // pgid and wait_with_output() blocks forever). --rm reaps the container.
        .process_group(0)
        .spawn()
        .expect("spawn docker");
    feed_stdin(&mut child, probe_b64);
    // Docker side has no carrick guests to reap; run_id only labels the sample.
    drain_with_deadline(child, repo_root, run_id)
}
