//! Differential syscall conformance: carrick vs real Linux.
//!
//! Each case is a `/bin/sh -c` snippet exercising syscall-observable
//! behaviour. We run the IDENTICAL snippet under carrick (`--fs host`) and
//! inside a real arm64 Linux container (via the `bollard` Docker client) and
//! diff the output. A difference is a candidate gap in carrick's syscall
//! layer — surfaced by name immediately instead of via downstream
//! archaeology ("dpkg returned 100").
//!
//! The test self-skips (passes) when the carrick release binary isn't built
//! or Docker isn't reachable, so `cargo test` stays green everywhere. Run it
//! deliberately with Docker running and the signed release binary present:
//!   cargo test --test conformance -- --nocapture

// Test code: helpers are plain `fn`s (not `#[test]`/`#[cfg(test)]`), so clippy's
// allow-expect-in-tests heuristic does not exempt them. The no-panic gate targets
// production code, so allow unwrap/expect across this integration test file.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

/// Serializes the conformance test FUNCTIONS against each other so the total
/// HVF/Docker concurrency stays bounded (each function internally fans its
/// cases out; we don't want three functions' fan-outs stacking). Per-CASE
/// cleanup is now scoped by run id (see `case_run_id`/`scoped_kill_guests`), so
/// cases within a function — and other lanes/worktrees — no longer reap each
/// other; this lock is only the cross-function bound.
static CONFORMANCE_LOCK: Mutex<()> = Mutex::new(());

/// Probes that currently diverge from Linux due to a KNOWN, tracked gap.
/// A divergence in one of these is treated as an expected-fail (the suite
/// stays green), but if a known-gap probe unexpectedly PASSES, the test
/// FAILS so we remove it from this list — that's the signal the gap was
/// fixed. Each entry must cite the gap.
const KNOWN_PROBE_GAPS: &[&str] = &[
    // Audit remediation program (docs/superpowers/plans/2026-05-29-audit-remediation-program.md).
    // Each probe encodes a confirmed, dynamically-validated finding whose fix is
    // scheduled for the cited milestone; removed from this list when the fix lands
    // (the "UNEXPECTED PASS" guard fails the suite if we forget).
    // fsetfl FIXED in M4 (F_SETFL preserves access mode, masks mutable bits) — now PASSES.
    // rosharedbus FIXED in M1 (write_guest_bytes_checked perms check) — now PASSES.
    // mapfixed FIXED in M5 (private overlay aperture + stage-1 repoint; no late
    //   hv_vm_map) — MAP_FIXED|MAP_PRIVATE over a shared-aperture VA now gets
    //   genuinely-private backing, so a child's store stays private. now PASSES.
    // forkaltstack FIXED in M2 (migrate_thread_signal_state) — now PASSES.
    // pselecteintr FIXED in M3 (WaitOnFdsSelect: select/pselect6 hand off to the
    //   signal-interruptible waiter; fd-sets left intact across the wait, zeroed
    //   only on timeout) — now PASSES.
    // forkfpregs FIXED in M2 (VcpuSnapshot V0-V31/FPSR/FPCR) — now PASSES.
    // M4/M3 batch — probes on disk, fixes integrated one batch at a time; each
    // entry is removed in the same commit that lands its fix.
    // linuxsysinfo FIXED in M4 (struct padding) — now PASSES.
    // recvmsgtrunc FIXED in M4 (host recvmsg + msg_flags translation) — now PASSES.
    // termiosbits FIXED in M4 (c_cflag/c_iflag per-field translation) — now PASSES.
    // timersettimeabs FIXED in M4 (ABSTIME + timespec validation) — now PASSES.
    // iouringenterflag FIXED in M4 (flag/arg validation + to_submit bound) — now PASSES.
    // sotimeo FIXED in M3 (SO_RCVTIMEO/SO_SNDTIMEO stored per-OFD + threaded into blocking_io) — now PASSES.
    // epollstaledel FIXED in M3 (pending_ready keyed by fd) — now PASSES.
    // forksleepfork: a multithreaded fork with a sleeping sibling. The first
    // deadlock (fork-quiesce spinning because a sibling stuck in a synchronous
    // host nanosleep never parked) is FIXED by DispatchOutcome::WaitOnSleep, but
    // a SECOND, pre-existing deadlock remains in the HVF VM rebuild
    // (engine.fork()/hv_vm_destroy with a parked native sibling — the known
    // HV_BUSY/leaked-vCPU area). Until that lands, the fork still wedges and the
    // probe DIFFs. See docs/cpython-baseline/TRIAGE.md cluster 1.
    "forksleepfork",
];
use std::time::{Duration, Instant};

/// Per-case wall-clock deadline. A single wedged guest process (e.g. a
/// forked `rm`/`http` stuck on an HVF vCPU) must not stall the whole run —
/// the case is killed, marked FAIL(timeout), and the harness moves on.
const CASE_DEADLINE: Duration = Duration::from_secs(45);

use bollard::Docker;
use bollard::container::{Config, CreateContainerOptions, LogsOptions, RemoveContainerOptions};
use bollard::image::CreateImageOptions;
use futures_util::StreamExt;

const IMAGE: &str = "docker.io/library/ubuntu:24.04";
const PLATFORM: &str = "linux/arm64";

struct Case {
    name: &'static str,
    snippet: &'static str,
}

/// Snippets must be deterministic: no timestamps, pids, or hashes.
const CASES: &[Case] = &[
    Case {
        name: "getcwd",
        snippet: "cd /tmp && mkdir -p a/b && cd a/b && pwd",
    },
    Case {
        name: "mkdir_chdir",
        snippet: "mkdir -p /x/y/z && cd /x/y/z && pwd",
    },
    Case {
        name: "access_root",
        snippet: "test -w /var/lib/dpkg && echo W || echo noW; test -r /etc/passwd && echo R || echo noR; test -x /bin/sh && echo X || echo noX",
    },
    Case {
        name: "readdir_created",
        snippet: "cd /tmp && touch zz_newfile && ls zz_newfile && ls | grep -c zz_newfile",
    },
    Case {
        name: "pipe_cat",
        snippet: "echo hello | cat",
    },
    Case {
        name: "rename",
        snippet: "cd /tmp && echo content > a.txt && mv a.txt b.txt && cat b.txt && (ls a.txt 2>&1 | sed 's/.*: //')",
    },
    Case {
        name: "symlink",
        snippet: "cd /tmp && ln -sf /etc/hostname lnk && readlink lnk",
    },
    Case {
        name: "hardlink",
        snippet: "cd /tmp && echo hl > f1 && ln f1 f2 && cat f2",
    },
    Case {
        name: "stat",
        snippet: "stat -c '%s %F %a' /etc/passwd",
    },
    Case {
        name: "copy_file_range",
        snippet: "cp /etc/hostname /tmp/h2 && cat /tmp/h2 >/dev/null && echo cp_ok",
    },
    Case {
        name: "fd_redirect",
        snippet: "exec 3>/tmp/fd3.txt; echo via3 >&3; exec 3>&-; cat /tmp/fd3.txt",
    },
    Case {
        name: "chmod",
        snippet: "cd /tmp && touch m && chmod 640 m && stat -c '%a' m",
    },
    Case {
        name: "truncate",
        snippet: "cd /tmp && printf 'abcdef' > t && truncate -s 3 t && cat t && echo",
    },
    Case {
        name: "append",
        snippet: "cd /tmp && echo one > ap && echo two >> ap && cat ap",
    },
    Case {
        name: "mkdir_rmdir",
        snippet: "cd /tmp && mkdir rd && rmdir rd && (ls rd 2>&1 | sed 's/.*: //')",
    },
    Case {
        name: "id_root",
        snippet: "id -u; id -g",
    },
];

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("carrick-cli lives under crates/carrick-cli")
        .to_path_buf()
}

fn repo_path(path: &str) -> PathBuf {
    repo_root().join(path)
}

fn carrick_bin() -> Option<PathBuf> {
    let p = repo_path("target/release/carrick");
    p.exists().then_some(p)
}

/// True if `bin` already carries the hypervisor entitlement.
fn is_signed_with_hypervisor(bin: &PathBuf) -> bool {
    Command::new("codesign")
        .args(["-d", "--entitlements", "-"])
        .arg(bin)
        .output()
        .map(|o| {
            String::from_utf8_lossy(&o.stdout).contains("com.apple.security.hypervisor")
                || String::from_utf8_lossy(&o.stderr).contains("com.apple.security.hypervisor")
        })
        .unwrap_or(false)
}

/// Ensure the carrick binary carries the hypervisor entitlement. `cargo build`
/// strips the codesignature on macOS, which makes EVERY guest run fail with
/// HV_DENIED (0xfae94007) — the dominant source of conformance "flakiness".
/// Idempotent: skip if already signed, so we don't re-sign in place on every
/// run (wasted work, and a window that could race a concurrent test process in
/// the same worktree). build-signed.sh normally signs it; this is the belt for
/// a plain `cargo build`. The binary is per-worktree (build-signed materialises
/// ./target/release/carrick even under a shared CARGO_TARGET_DIR), so signing
/// it never disturbs another worktree's binary.
fn ensure_signed(bin: &PathBuf) {
    if is_signed_with_hypervisor(bin) {
        return;
    }
    // No concurrent-signer race: all three conformance #[test] fns acquire
    // CONFORMANCE_LOCK before calling this, and each worktree signs its OWN
    // ./target/release/carrick (build-signed materialises a per-worktree binary),
    // so two cargo-test processes never `codesign --force` the same file.
    let plist = repo_path("scripts/entitlements.plist");
    let out = Command::new("codesign")
        .args(["--force", "--sign", "-", "--entitlements"])
        .arg(&plist)
        .arg(bin)
        .output();
    // Surface a signing failure instead of swallowing it — an unsigned binary
    // degrades into a silent HV_DENIED (0xfae94007) on every guest run, the
    // exact "flakiness" this function exists to prevent.
    match out {
        Ok(o) if o.status.success() => {}
        Ok(o) => panic!(
            "codesign of {} failed: {}",
            bin.display(),
            String::from_utf8_lossy(&o.stderr)
        ),
        Err(e) => panic!("codesign of {} could not run: {e}", bin.display()),
    }
}

/// Drop carrick's scratch warning so output lines up with Docker's.
fn normalize(s: &str) -> String {
    s.lines()
        .filter(|l| !l.contains("case-insensitive; defaulting") && !l.contains("Pass `--fs host`"))
        .map(|l| l.trim_end())
        .collect::<Vec<_>>()
        .join("\n")
        .trim_end()
        .to_string()
}

/// Per-case run id, stamped into the carrick guest's title via CARRICK_RUN_ID
/// (inherited across guest forks). Lets each case reap ONLY its own guests, so
/// cases run concurrently — and alongside other lanes/worktrees — without the
/// old global sweep killing each other's in-flight guests.
static CASE_SEQ: AtomicU64 = AtomicU64::new(0);
fn case_run_id() -> String {
    format!(
        "cr-gate-{}-{}",
        std::process::id(),
        CASE_SEQ.fetch_add(1, Ordering::Relaxed)
    )
}

/// Reap only run `run_id`'s wedged guests (kill.sh's scoped mode) — the belt to
/// the per-pgid `kill(-pid)` suspenders, catching a guest that escaped its
/// process group via setpgid/setsid. Best-effort (needs NOPASSWD sudo).
fn scoped_kill_guests(run_id: &str) {
    let kill_script = repo_path("scripts/sudo/kill.sh");
    let _ = Command::new("sudo")
        .args(["-n"])
        .arg(kill_script)
        .arg(run_id)
        .output();
}

fn run_carrick(bin: &PathBuf, snippet: &str) -> String {
    use std::os::unix::process::CommandExt;
    let run_id = case_run_id();
    let child = Command::new(bin)
        .args([
            "run", IMAGE, "--raw", "--fs", "host", "/bin/sh", "-c", snippet,
        ])
        .env("CARRICK_RUN_ID", &run_id)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        // New process group so we can signal the whole guest tree on timeout.
        .process_group(0)
        .spawn()
        .expect("spawn carrick");
    let pid = child.id() as i32;
    let done = Arc::new(AtomicBool::new(false));
    let watcher = {
        let done = Arc::clone(&done);
        let run_id = run_id.clone();
        std::thread::spawn(move || {
            let start = Instant::now();
            while !done.load(Ordering::Relaxed) {
                if start.elapsed() > CASE_DEADLINE {
                    // Kill the process group, then scoped-reap only this case's
                    // guests if one escaped it — never another concurrent case's.
                    unsafe { libc::kill(-pid, libc::SIGKILL) };
                    scoped_kill_guests(&run_id);
                    return true;
                }
                std::thread::sleep(Duration::from_millis(200));
            }
            false
        })
    };
    let out = child.wait_with_output().expect("wait carrick");
    done.store(true, Ordering::Relaxed);
    let timed_out = watcher.join().unwrap_or(false);
    if timed_out {
        return format!("<TIMEOUT after {}s>", CASE_DEADLINE.as_secs());
    }
    let mut combined = String::from_utf8_lossy(&out.stdout).into_owned();
    combined.push_str(&String::from_utf8_lossy(&out.stderr));
    normalize(&combined)
}

async fn ensure_image(docker: &Docker) -> anyhow::Result<()> {
    if docker.inspect_image(IMAGE).await.is_ok() {
        return Ok(());
    }
    let mut stream = docker.create_image(
        Some(CreateImageOptions {
            from_image: IMAGE,
            platform: PLATFORM,
            ..Default::default()
        }),
        None,
        None,
    );
    while let Some(item) = stream.next().await {
        item?;
    }
    Ok(())
}

async fn run_docker(docker: &Docker, snippet: &str) -> anyhow::Result<String> {
    let config = Config {
        image: Some(IMAGE.to_string()),
        cmd: Some(vec!["/bin/sh".into(), "-c".into(), snippet.to_string()]),
        ..Default::default()
    };
    let created = docker
        .create_container(
            Some(CreateContainerOptions {
                name: format!("carrick-conf-{}", std::process::id()),
                platform: Some(PLATFORM.to_string()),
            }),
            config,
        )
        .await?;
    let id = created.id;
    let result = async {
        docker.start_container::<String>(&id, None).await?;
        let mut wait = docker.wait_container::<String>(&id, None);
        while let Some(w) = wait.next().await {
            // Non-zero container exit is fine — we compare output, and the
            // wait stream surfaces it as an Err we deliberately ignore.
            let _ = w;
        }
        let mut logs = docker.logs::<String>(
            &id,
            Some(LogsOptions {
                stdout: true,
                stderr: true,
                ..Default::default()
            }),
        );
        let mut buf = String::new();
        while let Some(item) = logs.next().await {
            if let Ok(out) = item {
                buf.push_str(&out.to_string());
            }
        }
        Ok::<_, anyhow::Error>(normalize(&buf))
    }
    .await;
    let _ = docker
        .remove_container(
            &id,
            Some(RemoveContainerOptions {
                force: true,
                ..Default::default()
            }),
        )
        .await;
    result
}

#[test]
fn conformance() {
    let _serial = CONFORMANCE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let Some(bin) = carrick_bin() else {
        eprintln!("SKIP conformance: target/release/carrick not built");
        return;
    };
    ensure_signed(&bin);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    rt.block_on(async {
        let docker = match Docker::connect_with_local_defaults() {
            Ok(d) => match d.ping().await {
                Ok(_) => d,
                Err(e) => {
                    eprintln!("SKIP conformance: Docker not reachable: {e}");
                    return;
                }
            },
            Err(e) => {
                eprintln!("SKIP conformance: Docker connect failed: {e}");
                return;
            }
        };
        if let Err(e) = ensure_image(&docker).await {
            eprintln!("SKIP conformance: cannot pull {IMAGE}: {e}");
            return;
        }

        let mut failures = Vec::new();
        for case in CASES {
            let carrick_out = run_carrick(&bin, case.snippet);
            let docker_fut = run_docker(&docker, case.snippet);
            let docker_out = match tokio::time::timeout(CASE_DEADLINE, docker_fut).await {
                Ok(Ok(o)) => o,
                Ok(Err(e)) => {
                    eprintln!("FAIL  {} (docker error: {e})", case.name);
                    failures.push(case.name);
                    continue;
                }
                Err(_) => {
                    eprintln!("FAIL  {} (docker timeout)", case.name);
                    failures.push(case.name);
                    continue;
                }
            };
            if carrick_out == docker_out {
                eprintln!("PASS  {}", case.name);
            } else {
                eprintln!(
                    "FAIL  {}\n  --- carrick ---\n{}\n  --- linux ---\n{}",
                    case.name,
                    indent(&carrick_out),
                    indent(&docker_out)
                );
                failures.push(case.name);
            }
        }
        assert!(failures.is_empty(), "conformance gaps: {failures:?}");
    });
}

fn indent(s: &str) -> String {
    s.lines()
        .map(|l| format!("    {l}"))
        .collect::<Vec<_>>()
        .join("\n")
}

// ---------------------------------------------------------------------------
// Probe binaries: compiled static aarch64-linux-musl ELFs (built by
// scripts/build-probes.sh) run UNDER carrick and UNDER Docker, byte-identical.
// Each probe prints deterministic, one-line-per-observation output. We ship
// the binary into the guest by base64-encoding it and feeding the encoded
// bytes to `base64 -d` on the child's STDIN (it's ~600KB — too big for argv).
// ---------------------------------------------------------------------------

/// `base64 -d > /tmp/p && chmod +x /tmp/p && /tmp/p` — the binary arrives on
/// stdin, so the same snippet works under carrick and Docker.
const PROBE_SNIPPET: &str = "base64 -d > /tmp/p && chmod +x /tmp/p && /tmp/p";

/// Directory holding the compiled probe executables, if built.
fn probes_dir() -> PathBuf {
    repo_path("conformance-probes/target/aarch64-unknown-linux-musl/release")
}

/// Enumerate probe executables in `probes_dir()`: top-level files only, no
/// extensions (skip anything with a '.'), skipping cargo's bookkeeping dirs.
fn probe_binaries() -> Vec<PathBuf> {
    let dir = probes_dir();
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(ft) = entry.file_type() else { continue };
        if !ft.is_file() {
            continue; // skips build/ deps/ examples/ incremental/
        }
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if name.contains('.') {
            continue; // skips *.d, *.rlib, .fingerprint files, etc.
        }
        out.push(path);
    }
    out.sort();
    out
}

/// Run the probe-injection snippet under carrick, feeding `stdin_bytes` (the
/// base64 of the probe) to the child's STDIN. Mirrors `run_carrick`'s
/// deadline + process-group-kill + sweep pattern, but pipes stdin.
fn run_carrick_probe(bin: &PathBuf, stdin_bytes: &[u8]) -> String {
    use std::io::Write;
    use std::os::unix::process::CommandExt;
    let run_id = case_run_id();
    let mut child = Command::new(bin)
        .args([
            "run",
            IMAGE,
            "--raw",
            "--fs",
            "host",
            "/bin/sh",
            "-c",
            PROBE_SNIPPET,
        ])
        .env("CARRICK_RUN_ID", &run_id)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .process_group(0)
        .spawn()
        .expect("spawn carrick probe");
    let pid = child.id() as i32;
    // Hand the base64 to the child on its own thread so a full stdout pipe
    // can't deadlock the write.
    {
        let mut stdin = child.stdin.take().expect("carrick stdin");
        let bytes = stdin_bytes.to_vec();
        std::thread::spawn(move || {
            let _ = stdin.write_all(&bytes);
            // dropping stdin closes it, signalling EOF to `base64 -d`
        });
    }
    let done = Arc::new(AtomicBool::new(false));
    let watcher = {
        let done = Arc::clone(&done);
        let run_id = run_id.clone();
        std::thread::spawn(move || {
            let start = Instant::now();
            while !done.load(Ordering::Relaxed) {
                if start.elapsed() > CASE_DEADLINE {
                    unsafe { libc::kill(-pid, libc::SIGKILL) };
                    scoped_kill_guests(&run_id);
                    return true;
                }
                std::thread::sleep(Duration::from_millis(200));
            }
            false
        })
    };
    let out = child.wait_with_output().expect("wait carrick probe");
    done.store(true, Ordering::Relaxed);
    let timed_out = watcher.join().unwrap_or(false);
    if timed_out {
        return format!("<TIMEOUT after {}s>", CASE_DEADLINE.as_secs());
    }
    let mut combined = String::from_utf8_lossy(&out.stdout).into_owned();
    combined.push_str(&String::from_utf8_lossy(&out.stderr));
    normalize(&combined)
}

/// Run the probe-injection snippet under real Linux via `docker run -i`,
/// feeding `stdin_bytes` to the container's STDIN. Uses std::process rather
/// than bollard because bollard stdin-attach is awkward; the shell-case path
/// keeps using `run_docker` (bollard) unchanged.
fn run_docker_probe(stdin_bytes: &[u8]) -> std::io::Result<String> {
    use std::io::Write;
    let mut child = Command::new("docker")
        .args([
            "run",
            "-i",
            "--rm",
            "--platform",
            PLATFORM,
            IMAGE,
            "/bin/sh",
            "-c",
            PROBE_SNIPPET,
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;
    {
        let mut stdin = child.stdin.take().expect("docker stdin");
        let bytes = stdin_bytes.to_vec();
        std::thread::spawn(move || {
            let _ = stdin.write_all(&bytes);
        });
    }
    let out = child.wait_with_output()?;
    let mut combined = String::from_utf8_lossy(&out.stdout).into_owned();
    combined.push_str(&String::from_utf8_lossy(&out.stderr));
    Ok(normalize(&combined))
}

/// Line-by-line diff: returns `None` if identical, else a unified-ish dump of
/// the differing lines (carrick vs linux) so the divergence pinpoints the
/// offending syscall.
fn diff_lines(carrick: &str, linux: &str) -> Option<String> {
    if carrick == linux {
        return None;
    }
    let c: Vec<&str> = carrick.lines().collect();
    let l: Vec<&str> = linux.lines().collect();
    let mut buf = String::new();
    for i in 0..c.len().max(l.len()) {
        let cl = c.get(i).copied();
        let ll = l.get(i).copied();
        if cl == ll {
            continue;
        }
        buf.push_str(&format!("  line {}:\n", i + 1));
        match cl {
            Some(s) => buf.push_str(&format!("    - carrick: {s}\n")),
            None => buf.push_str("    - carrick: <missing>\n"),
        }
        match ll {
            Some(s) => buf.push_str(&format!("    + linux:   {s}\n")),
            None => buf.push_str("    + linux:   <missing>\n"),
        }
    }
    Some(buf)
}

/// Timing/async-sensitive probes that flake under concurrent CPU contention
/// (deadlines, sleeps, io_uring readiness). Run these SERIALLY after the
/// parallel batch — far cheaper than hardening every probe's waits, and the
/// ltp-conformance skill's standing warning about jitter-under-load applies.
const TIMING_SENSITIVE_PROBES: &[&str] = &[
    "iouring",
    "iouringenterflag",
    "posixtimers",
    "itimer",
    "timersettimeabs",
    "selecttimeout",
    "pauseeintr",
    "ppollsig",
    "pselecteintr",
    "timeclock",
    "timeextra",
    "clockgetres",
    "netpoll",
    // futex wake-COUNT probes: macOS __ulock can report zombie wake successes
    // for ~µs after a wake under contention (see project_macos_ulock_zombie),
    // so exact counts flake under the parallel CPU load — quarantine them.
    "futexwakecount",
    "futexrequeue",
    "futexshare",
    "futexghost",
    "futexextra",
];

fn is_timing_sensitive(probe: &std::path::Path) -> bool {
    probe
        .file_name()
        .and_then(|n| n.to_str())
        .map(|n| TIMING_SENSITIVE_PROBES.contains(&n))
        .unwrap_or(false)
}

enum ProbeOutcome {
    Pass,
    UnexpectedPass,
    Fail(String),
    Xfail(String),
    Error(String),
}

/// Run one probe under carrick + Docker and classify the result. Self-contained
/// (its own per-case run id via `run_carrick_probe`), so it is safe to call from
/// multiple worker threads concurrently.
fn run_one_probe(bin: &PathBuf, probe: &std::path::Path) -> (String, ProbeOutcome) {
    use base64::Engine as _;
    let engine = base64::engine::general_purpose::STANDARD;
    let name = probe
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("<unknown>")
        .to_string();
    let raw = match std::fs::read(probe) {
        Ok(b) => b,
        Err(e) => return (name, ProbeOutcome::Error(format!("read probe: {e}"))),
    };
    let encoded = engine.encode(&raw).into_bytes();
    let carrick_out = run_carrick_probe(bin, &encoded);
    let docker_out = match run_docker_probe(&encoded) {
        Ok(o) => o,
        Err(e) => return (name, ProbeOutcome::Error(format!("docker error: {e}"))),
    };
    let known_gap = KNOWN_PROBE_GAPS.contains(&name.as_str());
    let outcome = match (diff_lines(&carrick_out, &docker_out), known_gap) {
        (None, false) => ProbeOutcome::Pass,
        (None, true) => ProbeOutcome::UnexpectedPass,
        (Some(diff), false) => ProbeOutcome::Fail(diff),
        (Some(diff), true) => ProbeOutcome::Xfail(diff),
    };
    (name, outcome)
}

#[test]
fn conformance_probes() {
    let _serial = CONFORMANCE_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let Some(bin) = carrick_bin() else {
        eprintln!("SKIP conformance_probes: target/release/carrick not built");
        return;
    };
    let dir = probes_dir();
    if !dir.exists() {
        eprintln!(
            "SKIP conformance_probes: probes not built ({})",
            dir.display()
        );
        return;
    }
    // Docker reachability check (std::process side, so no bollard ping here):
    // a trivial `docker version` must succeed.
    let docker_ok = Command::new("docker")
        .arg("version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !docker_ok {
        eprintln!("SKIP conformance_probes: Docker not reachable");
        return;
    }

    ensure_signed(&bin);

    let probes = probe_binaries();
    if probes.is_empty() {
        eprintln!(
            "SKIP conformance_probes: no probe binaries in {}",
            dir.display()
        );
        return;
    }

    // Fan the probes out across a bounded worker pool — each case is now
    // hermetic (own run id + own host-fs scratch), so the only shared resources
    // are the Docker daemon and the host CPUs. Cap at min(cores-2, 8) to avoid
    // saturating the Docker LinuxKit VM. Timing-sensitive probes are quarantined
    // to a serial tail to keep them off the contended path.
    let (quarantine, parallel): (Vec<PathBuf>, Vec<PathBuf>) =
        probes.into_iter().partition(|p| is_timing_sensitive(p));

    let n_workers = std::thread::available_parallelism()
        .map(|n| n.get().saturating_sub(2).clamp(1, 8))
        .unwrap_or(4);

    let parallel = Arc::new(parallel);
    let next = Arc::new(AtomicUsize::new(0));
    let results: Arc<Mutex<Vec<(String, ProbeOutcome)>>> = Arc::new(Mutex::new(Vec::new()));
    std::thread::scope(|scope| {
        for _ in 0..n_workers {
            let parallel = Arc::clone(&parallel);
            let next = Arc::clone(&next);
            let results = Arc::clone(&results);
            let bin = bin.clone();
            scope.spawn(move || {
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some(probe) = parallel.get(i) else { break };
                    let r = run_one_probe(&bin, probe);
                    results.lock().unwrap_or_else(|e| e.into_inner()).push(r);
                }
            });
        }
    });
    // Quarantined probes: serial, after the fan-out drains.
    for probe in &quarantine {
        let r = run_one_probe(&bin, probe);
        results.lock().unwrap_or_else(|e| e.into_inner()).push(r);
    }

    let mut results = Arc::try_unwrap(results)
        .map(|m| m.into_inner().unwrap_or_else(|e| e.into_inner()))
        .unwrap_or_default();
    results.sort_by(|a, b| a.0.cmp(&b.0)); // deterministic report order

    let mut failures = Vec::new();
    let mut fixed_gaps = Vec::new();
    for (name, outcome) in &results {
        match outcome {
            ProbeOutcome::Pass => eprintln!("PASS {name}"),
            ProbeOutcome::UnexpectedPass => {
                // A known-gap probe started passing → the gap is fixed. Fail
                // loudly so the entry gets removed from KNOWN_PROBE_GAPS.
                eprintln!("UNEXPECTED PASS {name} (remove from KNOWN_PROBE_GAPS)");
                fixed_gaps.push(name.clone());
            }
            ProbeOutcome::Fail(diff) => {
                eprintln!("FAIL {name}\n{diff}");
                failures.push(name.clone());
            }
            ProbeOutcome::Xfail(diff) => eprintln!("XFAIL {name} (known gap)\n{diff}"),
            ProbeOutcome::Error(e) => {
                eprintln!("FAIL {name} ({e})");
                failures.push(name.clone());
            }
        }
    }
    assert!(
        fixed_gaps.is_empty(),
        "known-gap probes now PASS — remove from KNOWN_PROBE_GAPS: {fixed_gaps:?}"
    );
    assert!(failures.is_empty(), "probe conformance gaps: {failures:?}");
}

#[test]
fn conformance_go_fixture() {
    let _serial = CONFORMANCE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    use base64::Engine as _;

    let Some(bin) = carrick_bin() else {
        eprintln!("SKIP conformance_go_fixture: target/release/carrick not built");
        return;
    };

    let docker_ok = Command::new("docker")
        .arg("version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !docker_ok {
        eprintln!("SKIP conformance_go_fixture: Docker not reachable");
        return;
    }

    ensure_signed(&bin);

    let output = std::process::Command::new(repo_path("scripts/build-go-fixtures.sh"))
        .current_dir(repo_root())
        .output()
        .unwrap();
    assert!(output.status.success(), "Go fixture build failed");

    let go_artifact =
        repo_path("fixtures/go-aarch64-hello/target/release/carrick-linux-aarch64-go-hello");

    let raw = std::fs::read(&go_artifact).expect("read Go binary");
    let engine = base64::engine::general_purpose::STANDARD;
    let encoded = engine.encode(&raw).into_bytes();

    let carrick_out = run_carrick_probe(&bin, &encoded);
    let docker_out = match run_docker_probe(&encoded) {
        Ok(o) => o,
        Err(e) => {
            panic!("Docker run failed: {e}");
        }
    };

    if let Some(diff) = diff_lines(&carrick_out, &docker_out) {
        panic!("Go fixture conformance mismatch:\n{diff}");
    } else {
        println!("PASS conformance_go_fixture");
    }
}
