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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// Serializes the two conformance test functions. They both spawn carrick
/// guests AND call `sweep_wedged_guests()` (a global `kill.sh` that SIGKILLs
/// every `carrick:` process on the box). If the two `#[test]` fns run on
/// parallel threads (cargo's default), each one's per-case sweep kills the
/// OTHER's in-flight guest, producing spurious empty-output failures. A
/// shared lock makes them run one-at-a-time regardless of `--test-threads`.
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
    "mapfixed",     // M5: MAP_FIXED|MAP_PRIVATE over shared aperture must remap private
    // forkaltstack FIXED in M2 (migrate_thread_signal_state) — now PASSES.
    "pselecteintr", // M3: select()/pselect6 blocks uninterruptibly (no EINTR)
    // forkfpregs FIXED in M2 (VcpuSnapshot V0-V31/FPSR/FPCR) — now PASSES.
    // M4/M3 batch — probes on disk, fixes integrated one batch at a time; each
    // entry is removed in the same commit that lands its fix.
    // linuxsysinfo FIXED in M4 (struct padding) — now PASSES.
    "recvmsgtrunc",    // M4: recvmsg never reports MSG_TRUNC
    "termiosbits",     // M4: termios c_cflag/c_iflag bit translation
    // timersettimeabs FIXED in M4 (ABSTIME + timespec validation) — now PASSES.
    "iouringenterflag",// M4: io_uring_enter unsupported-flag/arg validation + bound
    "sotimeo",         // M3: SO_RCVTIMEO/SO_SNDTIMEO honored on blocking recv/send
    // epollstaledel FIXED in M3 (pending_ready keyed by fd) — now PASSES.
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

/// Re-sign the carrick binary with the hypervisor entitlement. `cargo build`
/// strips the codesignature on macOS, which makes EVERY guest run fail with
/// HV_DENIED (0xfae94007) — the dominant source of conformance "flakiness".
/// Signing in setup guarantees the harness never tests an unsigned build.
fn ensure_signed(bin: &PathBuf) {
    let plist = repo_path("scripts/entitlements.plist");
    let _ = Command::new("codesign")
        .args(["--force", "--sign", "-", "--entitlements"])
        .arg(&plist)
        .arg(bin)
        .output();
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

/// Sweep leftover wedged `carrick:` guest procs (an HVF vCPU can wedge a
/// forked child past its parent's exit). Done before each case so one
/// case's leak can't make the next flaky. Best-effort (needs the project's
/// NOPASSWD sudo path); ignored if unavailable.
fn sweep_wedged_guests() {
    let kill_script = repo_path("scripts/sudo/kill.sh");
    let _ = Command::new("sudo").args(["-n"]).arg(kill_script).output();
}

fn run_carrick(bin: &PathBuf, snippet: &str) -> String {
    use std::os::unix::process::CommandExt;
    sweep_wedged_guests();
    let child = Command::new(bin)
        .args([
            "run", IMAGE, "--raw", "--fs", "host", "/bin/sh", "-c", snippet,
        ])
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
        std::thread::spawn(move || {
            let start = Instant::now();
            while !done.load(Ordering::Relaxed) {
                if start.elapsed() > CASE_DEADLINE {
                    // Kill the process group, then sweep any reparented wedged
                    // guest procs so the next case starts clean.
                    unsafe { libc::kill(-pid, libc::SIGKILL) };
                    let kill_script = repo_path("scripts/sudo/kill.sh");
                    let _ = Command::new("sudo").args(["-n"]).arg(kill_script).output();
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
    sweep_wedged_guests();
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
        std::thread::spawn(move || {
            let start = Instant::now();
            while !done.load(Ordering::Relaxed) {
                if start.elapsed() > CASE_DEADLINE {
                    unsafe { libc::kill(-pid, libc::SIGKILL) };
                    let kill_script = repo_path("scripts/sudo/kill.sh");
                    let _ = Command::new("sudo").args(["-n"]).arg(kill_script).output();
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

#[test]
fn conformance_probes() {
    let _serial = CONFORMANCE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    use base64::Engine as _;

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

    let engine = base64::engine::general_purpose::STANDARD;
    let mut failures = Vec::new();
    let mut fixed_gaps = Vec::new();
    for probe in &probes {
        let name = probe
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("<unknown>")
            .to_string();
        let raw = match std::fs::read(probe) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("FAIL {name} (read probe: {e})");
                failures.push(name);
                continue;
            }
        };
        let encoded = engine.encode(&raw).into_bytes();

        let carrick_out = run_carrick_probe(&bin, &encoded);
        let docker_out = match run_docker_probe(&encoded) {
            Ok(o) => o,
            Err(e) => {
                eprintln!("FAIL {name} (docker error: {e})");
                failures.push(name);
                continue;
            }
        };

        let known_gap = KNOWN_PROBE_GAPS.contains(&name.as_str());
        match (diff_lines(&carrick_out, &docker_out), known_gap) {
            (None, false) => eprintln!("PASS {name}"),
            (None, true) => {
                // A known-gap probe started passing → the gap is fixed.
                // Fail loudly so the entry gets removed from KNOWN_PROBE_GAPS.
                eprintln!("UNEXPECTED PASS {name} (remove from KNOWN_PROBE_GAPS)");
                fixed_gaps.push(name);
            }
            (Some(diff), false) => {
                eprintln!("FAIL {name}\n{diff}");
                failures.push(name);
            }
            (Some(diff), true) => {
                eprintln!("XFAIL {name} (known gap)\n{diff}");
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
