//! Differential syscall conformance: carrick vs real Linux.
//!
//! Each case is a `/bin/sh -c` snippet exercising syscall-observable
//! behaviour. We run the IDENTICAL snippet under carrick (`--fs host`) and
//! inside a real Linux container (via the `bollard` Docker client) and
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

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
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
    // Audit remediation program.
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
];

/// Probes kept as standalone REDUCERS but NOT run by the gate, for one of two
/// reasons: (1) they reproduce a real but as-yet-UNFIXED carrick failure whose
/// root cause is not yet verified, and whose hard-wedge is costly/destabilizing
/// in the gate (it burns the case deadline and perturbs the timing-sensitive
/// quarantine); or (2) the DIFFERENTIAL ORACLE itself cannot exercise the
/// behaviour on this host, so there is no MATCH to be had — carrick is correct,
/// the oracle is incapable. Run them by hand with `scripts/run-probe.sh <name>`,
/// or gate them on a host whose oracle CAN run them. Do NOT use this to hide a
/// real regression.
const GATE_SKIP_PROBES: &[&str] = &[
    // forksleepfork: a multithreaded fork from a NESTED (fork+exec'd) process
    // wedges — empirically reproduces the failure, but the root cause is NOT yet
    // verified (the related execve-EINVAL turned out to be a non-UTF-8 ABI bug,
    // not the coherence race first assumed — so treat the HVF-race label as a
    // hypothesis). It hard-wedges to the case deadline (~45s) and destabilizes
    // the gate's timing probes; keep it as a manual reducer until rooted+fixed.
    // See docs/cpython-baseline/TRIAGE.md cluster 1.
    "forksleepfork",
    // mtforkcorrupt: WIP reducer for the test_subprocess parent-heap-corruption
    // SEGV (a long-lived multithreaded parent's heap pointer → 0x7878... after
    // ~130 fork+exec cycles; fault-traced 2026-05-30). This v1 (sibling pipe
    // churn + main forks a failed-exec child) does NOT yet reproduce — it
    // MATCHes Docker — so it's a negative-result baseline, not a gate signal.
    // Skipped until a variant reproduces (successful execs / PIPE+dup2 child /
    // large parent heap are the next ingredients). See project memory.
    "mtforkcorrupt",
    // manythreads: spawns 96 guest threads. MATCHes Docker when run STANDALONE
    // (run-probe.sh), but SEGVs ("core dumped") under the gate's CONCURRENT load
    // (8 parallel guests). A real load-sensitive concurrency crash in the
    // thread-spawn path — likely the same family as the test_subprocess SEGV
    // (a multithreaded guest corrupting under contention). Kept as a manual
    // reducer (run it alongside other guests to reproduce); NOT a gate signal
    // until the underlying contention bug is fixed. See project memory.
    "manythreads",
    // mqueue: exercises the full POSIX message-queue family (mq_open/mq_timedsend/
    // mq_timedreceive/mq_getsetattr/mq_unlink), which carrick emulates correctly
    // on a host-file backing (see carrick-runtime dispatch/mqueue.rs). Reason (2)
    // above — the ORACLE is the limited side: Docker Desktop's LinuxKit kernel
    // refuses mq_open(O_CREAT) with EACCES even under --privileged and --ipc=host
    // (the mqueue fs is mounted rw, but creation is blocked at the VM-kernel
    // level), so carrick's correct success can never MATCH the oracle's EACCES.
    // Kept as a reducer; gate it against a native-Linux oracle (the kvm/bhyve
    // lanes), where mq_open actually works.
    "mqueue",
    // bridge_tcp_peer must run under `--net bridge`; the generic probe runner
    // uses the default host network. Covered by conformance_bridge_tcp_peer.
    "bridge_tcp_peer",
    // bridge_publish_tcp requires the harness to start carrick with `-p` and
    // connect from the host side after the guest listener is ready. The generic
    // probe runner only injects and waits, so this probe is covered by the
    // dedicated conformance_bridge_publish_tcp test below.
    "bridge_publish_tcp",
    // bridge_udp_peer must run under `--net bridge`; the generic probe runner
    // uses the default host network. Covered by conformance_bridge_udp_peer.
    "bridge_udp_peer",
    // bridge_net_identity must run under `--net bridge`; the generic probe
    // runner uses the default host network. Covered by conformance_bridge_net_identity.
    "bridge_net_identity",
    // bridge_loopback_isolation must run under `--net bridge`; the generic probe
    // runner uses the default host network. Covered by conformance_bridge_loopback_isolation.
    "bridge_loopback_isolation",
    // bridge_tcp_nonblocking_refused must run under `--net bridge`; the generic
    // probe runner uses the default host network. Covered by
    // conformance_bridge_tcp_nonblocking_refused.
    "bridge_tcp_nonblocking_refused",
    // bridge_udp_connected_unreachable must run under `--net bridge`; the generic
    // probe runner uses the default host network. Covered by
    // conformance_bridge_udp_connected_unreachable.
    "bridge_udp_connected_unreachable",
    // bridge_udp_sendto_unreachable must run under `--net bridge`; the generic
    // probe runner uses the default host network. Covered by
    // conformance_bridge_udp_sendto_unreachable.
    "bridge_udp_sendto_unreachable",
    // bridge_reuse_sockopts must run under `--net bridge`; the generic probe
    // runner uses the default host network. Covered by
    // conformance_bridge_reuse_sockopts.
    "bridge_reuse_sockopts",
    // bridge_compose_* are a multi-process bridge workload and must be launched
    // by their dedicated harness.
    "bridge_compose_server",
    "bridge_compose_client",
    // host_gateway_client depends on a host-side listener and Docker Desktop
    // host-gateway name injection. Covered by docker_compose_host_gateway_smoke
    // and docker_compose_network_surface_smoke.
    "host_gateway_client",
    // multi_network_* are service-role probes for Compose/API workloads with
    // named networks, aliases, and peer containers. Covered by the multi-network
    // Compose smokes and runtime connect/disconnect tests.
    "multi_network_client",
    "multi_network_dns_client",
    "multi_network_server",
    // sidecar_loopback_* must be launched as a shared-network-namespace service
    // group. Covered by docker_compose_shared_network_namespace_smoke.
    "sidecar_loopback_client",
    "sidecar_loopback_isolated_client",
    "sidecar_loopback_server",
    // udp_published_* require a peer service and a host UDP published-port
    // mapping. Covered by docker_compose_udp_published_port_smoke.
    "udp_published_client",
    "udp_published_server",
];
use std::time::{Duration, Instant};

/// Per-case wall-clock deadline. A single wedged guest process (e.g. a
/// forked `rm`/`http` stuck on an HVF vCPU) must not stall the whole run —
/// the case is killed, marked FAIL(timeout), and the harness moves on.
const CASE_DEADLINE: Duration = Duration::from_secs(45);
const WAITEXITSTORM_DEADLINE: Duration = Duration::from_secs(60);

use bollard::Docker;
use bollard::container::{
    Config, CreateContainerOptions, LogOutput, LogsOptions, RemoveContainerOptions,
};
use bollard::image::CreateImageOptions;
use futures_util::StreamExt;

/// One libc flavour of the probe suite for a lane. The SAME probe sources are
/// cross-compiled per libc (scripts/build-probes.sh) and run, base64-injected,
/// inside the lane's glibc image under both carrick and Docker. Running both
/// `musl` and `gnu` is the whole point of the matrix: glibc issues ABIs musl
/// never does (e.g. tcgetattr/isatty via TCGETS2), so a musl-only suite is
/// blind to glibc-only divergences — exactly how the TCGETS2 gap shipped.
#[derive(Clone, Copy)]
struct ProbeSet {
    /// Display tag in the qualified result name (`{lane}:{libc}:{probe}`).
    libc: &'static str,
    /// Cargo target triple → `conformance-probes/target/{target}/release`.
    target: &'static str,
    /// When true a DIFF vs Linux fails the test. The gnu lane starts
    /// NON-gating (report-only) so newly-surfaced glibc-path gaps are visible
    /// without flipping the gate red before each is triaged into a gap list or
    /// fixed; flip to gating once the gnu set is clean.
    gating: bool,
}

#[derive(Clone, Copy)]
struct Lane {
    label: &'static str,
    platform: &'static str,
    image: &'static str,
    probe_sets: &'static [ProbeSet],
}

const ARM64: Lane = Lane {
    label: "arm64",
    platform: "linux/arm64",
    image: "docker.io/library/ubuntu:24.04",
    probe_sets: &[
        ProbeSet {
            libc: "musl",
            target: "aarch64-unknown-linux-musl",
            gating: true,
        },
        ProbeSet {
            libc: "gnu",
            target: "aarch64-unknown-linux-gnu",
            gating: false,
        },
    ],
};

const AMD64: Lane = Lane {
    // Host-neutral label: this lane now serves BOTH the macOS-Rosetta x86_64
    // guest path AND the native x86_64 fleet (Linux/KVM, FreeBSD/bhyve,
    // NetBSD/NVMM), where carrick executes the guest directly via carrick-x86.
    // `lane_runnable_here` decides whether the current host can run it (native
    // x86_64 OR Rosetta-on-macOS); the probe sets below are the same portable
    // sources cross-compiled for x86_64, mirroring the ARM64 lane.
    label: "amd64",
    platform: "linux/amd64",
    image: "docker.io/library/ubuntu:24.04",
    probe_sets: &[
        ProbeSet {
            libc: "musl",
            // REPORT-ONLY for now (like the gnu set started): on the native
            // x86_64 fleet this lane surfaces ~34 genuine carrick-x86 ABI gaps
            // (SEGVs on aliassize/mapfixed private-overlay, SysV msg, CLOCK_BOOTTIME,
            // si_value propagation, …) — real carrick-x86 BRING-UP work, since
            // x86_64 is an active lane behind the mature HVF/aarch64 reference
            // (the same probes PASS on ARM64). The run prints a SUMMARY of every
            // DIFF each pass so the gaps stay visible and shrink-tracked; flip
            // this to `gating: true` once carrick-x86 reaches probe parity. On
            // macOS this lane only runs via Rosetta and is report-only regardless
            // (Rosetta, not carrick, does the translation — see `set_gates_here`).
            target: "x86_64-unknown-linux-musl",
            gating: false,
        },
        ProbeSet {
            libc: "gnu",
            target: "x86_64-unknown-linux-gnu",
            gating: false,
        },
    ],
};

const LANES: &[Lane] = &[ARM64, AMD64];

struct Case {
    name: &'static str,
    snippet: &'static str,
}

/// Snippets must be deterministic: no timestamps, pids, or hashes.
const CASES: &[Case] = &[
    Case {
        name: "uname_m",
        snippet: "uname -m",
    },
    Case {
        name: "dpkg_arch",
        snippet: "dpkg --print-architecture",
    },
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

fn bridge_publish_probe_args(platform: &str, image: &str, host_port: u16) -> Vec<String> {
    vec![
        "run".to_string(),
        "--platform".to_string(),
        platform.to_string(),
        "--raw".to_string(),
        "--fs".to_string(),
        "host".to_string(),
        "--net".to_string(),
        "bridge".to_string(),
        "-p".to_string(),
        format!("127.0.0.1:{host_port}:8080"),
        image.to_string(),
        "/bin/sh".to_string(),
        "-c".to_string(),
        PROBE_SNIPPET.to_string(),
    ]
}

fn docker_bridge_publish_probe_args(platform: &str, image: &str, host_port: u16) -> Vec<String> {
    vec![
        "run".to_string(),
        "-i".to_string(),
        "--rm".to_string(),
        "--platform".to_string(),
        platform.to_string(),
        "-p".to_string(),
        format!("127.0.0.1:{host_port}:8080"),
        image.to_string(),
        "/bin/sh".to_string(),
        "-c".to_string(),
        PROBE_SNIPPET.to_string(),
    ]
}

fn bridge_probe_args(platform: &str, image: &str) -> Vec<String> {
    vec![
        "run".to_string(),
        "--platform".to_string(),
        platform.to_string(),
        "--raw".to_string(),
        "--fs".to_string(),
        "host".to_string(),
        "--net".to_string(),
        "bridge".to_string(),
        image.to_string(),
        "/bin/sh".to_string(),
        "-c".to_string(),
        PROBE_SNIPPET.to_string(),
    ]
}

fn bridge_named_probe_args(
    platform: &str,
    image: &str,
    name: &str,
    env: &[(&str, String)],
) -> Vec<String> {
    let mut args = vec![
        "run".to_string(),
        "--platform".to_string(),
        platform.to_string(),
        "--raw".to_string(),
        "--fs".to_string(),
        "host".to_string(),
        "--net".to_string(),
        "bridge".to_string(),
        "--name".to_string(),
        name.to_string(),
    ];
    for (key, value) in env {
        args.push("-e".to_string());
        args.push(format!("{key}={value}"));
    }
    args.extend([
        image.to_string(),
        "/bin/sh".to_string(),
        "-c".to_string(),
        PROBE_SNIPPET.to_string(),
    ]);
    args
}

fn free_loopback_port() -> u16 {
    let listener =
        std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).expect("reserve port");
    listener.local_addr().expect("local addr").port()
}

fn run_bridge_probe(bin: &PathBuf, lane: Lane, stdin_bytes: &[u8]) -> String {
    use std::io::Write;
    use std::os::unix::process::CommandExt;

    let run_id = case_run_id();
    let mut child = Command::new(bin)
        .args(bridge_probe_args(lane.platform, lane.image))
        .env("CARRICK_RUN_ID", &run_id)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .process_group(0)
        .spawn()
        .expect("spawn bridge probe");
    let pid = child.id() as i32;
    {
        let mut stdin = child.stdin.take().expect("carrick stdin");
        let bytes = stdin_bytes.to_vec();
        std::thread::spawn(move || {
            let _ = stdin.write_all(&bytes);
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
    let out = child.wait_with_output().expect("wait bridge probe");
    done.store(true, Ordering::Relaxed);
    let timed_out = watcher.join().unwrap_or(false);
    if timed_out {
        return format!("<TIMEOUT after {}s>", CASE_DEADLINE.as_secs());
    }
    let mut combined = String::from_utf8_lossy(&out.stdout).into_owned();
    combined.push_str(&String::from_utf8_lossy(&out.stderr));
    normalize(&combined)
}

fn run_bridge_named_probe(
    bin: &PathBuf,
    lane: Lane,
    name: &str,
    env: &[(&str, String)],
    stdin_bytes: &[u8],
) -> String {
    use std::io::Write;
    use std::os::unix::process::CommandExt;

    let run_id = case_run_id();
    let mut child = Command::new(bin)
        .args(bridge_named_probe_args(
            lane.platform,
            lane.image,
            name,
            env,
        ))
        .env("CARRICK_RUN_ID", &run_id)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .process_group(0)
        .spawn()
        .expect("spawn named bridge probe");
    let pid = child.id() as i32;
    {
        let mut stdin = child.stdin.take().expect("carrick stdin");
        let bytes = stdin_bytes.to_vec();
        std::thread::spawn(move || {
            let _ = stdin.write_all(&bytes);
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
    let out = child.wait_with_output().expect("wait named bridge probe");
    done.store(true, Ordering::Relaxed);
    let timed_out = watcher.join().unwrap_or(false);
    if timed_out {
        return format!("<TIMEOUT after {}s>", CASE_DEADLINE.as_secs());
    }
    let mut combined = String::from_utf8_lossy(&out.stdout).into_owned();
    combined.push_str(&String::from_utf8_lossy(&out.stderr));
    normalize(&combined)
}

fn run_bridge_publish_probe(
    bin: &PathBuf,
    lane: Lane,
    host_port: u16,
    stdin_bytes: &[u8],
) -> String {
    use std::io::{BufRead, Read, Write};
    use std::os::unix::process::CommandExt;
    use std::sync::mpsc;

    let run_id = case_run_id();
    let mut child = Command::new(bin)
        .args(bridge_publish_probe_args(
            lane.platform,
            lane.image,
            host_port,
        ))
        .env("CARRICK_RUN_ID", &run_id)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .process_group(0)
        .spawn()
        .expect("spawn bridge publish probe");
    let pid = child.id() as i32;

    {
        let mut stdin = child.stdin.take().expect("carrick stdin");
        let bytes = stdin_bytes.to_vec();
        std::thread::spawn(move || {
            let _ = stdin.write_all(&bytes);
        });
    }

    let stdout = child.stdout.take().expect("carrick stdout");
    let stderr = child.stderr.take().expect("carrick stderr");
    let (line_tx, line_rx) = mpsc::channel::<String>();
    let stdout_reader = std::thread::spawn(move || {
        let mut out = String::new();
        let mut reader = std::io::BufReader::new(stdout);
        let mut line = String::new();
        loop {
            line.clear();
            let n = reader.read_line(&mut line).unwrap_or(0);
            if n == 0 {
                break;
            }
            out.push_str(&line);
            let _ = line_tx.send(line.trim_end().to_string());
        }
        out
    });
    let stderr_reader = std::thread::spawn(move || {
        let mut err = String::new();
        let mut reader = std::io::BufReader::new(stderr);
        let _ = reader.read_to_string(&mut err);
        err
    });

    let ready_deadline = Instant::now() + Duration::from_secs(15);
    let mut ready = false;
    while Instant::now() < ready_deadline {
        match line_rx.recv_timeout(Duration::from_millis(100)) {
            Ok(line) if line == "bridge_publish_listener_ready=true" => {
                ready = true;
                break;
            }
            Ok(_) => {}
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    if !ready {
        unsafe { libc::kill(-pid, libc::SIGKILL) };
        scoped_kill_guests(&run_id);
        let _ = child.wait();
        let out = stdout_reader.join().unwrap_or_default();
        let err = stderr_reader.join().unwrap_or_default();
        return normalize(&format!("{out}{err}<TIMEOUT waiting for listener>"));
    }

    let mut stream = connect_loopback_with_retry(host_port).expect("connect published port");
    stream.write_all(b"ping").expect("write host ping");
    let mut reply = [0_u8; 2];
    stream.read_exact(&mut reply).expect("read host reply");
    assert_eq!(&reply, b"ok");

    let wait_deadline = Instant::now() + Duration::from_secs(15);
    loop {
        match child.try_wait().expect("poll bridge publish probe") {
            Some(status) => {
                let out = stdout_reader.join().unwrap_or_default();
                let err = stderr_reader.join().unwrap_or_default();
                let combined = normalize(&format!("{out}{err}"));
                assert!(
                    status.success(),
                    "bridge publish probe exited {status}: {combined}"
                );
                return combined;
            }
            None if Instant::now() >= wait_deadline => {
                unsafe { libc::kill(-pid, libc::SIGKILL) };
                scoped_kill_guests(&run_id);
                let _ = child.wait();
                let out = stdout_reader.join().unwrap_or_default();
                let err = stderr_reader.join().unwrap_or_default();
                return normalize(&format!("{out}{err}<TIMEOUT waiting for exit>"));
            }
            None => std::thread::sleep(Duration::from_millis(100)),
        }
    }
}

fn run_bridge_compose_pair(
    bin: &PathBuf,
    lane: Lane,
    server_stdin: &[u8],
    client_stdin: &[u8],
) -> (String, String) {
    use std::io::{BufRead, Read, Write};
    use std::os::unix::process::CommandExt;
    use std::sync::mpsc;

    let run_id = case_run_id();
    let mut server = Command::new(bin)
        .args(bridge_named_probe_args(
            lane.platform,
            lane.image,
            "db",
            &[],
        ))
        .env("CARRICK_RUN_ID", &run_id)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .process_group(0)
        .spawn()
        .expect("spawn compose server probe");
    let server_pid = server.id() as i32;
    {
        let mut stdin = server.stdin.take().expect("server stdin");
        let bytes = server_stdin.to_vec();
        std::thread::spawn(move || {
            let _ = stdin.write_all(&bytes);
        });
    }

    let stdout = server.stdout.take().expect("server stdout");
    let stderr = server.stderr.take().expect("server stderr");
    let (line_tx, line_rx) = mpsc::channel::<String>();
    let server_stdout_reader = std::thread::spawn(move || {
        let mut out = String::new();
        let mut reader = std::io::BufReader::new(stdout);
        let mut line = String::new();
        loop {
            line.clear();
            let n = reader.read_line(&mut line).unwrap_or(0);
            if n == 0 {
                break;
            }
            out.push_str(&line);
            let _ = line_tx.send(line.trim_end().to_string());
        }
        out
    });
    let server_stderr_reader = std::thread::spawn(move || {
        let mut err = String::new();
        let mut reader = std::io::BufReader::new(stderr);
        let _ = reader.read_to_string(&mut err);
        err
    });

    let ready_deadline = Instant::now() + Duration::from_secs(15);
    let mut server_ip: Option<String> = None;
    let mut ready = false;
    while Instant::now() < ready_deadline {
        match line_rx.recv_timeout(Duration::from_millis(100)) {
            Ok(line) if line == "bridge_compose_server_ready=true" => {
                ready = true;
                if server_ip.is_some() {
                    break;
                }
            }
            Ok(line) if line.starts_with("bridge_compose_server_ip=") => {
                server_ip = Some(line["bridge_compose_server_ip=".len()..].to_string());
                if ready {
                    break;
                }
            }
            Ok(_) => {}
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    if !ready || server_ip.is_none() {
        unsafe { libc::kill(-server_pid, libc::SIGKILL) };
        scoped_kill_guests(&run_id);
        let _ = server.wait();
        let out = server_stdout_reader.join().unwrap_or_default();
        let err = server_stderr_reader.join().unwrap_or_default();
        return (
            normalize(&format!("{out}{err}<TIMEOUT waiting for compose server>")),
            String::new(),
        );
    }

    let _target_ip = server_ip.expect("server ip recorded");
    let client_out = run_bridge_named_probe(bin, lane, "web", &[], client_stdin);

    let wait_deadline = Instant::now() + Duration::from_secs(15);
    let server_out = loop {
        match server.try_wait().expect("poll compose server") {
            Some(status) => {
                let out = server_stdout_reader.join().unwrap_or_default();
                let err = server_stderr_reader.join().unwrap_or_default();
                let combined = normalize(&format!("{out}{err}"));
                assert!(
                    status.success(),
                    "compose server exited {status}: {combined}"
                );
                break combined;
            }
            None if Instant::now() >= wait_deadline => {
                unsafe { libc::kill(-server_pid, libc::SIGKILL) };
                scoped_kill_guests(&run_id);
                let _ = server.wait();
                let out = server_stdout_reader.join().unwrap_or_default();
                let err = server_stderr_reader.join().unwrap_or_default();
                break normalize(&format!(
                    "{out}{err}<TIMEOUT waiting for compose server exit>"
                ));
            }
            None => std::thread::sleep(Duration::from_millis(100)),
        }
    };

    (server_out, client_out)
}

fn run_docker_bridge_publish_probe(
    lane: Lane,
    host_port: u16,
    stdin_bytes: &[u8],
) -> std::io::Result<String> {
    use std::io::{BufRead, Read, Write};
    use std::sync::mpsc;

    let mut child = Command::new("docker")
        .args(docker_bridge_publish_probe_args(
            lane.platform,
            lane.image,
            host_port,
        ))
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

    let stdout = child.stdout.take().expect("docker stdout");
    let stderr = child.stderr.take().expect("docker stderr");
    let (line_tx, line_rx) = mpsc::channel::<String>();
    let stdout_reader = std::thread::spawn(move || {
        let mut out = String::new();
        let mut reader = std::io::BufReader::new(stdout);
        let mut line = String::new();
        loop {
            line.clear();
            let n = reader.read_line(&mut line).unwrap_or(0);
            if n == 0 {
                break;
            }
            out.push_str(&line);
            let _ = line_tx.send(line.trim_end().to_string());
        }
        out
    });
    let stderr_reader = std::thread::spawn(move || {
        let mut err = String::new();
        let mut reader = std::io::BufReader::new(stderr);
        let _ = reader.read_to_string(&mut err);
        err
    });

    let ready_deadline = Instant::now() + Duration::from_secs(15);
    let mut ready = false;
    while Instant::now() < ready_deadline {
        match line_rx.recv_timeout(Duration::from_millis(100)) {
            Ok(line) if line == "bridge_publish_listener_ready=true" => {
                ready = true;
                break;
            }
            Ok(_) => {}
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    if !ready {
        let _ = child.kill();
        let _ = child.wait();
        let out = stdout_reader.join().unwrap_or_default();
        let err = stderr_reader.join().unwrap_or_default();
        return Ok(normalize(&format!(
            "{out}{err}<TIMEOUT waiting for listener>"
        )));
    }

    let mut stream = connect_loopback_with_retry(host_port)?;
    stream.write_all(b"ping")?;
    let mut reply = [0_u8; 2];
    stream.read_exact(&mut reply)?;
    assert_eq!(&reply, b"ok");

    let wait_deadline = Instant::now() + Duration::from_secs(15);
    loop {
        match child.try_wait()? {
            Some(status) => {
                let out = stdout_reader.join().unwrap_or_default();
                let err = stderr_reader.join().unwrap_or_default();
                let combined = normalize(&format!("{out}{err}"));
                assert!(
                    status.success(),
                    "docker bridge publish probe exited {status}: {combined}"
                );
                return Ok(combined);
            }
            None if Instant::now() >= wait_deadline => {
                let _ = child.kill();
                let _ = child.wait();
                let out = stdout_reader.join().unwrap_or_default();
                let err = stderr_reader.join().unwrap_or_default();
                return Ok(normalize(&format!("{out}{err}<TIMEOUT waiting for exit>")));
            }
            None => std::thread::sleep(Duration::from_millis(100)),
        }
    }
}

fn connect_loopback_with_retry(port: u16) -> std::io::Result<std::net::TcpStream> {
    let mut last_error = None;
    for _ in 0..100 {
        match std::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port)) {
            Ok(stream) => return Ok(stream),
            Err(err) => {
                last_error = Some(err);
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
    Err(last_error.unwrap_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::TimedOut, "connect retry exhausted")
    }))
}

#[test]
fn bridge_publish_probe_args_enable_bridge_and_publish() {
    let args = bridge_publish_probe_args("linux/arm64", "docker.io/library/ubuntu:24.04", 18080);
    assert!(args.windows(2).any(|w| w == ["--net", "bridge"]));
    assert!(args.windows(2).any(|w| w == ["-p", "127.0.0.1:18080:8080"]));
    let image_pos = args
        .iter()
        .position(|arg| arg == "docker.io/library/ubuntu:24.04")
        .expect("image arg");
    let net_pos = args.iter().position(|arg| arg == "--net").expect("net arg");
    let publish_pos = args
        .iter()
        .position(|arg| arg == "-p")
        .expect("publish arg");
    assert!(net_pos < image_pos);
    assert!(publish_pos < image_pos);
}

#[test]
fn docker_bridge_publish_probe_args_publish_before_image() {
    let args =
        docker_bridge_publish_probe_args("linux/arm64", "docker.io/library/ubuntu:24.04", 18080);
    assert!(args.windows(2).any(|w| w == ["-p", "127.0.0.1:18080:8080"]));
    let image_pos = args
        .iter()
        .position(|arg| arg == "docker.io/library/ubuntu:24.04")
        .expect("image arg");
    let publish_pos = args
        .iter()
        .position(|arg| arg == "-p")
        .expect("publish arg");
    assert!(publish_pos < image_pos);
}

#[test]
fn bridge_probe_args_enable_bridge() {
    let args = bridge_probe_args("linux/arm64", "docker.io/library/ubuntu:24.04");
    assert!(args.windows(2).any(|w| w == ["--net", "bridge"]));
    let image_pos = args
        .iter()
        .position(|arg| arg == "docker.io/library/ubuntu:24.04")
        .expect("image arg");
    let net_pos = args.iter().position(|arg| arg == "--net").expect("net arg");
    assert!(net_pos < image_pos);
}

#[test]
fn conformance_bridge_tcp_peer() {
    let _serial = CONFORMANCE_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let Some(bin) = carrick_bin() else {
        eprintln!("SKIP conformance_bridge_tcp_peer: target/release/carrick not built");
        return;
    };
    let lane = ARM64;
    if !lane_runnable_here(&lane) {
        eprintln!(
            "SKIP conformance_bridge_tcp_peer: host ({}) cannot run {} guests",
            std::env::consts::ARCH,
            lane.platform
        );
        return;
    }
    let docker_ok = Command::new("docker")
        .arg("version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !docker_ok {
        eprintln!("SKIP conformance_bridge_tcp_peer: Docker not reachable");
        return;
    }
    let probe = probes_dir("aarch64-unknown-linux-musl").join("bridge_tcp_peer");
    if !probe.exists() {
        eprintln!(
            "SKIP conformance_bridge_tcp_peer: probe not built ({})",
            probe.display()
        );
        return;
    }

    ensure_signed(&bin);
    let raw = std::fs::read(&probe).expect("read bridge_tcp_peer probe");
    use base64::Engine as _;
    let encoded = base64::engine::general_purpose::STANDARD
        .encode(raw)
        .into_bytes();
    let carrick_out = run_bridge_probe(&bin, lane, &encoded);
    let docker_out = run_docker_probe(lane, &encoded).expect("docker bridge tcp peer probe");
    if let Some(diff) = diff_lines(&carrick_out, &docker_out) {
        panic!("bridge tcp peer conformance mismatch:\n{diff}");
    }
}

#[test]
fn conformance_bridge_publish_tcp() {
    let _serial = CONFORMANCE_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let Some(bin) = carrick_bin() else {
        eprintln!("SKIP conformance_bridge_publish_tcp: target/release/carrick not built");
        return;
    };
    let lane = ARM64;
    if !lane_runnable_here(&lane) {
        eprintln!(
            "SKIP conformance_bridge_publish_tcp: host ({}) cannot run {} guests",
            std::env::consts::ARCH,
            lane.platform
        );
        return;
    }
    let docker_ok = Command::new("docker")
        .arg("version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !docker_ok {
        eprintln!("SKIP conformance_bridge_publish_tcp: Docker not reachable");
        return;
    }
    let probe = probes_dir("aarch64-unknown-linux-musl").join("bridge_publish_tcp");
    if !probe.exists() {
        eprintln!(
            "SKIP conformance_bridge_publish_tcp: probe not built ({})",
            probe.display()
        );
        return;
    }

    ensure_signed(&bin);
    let host_port = free_loopback_port();
    let raw = std::fs::read(&probe).expect("read bridge_publish_tcp probe");
    use base64::Engine as _;
    let encoded = base64::engine::general_purpose::STANDARD
        .encode(raw)
        .into_bytes();
    let carrick_out = run_bridge_publish_probe(&bin, lane, host_port, &encoded);
    assert!(
        carrick_out.contains("bridge_publish_listener_ready=true"),
        "missing listener-ready line in output:\n{carrick_out}"
    );
    assert!(
        carrick_out.contains("bridge_publish_tcp_ok=true"),
        "missing completion line in output:\n{carrick_out}"
    );
    let docker_host_port = free_loopback_port();
    let docker_out = run_docker_bridge_publish_probe(lane, docker_host_port, &encoded)
        .expect("docker bridge publish probe");
    if let Some(diff) = diff_lines(&carrick_out, &docker_out) {
        panic!("bridge publish tcp conformance mismatch:\n{diff}");
    }
}

#[test]
fn conformance_bridge_udp_peer() {
    let _serial = CONFORMANCE_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let Some(bin) = carrick_bin() else {
        eprintln!("SKIP conformance_bridge_udp_peer: target/release/carrick not built");
        return;
    };
    let lane = ARM64;
    if !lane_runnable_here(&lane) {
        eprintln!(
            "SKIP conformance_bridge_udp_peer: host ({}) cannot run {} guests",
            std::env::consts::ARCH,
            lane.platform
        );
        return;
    }
    let docker_ok = Command::new("docker")
        .arg("version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !docker_ok {
        eprintln!("SKIP conformance_bridge_udp_peer: Docker not reachable");
        return;
    }
    let probe = probes_dir("aarch64-unknown-linux-musl").join("bridge_udp_peer");
    if !probe.exists() {
        eprintln!(
            "SKIP conformance_bridge_udp_peer: probe not built ({})",
            probe.display()
        );
        return;
    }

    ensure_signed(&bin);
    let raw = std::fs::read(&probe).expect("read bridge_udp_peer probe");
    use base64::Engine as _;
    let encoded = base64::engine::general_purpose::STANDARD
        .encode(raw)
        .into_bytes();
    let carrick_out = run_bridge_probe(&bin, lane, &encoded);
    assert!(
        carrick_out.contains("bridge_udp_sendto_ok=true"),
        "missing sendto completion line in output:\n{carrick_out}"
    );
    assert!(
        carrick_out.contains("bridge_udp_reply=ok"),
        "missing reply line in output:\n{carrick_out}"
    );
    let docker_out = run_docker_probe(lane, &encoded).expect("docker bridge udp peer probe");
    if let Some(diff) = diff_lines(&carrick_out, &docker_out) {
        panic!("bridge udp peer conformance mismatch:\n{diff}");
    }
}

#[test]
fn conformance_bridge_tcp_nonblocking_refused() {
    let _serial = CONFORMANCE_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let Some(bin) = carrick_bin() else {
        eprintln!(
            "SKIP conformance_bridge_tcp_nonblocking_refused: target/release/carrick not built"
        );
        return;
    };
    let lane = ARM64;
    if !lane_runnable_here(&lane) {
        eprintln!(
            "SKIP conformance_bridge_tcp_nonblocking_refused: host ({}) cannot run {} guests",
            std::env::consts::ARCH,
            lane.platform
        );
        return;
    }
    let docker_ok = Command::new("docker")
        .arg("version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !docker_ok {
        eprintln!("SKIP conformance_bridge_tcp_nonblocking_refused: Docker not reachable");
        return;
    }
    let probe = probes_dir("aarch64-unknown-linux-musl").join("bridge_tcp_nonblocking_refused");
    if !probe.exists() {
        eprintln!(
            "SKIP conformance_bridge_tcp_nonblocking_refused: probe not built ({})",
            probe.display()
        );
        return;
    }

    ensure_signed(&bin);
    let raw = std::fs::read(&probe).expect("read bridge_tcp_nonblocking_refused probe");
    use base64::Engine as _;
    let encoded = base64::engine::general_purpose::STANDARD
        .encode(raw)
        .into_bytes();
    let carrick_out = run_bridge_probe(&bin, lane, &encoded);
    let docker_out =
        run_docker_probe(lane, &encoded).expect("docker bridge tcp nonblocking refused probe");
    if let Some(diff) = diff_lines(&carrick_out, &docker_out) {
        panic!("bridge tcp nonblocking refused conformance mismatch:\n{diff}");
    }
}

#[test]
fn conformance_bridge_udp_connected_unreachable() {
    let _serial = CONFORMANCE_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let Some(bin) = carrick_bin() else {
        eprintln!(
            "SKIP conformance_bridge_udp_connected_unreachable: target/release/carrick not built"
        );
        return;
    };
    let lane = ARM64;
    if !lane_runnable_here(&lane) {
        eprintln!(
            "SKIP conformance_bridge_udp_connected_unreachable: host ({}) cannot run {} guests",
            std::env::consts::ARCH,
            lane.platform
        );
        return;
    }
    let docker_ok = Command::new("docker")
        .arg("version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !docker_ok {
        eprintln!("SKIP conformance_bridge_udp_connected_unreachable: Docker not reachable");
        return;
    }
    let probe = probes_dir("aarch64-unknown-linux-musl").join("bridge_udp_connected_unreachable");
    if !probe.exists() {
        eprintln!(
            "SKIP conformance_bridge_udp_connected_unreachable: probe not built ({})",
            probe.display()
        );
        return;
    }

    ensure_signed(&bin);
    let raw = std::fs::read(&probe).expect("read bridge_udp_connected_unreachable probe");
    use base64::Engine as _;
    let encoded = base64::engine::general_purpose::STANDARD
        .encode(raw)
        .into_bytes();
    let carrick_out = run_bridge_probe(&bin, lane, &encoded);
    let docker_out =
        run_docker_probe(lane, &encoded).expect("docker bridge udp connected unreachable probe");
    if let Some(diff) = diff_lines(&carrick_out, &docker_out) {
        panic!("bridge udp connected unreachable conformance mismatch:\n{diff}");
    }
}

#[test]
fn conformance_bridge_udp_sendto_unreachable() {
    let _serial = CONFORMANCE_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let Some(bin) = carrick_bin() else {
        eprintln!(
            "SKIP conformance_bridge_udp_sendto_unreachable: target/release/carrick not built"
        );
        return;
    };
    let lane = ARM64;
    if !lane_runnable_here(&lane) {
        eprintln!(
            "SKIP conformance_bridge_udp_sendto_unreachable: host ({}) cannot run {} guests",
            std::env::consts::ARCH,
            lane.platform
        );
        return;
    }
    let docker_ok = Command::new("docker")
        .arg("version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !docker_ok {
        eprintln!("SKIP conformance_bridge_udp_sendto_unreachable: Docker not reachable");
        return;
    }
    let probe = probes_dir("aarch64-unknown-linux-musl").join("bridge_udp_sendto_unreachable");
    if !probe.exists() {
        eprintln!(
            "SKIP conformance_bridge_udp_sendto_unreachable: probe not built ({})",
            probe.display()
        );
        return;
    }

    ensure_signed(&bin);
    let raw = std::fs::read(&probe).expect("read bridge_udp_sendto_unreachable probe");
    use base64::Engine as _;
    let encoded = base64::engine::general_purpose::STANDARD
        .encode(raw)
        .into_bytes();
    let carrick_out = run_bridge_probe(&bin, lane, &encoded);
    let docker_out =
        run_docker_probe(lane, &encoded).expect("docker bridge udp sendto unreachable probe");
    if let Some(diff) = diff_lines(&carrick_out, &docker_out) {
        panic!("bridge udp sendto unreachable conformance mismatch:\n{diff}");
    }
}

#[test]
fn conformance_bridge_reuse_sockopts() {
    let _serial = CONFORMANCE_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let Some(bin) = carrick_bin() else {
        eprintln!("SKIP conformance_bridge_reuse_sockopts: target/release/carrick not built");
        return;
    };
    let lane = ARM64;
    if !lane_runnable_here(&lane) {
        eprintln!(
            "SKIP conformance_bridge_reuse_sockopts: host ({}) cannot run {} guests",
            std::env::consts::ARCH,
            lane.platform
        );
        return;
    }
    let docker_ok = Command::new("docker")
        .arg("version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !docker_ok {
        eprintln!("SKIP conformance_bridge_reuse_sockopts: Docker not reachable");
        return;
    }
    let probe = probes_dir("aarch64-unknown-linux-musl").join("bridge_reuse_sockopts");
    if !probe.exists() {
        eprintln!(
            "SKIP conformance_bridge_reuse_sockopts: probe not built ({})",
            probe.display()
        );
        return;
    }

    ensure_signed(&bin);
    let raw = std::fs::read(&probe).expect("read bridge_reuse_sockopts probe");
    use base64::Engine as _;
    let encoded = base64::engine::general_purpose::STANDARD
        .encode(raw)
        .into_bytes();
    let carrick_out = run_bridge_probe(&bin, lane, &encoded);
    let docker_out = run_docker_probe(lane, &encoded).expect("docker bridge reuse sockopts probe");
    if let Some(diff) = diff_lines(&carrick_out, &docker_out) {
        panic!("bridge reuse sockopts conformance mismatch:\n{diff}");
    }
}

#[test]
fn conformance_bridge_compose_pair() {
    let _serial = CONFORMANCE_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let Some(bin) = carrick_bin() else {
        eprintln!("SKIP conformance_bridge_compose_pair: target/release/carrick not built");
        return;
    };
    let lane = ARM64;
    if !lane_runnable_here(&lane) {
        eprintln!(
            "SKIP conformance_bridge_compose_pair: host ({}) cannot run {} guests",
            std::env::consts::ARCH,
            lane.platform
        );
        return;
    }
    let probes = probes_dir("aarch64-unknown-linux-musl");
    let server_probe = probes.join("bridge_compose_server");
    if !server_probe.exists() {
        eprintln!(
            "SKIP conformance_bridge_compose_pair: server probe not built ({})",
            server_probe.display()
        );
        return;
    }
    let client_probe = probes.join("bridge_compose_client");
    if !client_probe.exists() {
        eprintln!(
            "SKIP conformance_bridge_compose_pair: client probe not built ({})",
            client_probe.display()
        );
        return;
    }

    ensure_signed(&bin);
    use base64::Engine as _;
    let server_encoded = base64::engine::general_purpose::STANDARD
        .encode(std::fs::read(&server_probe).expect("read bridge_compose_server probe"))
        .into_bytes();
    let client_encoded = base64::engine::general_purpose::STANDARD
        .encode(std::fs::read(&client_probe).expect("read bridge_compose_client probe"))
        .into_bytes();

    let (server_out, client_out) =
        run_bridge_compose_pair(&bin, lane, &server_encoded, &client_encoded);
    assert!(
        client_out.contains("bridge_compose_client_connect_ok=true"),
        "missing client completion line:\nserver:\n{server_out}\nclient:\n{client_out}"
    );
    assert!(
        client_out.contains("bridge_compose_client_response=pong"),
        "missing client response line:\nserver:\n{server_out}\nclient:\n{client_out}"
    );
    assert!(
        server_out.contains("bridge_compose_server_peer_is_bridge=true"),
        "server did not see bridge peer:\nserver:\n{server_out}\nclient:\n{client_out}"
    );
    assert!(
        server_out.contains("bridge_compose_server_peer_is_distinct=true"),
        "server saw its own bridge IP as peer:\nserver:\n{server_out}\nclient:\n{client_out}"
    );
    assert!(
        server_out.contains("bridge_compose_server_done=true"),
        "server did not complete:\nserver:\n{server_out}\nclient:\n{client_out}"
    );
}

#[test]
fn conformance_bridge_net_identity() {
    let _serial = CONFORMANCE_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let Some(bin) = carrick_bin() else {
        eprintln!("SKIP conformance_bridge_net_identity: target/release/carrick not built");
        return;
    };
    let lane = ARM64;
    if !lane_runnable_here(&lane) {
        eprintln!(
            "SKIP conformance_bridge_net_identity: host ({}) cannot run {} guests",
            std::env::consts::ARCH,
            lane.platform
        );
        return;
    }
    let docker_ok = Command::new("docker")
        .arg("version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !docker_ok {
        eprintln!("SKIP conformance_bridge_net_identity: Docker not reachable");
        return;
    }
    let probe = probes_dir("aarch64-unknown-linux-musl").join("bridge_net_identity");
    if !probe.exists() {
        eprintln!(
            "SKIP conformance_bridge_net_identity: probe not built ({})",
            probe.display()
        );
        return;
    }

    ensure_signed(&bin);
    let raw = std::fs::read(&probe).expect("read bridge_net_identity probe");
    use base64::Engine as _;
    let encoded = base64::engine::general_purpose::STANDARD
        .encode(raw)
        .into_bytes();
    let carrick_out = run_bridge_probe(&bin, lane, &encoded);
    let docker_out = run_docker_probe(lane, &encoded).expect("docker bridge identity probe");
    if let Some(diff) = diff_lines(&carrick_out, &docker_out) {
        panic!("bridge net identity conformance mismatch:\n{diff}");
    }
}

#[test]
fn conformance_bridge_loopback_isolation() {
    let _serial = CONFORMANCE_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let Some(bin) = carrick_bin() else {
        eprintln!("SKIP conformance_bridge_loopback_isolation: target/release/carrick not built");
        return;
    };
    let lane = ARM64;
    if !lane_runnable_here(&lane) {
        eprintln!(
            "SKIP conformance_bridge_loopback_isolation: host ({}) cannot run {} guests",
            std::env::consts::ARCH,
            lane.platform
        );
        return;
    }
    let docker_ok = Command::new("docker")
        .arg("version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !docker_ok {
        eprintln!("SKIP conformance_bridge_loopback_isolation: Docker not reachable");
        return;
    }
    let probe = probes_dir("aarch64-unknown-linux-musl").join("bridge_loopback_isolation");
    if !probe.exists() {
        eprintln!(
            "SKIP conformance_bridge_loopback_isolation: probe not built ({})",
            probe.display()
        );
        return;
    }

    ensure_signed(&bin);
    let raw = std::fs::read(&probe).expect("read bridge_loopback_isolation probe");
    use base64::Engine as _;
    let encoded = base64::engine::general_purpose::STANDARD
        .encode(raw)
        .into_bytes();
    let carrick_out = run_bridge_probe(&bin, lane, &encoded);
    let docker_out = run_docker_probe(lane, &encoded).expect("docker bridge loopback probe");
    if let Some(diff) = diff_lines(&carrick_out, &docker_out) {
        panic!("bridge loopback isolation conformance mismatch:\n{diff}");
    }
}

fn rosetta_available() -> bool {
    std::path::Path::new("/Library/Apple/usr/libexec/oah/RosettaLinux/rosetta").exists()
}

/// Whether the CURRENT host can actually execute a lane's GUEST architecture
/// under carrick — used to SKIP (not fail) a lane whose guest arch this host
/// can't run. carrick is not an emulator: it runs the guest's native ISA on a
/// hardware vCPU, so the runnable matrix is keyed on host arch, not just on
/// "is the VMM present".
///
///   * aarch64 guests (`linux/arm64`) — runnable on an **aarch64 host**
///     (macOS/HVF, or a Linux/KVM aarch64 box) natively. On an x86_64 host the
///     shared carrick-x86 engine CANNOT execute aarch64 code (it would fail with
///     `unsupported ELF machine: 183`), so the lane is SKIPPED there.
///   * x86_64 guests (`linux/amd64`) — runnable **natively on an x86_64 host**
///     (the Linux/KVM + FreeBSD/bhyve + NetBSD/NVMM fleet, `carrick-x86`), OR via
///     Apple's in-guest Linux Rosetta on a macOS/arm64 host. On macOS/arm64
///     `cfg!(target_arch = "x86_64")` is false, so the Rosetta predicate is the
///     only thing that keeps this lane alive there — exactly as before.
///
/// Net effect: macOS keeps gating ARM64 and runs amd64 via Rosetta (report-only
/// — see `set_gates_here`); the x86_64 fleet gates AMD64 and SKIPs ARM64 instead
/// of erroring on it.
fn lane_runnable_here(lane: &Lane) -> bool {
    match lane.platform {
        // aarch64 guests need an aarch64 host (no cross-ISA execution).
        "linux/arm64" => cfg!(target_arch = "aarch64"),
        // x86_64 guests run natively on an x86_64 host, or via Rosetta on macOS.
        "linux/amd64" => cfg!(target_arch = "x86_64") || rosetta_available(),
        // Unknown platform: be conservative and skip rather than error.
        _ => false,
    }
}

/// A requested same-ISA native campaign must not spill into the macOS Rosetta
/// lane. Other backends retain the ordinary host-runnable matrix.
fn lane_allowed_for_backend(lane: &Lane, exec_backend: Option<&str>) -> bool {
    exec_backend != Some("native") || lane.platform == "linux/arm64"
}

/// Whether a probe set's DIFFs should fail the gate ON THIS HOST. A probe set is
/// only the system-under-test where carrick ITSELF executes the guest ISA — i.e.
/// the host arch matches the guest arch. The macOS amd64 lane runs through
/// Apple's in-guest Linux Rosetta (a translation layer that is NOT carrick's ABI
/// path), so a DIFF there reflects Rosetta-vs-Docker, not a carrick x86_64 gap:
/// keep that lane REPORT-ONLY on macOS even for an intent-gating (musl) set.
/// On the native x86_64 fleet carrick-x86 IS the implementation under test, so
/// the amd64 musl set gates there. The aarch64 lane only runs on an aarch64 host
/// (lane_runnable_here), where it is always native — so its intent-gating is
/// honoured unchanged.
fn set_gates_here(lane: &Lane, set: &ProbeSet) -> bool {
    if !set.gating {
        return false;
    }
    match lane.platform {
        // Gates only when carrick runs the guest natively (host arch == guest).
        "linux/amd64" => cfg!(target_arch = "x86_64"),
        "linux/arm64" => cfg!(target_arch = "aarch64"),
        _ => false,
    }
}

/// Curated allowlist of x86_64 probes permitted to GATE (fail the build red) on
/// the amd64 lane even though the lane as a whole is report-only carrick-x86
/// BRING-UP. A probe here gates on the native x86_64 fleet; everything else stays
/// report-only, so the ~34 open carrick-x86 ABI gaps (SEGVs on aliassize/mapfixed
/// private-overlay, SysV msg, CLOCK_BOOTTIME, si_value, …) don't flip the gate.
///
/// INTENTIONALLY EMPTY for now. A probe earns a slot only once a *native
/// x86_64 fleet* run (Linux/KVM, FreeBSD/bhyve, NetBSD/NVMM) proves it MATCHes
/// the oracle — which can NOT be confirmed from the macOS reference box this
/// change is authored on. Add only ISA-neutral, pure-logic probes (no x86
/// register / FP / signal-frame specifics; they already PASS on ARM64), so that
/// a future regression on a probe carrick already passes flips the gate red
/// instead of silently sliding back into the report-only pile.
///
/// TODO(fleet): populate from a green native-x86_64 fleet conformance run, one
/// probe at a time, each cited with the run that proved it green.
const X86_GATING_PROBES: &[&str] = &[];

/// Pure per-probe gating decision (host-arch-independent inputs, so it is
/// unit-testable off the x86 fleet). A probe gates iff its SET already gates
/// here (`set_gates`, the native-ISA intent-gating path) OR it is an explicitly
/// allowlisted x86 probe on a host where carrick itself executes the x86_64
/// guest (`native_amd64` — never the macOS-via-Rosetta path, where Rosetta, not
/// carrick, does the translation).
fn probe_gates_decision(set_gates: bool, native_amd64: bool, allowlisted: bool) -> bool {
    set_gates || (native_amd64 && allowlisted)
}

/// Whether one probe's DIFF should fail the gate on this host — the per-probe
/// replacement for the lane-wide `set_gates_here`, so a curated subset of x86
/// probes can gate while the rest of the bring-up lane stays report-only.
fn probe_gates(lane: &Lane, set: &ProbeSet, name: &str) -> bool {
    // Bind the host-arch cfg to a value first: a bare `&& cfg!(...)` reduces to
    // `x && false` off-x86_64, which clippy flags as an always-false expression.
    let host_is_x86_64 = cfg!(target_arch = "x86_64");
    let native_amd64 = host_is_x86_64 && lane.platform == "linux/amd64";
    probe_gates_decision(
        set_gates_here(lane, set),
        native_amd64,
        X86_GATING_PROBES.contains(&name),
    )
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
#[allow(clippy::panic)]
fn ensure_signed(bin: &PathBuf) {
    // codesign + the hypervisor entitlement are macOS/HVF-only. Off-macOS the
    // binary runs directly (KVM/bhyve/NVMM carry no entitlement) and `codesign`
    // does not exist, so signing is both meaningless and impossible — skip it so
    // the conformance/probe gate runs on the Linux/FreeBSD fleet too.
    if cfg!(not(target_os = "macos")) {
        return;
    }
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

// ---------------------------------------------------------------------------
// Probe-oracle cache. The Docker oracle's output for a probe is DETERMINISTIC
// (fixed by the probe source + libc + lane image), so it is captured ONCE
// ("blessed") on a Docker host, committed, and reused: routine gates then run
// carrick only and diff against the cached oracle — no Docker. This makes the
// probe gate runnable where there is NO local Docker (notably FreeBSD/bhyve)
// and stops the gate re-running the entire Docker oracle every time. Same
// philosophy as the suite oracle cache (scripts/conformance/oracle-cache.jsonl).
//
// Layout — one file per probe:
//   crates/carrick-cli/tests/probe-oracle/<lane>-<libc>/<probe>
// First line = the probe SOURCE hash (a source edit invalidates the entry → it
// must be re-blessed); the remainder is the EXACT `run_docker_probe` output
// (normalized stdout+stderr). (Re-)bless from a Docker host with:
//   cargo test -p carrick-cli --test conformance <platform features> -- \
//       --ignored bless_probe_oracle --nocapture
// then commit the updated probe-oracle/ tree. Timing-sensitive probes
// (is_timing_sensitive) and perf_* are NOT cached — their output is
// non-deterministic, so they always need a live oracle and are skipped where
// Docker is absent.

fn probe_oracle_dir(lane_label: &str, libc: &str) -> PathBuf {
    repo_path(&format!(
        "crates/carrick-cli/tests/probe-oracle/{lane_label}-{libc}"
    ))
}

/// Stable content fingerprint of a probe's source, so a source edit invalidates
/// its cached oracle. Not cryptographic — it only needs to detect change.
fn probe_src_hash(name: &str) -> String {
    use std::hash::{Hash, Hasher};
    match std::fs::read(repo_path(&format!("conformance-probes/src/bin/{name}.rs"))) {
        Ok(bytes) => {
            let mut h = std::collections::hash_map::DefaultHasher::new();
            bytes.hash(&mut h);
            format!("{:016x}", h.finish())
        }
        Err(_) => "nosrc".to_string(),
    }
}

/// Cached Docker-oracle output for a probe, iff present AND its source hash
/// still matches (a stale entry — source changed since bless — reads as a miss).
fn cached_probe_oracle(lane_label: &str, libc: &str, name: &str) -> Option<String> {
    let raw = std::fs::read_to_string(probe_oracle_dir(lane_label, libc).join(name)).ok()?;
    let (hash_line, body) = raw.split_once('\n')?;
    (hash_line == probe_src_hash(name)).then(|| normalize(body))
}

/// Persist a freshly-captured Docker-oracle output for a probe (the bless step).
fn write_probe_oracle(
    lane_label: &str,
    libc: &str,
    name: &str,
    output: &str,
) -> std::io::Result<()> {
    let dir = probe_oracle_dir(lane_label, libc);
    std::fs::create_dir_all(&dir)?;
    std::fs::write(
        dir.join(name),
        format!("{}\n{output}", probe_src_hash(name)),
    )
}

/// Where a probe's Docker oracle comes from for this gate run.
enum OracleSource {
    /// Read from the committed cache — no Docker touched.
    Cached(String),
    /// Run live against Docker (cache miss / stale, Docker available).
    Live(std::io::Result<String>),
    /// Cache miss AND no Docker — cannot gate this probe; loudly skipped.
    Unblessed,
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

fn run_carrick(bin: &PathBuf, lane: Lane, snippet: &str) -> String {
    use std::os::unix::process::CommandExt;
    let run_id = case_run_id();
    let mut command = Command::new(bin);
    command
        .args([
            "run",
            "--platform",
            lane.platform,
            "--raw",
            "--fs",
            "host",
            lane.image,
            "/bin/sh",
            "-c",
            snippet,
        ])
        .env("CARRICK_RUN_ID", &run_id)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        // New process group so we can signal the whole guest tree on timeout.
        .process_group(0);
    if lane.platform == "linux/amd64" {
        command.env("CARRICK_ACCEPT_ROSETTA_TERMS", "1");
    }
    let child = command.spawn().expect("spawn carrick");
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

async fn ensure_image(docker: &Docker, lane: Lane) -> anyhow::Result<()> {
    let mut stream = docker.create_image(
        Some(CreateImageOptions {
            from_image: lane.image,
            platform: lane.platform,
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

async fn run_docker(docker: &Docker, lane: Lane, snippet: &str) -> anyhow::Result<String> {
    let config = Config {
        image: Some(lane.image.to_string()),
        cmd: Some(vec!["/bin/sh".into(), "-c".into(), snippet.to_string()]),
        ..Default::default()
    };
    let created = docker
        .create_container(
            Some(CreateContainerOptions {
                name: format!(
                    "carrick-conf-{}-{}-{}",
                    lane.label,
                    std::process::id(),
                    CASE_SEQ.fetch_add(1, Ordering::Relaxed)
                ),
                platform: Some(lane.platform.to_string()),
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
        let docker = match Docker::connect_with_defaults() {
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
        let mut failures = Vec::new();
        for lane in LANES {
            if !lane_runnable_here(lane) {
                eprintln!(
                    "SKIP conformance[{}]: host ({}) cannot run {} guests \
                     (no cross-ISA execution; Rosetta absent for amd64-on-macOS)",
                    lane.label,
                    std::env::consts::ARCH,
                    lane.platform
                );
                continue;
            }
            if let Err(e) = ensure_image(&docker, *lane).await {
                eprintln!(
                    "SKIP conformance[{}]: cannot pull {} for {}: {e}",
                    lane.label, lane.image, lane.platform
                );
                continue;
            }
            for case in CASES {
                let carrick_out = run_carrick(&bin, *lane, case.snippet);
                let docker_fut = run_docker(&docker, *lane, case.snippet);
                let docker_out = match tokio::time::timeout(CASE_DEADLINE, docker_fut).await {
                    Ok(Ok(o)) => o,
                    Ok(Err(e)) => {
                        eprintln!("FAIL  {}:{} (docker error: {e})", lane.label, case.name);
                        failures.push(format!("{}:{}", lane.label, case.name));
                        continue;
                    }
                    Err(_) => {
                        eprintln!("FAIL  {}:{} (docker timeout)", lane.label, case.name);
                        failures.push(format!("{}:{}", lane.label, case.name));
                        continue;
                    }
                };
                if carrick_out == docker_out {
                    eprintln!("PASS  {}:{}", lane.label, case.name);
                } else {
                    eprintln!(
                        "FAIL  {}:{}\n  --- carrick ---\n{}\n  --- linux ---\n{}",
                        lane.label,
                        case.name,
                        indent(&carrick_out),
                        indent(&docker_out)
                    );
                    failures.push(format!("{}:{}", lane.label, case.name));
                }
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
// Default-run contract: unlike `conformance` (which runs `--raw` and merges
// streams), this asserts the DEFAULT `carrick run` path is docker-shaped —
// exit-code parity, no JSON envelope on stdout, and stdout/stderr separation —
// against the real-docker oracle. This is the guard that the default path (the
// one a user types most) behaves like `docker run`. It also exercises the
// `--pid private` default, so it regression-guards the NsSupervisor exit-code
// harvest.
// ---------------------------------------------------------------------------

struct ExitCase {
    name: &'static str,
    snippet: &'static str,
}

const EXIT_CASES: &[ExitCase] = &[
    ExitCase {
        name: "exit_zero",
        snippet: "true",
    },
    ExitCase {
        name: "exit_one",
        snippet: "exit 1",
    },
    ExitCase {
        name: "exit_42",
        snippet: "exit 42",
    },
    ExitCase {
        name: "stdout_only",
        snippet: "echo OUT",
    },
    ExitCase {
        name: "stream_separation",
        snippet: "echo OUT; echo ERR 1>&2; exit 3",
    },
];

/// Run a snippet under carrick on the DEFAULT path (no `--raw`): returns
/// `(host_exit_code, stdout, stderr)` with the streams captured separately.
/// Mirrors `run_carrick`'s deadline + process-group-kill guard.
fn run_carrick_default(bin: &PathBuf, snippet: &str) -> (i32, String, String) {
    use std::os::unix::process::CommandExt;
    let run_id = case_run_id();
    let child = Command::new(bin)
        .args(["run", ARM64.image, "--fs", "host", "/bin/sh", "-c", snippet])
        .env("CARRICK_RUN_ID", &run_id)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
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
        return (
            -1,
            format!("<TIMEOUT after {}s>", CASE_DEADLINE.as_secs()),
            String::new(),
        );
    }
    (
        out.status.code().unwrap_or(-1),
        normalize(&String::from_utf8_lossy(&out.stdout)),
        normalize(&String::from_utf8_lossy(&out.stderr)),
    )
}

/// Run a snippet under Docker, returning `(exit_code, stdout, stderr)`. The exit
/// code comes from `inspect` (robust for non-zero exits, which `wait_container`
/// surfaces as a stream error); the streams are partitioned by `LogOutput`.
async fn run_docker_contract(
    docker: &Docker,
    snippet: &str,
    seq: usize,
) -> anyhow::Result<(i64, String, String)> {
    let config = Config {
        image: Some(ARM64.image.to_string()),
        cmd: Some(vec!["/bin/sh".into(), "-c".into(), snippet.to_string()]),
        ..Default::default()
    };
    let name = format!("carrick-exit-{}-{}", std::process::id(), seq);
    let created = docker
        .create_container(
            Some(CreateContainerOptions {
                name,
                platform: Some(ARM64.platform.to_string()),
            }),
            config,
        )
        .await?;
    let id = created.id;
    let result = async {
        docker.start_container::<String>(&id, None).await?;
        let mut wait = docker.wait_container::<String>(&id, None);
        // Drain the wait stream (a non-zero exit arrives as an Err we ignore;
        // the authoritative code comes from inspect below).
        while let Some(w) = wait.next().await {
            let _ = w;
        }
        let inspect = docker.inspect_container(&id, None).await?;
        let code = inspect.state.and_then(|s| s.exit_code).unwrap_or(-1);
        let mut logs = docker.logs::<String>(
            &id,
            Some(LogsOptions {
                stdout: true,
                stderr: true,
                ..Default::default()
            }),
        );
        let (mut so, mut se) = (String::new(), String::new());
        while let Some(item) = logs.next().await {
            match item {
                Ok(LogOutput::StdOut { message }) => {
                    so.push_str(&String::from_utf8_lossy(&message))
                }
                Ok(LogOutput::StdErr { message }) => {
                    se.push_str(&String::from_utf8_lossy(&message))
                }
                _ => {}
            }
        }
        Ok::<_, anyhow::Error>((code, normalize(&so), normalize(&se)))
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
fn conformance_default_run_contract() {
    let _serial = CONFORMANCE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let Some(bin) = carrick_bin() else {
        eprintln!("SKIP conformance_default_run_contract: target/release/carrick not built");
        return;
    };
    // This contract runs the ARM64 (aarch64) image on the default path; an
    // x86_64 host can't execute aarch64 guests, so skip there rather than error.
    if !lane_runnable_here(&ARM64) {
        eprintln!(
            "SKIP conformance_default_run_contract: host ({}) cannot run aarch64 guests",
            std::env::consts::ARCH
        );
        return;
    }
    ensure_signed(&bin);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    rt.block_on(async {
        let docker = match Docker::connect_with_defaults() {
            Ok(d) => match d.ping().await {
                Ok(_) => d,
                Err(e) => {
                    eprintln!("SKIP conformance_default_run_contract: Docker not reachable: {e}");
                    return;
                }
            },
            Err(e) => {
                eprintln!("SKIP conformance_default_run_contract: Docker connect failed: {e}");
                return;
            }
        };
        if let Err(e) = ensure_image(&docker, ARM64).await {
            eprintln!(
                "SKIP conformance_default_run_contract: cannot pull {}: {e}",
                ARM64.image
            );
            return;
        }

        let mut failures = Vec::new();
        for (seq, case) in EXIT_CASES.iter().enumerate() {
            let (c_code, c_out, c_err) = run_carrick_default(&bin, case.snippet);
            let (d_code, d_out, d_err) = match tokio::time::timeout(
                CASE_DEADLINE,
                run_docker_contract(&docker, case.snippet, seq),
            )
            .await
            {
                Ok(Ok(d)) => d,
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

            let mut problems = Vec::new();
            // Exit-code parity — the core P1 guarantee, and the regression guard
            // for the NsSupervisor exit-code harvest race.
            if i64::from(c_code) != d_code {
                problems.push(format!("exit: carrick={c_code} docker={d_code}"));
            }
            // stdout must match docker exactly: catches both the JSON envelope
            // and any stderr bleeding into stdout.
            if c_out != d_out {
                problems.push(format!("stdout: carrick={c_out:?} docker={d_out:?}"));
            }
            // Explicit envelope check (redundant with the stdout match, but names
            // the failure clearly).
            if c_out.contains("\"exit_code\"") || c_out.contains("\"report\"") {
                problems.push("stdout carries the JSON envelope".to_string());
            }
            // stderr: docker's stderr must be present in carrick's (lenient —
            // carrick may add host-side notices that `normalize` doesn't strip).
            if !d_err.is_empty() && !c_err.contains(&d_err) {
                problems.push(format!(
                    "stderr: carrick={c_err:?} missing docker={d_err:?}"
                ));
            }

            if problems.is_empty() {
                eprintln!("PASS  {} (exit={c_code})", case.name);
            } else {
                eprintln!("FAIL  {}\n    {}", case.name, problems.join("\n    "));
                failures.push(case.name);
            }
        }
        assert!(
            failures.is_empty(),
            "default-run contract gaps: {failures:?}"
        );
    });
}

// ---------------------------------------------------------------------------
// Probe binaries: compiled Linux ELFs (built by scripts/build-probes.sh) run
// UNDER carrick and UNDER Docker, byte-identical. The target triple is per
// ProbeSet — aarch64-linux-{musl,gnu} for the ARM64 lane, x86_64-linux-{musl,
// gnu} for the AMD64 lane — so the SAME portable probe sources gate both the
// macOS/aarch64 reference path and the x86_64 fleet (Linux/KVM, FreeBSD/bhyve).
// Each probe prints deterministic, one-line-per-observation output. The default
// transport base64-encodes the binary and feeds it to `base64 -d` on the child's
// STDIN (it is too large for argv). Native musl campaigns bind the static probe
// as the container command so an unrelated dynamic image utility cannot fail
// before the probe starts.
// ---------------------------------------------------------------------------

/// `base64 -d > /tmp/p && chmod +x /tmp/p && /tmp/p` — the binary arrives on
/// stdin, so the same snippet works under carrick and Docker.
const PROBE_SNIPPET: &str = "base64 -d > /tmp/p && chmod +x /tmp/p && /tmp/p";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProbeTransport {
    ContainerInjection,
    DirectElf,
}

fn probe_transport(exec_backend: Option<&str>, libc: &str) -> ProbeTransport {
    if exec_backend == Some("native") && libc == "musl" {
        ProbeTransport::DirectElf
    } else {
        ProbeTransport::ContainerInjection
    }
}

/// Directory holding the compiled probe executables for a target triple, if built.
fn probes_dir(target: &str) -> PathBuf {
    repo_path(&format!("conformance-probes/target/{target}/release"))
}

fn probe_campaign_dir(target: &str, exec_backend: Option<&str>) -> PathBuf {
    if exec_backend == Some("native") && target.starts_with("aarch64-") {
        repo_path(&format!(
            "conformance-probes/target/native-pie/{target}/release"
        ))
    } else {
        probes_dir(target)
    }
}

fn probe_source_names() -> BTreeSet<String> {
    let src_dir = repo_path("conformance-probes/src/bin");
    let Ok(entries) = std::fs::read_dir(src_dir) else {
        return BTreeSet::new();
    };
    entries
        .flatten()
        .filter_map(|entry| {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                return None;
            }
            path.file_stem()
                .and_then(|n| n.to_str())
                .map(str::to_string)
        })
        .collect()
}

/// Enumerate built probe executables with matching `src/bin/*.rs` sources.
/// Cargo leaves deleted binaries in `target/.../release`; filtering through the
/// source list keeps stale artifacts out of the line-exact gate.
fn probe_binaries(target: &str) -> Vec<PathBuf> {
    let dir = probes_dir(target);
    probe_binaries_in(&dir)
}

fn probe_binaries_in(dir: &Path) -> Vec<PathBuf> {
    let source_names = probe_source_names();
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
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
        if !source_names.contains(name) {
            continue; // skips stale binaries for probes whose source was removed
        }
        out.push(path);
    }
    out.sort();
    out
}

/// Run the probe-injection snippet under carrick, feeding `stdin_bytes` (the
/// base64 of the probe) to the child's STDIN. Mirrors `run_carrick`'s
/// deadline + process-group-kill + sweep pattern, but pipes stdin.
fn run_carrick_probe(bin: &PathBuf, lane: Lane, stdin_bytes: &[u8]) -> String {
    run_carrick_probe_with_deadline(bin, lane, stdin_bytes, CASE_DEADLINE)
}

fn run_carrick_probe_with_deadline(
    bin: &PathBuf,
    lane: Lane,
    stdin_bytes: &[u8],
    deadline: Duration,
) -> String {
    run_carrick_probe_with_backend_env(bin, lane, stdin_bytes, deadline, None)
}

fn run_carrick_probe_with_backend(
    bin: &PathBuf,
    lane: Lane,
    stdin_bytes: &[u8],
    deadline: Duration,
    exec_backend: &'static str,
    native_page_profile: &'static str,
) -> String {
    run_carrick_probe_with_backend_env(
        bin,
        lane,
        stdin_bytes,
        deadline,
        Some((exec_backend, native_page_profile)),
    )
}

fn run_carrick_probe_with_backend_env(
    bin: &PathBuf,
    lane: Lane,
    stdin_bytes: &[u8],
    deadline: Duration,
    backend_env: Option<(&'static str, &'static str)>,
) -> String {
    let mut command = Command::new(bin);
    command
        .args([
            "run",
            "--platform",
            lane.platform,
            "--raw",
            "--fs",
            "host",
            lane.image,
            "/bin/sh",
            "-c",
            PROBE_SNIPPET,
        ])
        .env(
            "CARRICK_ACCEPT_ROSETTA_TERMS",
            if lane.platform == "linux/amd64" {
                "1"
            } else {
                "0"
            },
        );
    if let Some((exec_backend, native_page_profile)) = backend_env {
        command
            .env("CARRICK_EXEC_BACKEND", exec_backend)
            .env("CARRICK_NATIVE_PAGE_PROFILE", native_page_profile);
    }
    run_carrick_probe_process(command, Some(stdin_bytes), deadline)
}

fn run_carrick_bound_probe(bin: &PathBuf, lane: Lane, probe: &Path, deadline: Duration) -> String {
    let volume = format!("{}:/tmp/carrick-probe:ro", probe.display());
    let mut command = Command::new(bin);
    command
        .args([
            "run",
            "--platform",
            lane.platform,
            "--raw",
            "--fs",
            "host",
            "--volume",
        ])
        .arg(volume)
        .arg(lane.image)
        .arg("/tmp/carrick-probe")
        .env("CARRICK_ACCEPT_ROSETTA_TERMS", "0");
    // Docker consumes the injected payload before exec, leaving the probe an
    // EOF pipe on stdin. Preserve that fd shape for direct native probes.
    run_carrick_probe_process(command, Some(&[]), deadline)
}

fn run_carrick_probe_process(
    mut command: Command,
    stdin_bytes: Option<&[u8]>,
    deadline: Duration,
) -> String {
    use std::io::Write;
    use std::os::unix::process::CommandExt;

    let run_id = case_run_id();
    command
        .env("CARRICK_RUN_ID", &run_id)
        .stdin(if stdin_bytes.is_some() {
            std::process::Stdio::piped()
        } else {
            std::process::Stdio::null()
        })
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .process_group(0);
    let mut child = command.spawn().expect("spawn carrick probe");
    let pid = child.id() as i32;
    if let Some(stdin_bytes) = stdin_bytes {
        // Hand the base64 to the child on its own thread so a full stdout pipe
        // can't deadlock the write.
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
                if start.elapsed() > deadline {
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
        return format!("<TIMEOUT after {}s>", deadline.as_secs());
    }
    let mut combined = String::from_utf8_lossy(&out.stdout).into_owned();
    combined.push_str(&String::from_utf8_lossy(&out.stderr));
    normalize(&combined)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn ensure_native_smoke_probe() -> PathBuf {
    let probe = probes_dir("aarch64-unknown-linux-musl").join("native_smoke");

    std::fs::create_dir_all(probe.parent().expect("native smoke target directory"))
        .expect("create native smoke target directory");
    let status = Command::new("clang")
        .current_dir(repo_path("."))
        .args([
            "--target=aarch64-linux-musl",
            "-fuse-ld=lld",
            "-nostdlib",
            "-static-pie",
            "-o",
        ])
        .arg(&probe)
        .args(["conformance-probes/native_smoke.S"])
        .status()
        .expect("build native_smoke probe");
    if !status.success() {
        let fallback_status = Command::new("clang")
            .current_dir(repo_path("."))
            .args([
                "--target=aarch64-linux-musl",
                "-fuse-ld=/opt/homebrew/bin/ld.lld",
                "-nostdlib",
                "-static-pie",
                "-o",
            ])
            .arg(&probe)
            .args(["conformance-probes/native_smoke.S"])
            .status()
            .expect("build native_smoke probe with explicit ld.lld");
        assert!(
            fallback_status.success(),
            "failed to build native_smoke probe"
        );
    }
    assert!(probe.exists(), "native_smoke probe missing after build");
    assert_eq!(
        elf_file_type(&probe),
        Some(3),
        "native_smoke must be an ET_DYN static PIE probe for high native mapping"
    );
    probe
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn ensure_native_static_pie_probe(name: &str) -> PathBuf {
    let probe = probe_campaign_dir("aarch64-unknown-linux-musl", Some("native")).join(name);
    if !probe.exists() {
        let status = Command::new(repo_path("scripts/build-probes.sh"))
            .current_dir(repo_root())
            .arg("--native-pie")
            .status()
            .expect("build native PIE probe campaign");
        assert!(
            status.success(),
            "failed to build native PIE probe campaign for {name}"
        );
    }
    assert!(probe.exists(), "native static PIE probe missing: {name}");
    assert_eq!(
        elf_file_type(&probe),
        Some(3),
        "native static PIE probe {name} must be ET_DYN for high native mapping"
    );
    probe
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn ensure_native_et_exec_probe(name: &str) -> PathBuf {
    let target_dir = repo_path("conformance-probes/target/native-et-exec");
    let status = Command::new("cargo")
        .current_dir(repo_path("conformance-probes"))
        .env("CARGO_TARGET_DIR", &target_dir)
        .args([
            "build",
            "--release",
            "--target",
            "aarch64-unknown-linux-musl",
            "--bin",
            name,
        ])
        .status()
        .expect("build native ET_EXEC probe");
    assert!(
        status.success(),
        "failed to build native ET_EXEC probe {name}"
    );
    let probe = target_dir
        .join("aarch64-unknown-linux-musl")
        .join("release")
        .join(name);
    assert!(probe.exists(), "native ET_EXEC probe missing: {name}");
    assert_eq!(
        elf_file_type(&probe),
        Some(2),
        "native fixed-address probe {name} must be ET_EXEC"
    );
    probe
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn elf_file_type(path: &PathBuf) -> Option<u16> {
    let bytes = std::fs::read(path).ok()?;
    let raw = bytes.get(16..18)?;
    Some(u16::from_le_bytes([raw[0], raw[1]]))
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn run_native_run_elf(bin: &PathBuf, probe: &PathBuf, native_page_profile: &'static str) -> String {
    run_native_run_elf_with_args(bin, probe, native_page_profile, &[])
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn run_native_run_elf_with_args(
    bin: &PathBuf,
    probe: &PathBuf,
    native_page_profile: &'static str,
    guest_args: &[&str],
) -> String {
    use std::os::unix::process::CommandExt;

    let run_id = case_run_id();
    let mut command = Command::new(bin);
    command
        .args([
            "run-elf",
            "--raw",
            "--exec-backend",
            "native",
            "--native-page-profile",
            native_page_profile,
        ])
        .arg(probe);
    if !guest_args.is_empty() {
        command.arg("--").args(guest_args);
    }
    let child = command
        .env("CARRICK_RUN_ID", &run_id)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .process_group(0)
        .spawn()
        .expect("spawn native run-elf probe");
    let pid = child.id() as i32;
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
    let out = child.wait_with_output().expect("wait native run-elf probe");
    done.store(true, Ordering::Relaxed);
    let timed_out = watcher.join().unwrap_or(false);
    if timed_out {
        return format!("<TIMEOUT after {}s>", CASE_DEADLINE.as_secs());
    }

    let mut combined = String::new();
    combined.push_str("status=");
    combined.push_str(&out.status.to_string());
    combined.push('\n');
    combined.push_str(&String::from_utf8_lossy(&out.stdout));
    combined.push_str(&String::from_utf8_lossy(&out.stderr));
    normalize(&combined)
}

/// Run the probe-injection snippet under real Linux via `docker run -i`,
/// feeding `stdin_bytes` to the container's STDIN. Uses std::process rather
/// than bollard because bollard stdin-attach is awkward; the shell-case path
/// keeps using `run_docker` (bollard) unchanged.
fn run_docker_probe(lane: Lane, stdin_bytes: &[u8]) -> std::io::Result<String> {
    use std::io::Write;
    let mut child = Command::new("docker")
        .args([
            "run",
            "-i",
            "--rm",
            "--platform",
            lane.platform,
            lane.image,
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
    // splicenetpoll pushes 1 MiB through socket->pipe->socket splices against a
    // 12s deadline with a throttled drainer + 32 KiB socket buffers + edge-
    // triggered epoll. carrick is faithful (real SO_SNDBUF passthrough, EPOLLOUT
    // readiness via a real host poll(), correct EPOLLET re-arm) but ~10% lower
    // per-syscall overhead, so it moves the MiB in ~10.5s while throttled-loopback
    // Docker lands near the 12s line — the DOCKER oracle ITSELF flips (measured
    // 4 false / 2 true across 6 native-amd64 runs), so the verdict is a coin-flip
    // on the deadline, not a correctness signal. (The earlier exit-125 abort was
    // the /dev/shm absence, fixed separately; the splice/poll path is correct.)
    "splicenetpoll",
    // mmaprecl churns 800 x 64 MiB anonymous map/unmap cycles. It validates
    // arena reuse and zero-on-reuse, but under the full parallel gate the host
    // can spend enough time in unrelated guests/Docker that the probe exceeds
    // the per-case deadline. Standalone Carrick and Docker runs match.
    "mmaprecl",
    // futex wake-COUNT probes: macOS __ulock can report zombie wake successes
    // for ~µs after a wake under contention,
    // so exact counts flake under the parallel CPU load — quarantine them.
    "futexwakecount",
    "futexrequeue",
    "futexshare",
    // futexsharedalias is correctness-deterministic standalone, but it forks two
    // waiters and asserts post-wake liveness through pipes. Under the full
    // parallel guest batch the single-wake ordering can miss the observation
    // window; scripts/run-probe.sh matches Docker.
    "futexsharedalias",
    "futexghost",
    "futexextra",
    // mmapfileforkwriteback validates fork-time MAP_SHARED file writeback and
    // post-wait parent visibility. The invariant matches standalone, but the
    // fork/readback window is noisy under the 8-way guest fan-out.
    "mmapfileforkwriteback",
    // sigchld: ROOT-CAUSED to host-scheduling tail-latency, NOT a carrick bug.
    // The probe busy-spins (no syscall) ≤10s for an async SIGCHLD; carrick's
    // delivery path is correct + fully event-driven (signal pump's kqueue
    // NOTE_EXIT → publish_pending_for → kicker.kick(parent_tid)=hv_vcpus_exit
    // forces the spinning vCPU out → run loop injects). EVIDENCE it's env, not a
    // gap: run-elf passes 72/72 incl. 12/12 under 2× CPU oversubscription (20
    // busy loops on 10 cores); it only flakes in the FULL gate, where 8 carrick
    // guests + the CPU-hungry Docker-oracle VM oversubscribe the host and the
    // pump/vCPU threads for one guest occasionally aren't scheduled to deliver
    // within 10s. The serial lane removes the 8-way carrick contention so the
    // probe still validates delivery without the host-saturation false flake.
    "sigchld",
    // waitsiblingsigchld: same root cause as sigchld (cross-process SIGCHLD
    // delivery is timing-sensitive). MATCHes standalone; flaked once under the
    // 8-way gate load while a DIFFERENT probe flaked the next run — the
    // signature of host-saturation jitter, not a code regression. Serial lane.
    "waitsiblingsigchld",
    // pidnsinitreap: the orphan polls getppid() for reparent-to-init within a
    // bounded ~2.5s window; under the 8-way gate load the NsSupervisor reparent
    // translation can miss the window and the orphan's pipe report is lost
    // (grandchild_report_ok=false). MATCHes 6/6 standalone — same host-saturation
    // jitter class as sigchld/waitsiblingsigchld, not a code regression.
    "pidnsinitreap",
    // waitexitstorm: 1050 fork+blocking-wait cycles intentionally exceed the
    // old 1024 namespace-member capacity. It MATCHes standalone, but runs close
    // enough to the default 45s case deadline that full-gate host load can trip
    // a false timeout. Keep it in the serial lane and give it the same 60s bound
    // as scripts/run-probe.sh so the gate still runs it without weakening the
    // invariant.
    "waitexitstorm",
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
/// (its own per-case run id via the selected transport), so it is safe to call
/// from multiple worker threads concurrently.
fn run_one_probe(
    bin: &PathBuf,
    lane: Lane,
    probe: &std::path::Path,
    transport: ProbeTransport,
) -> (String, ProbeOutcome) {
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
    // carrick THEN docker, sequentially — so a single `run_one_probe` call never
    // overlaps the two. (The parallel gate path uses the two-phase split below so
    // it doesn't either; this fn is the serial quarantine path.)
    let deadline = if name == "waitexitstorm" {
        WAITEXITSTORM_DEADLINE
    } else {
        CASE_DEADLINE
    };
    let carrick_out = match transport {
        ProbeTransport::ContainerInjection => {
            run_carrick_probe_with_deadline(bin, lane, &encoded, deadline)
        }
        ProbeTransport::DirectElf => run_carrick_bound_probe(bin, lane, probe, deadline),
    };
    let docker_out = run_docker_probe(lane, &encoded);
    classify_probe(name, lane.label, &carrick_out, docker_out)
}

/// Classify a probe from its (already-collected) carrick + docker outputs — pure,
/// runs no carrick/docker, so it is the safe "phase 3" after the two-phase split.
/// Probes that diverge ONLY on a specific lane because that lane's ORACLE — not
/// carrick — is the limited side. carrick is correct; the divergence is the
/// amd64 oracle box (Debian 12 / kernel 6.1, overlayfs, host net-ns) failing to
/// match. Lane-scoped (NOT global `KNOWN_PROBE_GAPS`) so the aarch64 lane, whose
/// LinuxKit oracle differs, is unaffected. Like `KNOWN_PROBE_GAPS`, an
/// UNEXPECTED pass here fails the suite (the oracle improved → un-excuse it).
const KNOWN_LANE_GAPS: &[(&str, &str)] = &[
    // The amd64 oracle box runs Debian 12 / kernel 6.1, predating these syscalls;
    // carrick implements them, so the probe sees carrick-success vs oracle-ENOSYS.
    // A 6.5+/6.6+ oracle kernel makes these simply PASS (carrick is already right).
    ("amd64", "cachestatpages"), // cachestat(451) — Linux 6.5
    ("amd64", "chmodsetgid"),    // fchmodat2(452) — Linux 6.6
    // carrick's `--fs host` backend is a real ext4 → O_TMPFILE works; Docker's
    // overlayfs returns EOPNOTSUPP. carrick is MORE capable — a filesystem-backend
    // difference, not a syscall gap, and kernel-independent.
    ("amd64", "otmpfileforkexec"),
    ("amd64", "tmpfilewrite"),
    // Unprivileged ICMP ping sockets are gated by net.ipv4.ping_group_range, which
    // Docker opens per-container in its OWN net-ns; carrick has no net-ns
    // (--net=host) so it inherits the host's default-closed range ("1 0"). Closing
    // this needs network-namespace support (the net-ns roadmap).
    ("amd64", "icmp"),
];

fn classify_probe(
    name: String,
    lane_label: &str,
    carrick_out: &str,
    docker_out: std::io::Result<String>,
) -> (String, ProbeOutcome) {
    let docker_out = match docker_out {
        Ok(o) => o,
        Err(e) => return (name, ProbeOutcome::Error(format!("docker error: {e}"))),
    };
    let known_gap = KNOWN_PROBE_GAPS.contains(&name.as_str())
        || KNOWN_LANE_GAPS.contains(&(lane_label, name.as_str()));
    let outcome = match (diff_lines(carrick_out, &docker_out), known_gap) {
        (None, false) => ProbeOutcome::Pass,
        (None, true) => ProbeOutcome::UnexpectedPass,
        (Some(diff), false) => ProbeOutcome::Fail(diff),
        // An excused (known-gap) DIFF: Xfail ONLY while the carrick-side output
        // still matches the recorded excuse fingerprint — otherwise the
        // divergence itself changed and a NEW regression is hiding behind the
        // name-keyed excuse, so fail.
        (Some(diff), true) => {
            excused_probe_outcome(diff, excuse_fingerprint(lane_label, &name), carrick_out)
        }
    };
    (name, outcome)
}

/// Recorded carrick-SIDE output fingerprints for excused (known-gap) probes. An
/// entry pins the EXACT carrick output behind a known-gap excuse, so a CHANGE in
/// that output (a new, different regression) is no longer masked by the
/// name-keyed excuse — it surfaces as a real Fail instead of a silent Xfail.
/// `"*"` in the lane slot matches any lane (a global `KNOWN_PROBE_GAPS` excuse);
/// a concrete lane label matches a `KNOWN_LANE_GAPS` excuse. The fingerprint is
/// `carrick_side_fingerprint` of the normalized carrick output.
///
/// INTENTIONALLY EMPTY for now: capturing a probe's canonical carrick-side
/// output requires a run on the host that owns the excuse (the amd64 fleet for
/// the `KNOWN_LANE_GAPS` entries), which can't be done from the macOS reference
/// box. An excuse with no recorded fingerprint falls back to the legacy
/// Xfail-any-diff behavior (`excused_probe_outcome` with `None`), so this is a
/// pure tightening: adding a fingerprint can only ever turn a masked regression
/// into a visible Fail, never the reverse.
///
/// TODO(fleet): record `(lane, probe, carrick_side_fingerprint(output))` for each
/// `KNOWN_LANE_GAPS` excuse from a fleet run that exhibits the excused divergence.
const EXCUSE_FINGERPRINTS: &[(&str, &str, &str)] = &[];

/// The recorded carrick-side fingerprint for an excused probe, if one is pinned.
/// Matches a lane-specific entry first, then a global `"*"` entry.
fn excuse_fingerprint(lane_label: &str, name: &str) -> Option<&'static str> {
    EXCUSE_FINGERPRINTS
        .iter()
        .find(|(l, n, _)| *n == name && (*l == lane_label || *l == "*"))
        .map(|(_, _, fp)| *fp)
}

/// Stable (Rust-version-independent) content fingerprint of a probe's carrick-
/// side output — FNV-1a 64. Unlike `DefaultHasher` this is reproducible across
/// toolchains, so a recorded constant in `EXCUSE_FINGERPRINTS` stays comparable.
fn carrick_side_fingerprint(s: &str) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325; // FNV offset basis
    for b in s.as_bytes() {
        hash ^= u64::from(*b);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3); // FNV prime
    }
    format!("{hash:016x}")
}

/// Outcome for a probe whose DIFF is EXCUSED by a name-keyed known-gap. A
/// name-only excuse would Xfail ANY divergence, masking a NEW regression whose
/// carrick-side output changed. So when the excuse pins an expected carrick-side
/// fingerprint (`recorded_fp`), require the live carrick output to still match
/// it: a mismatch means the divergence changed → real Fail, not Xfail. An excuse
/// with no recorded fingerprint (`None`) keeps the legacy Xfail-any-diff behavior
/// (the conservative default until a fleet run supplies the fingerprint). Pure —
/// unit-tested directly.
fn excused_probe_outcome(
    diff: String,
    recorded_fp: Option<&str>,
    carrick_side: &str,
) -> ProbeOutcome {
    match recorded_fp {
        None => ProbeOutcome::Xfail(diff),
        Some(fp) if fp == carrick_side_fingerprint(carrick_side) => ProbeOutcome::Xfail(diff),
        Some(_) => ProbeOutcome::Fail(format!(
            "EXCUSED DIVERGENCE CHANGED — carrick-side output no longer matches the \
             recorded excuse fingerprint, so a NEW regression is hiding behind the \
             known-gap excuse. Re-triage (do NOT just re-bless the fingerprint):\n{diff}"
        )),
    }
}

/// Run `f(0..n_items)` across `n_workers` threads, returning results in index
/// order. Used to fan a single phase (all-carrick OR all-docker) out without
/// the two phases ever overlapping.
fn fan_out_indexed<T, F>(n_items: usize, n_workers: usize, f: F) -> Vec<T>
where
    T: Send,
    F: Fn(usize) -> T + Sync,
{
    let slots: Vec<Mutex<Option<T>>> = (0..n_items).map(|_| Mutex::new(None)).collect();
    let next = AtomicUsize::new(0);
    std::thread::scope(|scope| {
        for _ in 0..n_workers.max(1) {
            scope.spawn(|| {
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    if i >= n_items {
                        break;
                    }
                    let v = f(i);
                    *slots[i].lock().unwrap_or_else(|e| e.into_inner()) = Some(v);
                }
            });
        }
    });
    slots
        .into_iter()
        .map(|m| {
            m.into_inner()
                .unwrap_or_else(|e| e.into_inner())
                .expect("every slot filled")
        })
        .collect()
}

#[test]
fn conformance_probes() {
    let _serial = CONFORMANCE_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let Some(bin) = carrick_bin() else {
        eprintln!("SKIP conformance_probes: target/release/carrick not built");
        return;
    };
    // Docker reachability check (std::process side, so no bollard ping here):
    // a trivial `docker version` must succeed. Unlike before, the gate does NOT
    // bail when Docker is absent: it falls back to the committed probe-oracle
    // cache (a deterministic probe diffs against its blessed Docker output), so
    // the gate still runs carrick-only on a Docker-less host (e.g. FreeBSD/bhyve).
    let docker_available = Command::new("docker")
        .arg("version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !docker_available {
        eprintln!(
            "NOTE conformance_probes: Docker not reachable — diffing against the \
             committed probe-oracle cache (carrick-only). Probes with no cached \
             oracle are skipped; bless them on a Docker host."
        );
    }

    ensure_signed(&bin);

    let mut failures = Vec::new();
    let mut fixed_gaps = Vec::new();
    let mut unblessed: Vec<String> = Vec::new();

    let mut nongating_diffs: Vec<String> = Vec::new();
    let requested_exec_backend = std::env::var("CARRICK_EXEC_BACKEND").ok();
    for lane in LANES {
        if !lane_allowed_for_backend(lane, requested_exec_backend.as_deref()) {
            eprintln!(
                "SKIP conformance_probes[{}]: exec backend {} only supports same-ISA arm64 guests",
                lane.label,
                requested_exec_backend.as_deref().unwrap_or("default")
            );
            continue;
        }
        if !lane_runnable_here(lane) {
            eprintln!(
                "SKIP conformance_probes[{}]: host ({}) cannot run {} guests \
                 (no cross-ISA execution; Rosetta absent for amd64-on-macOS)",
                lane.label,
                std::env::consts::ARCH,
                lane.platform
            );
            continue;
        }
        // Each lane runs its probe suite once per libc flavour (musl, gnu): the
        // matrix. The gnu set is report-only (non-gating) until its glibc-path
        // gaps are triaged; the musl set gates — but only where carrick runs the
        // guest natively (set_gates_here): the macOS amd64-via-Rosetta lane is
        // report-only because Rosetta, not carrick, is translating it.
        for set in lane.probe_sets {
            // Set-level gating (whole-set intent-gating native ISA) drives the
            // report-only SUMMARY; individual probes additionally gate via the
            // per-probe `probe_gates` allowlist below (so a curated x86 subset can
            // gate while the rest of the bring-up lane stays report-only).
            let set_gates = set_gates_here(lane, set);
            let dir = probe_campaign_dir(set.target, requested_exec_backend.as_deref());
            if !dir.exists() {
                eprintln!(
                    "SKIP conformance_probes[{}:{}]: probes not built ({})",
                    lane.label,
                    set.libc,
                    dir.display()
                );
                continue;
            }

            let probes: Vec<PathBuf> = probe_binaries_in(&dir)
                .into_iter()
                .filter(|p| {
                    p.file_name()
                        .and_then(|n| n.to_str())
                        // Exclude gate-skip probes AND the perf_* benchmark probes:
                        // perf_* print non-deterministic timing (MB/s, us) consumed
                        // by the perf gate (tests/perf_runner.rs); they live in
                        // src/bin/ only to share build-probes.sh and have no place in
                        // a differential CORRECTNESS diff (their output never matches).
                        .map(|n| !GATE_SKIP_PROBES.contains(&n) && !n.starts_with("perf_"))
                        .unwrap_or(true)
                })
                .collect();
            if probes.is_empty() {
                eprintln!(
                    "SKIP conformance_probes[{}:{}]: no probe binaries in {}",
                    lane.label,
                    set.libc,
                    dir.display()
                );
                continue;
            }

            // Fan the probes out across a bounded worker pool — each case is now
            // hermetic (own run id + own host-fs scratch), so the only shared resources
            // are the Docker daemon and the host CPUs. Cap at min(cores-2, 8) to avoid
            // saturating the Docker LinuxKit VM. Timing-sensitive probes are quarantined
            // to a serial tail to keep them off the contended path.
            let (quarantine, parallel): (Vec<PathBuf>, Vec<PathBuf>) =
                probes.into_iter().partition(|p| is_timing_sensitive(p));
            let transport = probe_transport(requested_exec_backend.as_deref(), set.libc);

            let n_workers = std::thread::available_parallelism()
                .map(|n| n.get().saturating_sub(2).clamp(1, 8))
                .unwrap_or(4);

            // TWO PHASES so the HVF runtime under test NEVER runs concurrently with
            // the Docker LinuxKit VM (the oracle): mixing them starves both and skews
            // timing-sensitive probe results. Phase 1 fans out ALL carrick runs
            // (carrick||carrick is fine — that's the gate's speed win); phase 2 then
            // fans out ALL Docker runs (docker||docker, same VM cap); phase 3 is pure
            // classification. carrick and docker are thus disjoint in time.
            use base64::Engine as _;
            let engine = base64::engine::general_purpose::STANDARD;
            let jobs: Vec<(String, std::io::Result<Vec<u8>>)> = parallel
                .iter()
                .map(|p| {
                    let name = p
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("<unknown>")
                        .to_string();
                    (
                        name,
                        std::fs::read(p).map(|raw| engine.encode(&raw).into_bytes()),
                    )
                })
                .collect();

            // Phase 1 — carrick only.
            let carrick_outs: Vec<Option<String>> = fan_out_indexed(jobs.len(), n_workers, |i| {
                jobs[i].1.as_ref().ok().map(|enc| match transport {
                    ProbeTransport::ContainerInjection => run_carrick_probe(&bin, *lane, enc),
                    ProbeTransport::DirectElf => {
                        run_carrick_bound_probe(&bin, *lane, &parallel[i], CASE_DEADLINE)
                    }
                })
            });
            // Phase 2 — oracle, strictly after phase 1 (carrick and Docker never
            // overlap). Prefer the committed cache (no Docker); else live Docker on a
            // miss/stale entry; else Unblessed (no Docker + no cache → can't gate it).
            let oracle_outs: Vec<Option<OracleSource>> =
                fan_out_indexed(jobs.len(), n_workers, |i| {
                    jobs[i].1.as_ref().ok().map(|enc| {
                        let name = &jobs[i].0;
                        if let Some(cached) = cached_probe_oracle(lane.label, set.libc, name) {
                            OracleSource::Cached(cached)
                        } else if docker_available {
                            OracleSource::Live(run_docker_probe(*lane, enc))
                        } else {
                            OracleSource::Unblessed
                        }
                    })
                });
            // Phase 3 — classify (runs nothing).
            let mut results: Vec<(String, ProbeOutcome)> = Vec::new();
            for ((name, enc), (carrick_out, oracle)) in jobs
                .into_iter()
                .zip(carrick_outs.into_iter().zip(oracle_outs))
            {
                let outcome = match (enc, oracle) {
                    (Err(e), _) => (name, ProbeOutcome::Error(format!("read probe: {e}"))),
                    (Ok(_), Some(OracleSource::Unblessed)) | (Ok(_), None) => {
                        eprintln!(
                            "SKIP {}:{}:{name} (no cached oracle + no Docker — bless on a Docker host)",
                            lane.label, set.libc
                        );
                        unblessed.push(format!("{}:{}:{name}", lane.label, set.libc));
                        continue;
                    }
                    (Ok(_), Some(src)) => {
                        let docker_out = match src {
                            OracleSource::Cached(c) => Ok(c),
                            OracleSource::Live(r) => r,
                            OracleSource::Unblessed => Ok(String::new()),
                        };
                        classify_probe(
                            name,
                            lane.label,
                            &carrick_out.unwrap_or_default(),
                            docker_out,
                        )
                    }
                };
                results.push(outcome);
            }

            // Quarantined (timing-sensitive) probes: serial, after the fan-out — each
            // is carrick THEN docker, one at a time, so already non-overlapping. Their
            // output is non-deterministic → NOT cached, so where Docker is absent they
            // can't be gated and are loudly skipped.
            for probe in &quarantine {
                if docker_available {
                    results.push(run_one_probe(&bin, *lane, probe, transport));
                } else {
                    let name = probe
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("<unknown>");
                    eprintln!(
                        "SKIP {}:{}:{name} (timing-sensitive; needs a live Docker oracle)",
                        lane.label, set.libc
                    );
                    unblessed.push(format!("{}:{}:{name}", lane.label, set.libc));
                }
            }
            results.sort_by(|a, b| a.0.cmp(&b.0)); // deterministic report order

            let mut set_diffs = 0usize;
            for (name, outcome) in &results {
                let qualified = format!("{}:{}:{name}", lane.label, set.libc);
                // Per-probe gating: the whole set may be report-only while a
                // curated x86 subset (X86_GATING_PROBES) still gates.
                let gates = probe_gates(lane, set, name);
                match outcome {
                    ProbeOutcome::Pass => eprintln!("PASS {qualified}"),
                    ProbeOutcome::UnexpectedPass => {
                        // A known-gap probe started passing → the gap is fixed.
                        // Only a GATING probe asserts: remove it from
                        // KNOWN_PROBE_GAPS. (report-only probes don't.)
                        eprintln!(
                            "UNEXPECTED PASS {qualified} (remove from KNOWN_PROBE_GAPS / KNOWN_LANE_GAPS)"
                        );
                        if gates {
                            fixed_gaps.push(qualified);
                        }
                    }
                    ProbeOutcome::Fail(diff) => {
                        if gates {
                            eprintln!("FAIL {qualified}\n{diff}");
                            failures.push(qualified);
                        } else {
                            // Report-only DIFF (gnu set, or amd64-via-Rosetta on
                            // macOS): surface it as a gap to triage, but do NOT
                            // fail the gate yet.
                            set_diffs += 1;
                            eprintln!(
                                "DIFF {qualified} (report-only — ABI/Rosetta gap to triage)\n{diff}"
                            );
                            nongating_diffs.push(qualified);
                        }
                    }
                    ProbeOutcome::Xfail(diff) => eprintln!("XFAIL {qualified} (known gap)\n{diff}"),
                    ProbeOutcome::Error(e) => {
                        if gates {
                            eprintln!("FAIL {qualified} ({e})");
                            failures.push(qualified);
                        } else {
                            set_diffs += 1;
                            eprintln!("DIFF {qualified} (report-only — error: {e})");
                            nongating_diffs.push(qualified);
                        }
                    }
                }
            }
            if !set_gates {
                eprintln!(
                    "SUMMARY {}:{} (report-only): {}/{} probes DIFF from Linux",
                    lane.label,
                    set.libc,
                    set_diffs,
                    results.len()
                );
            }
        }
    }
    if !nongating_diffs.is_empty() {
        eprintln!(
            "NOTE {} report-only (gnu) probe DIFFs — glibc-path gaps to triage (non-gating): {nongating_diffs:?}",
            nongating_diffs.len()
        );
    }
    if !unblessed.is_empty() {
        eprintln!(
            "NOTE {} probe(s) had no cached oracle and no Docker — not gated this run; \
             bless them on a Docker host (`-- --ignored bless_probe_oracle`): {unblessed:?}",
            unblessed.len()
        );
    }
    assert!(
        fixed_gaps.is_empty(),
        "known-gap probes now PASS — remove from KNOWN_PROBE_GAPS / KNOWN_LANE_GAPS: {fixed_gaps:?}"
    );
    assert!(failures.is_empty(), "probe conformance gaps: {failures:?}");
}

#[test]
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn native_conformance_container_executes_libc_probe() {
    let _serial = CONFORMANCE_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let Some(bin) = carrick_bin() else {
        eprintln!(
            "SKIP native_conformance_container_executes_libc_probe: target/release/carrick not built"
        );
        return;
    };
    ensure_signed(&bin);

    let probe = ensure_native_static_pie_probe("devnullseek");

    use base64::Engine as _;
    let engine = base64::engine::general_purpose::STANDARD;
    let encoded = engine
        .encode(std::fs::read(&probe).expect("read native libc probe"))
        .into_bytes();
    for profile in ["native16k", "linux4k"] {
        let out =
            run_carrick_probe_with_backend(&bin, ARM64, &encoded, CASE_DEADLINE, "native", profile);
        assert!(
            out.contains("devnull_lseek_cur0=true")
                && out.contains("devnull_lseek_set=true")
                && !out.contains("unsupported in this backend")
                && !out.contains("no HVF fallback was attempted"),
            "native container libc probe failed for profile {profile}:\n{out}"
        );
    }
}

#[test]
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn native_conformance_run_elf_executes_smoke_probe() {
    let _serial = CONFORMANCE_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let Some(bin) = carrick_bin() else {
        eprintln!(
            "SKIP native_conformance_run_elf_executes_smoke_probe: target/release/carrick not built"
        );
        return;
    };
    ensure_signed(&bin);
    let probe = ensure_native_smoke_probe();

    for profile in ["native16k", "linux4k"] {
        let out = run_native_run_elf(&bin, &probe, profile);
        assert!(
            out.contains("status=exit status: 0")
                && out.contains("native-smoke: ok")
                && !out.contains("no HVF fallback was attempted"),
            "native run-elf smoke probe failed for profile {profile}:\n{out}"
        );
    }
}

#[test]
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn native_conformance_run_elf_executes_libc_probe() {
    let _serial = CONFORMANCE_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let Some(bin) = carrick_bin() else {
        eprintln!(
            "SKIP native_conformance_run_elf_executes_libc_probe: target/release/carrick not built"
        );
        return;
    };
    ensure_signed(&bin);
    let probe = ensure_native_static_pie_probe("devnullseek");

    for profile in ["native16k", "linux4k"] {
        let out = run_native_run_elf(&bin, &probe, profile);
        assert!(
            out.contains("status=exit status: 0")
                && out.contains("devnull_lseek_cur0=true")
                && out.contains("devnull_lseek_set=true")
                && !out.contains("no HVF fallback was attempted"),
            "native run-elf libc probe failed for profile {profile}:\n{out}"
        );
    }
}

#[test]
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn native_conformance_rejects_fixed_et_exec_below_hard_pagezero() {
    let _serial = CONFORMANCE_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let Some(bin) = carrick_bin() else {
        eprintln!(
            "SKIP native_conformance_rejects_fixed_et_exec_below_hard_pagezero: target/release/carrick not built"
        );
        return;
    };
    ensure_signed(&bin);
    let probe = ensure_native_et_exec_probe("devnullseek");

    for profile in ["native16k", "linux4k"] {
        let out = run_native_run_elf(&bin, &probe, profile);
        assert!(
            out.contains("status=exit status: 125")
                && out.contains("hard 4 GiB __PAGEZERO")
                && out.contains("PIE/ET_DYN"),
            "native fixed ET_EXEC rejection was not typed for profile {profile}:\n{out}"
        );
    }
}

#[test]
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn native_conformance_preserves_x18_across_guarded_load() {
    let _serial = CONFORMANCE_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let Some(bin) = carrick_bin() else {
        eprintln!(
            "SKIP native_conformance_preserves_x18_across_guarded_load: target/release/carrick not built"
        );
        return;
    };
    ensure_signed(&bin);
    let probe = ensure_native_static_pie_probe("nativex18");

    for profile in ["native16k", "linux4k"] {
        let out = run_native_run_elf(&bin, &probe, profile);
        assert!(
            out.contains("status=exit status: 0")
                && out.contains("setup_ok=true")
                && out.contains("guarded_load_ok=true")
                && out.contains("x18_preserved=true"),
            "native x18 preservation failed for profile {profile}:\n{out}"
        );
    }
}

#[test]
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn native_conformance_run_elf_preserves_ip0_across_syscalls() {
    let _serial = CONFORMANCE_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let Some(bin) = carrick_bin() else {
        eprintln!(
            "SKIP native_conformance_run_elf_preserves_ip0_across_syscalls: target/release/carrick not built"
        );
        return;
    };
    ensure_signed(&bin);
    let probe = ensure_native_static_pie_probe("bigallocfree");

    for profile in ["native16k", "linux4k"] {
        for attempt in 1..=5 {
            let out = run_native_run_elf(&bin, &probe, profile);
            assert!(
                out.contains("status=exit status: 0")
                    && out.contains("bigalloc=loop-done")
                    && out.contains("bigalloc=OK"),
                "native run-elf bigallocfree failed for profile {profile} attempt {attempt}:\n{out}"
            );
        }
    }
}

#[test]
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn native_conformance_run_elf_supports_plain_fork_probe() {
    let _serial = CONFORMANCE_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let Some(bin) = carrick_bin() else {
        eprintln!(
            "SKIP native_conformance_run_elf_supports_plain_fork_probe: target/release/carrick not built"
        );
        return;
    };
    ensure_signed(&bin);
    let probe = ensure_native_static_pie_probe("mapfixed");

    for profile in ["native16k", "linux4k"] {
        let out = run_native_run_elf(&bin, &probe, profile);
        assert!(
            out.contains("status=exit status: 0")
                && out.contains("setup_ok=true")
                && out.contains("child_map_fixed_ok=true")
                && out.contains("parent_value_preserved=true")
                && out.contains("parent_clobbered_by_child=false"),
            "native run-elf mapfixed fork probe failed for profile {profile}:\n{out}"
        );
    }
}

#[test]
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn native_conformance_run_elf_supports_sysv_message_wakes() {
    let _serial = CONFORMANCE_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let Some(bin) = carrick_bin() else {
        eprintln!(
            "SKIP native_conformance_run_elf_supports_sysv_message_wakes: target/release/carrick not built"
        );
        return;
    };
    ensure_signed(&bin);
    let probe = ensure_native_static_pie_probe("sysvmsgwake");

    for profile in ["native16k", "linux4k"] {
        let out = run_native_run_elf(&bin, &probe, profile);
        assert!(
            out.contains("status=exit status: 0")
                && out.contains("nowait_empty_enomsg=true")
                && out.contains("nowait_full_eagain=true")
                && out.contains("fork_reader_wakes_sender=true")
                && out.contains("rmid_wakes_receiver=true"),
            "native run-elf SysV message wake probe failed for profile {profile}:\n{out}"
        );
    }
}

#[test]
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn native_conformance_run_elf_rounds_sysv_shm_to_page_profile() {
    let _serial = CONFORMANCE_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let Some(bin) = carrick_bin() else {
        eprintln!(
            "SKIP native_conformance_run_elf_rounds_sysv_shm_to_page_profile: target/release/carrick not built"
        );
        return;
    };
    ensure_signed(&bin);
    let probe = ensure_native_static_pie_probe("sysvshm");

    for profile in ["native16k", "linux4k"] {
        let out = run_native_run_elf(&bin, &probe, profile);
        assert!(
            out.contains("status=exit status: 0")
                && out.contains("null_attach_ok=true")
                && out.contains("aligned_attach_ok=true")
                && out.contains("child_aligned_status=0")
                && out.contains("rounded_attach_ok=true")
                && out.contains("readonly_signal=11"),
            "native run-elf SysV shared-memory probe failed for profile {profile}:\n{out}"
        );
    }
}

#[test]
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn native16k_conformance_waits_publish_sleeping_state() {
    let _serial = CONFORMANCE_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let Some(bin) = carrick_bin() else {
        eprintln!(
            "SKIP native16k_conformance_waits_publish_sleeping_state: target/release/carrick not built"
        );
        return;
    };
    ensure_signed(&bin);

    let procstat = run_native_run_elf(
        &bin,
        &ensure_native_static_pie_probe("procstatstate"),
        "native16k",
    );
    assert!(
        procstat.contains("status=exit status: 0")
            && procstat.contains("child_state=S")
            && procstat.contains("child_state_is_sleeping=true")
            && procstat.contains("child_reaped=true"),
        "native16k shared-futex wait did not publish sleeping state:\n{procstat}"
    );

    let pause = run_native_run_elf_with_args(
        &bin,
        &ensure_native_static_pie_probe("pauseinterrupt2"),
        "native16k",
        &["--report-state"],
    );
    assert!(
        pause.contains("status=exit status: 0")
            && pause.contains("child_state=S")
            && pause.contains("child_sleeping=true")
            && pause.contains("send_sigint_ok=true")
            && pause.contains("child_exit_zero=true")
            && pause.contains("child_not_signaled=true"),
        "native16k signal wait did not publish sleeping state:\n{pause}"
    );
}

#[test]
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn native_conformance_rejects_readonly_syscall_output() {
    let _serial = CONFORMANCE_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let Some(bin) = carrick_bin() else {
        eprintln!(
            "SKIP native_conformance_rejects_readonly_syscall_output: target/release/carrick not built"
        );
        return;
    };
    ensure_signed(&bin);

    let probe = ensure_native_static_pie_probe("epollcluster");
    for profile in ["native16k", "linux4k"] {
        let output = run_native_run_elf(&bin, &probe, profile);
        assert!(
            output.contains("status=exit status: 0")
                && output.contains("rodata_events_errno=14")
                && output.contains("mmap_ro_events_errno=14"),
            "{profile} epoll output buffers did not enforce ELF and mmap read-only state:\n{output}"
        );
    }
}

#[test]
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn native_conformance_run_elf_supports_clone_child_stack() {
    let _serial = CONFORMANCE_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let Some(bin) = carrick_bin() else {
        eprintln!(
            "SKIP native_conformance_run_elf_supports_clone_child_stack: target/release/carrick not built"
        );
        return;
    };
    ensure_signed(&bin);
    let probe = ensure_native_static_pie_probe("clonestack");

    for profile in ["native16k", "linux4k"] {
        let out = run_native_run_elf(&bin, &probe, profile);
        assert!(
            out.contains("status=exit status: 0")
                && out.contains("clone_ok=true")
                && out.contains("wait_ok=true")
                && out.contains("child_exit_42=true"),
            "native run-elf clonestack probe failed for profile {profile}:\n{out}"
        );
    }
}

/// Bless the probe-oracle cache: capture each DETERMINISTIC probe's Docker
/// output once and commit it under `probe-oracle/`, so routine gates run
/// carrick-only and Docker-less hosts (FreeBSD/bhyve) can gate at all. Runs NO
/// carrick (Docker only), so it is safe to bless on any Docker host without the
/// HVF guest churn of a full gate. `#[ignore]` — run deliberately:
///   cargo test -p carrick-cli --test conformance <platform features> -- \
///       --ignored bless_probe_oracle --nocapture
/// then `git add crates/carrick-cli/tests/probe-oracle && git commit`.
#[test]
#[ignore = "bless step: writes the committed probe-oracle cache from live Docker"]
fn bless_probe_oracle() {
    let _serial = CONFORMANCE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    use base64::Engine as _;
    let engine = base64::engine::general_purpose::STANDARD;

    let docker_available = Command::new("docker")
        .arg("version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    assert!(
        docker_available,
        "bless_probe_oracle needs a reachable Docker daemon (DOCKER_HOST honoured)"
    );

    let mut blessed = 0usize;
    for lane in LANES {
        for set in lane.probe_sets {
            if !probes_dir(set.target).exists() {
                continue;
            }
            for probe in probe_binaries(set.target) {
                let Some(name) = probe
                    .file_name()
                    .and_then(|n| n.to_str())
                    .map(str::to_string)
                else {
                    continue;
                };
                // Non-deterministic probes can't be cached.
                if GATE_SKIP_PROBES.contains(&name.as_str())
                    || name.starts_with("perf_")
                    || is_timing_sensitive(&probe)
                {
                    continue;
                }
                let Ok(raw) = std::fs::read(&probe) else {
                    continue;
                };
                let encoded = engine.encode(&raw).into_bytes();
                match run_docker_probe(*lane, &encoded) {
                    Ok(out) => {
                        write_probe_oracle(lane.label, set.libc, &name, &out)
                            .expect("write probe oracle");
                        blessed += 1;
                        eprintln!("BLESSED {}:{}:{name}", lane.label, set.libc);
                    }
                    Err(e) => eprintln!(
                        "SKIP-BLESS {}:{}:{name} (docker error: {e})",
                        lane.label, set.libc
                    ),
                }
            }
        }
    }
    eprintln!("bless_probe_oracle: wrote {blessed} probe oracle(s)");
}

#[test]
fn probe_oracle_entry_roundtrip() {
    // The on-disk entry is `<src_hash>\n<output>`; reading splits at the FIRST
    // newline, so an output that itself contains newlines round-trips exactly.
    let output = "first\nsecond  \n\nfourth";
    let entry = format!("{}\n{output}", "deadbeefcafe0000");
    let (hash_line, body) = entry.split_once('\n').expect("entry has a hash line");
    assert_eq!(hash_line, "deadbeefcafe0000");
    assert_eq!(body, output);
    // A probe with no source file gets the stable sentinel hash.
    assert_eq!(probe_src_hash("__definitely_not_a_real_probe__"), "nosrc");
}

#[test]
fn cached_probe_oracle_output_is_normalized() {
    let cached = cached_probe_oracle("arm64", "musl", "syscallregpreserve")
        .expect("shipped syscallregpreserve oracle matches its source");
    assert_eq!(cached, normalize(&cached));
}

#[test]
fn probe_gates_decision_allowlist_logic() {
    // A set that already gates (native ISA, intent-gating) gates every probe,
    // regardless of allowlist / host.
    assert!(probe_gates_decision(true, false, false));
    assert!(probe_gates_decision(true, true, true));
    // A report-only set gates an INDIVIDUAL probe iff it is allowlisted AND the
    // host runs the x86_64 guest natively (carrick-x86 is under test).
    assert!(probe_gates_decision(false, true, true));
    // Allowlisted but not native (e.g. amd64-via-Rosetta on macOS) -> no gate.
    assert!(!probe_gates_decision(false, false, true));
    // Native but not allowlisted -> stays report-only (the ~34 bring-up gaps).
    assert!(!probe_gates_decision(false, true, false));
    // Neither -> report-only.
    assert!(!probe_gates_decision(false, false, false));
    // The shipped allowlist is intentionally empty until fleet confirmation, so
    // a sample probe does not gate the amd64 lane by allowlist alone today.
    assert!(!probe_gates_decision(
        false,
        true,
        X86_GATING_PROBES.contains(&"icmp")
    ));
}

#[test]
fn native_probe_campaign_selects_only_same_isa_lane() {
    assert!(lane_allowed_for_backend(&ARM64, Some("native")));
    assert!(!lane_allowed_for_backend(&AMD64, Some("native")));
    assert!(lane_allowed_for_backend(&ARM64, Some("hvf")));
    assert!(lane_allowed_for_backend(&AMD64, None));
}

#[test]
fn native_probe_campaign_uses_pie_artifacts() {
    assert!(
        probe_campaign_dir("aarch64-unknown-linux-musl", Some("native"))
            .ends_with("conformance-probes/target/native-pie/aarch64-unknown-linux-musl/release")
    );
    assert!(
        probe_campaign_dir("aarch64-unknown-linux-musl", None)
            .ends_with("conformance-probes/target/aarch64-unknown-linux-musl/release")
    );
}

#[test]
fn native_musl_probe_campaign_uses_direct_elf_transport() {
    assert_eq!(
        probe_transport(Some("native"), "musl"),
        ProbeTransport::DirectElf
    );
    assert_eq!(
        probe_transport(Some("native"), "gnu"),
        ProbeTransport::ContainerInjection
    );
    assert_eq!(
        probe_transport(Some("hvf"), "musl"),
        ProbeTransport::ContainerInjection
    );
}

#[test]
fn excused_probe_outcome_fingerprint_guard() {
    // FNV-1a is stable & deterministic for a given input.
    let carrick_side = "line1\nline2\n";
    let fp = carrick_side_fingerprint(carrick_side);
    assert_eq!(fp, carrick_side_fingerprint(carrick_side), "deterministic");

    // No recorded fingerprint -> legacy Xfail-any-diff (conservative default).
    assert!(matches!(
        excused_probe_outcome("d".into(), None, carrick_side),
        ProbeOutcome::Xfail(_)
    ));
    // Recorded fingerprint MATCHES the live carrick output -> still Xfail (the
    // SAME, already-triaged divergence).
    assert!(matches!(
        excused_probe_outcome("d".into(), Some(fp.as_str()), carrick_side),
        ProbeOutcome::Xfail(_)
    ));
    // Recorded fingerprint does NOT match (the carrick-side output changed) -> a
    // new regression hiding behind the excuse, so FAIL not Xfail.
    assert!(matches!(
        excused_probe_outcome("d".into(), Some("0000000000000000"), carrick_side),
        ProbeOutcome::Fail(_)
    ));
    // A different carrick output produces a different fingerprint.
    assert_ne!(fp, carrick_side_fingerprint("line1\nDIFFERENT\n"));
}

#[test]
fn excuse_fingerprint_lookup_misses_when_unrecorded() {
    // The shipped table is empty (fleet-population pending), so every lookup
    // currently misses -> excuses fall back to the legacy Xfail-any-diff path.
    assert_eq!(excuse_fingerprint("amd64", "icmp"), None);
    assert_eq!(excuse_fingerprint("arm64", "uname_m"), None);
}

#[test]
fn conformance_go_fixture() {
    let _serial = CONFORMANCE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    use base64::Engine as _;

    let Some(bin) = carrick_bin() else {
        eprintln!("SKIP conformance_go_fixture: target/release/carrick not built");
        return;
    };
    // The fixture is an aarch64 Go binary run under the ARM64 lane; on an
    // x86_64 host carrick can't execute aarch64 guests (no cross-ISA), so skip
    // rather than error on the unsupported ELF machine.
    if !lane_runnable_here(&ARM64) {
        eprintln!(
            "SKIP conformance_go_fixture: host ({}) cannot run aarch64 guests",
            std::env::consts::ARCH
        );
        return;
    }

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

    let carrick_out = run_carrick_probe(&bin, ARM64, &encoded);
    let docker_out = match run_docker_probe(ARM64, &encoded) {
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
