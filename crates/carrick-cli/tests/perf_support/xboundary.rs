//! Cross-boundary network test: a macOS-HOST client (`perf_net_xclient`)
//! connects to a GUEST echo server (`perf_net_xserver`) exposed to the host —
//! carrick's real Darwin socket (directly reachable, no publish) vs Docker's
//! `-p`/vpnkit NAT across the VM boundary, vs a native host-to-host server as
//! the ceiling. The metric is measured HOST-side by the client; the server (the
//! engine under test) is CPU-pinned. This is a fundamentally different shape
//! than the self-contained probes, so it lives here and is dispatched from
//! `perf_gate` for `cross_boundary` cases.
//!
//! Per rep, per engine: start the server (engine-specific launch) → poll-connect
//! until the port is open → run the native client (it times RTT + stream) → tear
//! the server down. carrick and Docker are still strictly serial (one server at
//! a time), preserving the never-co-run rule.
use super::cases::PerfCase;
use super::metric::Metrics;
use super::provenance::{self, HostFacts, ResultRow};
use super::stats::{self, Summary};
use std::io::Write;
use std::net::TcpStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

const PLATFORM: &str = "linux/arm64";
const IMAGE: &str = "docker.io/library/ubuntu:24.04";
const CPU_PIN: u32 = 4;

static SEQ: AtomicU64 = AtomicU64::new(0);

fn server_snippet(port: u16) -> String {
    format!("export PORT={port}; base64 -d > /tmp/s && chmod +x /tmp/s && /tmp/s")
}

/// Poll-connect to 127.0.0.1:port until success or timeout.
fn wait_ready(port: u16, timeout: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(150));
    }
    false
}

fn feed_stdin(child: &mut Child, bytes: &[u8]) {
    if let Some(mut stdin) = child.stdin.take() {
        let bytes = bytes.to_vec();
        std::thread::spawn(move || {
            let _ = stdin.write_all(&bytes);
        });
    }
}

/// A running server + the handles needed to tear it down.
struct Server {
    child: Child,
    run_id: Option<String>,      // carrick: for scoped_kill_guests
    docker_name: Option<String>, // docker: for `docker rm -f`
}

fn start_server(
    engine: &str,
    bin: &PathBuf,
    native_server: &Path,
    server_b64: &[u8],
    port: u16,
) -> Option<Server> {
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    match engine {
        "macos" => {
            // process_group(0) is ESSENTIAL: the native server is an unconditional
            // accept loop (`runs until killed`), and stop_server reaps it with
            // `kill(-pid)`. Without its own group it inherits the test runner's
            // pgid, kill(-childpid) hits a nonexistent group (ESRCH), the server
            // never dies, and child.wait() deadlocks forever. carrick/docker set
            // this for the same reason — macos must too.
            let child = Command::new(native_server)
                .env("PORT", port.to_string())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .process_group(0)
                .spawn()
                .ok()?;
            Some(Server {
                child,
                run_id: None,
                docker_name: None,
            })
        }
        "carrick" => {
            let run_id = format!("cr-xb-{}-{}", std::process::id(), seq);
            let mut child = Command::new(bin)
                .args([
                    "run",
                    "--platform",
                    PLATFORM,
                    "--raw",
                    "--fs",
                    "host",
                    IMAGE,
                    "/bin/sh",
                    "-c",
                    &server_snippet(port),
                ])
                .env("CARRICK_RUN_ID", &run_id)
                .env("CARRICK_EXPOSED_CPUS", CPU_PIN.to_string())
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .process_group(0)
                .spawn()
                .ok()?;
            feed_stdin(&mut child, server_b64);
            Some(Server {
                child,
                run_id: Some(run_id),
                docker_name: None,
            })
        }
        "docker" => {
            let name = format!("carrick-xb-{}-{}", std::process::id(), seq);
            let mut child = Command::new("docker")
                .args([
                    "run",
                    "-i",
                    "--rm",
                    "--name",
                    &name,
                    "-p",
                    &format!("127.0.0.1:{port}:{port}"),
                    "--cpuset-cpus",
                    "0-3",
                    "--platform",
                    PLATFORM,
                    IMAGE,
                    "/bin/sh",
                    "-c",
                    &server_snippet(port),
                ])
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .process_group(0)
                .spawn()
                .ok()?;
            feed_stdin(&mut child, server_b64);
            Some(Server {
                child,
                run_id: None,
                docker_name: Some(name),
            })
        }
        _ => None,
    }
}

fn stop_server(root: &Path, mut server: Server) {
    // Kill the launched process group, then engine-specific cleanup. Send to the
    // group (all three engines set process_group(0)) AND to the direct child —
    // belt-and-suspenders so a future engine spawned without its own group can
    // never re-deadlock child.wait() on an unkilled accept loop.
    let pid = server.child.id() as i32;
    unsafe {
        libc::kill(-pid, libc::SIGKILL);
        libc::kill(pid, libc::SIGKILL);
    }
    let _ = server.child.wait();
    if let Some(run_id) = &server.run_id {
        let _ = Command::new("sudo")
            .arg("-n")
            .arg(root.join("scripts/sudo/kill.sh"))
            .arg(run_id)
            .output();
    }
    if let Some(name) = &server.docker_name {
        // The CLI kill does NOT stop the daemon-side container; remove it.
        let _ = Command::new("docker").args(["rm", "-f", name]).output();
    }
    // Give the kernel a moment to release the listen port before the next rep.
    std::thread::sleep(Duration::from_millis(300));
}

fn run_client(client: &Path, port: u16) -> Option<Metrics> {
    let out = Command::new(client)
        .env("PORT", port.to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .ok()?;
    let mut s = String::from_utf8_lossy(&out.stdout).into_owned();
    s.push_str(&String::from_utf8_lossy(&out.stderr));
    Some(Metrics::parse(&s))
}

/// Measure a cross-boundary case across native/carrick/docker, append rows, and
/// return them. `date` is YYYY-MM-DD for the JSONL filename.
#[allow(clippy::too_many_arguments)]
pub fn run_cross_boundary(
    root: &Path,
    bin: &PathBuf,
    case: &PerfCase,
    reps: usize,
    warm: usize,
    cooldown: Duration,
    date: &str,
) -> Vec<ResultRow> {
    use base64::Engine as _;
    let server_probe = root.join(format!(
        "conformance-probes/target/aarch64-unknown-linux-musl/release/{}",
        case.probe
    ));
    let server_b64 = base64::engine::general_purpose::STANDARD
        .encode(std::fs::read(&server_probe).expect("read server probe"))
        .into_bytes();
    let native_server = root.join("bench-native/target/release/perf_net_xserver");
    let client = root.join("bench-native/target/release/perf_net_xclient");

    let host = HostFacts::capture();
    let sha = provenance::git_sha();
    let digest = provenance::image_digest(IMAGE);

    // (engine, lane, base port). Distinct port ranges so a TIME_WAIT from one
    // rep never blocks the next bind.
    let engines: [(&str, &str, u16); 3] = [
        ("macos", "native", 5700),
        ("carrick", "cold", 5800),
        ("docker", "docker", 5900),
    ];

    let mut rows: Vec<ResultRow> = Vec::new();
    for (engine, lane, base_port) in engines {
        let mut vals: Vec<f64> = Vec::new();
        let mut nproc: Option<u64> = None;
        for rep in 0..reps {
            let port = base_port + rep as u16;
            let m = match start_server(engine, bin, &native_server, &server_b64, port) {
                Some(server) => {
                    let ready = wait_ready(port, Duration::from_secs(12));
                    let m = if ready {
                        run_client(&client, port)
                    } else {
                        None
                    };
                    stop_server(root, server);
                    if !ready {
                        eprintln!(
                            "xbound[{}] {engine} rep {rep}: server never became ready on :{port}",
                            case.workload
                        );
                    }
                    m
                }
                None => None,
            };
            if let Some(m) = &m {
                nproc = m.get_u64("nproc").or(nproc);
                if rep >= warm
                    && let Some(v) = m.get_f64(case.metric_key)
                {
                    vals.push(v);
                }
            }
            eprintln!(
                "xbound[{}] {engine} rep {rep}/{reps}: {}={:?}",
                case.workload,
                case.metric_key,
                m.as_ref().and_then(|m| m.get_f64(case.metric_key))
            );
            std::thread::sleep(cooldown);
        }
        if vals.is_empty() {
            eprintln!(
                "xbound[{}] {engine}: no samples — skipping row",
                case.workload
            );
            continue;
        }
        let s: Summary = stats::summarize(&vals).expect("non-empty");
        let native = engine == "macos";
        rows.push(ResultRow {
            schema: 2,
            epoch_secs: provenance::epoch_secs(),
            dimension: case.dimension.into(),
            workload: case.workload.into(),
            engine: engine.into(),
            lane: lane.into(),
            metric: case.metric_key.into(),
            unit: case.unit.into(),
            higher_is_better: case.higher_is_better,
            summary: s,
            samples: vals.clone(),
            noisy: stats::is_noisy(&s),
            nproc,
            // The server is pinned to CPU_PIN (carrick/docker); the host client
            // is native. cpu_pin records the server pin (0 for native).
            cpu_pin: if native { 0 } else { CPU_PIN },
            fs_mode: "cross-boundary".into(),
            image: if native {
                "(native macos host)".into()
            } else {
                IMAGE.into()
            },
            image_digest: if native { None } else { digest.clone() },
            git_sha: sha.clone(),
            run_id: format!("cr-perf-{}", std::process::id()),
            host: host.clone(),
        });
    }

    // Direction-aware report (find engines by name; macos may be absent).
    let p50 = |e: &str| rows.iter().find(|r| r.engine == e).map(|r| r.summary.p50);
    let (cp, dp, np) = (p50("carrick"), p50("docker"), p50("macos"));
    for r in &rows {
        provenance::append_row(root, date, r).expect("append row");
        eprintln!(
            "xbound[{}] {} {}={:.3}{} p95={:.3} (n={}){}",
            case.workload,
            r.engine,
            r.metric,
            r.summary.p50,
            r.unit,
            r.summary.p95,
            r.summary.n,
            if r.noisy { " NOISY" } else { "" }
        );
    }
    if let (Some(c), Some(d)) = (cp, dp) {
        let winner_is_carrick = if case.higher_is_better {
            c >= d
        } else {
            c <= d
        };
        let factor = c.max(d) / c.min(d).max(f64::MIN_POSITIVE);
        eprintln!(
            "xbound[{}] WINNER={} ({factor:.2}x {}){}",
            case.workload,
            if winner_is_carrick {
                "carrick"
            } else {
                "docker"
            },
            if case.higher_is_better {
                "throughput"
            } else {
                "latency"
            },
            np.map(|n| format!("  [native ceiling={n:.3}{}]", case.unit))
                .unwrap_or_default()
        );
    }
    rows
}
