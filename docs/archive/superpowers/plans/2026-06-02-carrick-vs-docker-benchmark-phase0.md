# Carrick vs Docker Benchmark — Phase 0 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stand up the reusable differential perf-benchmark framework and produce its first end-to-end result — the marquee **NETWORK TCP_RR** (loopback request/response latency) row, carrick vs Docker, with strict CPU-count normalization and a provenance-stamped JSONL baseline.

**Architecture:** A new Cargo integration-test binary `tests/perf_runner.rs` (sibling to the proven `tests/conformance.rs`) hosts a `perf_gate()` test that reuses the conformance gate's discipline (per-sample `CARRICK_RUN_ID`, `scoped_kill_guests` cleanup, `ensure_signed`, base64-stdin probe injection) but runs **serial adjacent-pair** samples (carrick-then-docker per workload, never a fan-out) so the two numbers feeding the thesis ratio share a thermal state and never run concurrently. The actual latency is measured **in-guest** by a self-timing static-musl probe (`conformance-probes/src/bin/perf_net_tcp_rr.rs`) that prints `key=value` lines; the runner parses them, asserts `nproc==4` on both engines, repeats N reps, and appends a stats+provenance row to `docs/perf-results/`. Pure logic (stats, metric parsing, provenance serialization) lives in unit-tested modules under `tests/perf_support/`; the engine-driving glue is verified by the end-to-end run.

**Tech Stack:** Rust (workspace, edition 2024 host / 2021 probe crate), `std::net`/`std::thread`/`std::time` for the probe, `libc` for affinity, `serde`/`serde_json` for the JSONL store, `bollard`-free Docker invocation via `docker run -i` (matching `run_docker_probe`), `just` + a `scripts/measure-perf.sh` orchestrator. Requires a codesigned carrick (`just build`), Docker Desktop (linux/arm64, VM with ≥4 CPUs), macOS 15+.

---

## Background the engineer needs

- **You cannot run carrick and Docker at the same time during a timed sample** (they fight for perf-cores; see `docs/archive/superpowers/specs/2026-06-02-carrick-vs-docker-benchmark-design.md` §2). This plan's driver is strictly serial — it spawns one engine, waits for full exit, cools down, then the other. Never add a fan-out to a timed path.
- **carrick must be codesigned to run a guest.** `cargo build` strips the hypervisor entitlement → every run fails `HV_DENIED (0xfae94007)`. Build with `just build`; the test also calls `ensure_signed()` as a belt.
- **Probe binaries are static aarch64-musl ELFs** auto-discovered from `conformance-probes/src/bin/*.rs` and built in a container by `scripts/build-probes.sh` to `conformance-probes/target/aarch64-unknown-linux-musl/release/`. Add a probe by dropping a file in `src/bin/` (no Cargo.toml edit).
- **Probe injection path (reused verbatim):** the probe is base64-encoded onto the guest's stdin and decoded+exec'd via `PROBE_SNIPPET = "base64 -d > /tmp/p && chmod +x /tmp/p && /tmp/p"`, under `carrick run --platform linux/arm64 --raw --fs host ubuntu:24.04 /bin/sh -c <snippet>` and `docker run -i --rm --platform linux/arm64 ubuntu:24.04 /bin/sh -c <snippet>`.
- **CPU normalization:** carrick exposes the 4 performance cores; set `CARRICK_EXPOSED_CPUS=4` (read in `crates/carrick-host/src/host_facts.rs:157`). Docker's `--cpus=4` is only a CFS quota and does **not** change `nproc`; use **`--cpuset-cpus=0-3`** so `sched_getaffinity`/`nproc` returns 4 inside the container. We assert count-parity (`nproc==4` on both); we cannot pin Docker's VM vCPUs to physical P-cores — that residual asymmetry is a documented threat-to-validity, not something this phase equalizes.
- **Cargo test-layout rule:** every direct child `tests/*.rs` is compiled as its own test binary; files in **subdirectories** of `tests/` are not. So shared modules live under `tests/perf_support/` and are pulled in via `mod perf_support;` from `tests/perf_runner.rs`. Their `#[cfg(test)]` unit tests run as part of `cargo test --test perf_runner`.
- **No-panic gate exemption:** test code is exempt, but put `#![allow(clippy::unwrap_used, clippy::expect_used)]` at the top of `tests/perf_runner.rs` (matches `conformance.rs:18`). The probe crate is excluded from the workspace lints and uses `panic = "abort"`, so it may `unwrap`.

---

## File structure

| File | Responsibility |
|---|---|
| `conformance-probes/src/bin/perf_net_tcp_rr.rs` | **Create.** In-guest self-timing TCP_RR probe: server+client threads over `127.0.0.1`, times N round-trips with `Instant`, prints `tcp_rr_p50_us=`, `tcp_rr_p95_us=`, `tcp_rr_min_us=`, `rr_iters=`, `nproc=`. |
| `crates/carrick-cli/tests/perf_runner.rs` | **Create.** The `#[test] fn perf_gate()` integration entry: skip-guards, `CONFORMANCE_LOCK`, `ensure_signed`, the serial adjacent-pair rep loop, JSONL emit. `mod perf_support;`. |
| `crates/carrick-cli/tests/perf_support/mod.rs` | **Create.** `pub mod stats; pub mod metric; pub mod provenance; pub mod invoke; pub mod cases;` |
| `crates/carrick-cli/tests/perf_support/stats.rs` | **Create.** Pure stats: `Summary{p50,p95,min,iqr}`, `summarize(&[f64])`, `is_noisy(&Summary)`. Unit-tested. |
| `crates/carrick-cli/tests/perf_support/metric.rs` | **Create.** Parse `key=value` lines → `Metrics`; `get_f64`, `get_u64`. Unit-tested. |
| `crates/carrick-cli/tests/perf_support/provenance.rs` | **Create.** Host/git/image facts capture + the serde `ResultRow` written to JSONL. Unit-tested (serialization). |
| `crates/carrick-cli/tests/perf_support/invoke.rs` | **Create.** `perf_run_carrick` / `perf_run_docker`: per-sample run-id, deadline watcher, cleanup, base64-stdin injection with the perf-specific env/flags. |
| `crates/carrick-cli/tests/perf_support/cases.rs` | **Create.** `PerfCase` registry (Phase 0: the single `tcp_rr` case). |
| `crates/carrick-cli/Cargo.toml` | **Modify.** Add `serde`, `serde_json` to `[dev-dependencies]`. |
| `scripts/measure-perf.sh` | **Create.** Orchestrator: build probes, run `perf_gate`, print the resulting rows. `--quick`/`--full` profile env. |
| `justfile` | **Modify.** Add a `bench` recipe. |
| `.gitignore` | **Modify.** Add `/.bench-scratch/`. |
| `docs/perf-results/.gitkeep` | **Create.** Keep the committed baseline-store dir. |

---

### Task 0: Scaffolding (dev-deps, dirs, gitignore)

**Files:**
- Modify: `crates/carrick-cli/Cargo.toml`
- Modify: `.gitignore`
- Create: `docs/perf-results/.gitkeep`
- Create: `crates/carrick-cli/tests/perf_support/mod.rs`

- [ ] **Step 1: Add serde dev-deps.** Open `crates/carrick-cli/Cargo.toml`, find the `[dev-dependencies]` table (it already lists `bollard`, `futures-util`, etc.). Add:

```toml
serde = { workspace = true }
serde_json = { workspace = true }
```

- [ ] **Step 2: Ignore the disk scratch dir.** Append to `.gitignore`:

```
/.bench-scratch/
```

- [ ] **Step 3: Create the committed result-store dir.**

```bash
mkdir -p docs/perf-results
touch docs/perf-results/.gitkeep
mkdir -p crates/carrick-cli/tests/perf_support
```

- [ ] **Step 4: Create the module index.** Create `crates/carrick-cli/tests/perf_support/mod.rs`:

```rust
//! Shared helpers for the perf benchmark gate (`tests/perf_runner.rs`).
//! Lives in a subdirectory so cargo does NOT compile it as its own test binary;
//! it is pulled in via `mod perf_support;` from perf_runner.rs.
pub mod stats;
pub mod metric;
pub mod provenance;
pub mod invoke;
pub mod cases;
```

- [ ] **Step 5: Verify it compiles (empty modules will error — that's expected next task).** Skip building until Task 4 wires real modules; just confirm the Cargo.toml parses:

Run: `cargo metadata --no-deps --format-version 1 >/dev/null && echo OK`
Expected: `OK`

- [ ] **Step 6: Commit.**

```bash
git add crates/carrick-cli/Cargo.toml .gitignore docs/perf-results/.gitkeep crates/carrick-cli/tests/perf_support/mod.rs
git commit -m "$(printf 'chore(bench): phase-0 scaffolding (dev-deps, result store, module index)\n\nCo-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>')"
```

---

### Task 1: The TCP_RR self-timing probe

**Files:**
- Create: `conformance-probes/src/bin/perf_net_tcp_rr.rs`

The probe runs a 1-byte request/reply ping-pong over `127.0.0.1` between a server thread and the main thread, times each round-trip with `std::time::Instant` (CLOCK_MONOTONIC on Linux), and prints its own p50/p95/min over the timed iterations plus the visible CPU count. It is built as a static aarch64-musl ELF by `scripts/build-probes.sh`.

- [ ] **Step 1: Write the probe.** Create `conformance-probes/src/bin/perf_net_tcp_rr.rs`:

```rust
//! Perf probe: loopback TCP request/response latency (TCP_RR), self-timed
//! in-guest. A server thread echoes 1 byte; the main thread does WARMUP+ITERS
//! round-trips over 127.0.0.1, timing each with a monotonic clock, and prints
//! its own p50/p95/min in microseconds plus the CPU count the guest sees.
//!
//! Output is `key=value` lines (parsed by tests/perf_runner.rs), NOT diffed:
//!   tcp_rr_p50_us=<f>  tcp_rr_p95_us=<f>  tcp_rr_min_us=<f>  rr_iters=<u>  nproc=<u>
//!
//! This is Topology A (server+client in one guest) — it isolates the engine's
//! loopback syscall-translation path. TCP_NODELAY is set so we measure the
//! syscall round-trip, not Nagle batching.
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Instant;

const WARMUP: usize = 1000;
const ITERS: usize = 5000;

fn nproc() -> usize {
    thread::available_parallelism().map(|n| n.get()).unwrap_or(0)
}

fn main() {
    // Bind the echo server to an ephemeral loopback port.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    let server = thread::spawn(move || {
        let (mut conn, _) = listener.accept().expect("accept");
        conn.set_nodelay(true).ok();
        let mut byte = [0u8; 1];
        // Echo until the client hangs up (read returns 0).
        loop {
            match conn.read(&mut byte) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    if conn.write_all(&byte).is_err() {
                        break;
                    }
                }
            }
        }
    });

    let mut client = TcpStream::connect(addr).expect("connect");
    client.set_nodelay(true).expect("nodelay");
    let msg = [0x41u8; 1];
    let mut buf = [0u8; 1];

    // Warmup (not timed): primes caches and the connection.
    for _ in 0..WARMUP {
        client.write_all(&msg).expect("warmup write");
        client.read_exact(&mut buf).expect("warmup read");
    }

    // Timed round-trips.
    let mut samples_ns: Vec<u128> = Vec::with_capacity(ITERS);
    for _ in 0..ITERS {
        let t0 = Instant::now();
        client.write_all(&msg).expect("write");
        client.read_exact(&mut buf).expect("read");
        samples_ns.push(t0.elapsed().as_nanos());
    }

    // Close the client → server's read returns 0 → server thread exits.
    drop(client);
    server.join().ok();

    samples_ns.sort_unstable();
    let pct = |p: f64| -> f64 {
        // Nearest-rank percentile, in microseconds.
        let idx = (((samples_ns.len() as f64) * p).ceil() as usize)
            .saturating_sub(1)
            .min(samples_ns.len() - 1);
        samples_ns[idx] as f64 / 1000.0
    };

    println!("tcp_rr_p50_us={:.3}", pct(0.50));
    println!("tcp_rr_p95_us={:.3}", pct(0.95));
    println!("tcp_rr_min_us={:.3}", samples_ns[0] as f64 / 1000.0);
    println!("rr_iters={}", samples_ns.len());
    println!("nproc={}", nproc());
}
```

- [ ] **Step 2: Build the probe set (requires Docker; this is a build step, not a timed sample).**

Run: `scripts/build-probes.sh`
Expected: ends with `probes built: conformance-probes/target/aarch64-unknown-linux-musl/release/` and the file list includes `perf_net_tcp_rr`.

- [ ] **Step 3: Verify the probe's OUTPUT FORMAT under Docker alone** (no carrick involved, so concurrency rule is not in play). This confirms the probe runs and prints the five keys before we wire the harness.

Run:
```bash
B="conformance-probes/target/aarch64-unknown-linux-musl/release/perf_net_tcp_rr"
base64 -i "$B" | docker run -i --rm --platform linux/arm64 --cpuset-cpus=0-3 ubuntu:24.04 \
  /bin/sh -c 'base64 -d > /tmp/p && chmod +x /tmp/p && /tmp/p'
```
Expected: five lines, e.g.
```
tcp_rr_p50_us=8.421
tcp_rr_p95_us=14.002
tcp_rr_min_us=6.110
rr_iters=5000
nproc=4
```
(`nproc=4` confirms `--cpuset-cpus=0-3` is honored. If `nproc` is not 4, the Docker Desktop VM has fewer than 4 CPUs — raise it in Settings → Resources before continuing.)

- [ ] **Step 4: Commit.**

```bash
git add conformance-probes/src/bin/perf_net_tcp_rr.rs
git commit -m "$(printf 'feat(bench): in-guest TCP_RR self-timing probe\n\nCo-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>')"
```

---

### Task 2: Stats module (pure, TDD)

**Files:**
- Create: `crates/carrick-cli/tests/perf_support/stats.rs`

- [ ] **Step 1: Write the failing tests.** Create `crates/carrick-cli/tests/perf_support/stats.rs`:

```rust
//! Pure summary statistics over a set of per-rep metric values.
//! p50/p95 use the nearest-rank method (matches the in-guest probe), so the
//! harness and the probe speak the same percentile definition.

#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize)]
pub struct Summary {
    pub p50: f64,
    pub p95: f64,
    pub min: f64,
    pub iqr: f64,
    pub n: usize,
}

/// Nearest-rank percentile of an already-collected sample set (p in [0,1]).
fn nearest_rank(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return f64::NAN;
    }
    let idx = (((sorted.len() as f64) * p).ceil() as usize)
        .saturating_sub(1)
        .min(sorted.len() - 1);
    sorted[idx]
}

/// Summarize per-rep values. Returns None if empty.
pub fn summarize(values: &[f64]) -> Option<Summary> {
    if values.is_empty() {
        return None;
    }
    let mut s = values.to_vec();
    s.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let q1 = nearest_rank(&s, 0.25);
    let q3 = nearest_rank(&s, 0.75);
    Some(Summary {
        p50: nearest_rank(&s, 0.50),
        p95: nearest_rank(&s, 0.95),
        min: s[0],
        iqr: q3 - q1,
        n: s.len(),
    })
}

/// A row is NOISY if its spread is wide relative to its center: IQR/p50 > 0.10.
/// (Operationalizes the protocol's "stddev/median > 10%" using the
/// outlier-robust IQR rather than a thermal-spike-sensitive stddev.)
pub fn is_noisy(s: &Summary) -> bool {
    s.p50 > 0.0 && (s.iqr / s.p50) > 0.10
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summarize_basic_percentiles() {
        let v: Vec<f64> = (1..=10).map(|x| x as f64).collect(); // 1..10
        let s = summarize(&v).unwrap();
        assert_eq!(s.min, 1.0);
        assert_eq!(s.p50, 5.0); // nearest-rank: ceil(10*0.5)-1 = idx 4 -> value 5
        assert_eq!(s.p95, 10.0); // ceil(10*0.95)-1 = idx 9 -> value 10
        assert_eq!(s.n, 10);
        assert_eq!(s.iqr, 8.0 - 3.0); // q3=idx ceil(7.5)-1=7 ->8, q1=ceil(2.5)-1=2 ->3
    }

    #[test]
    fn summarize_empty_is_none() {
        assert!(summarize(&[]).is_none());
    }

    #[test]
    fn noisy_when_spread_wide() {
        let tight = Summary { p50: 100.0, p95: 105.0, min: 99.0, iqr: 5.0, n: 8 };
        let wide = Summary { p50: 100.0, p95: 180.0, min: 90.0, iqr: 40.0, n: 8 };
        assert!(!is_noisy(&tight));
        assert!(is_noisy(&wide));
    }
}
```

- [ ] **Step 2: Wire it into the test binary so the unit tests can run.** Create the minimal `crates/carrick-cli/tests/perf_runner.rs` so `cargo test --test perf_runner` compiles the module (the other modules don't exist yet, so temporarily declare only `stats`):

```rust
#![allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "perf_support/stats.rs"]
mod stats;
```

(We use `#[path]` single-module wiring now; Task 7 replaces this with `mod perf_support;` once every module exists.)

- [ ] **Step 3: Run the tests to verify they pass.**

Run: `cargo test -p carrick-cli --test perf_runner stats -- --nocapture`
Expected: `test stats::tests::summarize_basic_percentiles ... ok` (3 passing).

- [ ] **Step 4: Commit.**

```bash
git add crates/carrick-cli/tests/perf_support/stats.rs crates/carrick-cli/tests/perf_runner.rs
git commit -m "$(printf 'feat(bench): p50/p95/min/IQR summary + noisy detector (TDD)\n\nCo-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>')"
```

---

### Task 3: Metric parser (pure, TDD)

**Files:**
- Create: `crates/carrick-cli/tests/perf_support/metric.rs`
- Modify: `crates/carrick-cli/tests/perf_runner.rs`

- [ ] **Step 1: Write the parser + tests.** Create `crates/carrick-cli/tests/perf_support/metric.rs`:

```rust
//! Parse a probe's `key=value` stdout into a lookup. Tolerant of extra
//! non-`key=value` lines (warnings etc.); only well-formed pairs are kept.
use std::collections::HashMap;

#[derive(Debug, Default, Clone)]
pub struct Metrics(pub HashMap<String, String>);

impl Metrics {
    pub fn parse(output: &str) -> Self {
        let mut m = HashMap::new();
        for line in output.lines() {
            if let Some((k, v)) = line.split_once('=') {
                let k = k.trim();
                let v = v.trim();
                // Only accept bare identifier-ish keys, so a stray "a = b = c"
                // or an env dump line doesn't pollute the map.
                if !k.is_empty() && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                    m.insert(k.to_string(), v.to_string());
                }
            }
        }
        Metrics(m)
    }

    pub fn get_f64(&self, key: &str) -> Option<f64> {
        self.0.get(key).and_then(|v| v.parse::<f64>().ok())
    }

    pub fn get_u64(&self, key: &str) -> Option<u64> {
        self.0.get(key).and_then(|v| v.parse::<u64>().ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "tcp_rr_p50_us=8.421\ntcp_rr_p95_us=14.0\nrr_iters=5000\nnproc=4\n";

    #[test]
    fn parses_floats_and_ints() {
        let m = Metrics::parse(SAMPLE);
        assert_eq!(m.get_f64("tcp_rr_p50_us"), Some(8.421));
        assert_eq!(m.get_u64("rr_iters"), Some(5000));
        assert_eq!(m.get_u64("nproc"), Some(4));
    }

    #[test]
    fn ignores_noise_lines() {
        let m = Metrics::parse("carrick: --fs host warning\ntcp_rr_p50_us=9.0\n<TIMEOUT after 45s>\n");
        assert_eq!(m.get_f64("tcp_rr_p50_us"), Some(9.0));
        assert_eq!(m.0.len(), 1);
    }

    #[test]
    fn missing_key_is_none() {
        let m = Metrics::parse(SAMPLE);
        assert_eq!(m.get_f64("nope"), None);
    }
}
```

- [ ] **Step 2: Wire the module.** Edit `crates/carrick-cli/tests/perf_runner.rs` to add:

```rust
#[path = "perf_support/metric.rs"]
mod metric;
```

- [ ] **Step 3: Run the tests.**

Run: `cargo test -p carrick-cli --test perf_runner metric -- --nocapture`
Expected: 3 passing (`parses_floats_and_ints`, `ignores_noise_lines`, `missing_key_is_none`).

- [ ] **Step 4: Commit.**

```bash
git add crates/carrick-cli/tests/perf_support/metric.rs crates/carrick-cli/tests/perf_runner.rs
git commit -m "$(printf 'feat(bench): tolerant key=value metric parser (TDD)\n\nCo-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>')"
```

---

### Task 4: Provenance + JSONL ResultRow (pure, TDD)

**Files:**
- Create: `crates/carrick-cli/tests/perf_support/provenance.rs`
- Modify: `crates/carrick-cli/tests/perf_runner.rs`

- [ ] **Step 1: Write provenance capture + the serde row + tests.** Create `crates/carrick-cli/tests/perf_support/provenance.rs`:

```rust
//! Provenance capture and the append-only JSONL result row. Every row stamps
//! enough host/build/image context to make runs comparable across machines and
//! over time (the reusable-baseline requirement). Capture functions shell out to
//! `sysctl`/`sw_vers`/`git`/`docker`; all are best-effort (None on failure) so a
//! row is still written when an optional fact is unavailable.
use std::process::Command;
use super::stats::Summary;

fn cmd_stdout(program: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(program).args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() { None } else { Some(s) }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct HostFacts {
    pub model: Option<String>,
    pub perf_cores: Option<String>,
    pub eff_cores: Option<String>,
    pub macos: Option<String>,
    pub docker_version: Option<String>,
}

impl HostFacts {
    pub fn capture() -> Self {
        HostFacts {
            model: cmd_stdout("sysctl", &["-n", "hw.model"]),
            perf_cores: cmd_stdout("sysctl", &["-n", "hw.perflevel0.logicalcpu"]),
            eff_cores: cmd_stdout("sysctl", &["-n", "hw.perflevel1.logicalcpu"]),
            macos: cmd_stdout("sw_vers", &["-productVersion"]),
            docker_version: cmd_stdout("docker", &["version", "--format", "{{.Server.Version}}"]),
        }
    }
}

/// OCI digest of the pinned image, e.g. ubuntu:24.04 -> sha256:...
pub fn image_digest(image: &str) -> Option<String> {
    cmd_stdout("docker", &["image", "inspect", "--format", "{{index .RepoDigests 0}}", image])
}

pub fn git_sha() -> Option<String> {
    cmd_stdout("git", &["rev-parse", "HEAD"])
}

/// Seconds since the Unix epoch (avoids a chrono dep; the date is enough to
/// order rows and the filename carries the calendar day).
pub fn epoch_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// One appended line of the result store. `engine` is "carrick"|"docker";
/// `lane` is the carrick timing lane ("cold"|"warm"|"docker"); for Phase 0 the
/// carrick lane is "cold".
#[derive(Debug, Clone, serde::Serialize)]
pub struct ResultRow {
    pub schema: u32,
    pub epoch_secs: u64,
    pub dimension: String,
    pub workload: String,
    pub engine: String,
    pub lane: String,
    pub metric: String,
    pub unit: String,
    pub summary: Summary,
    pub samples: Vec<f64>,
    pub noisy: bool,
    pub nproc: Option<u64>,
    pub cpu_pin: u32,
    pub fs_mode: String,
    pub image: String,
    pub image_digest: Option<String>,
    pub git_sha: Option<String>,
    pub run_id: String,
    pub host: HostFacts,
}

/// Append a row as one JSON line to `docs/perf-results/<date>-<dim>.jsonl`.
pub fn append_row(repo_root: &std::path::Path, date: &str, row: &ResultRow) -> std::io::Result<()> {
    use std::io::Write;
    let dir = repo_root.join("docs/perf-results");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{date}-{}.jsonl", row.dimension));
    let mut f = std::fs::OpenOptions::new().create(true).append(true).open(path)?;
    let line = serde_json::to_string(row).map_err(std::io::Error::other)?;
    writeln!(f, "{line}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_row() -> ResultRow {
        ResultRow {
            schema: 1,
            epoch_secs: 1_700_000_000,
            dimension: "network".into(),
            workload: "tcp_rr".into(),
            engine: "carrick".into(),
            lane: "cold".into(),
            metric: "tcp_rr_p50_us".into(),
            unit: "us".into(),
            summary: Summary { p50: 8.4, p95: 14.0, min: 6.1, iqr: 1.2, n: 8 },
            samples: vec![8.4, 8.5, 8.3],
            noisy: false,
            nproc: Some(4),
            cpu_pin: 4,
            fs_mode: "host".into(),
            image: "ubuntu:24.04".into(),
            image_digest: Some("sha256:deadbeef".into()),
            git_sha: Some("abc123".into()),
            run_id: "cr-perf-1-0".into(),
            host: HostFacts {
                model: Some("Mac16,12".into()),
                perf_cores: Some("4".into()),
                eff_cores: Some("6".into()),
                macos: Some("26.6".into()),
                docker_version: Some("29.5.2".into()),
            },
        }
    }

    #[test]
    fn row_serializes_to_one_json_line() {
        let s = serde_json::to_string(&fake_row()).unwrap();
        assert!(!s.contains('\n'));
        assert!(s.contains("\"workload\":\"tcp_rr\""));
        assert!(s.contains("\"p50\":8.4"));
        assert!(s.contains("\"nproc\":4"));
    }

    #[test]
    fn append_writes_a_line() {
        let tmp = std::env::temp_dir().join(format!("perf-prov-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        append_row(&tmp, "2026-06-02", &fake_row()).unwrap();
        let body = std::fs::read_to_string(tmp.join("docs/perf-results/2026-06-02-network.jsonl")).unwrap();
        assert_eq!(body.lines().count(), 1);
        std::fs::remove_dir_all(&tmp).ok();
    }
}
```

- [ ] **Step 2: Wire the module** (it depends on `stats`, so use `super::stats`; switch to the package layout now). Replace the contents of `crates/carrick-cli/tests/perf_runner.rs` with:

```rust
#![allow(clippy::unwrap_used, clippy::expect_used)]
mod perf_support;
```

and ensure `crates/carrick-cli/tests/perf_support/mod.rs` currently declares only the modules that exist. Temporarily set it to:

```rust
pub mod stats;
pub mod metric;
pub mod provenance;
```

(We add `invoke` and `cases` in Tasks 5–6.)

- [ ] **Step 3: Run the tests.**

Run: `cargo test -p carrick-cli --test perf_runner provenance -- --nocapture`
Expected: 2 passing (`row_serializes_to_one_json_line`, `append_writes_a_line`).

- [ ] **Step 4: Commit.**

```bash
git add crates/carrick-cli/tests/perf_support/provenance.rs crates/carrick-cli/tests/perf_support/mod.rs crates/carrick-cli/tests/perf_runner.rs
git commit -m "$(printf 'feat(bench): provenance capture + JSONL ResultRow store (TDD)\n\nCo-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>')"
```

---

### Task 5: Engine-driving glue (`invoke`)

**Files:**
- Create: `crates/carrick-cli/tests/perf_support/invoke.rs`
- Modify: `crates/carrick-cli/tests/perf_support/mod.rs`

This duplicates the small invocation logic from `conformance.rs` (the two test binaries can't share private `fn`s) but adds the perf-specific env/flags: `CARRICK_EXPOSED_CPUS=4` on the carrick side, `--cpuset-cpus=0-3` on the Docker side. There is no host-side assertion here — it returns raw output; the gate parses and validates.

- [ ] **Step 1: Write the invoke helpers.** Create `crates/carrick-cli/tests/perf_support/invoke.rs`:

```rust
//! Run a base64-injected probe under carrick and under Docker, returning the
//! guest's combined stdout+stderr. Mirrors conformance.rs's run_*_probe path
//! (PROBE_SNIPPET stdin injection, per-sample CARRICK_RUN_ID, deadline watcher,
//! scoped cleanup) with perf-specific CPU normalization. SERIAL ONLY: callers
//! must run carrick and docker for the same sample non-concurrently.
use std::io::Write;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
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
    format!("cr-perf-{}-{}", std::process::id(), SEQ.fetch_add(1, Ordering::Relaxed))
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
}

/// Drain a child with a wall-clock deadline; on timeout SIGKILL the process
/// group and scoped-reap any escaped carrick guests. Returns combined output.
fn drain_with_deadline(mut child: std::process::Child, repo_root: &Path, run_id: &str) -> String {
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

/// Run `probe_b64` under carrick (cold lane: a fresh `carrick run`), with
/// CARRICK_EXPOSED_CPUS=CPU_PIN. `repo_root` is the workspace root; `run_id` is
/// reaped on timeout. Returns combined guest output.
pub fn run_carrick(bin: &PathBuf, repo_root: &Path, run_id: &str, probe_b64: &[u8]) -> String {
    let mut child = Command::new(bin)
        .args([
            "run", "--platform", PLATFORM, "--raw", "--fs", "host",
            IMAGE, "/bin/sh", "-c", PROBE_SNIPPET,
        ])
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

/// Run `probe_b64` under Docker, pinned to 4 CPUs via --cpuset-cpus so `nproc`
/// inside the container is 4 (CFS --cpus would NOT change nproc).
pub fn run_docker(repo_root: &Path, run_id: &str, probe_b64: &[u8]) -> String {
    let mut child = Command::new("docker")
        .args([
            "run", "-i", "--rm", "--platform", PLATFORM, "--cpuset-cpus", "0-3",
            IMAGE, "/bin/sh", "-c", PROBE_SNIPPET,
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn docker");
    feed_stdin(&mut child, probe_b64);
    // Docker side has no carrick guests to reap; run_id only labels the sample.
    drain_with_deadline(child, repo_root, run_id)
}
```

- [ ] **Step 2: Declare the module.** Add to `crates/carrick-cli/tests/perf_support/mod.rs`:

```rust
pub mod invoke;
```

- [ ] **Step 3: Compile-check (no unit test — this is engine glue, verified end-to-end in Task 9).**

Run: `cargo test -p carrick-cli --test perf_runner --no-run`
Expected: builds with no errors (warnings about unused `run_carrick`/`run_docker` are OK until Task 7 uses them).

- [ ] **Step 4: Commit.**

```bash
git add crates/carrick-cli/tests/perf_support/invoke.rs crates/carrick-cli/tests/perf_support/mod.rs
git commit -m "$(printf 'feat(bench): serial carrick/docker probe-injection glue with CPU pin\n\nCo-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>')"
```

---

### Task 6: Case registry

**Files:**
- Create: `crates/carrick-cli/tests/perf_support/cases.rs`
- Modify: `crates/carrick-cli/tests/perf_support/mod.rs`

The registry makes adding a workload a data edit. Phase 0 registers one case. A case names its probe binary, its dimension/workload labels, and the metric key to extract from the probe's output.

- [ ] **Step 1: Write the registry.** Create `crates/carrick-cli/tests/perf_support/cases.rs`:

```rust
//! Declarative perf-case registry. Adding a workload = adding a PerfCase entry
//! (and dropping its probe in conformance-probes/src/bin/). The runner builds
//! the probe path from `probe`, runs it under both engines, and pulls
//! `metric_key` out of each engine's parsed output as the per-rep value.

#[derive(Debug, Clone, Copy)]
pub struct PerfCase {
    /// Probe binary name in conformance-probes/.../release/ (no extension).
    pub probe: &'static str,
    pub dimension: &'static str,
    pub workload: &'static str,
    /// Key the probe prints whose value is the per-rep metric.
    pub metric_key: &'static str,
    pub unit: &'static str,
}

/// Phase 0: the marquee network case. Later phases append disk/fork/thread cases.
pub const CASES: &[PerfCase] = &[PerfCase {
    probe: "perf_net_tcp_rr",
    dimension: "network",
    workload: "tcp_rr",
    metric_key: "tcp_rr_p50_us",
    unit: "us",
}];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_is_nonempty_and_well_formed() {
        assert!(!CASES.is_empty());
        for c in CASES {
            assert!(!c.probe.is_empty());
            assert!(!c.metric_key.is_empty());
        }
    }
}
```

- [ ] **Step 2: Declare the module.** Add to `crates/carrick-cli/tests/perf_support/mod.rs`:

```rust
pub mod cases;
```

- [ ] **Step 3: Run the registry test.**

Run: `cargo test -p carrick-cli --test perf_runner cases -- --nocapture`
Expected: `registry_is_nonempty_and_well_formed ... ok`.

- [ ] **Step 4: Commit.**

```bash
git add crates/carrick-cli/tests/perf_support/cases.rs crates/carrick-cli/tests/perf_support/mod.rs
git commit -m "$(printf 'feat(bench): declarative perf-case registry (TCP_RR)\n\nCo-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>')"
```

---

### Task 7: The `perf_gate` serial adjacent-pair driver

**Files:**
- Modify: `crates/carrick-cli/tests/perf_runner.rs`

This wires everything: skip-guards (binary/docker/probes absent → pass, like `conformance`), `CONFORMANCE_LOCK` is **not** importable across test binaries, so we use a private `Mutex` plus the serial design to bound concurrency; `ensure_signed` is likewise re-implemented inline. For each case, run N reps of carrick-then-docker adjacent pairs with cooldowns, parse, assert `nproc==CPU_PIN` on both (else the rep is INVALID/excluded), summarize the valid per-rep values per engine, and append one ResultRow per engine.

- [ ] **Step 1: Write the driver.** Replace `crates/carrick-cli/tests/perf_runner.rs` with:

```rust
//! Differential perf gate: carrick vs Docker, serial adjacent-pair sampling.
//! Self-skips (passes) when the signed binary, Docker, or built probes are
//! absent — so `cargo test` stays green everywhere. Run it deliberately:
//!   just bench           # quick profile (this gate, env-tuned)
//!
//! HARD CONSTRAINT: carrick and Docker never run concurrently here. Every
//! timed sample is one engine process at a time; reps are carrick THEN docker.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod perf_support;

use perf_support::cases::{PerfCase, CASES};
use perf_support::invoke::{self, CPU_PIN, IMAGE};
use perf_support::metric::Metrics;
use perf_support::provenance::{self, HostFacts, ResultRow};
use perf_support::stats::{self, Summary};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::time::Duration;

static PERF_LOCK: Mutex<()> = Mutex::new(());

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent().and_then(|p| p.parent())
        .expect("carrick-cli under crates/")
        .to_path_buf()
}

fn carrick_bin(root: &Path) -> Option<PathBuf> {
    let p = root.join("target/release/carrick");
    p.exists().then_some(p)
}

fn probe_path(root: &Path, name: &str) -> PathBuf {
    root.join(format!(
        "conformance-probes/target/aarch64-unknown-linux-musl/release/{name}"
    ))
}

fn docker_ok() -> bool {
    Command::new("docker").arg("version")
        .stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null())
        .status().map(|s| s.success()).unwrap_or(false)
}

fn is_signed(bin: &Path) -> bool {
    Command::new("codesign").args(["-d", "--entitlements", "-"]).arg(bin).output()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("com.apple.security.hypervisor")
              || String::from_utf8_lossy(&o.stderr).contains("com.apple.security.hypervisor"))
        .unwrap_or(false)
}

fn ensure_signed(root: &Path, bin: &Path) {
    if is_signed(bin) { return; }
    let plist = root.join("scripts/entitlements.plist");
    let out = Command::new("codesign")
        .args(["--force", "--sign", "-", "--entitlements"]).arg(&plist).arg(bin)
        .output();
    match out {
        Ok(o) if o.status.success() => {}
        Ok(o) => panic!("codesign failed: {}", String::from_utf8_lossy(&o.stderr)),
        Err(e) => panic!("codesign could not run: {e}"),
    }
}

/// Profile knobs (env-overridable so `just bench` quick vs full can tune them
/// without recompiling). Defaults = quick profile.
fn reps() -> usize {
    std::env::var("CARRICK_PERF_REPS").ok().and_then(|s| s.parse().ok()).unwrap_or(5)
}
fn warmup_reps() -> usize {
    std::env::var("CARRICK_PERF_WARMUP").ok().and_then(|s| s.parse().ok()).unwrap_or(1)
}
fn cooldown() -> Duration {
    let secs = std::env::var("CARRICK_PERF_COOLDOWN_SECS").ok()
        .and_then(|s| s.parse().ok()).unwrap_or(15);
    Duration::from_secs(secs)
}

/// One engine's per-rep value plus the nproc it reported (for the norm gate).
struct Sample { value: Option<f64>, nproc: Option<u64> }

fn parse_sample(output: &str, metric_key: &str) -> Sample {
    let m = Metrics::parse(output);
    Sample { value: m.get_f64(metric_key), nproc: m.get_u64("nproc") }
}

fn run_case(root: &Path, bin: &PathBuf, case: &PerfCase) -> Vec<ResultRow> {
    use base64::Engine as _;
    let probe = probe_path(root, case.probe);
    let raw = std::fs::read(&probe).expect("read probe");
    let b64 = base64::engine::general_purpose::STANDARD.encode(&raw).into_bytes();

    let n = reps();
    let warm = warmup_reps().min(n);
    let mut carrick_vals: Vec<f64> = Vec::new();
    let mut docker_vals: Vec<f64> = Vec::new();
    let mut carrick_nproc: Option<u64> = None;
    let mut docker_nproc: Option<u64> = None;
    let mut invalid = 0usize;

    for rep in 0..n {
        // --- carrick sample ---
        let c_id = invoke::perf_run_id();
        let c_out = invoke::run_carrick(bin, root, &c_id, &b64);
        std::thread::sleep(cooldown());
        // --- docker sample (adjacent, never concurrent) ---
        let d_id = invoke::perf_run_id();
        let d_out = invoke::run_docker(root, &d_id, &b64);
        std::thread::sleep(cooldown());

        let c = parse_sample(&c_out, case.metric_key);
        let d = parse_sample(&d_out, case.metric_key);
        carrick_nproc = c.nproc.or(carrick_nproc);
        docker_nproc = d.nproc.or(docker_nproc);

        // CPU-normalization gate: both engines must report nproc==CPU_PIN, else
        // the rep is INVALID and excluded (per the design's fail-fast rule).
        let normalized = c.nproc == Some(CPU_PIN as u64) && d.nproc == Some(CPU_PIN as u64);
        let usable = rep >= warm && normalized && c.value.is_some() && d.value.is_some();
        if rep >= warm && !normalized {
            invalid += 1;
            eprintln!("perf[{}] rep {rep}: INVALID (carrick nproc={:?}, docker nproc={:?}, want {CPU_PIN})",
                      case.workload, c.nproc, d.nproc);
        }
        if usable {
            carrick_vals.push(c.value.unwrap());
            docker_vals.push(d.value.unwrap());
        }
        eprintln!("perf[{}] rep {rep}/{n}: carrick={:?} docker={:?}{}",
                  case.workload, c.value, d.value,
                  if rep < warm { " (warmup, discarded)" } else { "" });
    }

    assert!(!carrick_vals.is_empty() && !docker_vals.is_empty(),
        "perf[{}]: no valid normalized samples ({} invalid of {} reps) — check nproc pinning",
        case.workload, invalid, n);

    let date = today_string();
    let host = HostFacts::capture();
    let digest = provenance::image_digest(IMAGE);
    let sha = provenance::git_sha();
    let mk = |engine: &str, lane: &str, vals: &[f64], nproc: Option<u64>| -> ResultRow {
        let s: Summary = stats::summarize(vals).expect("non-empty");
        ResultRow {
            schema: 1,
            epoch_secs: provenance::epoch_secs(),
            dimension: case.dimension.into(),
            workload: case.workload.into(),
            engine: engine.into(),
            lane: lane.into(),
            metric: case.metric_key.into(),
            unit: case.unit.into(),
            summary: s,
            samples: vals.to_vec(),
            noisy: stats::is_noisy(&s),
            nproc,
            cpu_pin: CPU_PIN,
            fs_mode: "host".into(),
            image: IMAGE.into(),
            image_digest: digest.clone(),
            git_sha: sha.clone(),
            run_id: format!("cr-perf-{}", std::process::id()),
            host: host.clone(),
        }
    };
    let rows = vec![
        mk("carrick", "cold", &carrick_vals, carrick_nproc),
        mk("docker", "docker", &docker_vals, docker_nproc),
    ];
    for r in &rows {
        provenance::append_row(root, &date, r).expect("append row");
        let ratio = rows[0].summary.p50 / rows[1].summary.p50;
        eprintln!("perf[{}] {} {}={:.3}{} p95={:.3} (n={}){}",
            case.workload, r.engine, r.metric, r.summary.p50, r.unit, r.summary.p95, r.summary.n,
            if r.engine == "docker" { format!("  RATIO carrick/docker={ratio:.2}") } else { String::new() });
    }
    rows
}

/// YYYY-MM-DD from `date` (avoids a chrono dep).
fn today_string() -> String {
    Command::new("date").args(["+%Y-%m-%d"]).output().ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown-date".into())
}

#[test]
fn perf_gate() {
    let _serial = PERF_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let root = repo_root();

    let Some(bin) = carrick_bin(&root) else {
        eprintln!("SKIP perf_gate: target/release/carrick not built (run `just build`)");
        return;
    };
    if !docker_ok() {
        eprintln!("SKIP perf_gate: Docker not reachable");
        return;
    }
    // All probes built?
    for case in CASES {
        if !probe_path(&root, case.probe).exists() {
            eprintln!("SKIP perf_gate: probe {} not built (run scripts/build-probes.sh)", case.probe);
            return;
        }
    }
    ensure_signed(&root, &bin);

    for case in CASES {
        run_case(&root, &bin, case);
    }
}
```

- [ ] **Step 2: Compile-check.**

Run: `cargo test -p carrick-cli --test perf_runner --no-run`
Expected: builds clean. (`base64` is already a dep of carrick-cli's test deps via conformance; if the build complains `base64` is unresolved, add `base64 = { workspace = true }` to `[dev-dependencies]` and re-run.)

- [ ] **Step 3: Confirm the unit tests still pass and the gate self-skips cleanly when prerequisites are absent** (e.g. if the signed binary isn't built yet, it should SKIP, not fail):

Run: `cargo test -p carrick-cli --test perf_runner -- --nocapture`
Expected: the `stats`/`metric`/`provenance`/`cases` unit tests pass; `perf_gate` prints a `SKIP perf_gate: ...` line and passes (unless you've already built everything, in which case it runs — that's Task 9).

- [ ] **Step 4: Commit.**

```bash
git add crates/carrick-cli/tests/perf_runner.rs crates/carrick-cli/Cargo.toml
git commit -m "$(printf 'feat(bench): perf_gate serial adjacent-pair driver + JSONL emit\n\nCo-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>')"
```

---

### Task 8: Entry point (`just bench` + `scripts/measure-perf.sh`)

**Files:**
- Create: `scripts/measure-perf.sh`
- Modify: `justfile`

- [ ] **Step 1: Write the orchestrator.** Create `scripts/measure-perf.sh`:

```bash
#!/usr/bin/env bash
# Differential perf benchmark: carrick vs Docker. Builds the signed binary and
# the probe set, then runs the perf_gate (serial, carrick-then-docker, never
# concurrent) and prints the resulting rows. Profiles tune rep count + cooldown
# via env so a quick smoke and a full baseline share one code path.
#
# Usage: scripts/measure-perf.sh [quick|full]   (default: quick)
set -euo pipefail
cd "$(dirname "$0")/.."
profile="${1:-quick}"

case "$profile" in
  quick) export CARRICK_PERF_REPS="${CARRICK_PERF_REPS:-5}"
         export CARRICK_PERF_WARMUP="${CARRICK_PERF_WARMUP:-1}"
         export CARRICK_PERF_COOLDOWN_SECS="${CARRICK_PERF_COOLDOWN_SECS:-15}" ;;
  full)  export CARRICK_PERF_REPS="${CARRICK_PERF_REPS:-10}"
         export CARRICK_PERF_WARMUP="${CARRICK_PERF_WARMUP:-2}"
         export CARRICK_PERF_COOLDOWN_SECS="${CARRICK_PERF_COOLDOWN_SECS:-15}" ;;
  *) echo "unknown profile: $profile (use quick|full)"; exit 2 ;;
esac

echo "==> building signed carrick"
./scripts/build-signed.sh
echo "==> building probes"
./scripts/build-probes.sh >/dev/null
echo "==> running perf_gate (profile=$profile reps=$CARRICK_PERF_REPS)"
cargo test -p carrick-cli --test perf_runner perf_gate -- --nocapture --include-ignored

echo "==> latest result rows:"
latest="$(ls -t docs/perf-results/*.jsonl 2>/dev/null | head -1 || true)"
[ -n "$latest" ] && tail -n 4 "$latest" || echo "(no rows written)"
```

- [ ] **Step 2: Make it executable.**

```bash
chmod +x scripts/measure-perf.sh
```

- [ ] **Step 3: Add the `just` recipe.** Append to `justfile`:

```make
# Differential perf benchmark vs Docker (serial; needs Docker + signed binary).
# `just bench` = quick profile; `just bench full` = full profile.
bench PROFILE="quick":
    ./scripts/measure-perf.sh {{PROFILE}}
```

- [ ] **Step 4: Verify the recipe is registered.**

Run: `just --list | grep bench`
Expected: a line like `bench PROFILE="quick"  # Differential perf benchmark ...`.

- [ ] **Step 5: Commit.**

```bash
git add scripts/measure-perf.sh justfile
git commit -m "$(printf 'feat(bench): just bench entry point + measure-perf.sh orchestrator\n\nCo-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>')"
```

---

### Task 9: End-to-end verification (real carrick vs Docker run)

**Files:** none (verification + the first committed baseline row).

> This is the only task that runs the full stack. It needs Docker running, the Docker Desktop VM configured with **≥4 CPUs**, and ~3–6 minutes for the quick profile.

- [ ] **Step 1: Pre-pull the pinned image so no image pull lands inside a timed sample.**

Run: `docker pull --platform linux/arm64 ubuntu:24.04`
Expected: `Status: Image is up to date` (or a successful pull).

- [ ] **Step 2: Run the quick benchmark.**

Run: `just bench`
Expected (representative): build lines, then per-rep progress on stderr, then a summary like:
```
perf[tcp_rr] rep 0/5: carrick=Some(9.1) docker=Some(12.4) (warmup, discarded)
perf[tcp_rr] rep 1/5: carrick=Some(8.7) docker=Some(12.1)
...
perf[tcp_rr] carrick tcp_rr_p50_us=8.70us p95=9.40 (n=4)
perf[tcp_rr] docker tcp_rr_p50_us=12.10us p95=13.0 (n=4)  RATIO carrick/docker=0.72
==> latest result rows:
{"schema":1,...,"engine":"carrick",...}
{"schema":1,...,"engine":"docker",...}
```

- [ ] **Step 3: Validate the normalization gate actually fired.** Confirm no `INVALID` lines and that both rows carry `"nproc":4`:

Run: `tail -n 2 docs/perf-results/$(date +%Y-%m-%d)-network.jsonl | grep -o '"nproc":[0-9]*' | sort -u`
Expected: `"nproc":4` (a single line). If you see anything else, the CPU pin didn't hold — investigate before trusting the ratio (carrick: `sched_getaffinity` not honoring `CARRICK_EXPOSED_CPUS`; docker: VM has <4 CPUs).

- [ ] **Step 4: Sanity-check the result is well-formed JSON and has both engines.**

Run: `tail -n 2 docs/perf-results/$(date +%Y-%m-%d)-network.jsonl | python3 -c 'import sys,json; rows=[json.loads(l) for l in sys.stdin]; print({r["engine"]: r["summary"]["p50"] for r in rows})'`
Expected: a dict like `{'carrick': 8.7, 'docker': 12.1}`.

- [ ] **Step 5: Commit the first baseline row + record the result.**

```bash
git add docs/perf-results/
git commit -m "$(printf 'chore(bench): first TCP_RR baseline (carrick vs docker)\n\nCo-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>')"
```

- [ ] **Step 6: Record the headline in the design doc's results section (manual).** Append a short note to `docs/archive/superpowers/specs/2026-06-02-carrick-vs-docker-benchmark-design.md` under a new `## Results (running log)` heading: the date, the carrick/docker p50 µs, the ratio, and whether the thesis prediction (carrick wins loopback RR) held. Commit:

```bash
git add docs/archive/superpowers/specs/2026-06-02-carrick-vs-docker-benchmark-design.md
git commit -m "$(printf 'docs(bench): log first TCP_RR result vs thesis prediction\n\nCo-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>')"
```

---

## Definition of done (Phase 0)

- `just bench` runs end-to-end, serially (never carrick+Docker concurrent), and writes a provenance-stamped JSONL row per engine to `docs/perf-results/`.
- The TCP_RR ratio (`carrick_p50 / docker_p50`) is recorded with both engines confirmed at `nproc==4`.
- All pure modules (`stats`, `metric`, `provenance`, `cases`) have passing unit tests under `cargo test --test perf_runner`.
- The gate self-skips cleanly when the binary/Docker/probes are absent (CI stays green).
- The framework is extensible: a new workload is a `PerfCase` entry + a probe file (proven by the registry shape), and a new run is comparable to old ones via the stamped provenance.

## What Phase 0 deliberately defers (later plans)

- **Topology B (cross-boundary host→guest)** network test with `--network host` (the direct no-bridge thesis) — Phase 0 measures Topology A loopback only.
- **GUEST-ONLY (boot-subtracted) and WARM (`run -d`+`exec`) lanes** — Phase 0 reports the carrick **cold** lane only. (`provenance::ResultRow.lane` already carries the field.)
- **Disk (fio/dd + metadata storm), fork storm, thread sweep, epoll fan-out, TCP_STREAM** — each is a new `PerfCase` + probe.
- **Adaptive-N extension and `pmset` thermal discard/resample** — Phase 0 uses fixed reps + fixed cooldown; `is_noisy` already flags wide rows.
- **`scripts/measure-perf.sh` DTrace diagnosis lane and the markdown verdict table** — Phase 0 emits JSONL + a stderr summary only.
- **The shared `docker/perf-benchmark/Dockerfile`** (fio/iperf3/netperf/stress-ng) — Phase 0's probe is self-contained and runs on stock `ubuntu:24.04`.
