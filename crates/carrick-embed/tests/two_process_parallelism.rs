//! Two-process contention and parallelism tests for the carrier runtime.
//!
//! Run ONLY through `just test-embed` (scripts/test-signed.sh): it signs the test
//! executable with the hypervisor entitlement, exports `CARRICK_RUN_ID`, and runs
//! it under `RUST_TEST_THREADS=1`. Bare `cargo test` fails here with
//! `EmbedError::Entitlement` (HV_DENIED), by design, never a skip.

mod common;

use std::path::{Path, PathBuf};

use carrick_embed::{
    Carrier, ContainerBuilder, ContainerResult, EmbedError, ImageStore, PullPolicy,
};

#[derive(Debug, Clone)]
struct GuestResult {
    stdout: String,
    exit_code: i32,
    signal: Option<carrick_embed::Signal>,
}

impl GuestResult {
    fn empty() -> Self {
        Self {
            stdout: String::new(),
            exit_code: -1,
            signal: None,
        }
    }

    fn from_container_result(res: ContainerResult) -> Self {
        Self {
            stdout: res.stdout_utf8(),
            exit_code: res.exit_code,
            signal: res.signal,
        }
    }

    fn exit_ok(&self) -> bool {
        self.exit_code == 0 && self.signal.is_none()
    }
}

impl AsRef<str> for GuestResult {
    fn as_ref(&self) -> &str {
        &self.stdout
    }
}

impl std::ops::Deref for GuestResult {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        &self.stdout
    }
}

impl std::fmt::Display for GuestResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.stdout)
    }
}

fn forkstorm_binary() -> PathBuf {
    let root = common::repo_root();
    let musl = root.join("conformance-probes/target/aarch64-unknown-linux-musl/release/forkstorm");
    if musl.is_file() {
        return musl;
    }
    let gnu = root.join("conformance-probes/target/aarch64-unknown-linux-gnu/release/forkstorm");
    if gnu.is_file() {
        return gnu;
    }
    musl
}

fn carrier_or_fail() -> Option<Carrier> {
    let carrier_res = Carrier::new();
    let not_entitlement = !matches!(carrier_res, Err(EmbedError::Entitlement));
    assert!(
        not_entitlement,
        "HV_DENIED (0xfae94007): this test executable lacks \
         com.apple.security.hypervisor. Run it through `just test-embed` \
         (scripts/test-signed.sh signs it); a bare `cargo test -p carrick-embed` \
         can never boot a guest."
    );
    assert!(
        carrier_res.is_ok(),
        "carrier create failed: {:?}",
        carrier_res.as_ref().err()
    );
    carrier_res.ok()
}

fn assert_run_ok(outcome: &Result<ContainerResult, EmbedError>) {
    let not_entitlement = !matches!(outcome, Err(EmbedError::Entitlement));
    assert!(
        not_entitlement,
        "HV_DENIED (0xfae94007): this test executable lacks \
         com.apple.security.hypervisor. Run it through `just test-embed` \
         (scripts/test-signed.sh signs it); a bare `cargo test -p carrick-embed` \
         can never boot a guest."
    );
    assert!(
        outcome.is_ok(),
        "container run failed: {:?}",
        outcome.as_ref().err()
    );
}

fn configure_container(builder: ContainerBuilder, cmd: &[&str]) -> ContainerBuilder {
    let binary = forkstorm_binary();
    let p_dir = binary.parent().map(Path::to_path_buf).unwrap_or_else(|| {
        common::repo_root().join("conformance-probes/target/aarch64-unknown-linux-musl/release")
    });

    builder
        .image_store(ImageStore::default_for_user())
        .pull_policy(PullPolicy::Missing)
        .command(cmd.iter().copied())
        .mount_readonly(p_dir.to_string_lossy(), "/p")
}

fn run_guest(cmd: &[&str]) -> GuestResult {
    let _guest = common::guest_lock();
    let Some(carrier) = carrier_or_fail() else {
        return GuestResult::empty();
    };
    let builder = configure_container(carrier.container(common::SMOKE_IMAGE), cmd);
    let outcome = builder.run_blocking();
    assert_run_ok(&outcome);
    let Ok(result) = outcome else {
        return GuestResult::empty();
    };
    GuestResult::from_container_result(result)
}

fn run_two_guests(cmd_a: &[&str], cmd_b: &[&str]) -> (GuestResult, GuestResult) {
    let _guest = common::guest_lock();
    let Some(carrier) = carrier_or_fail() else {
        return (GuestResult::empty(), GuestResult::empty());
    };
    let builder_a = configure_container(carrier.container(common::SMOKE_IMAGE), cmd_a);
    let builder_b = configure_container(carrier.container(common::SMOKE_IMAGE), cmd_b);

    let rt_res = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build();
    assert!(rt_res.is_ok(), "tokio runtime build failed");
    let Ok(rt) = rt_res else {
        return (GuestResult::empty(), GuestResult::empty());
    };

    let (out_a, out_b) = rt.block_on(async {
        let task_a = tokio::spawn(builder_a.run());
        let task_b = tokio::spawn(builder_b.run());
        let (out_a, out_b) = tokio::join!(task_a, task_b);
        (out_a, out_b)
    });

    assert!(out_a.is_ok(), "task_a join failed");
    assert!(out_b.is_ok(), "task_b join failed");
    let Ok(res_a) = out_a else {
        return (GuestResult::empty(), GuestResult::empty());
    };
    let Ok(res_b) = out_b else {
        return (GuestResult::empty(), GuestResult::empty());
    };

    assert_run_ok(&res_a);
    assert_run_ok(&res_b);
    let Ok(res_a) = res_a else {
        return (GuestResult::empty(), GuestResult::empty());
    };
    let Ok(res_b) = res_b else {
        return (GuestResult::empty(), GuestResult::empty());
    };

    (
        GuestResult::from_container_result(res_a),
        GuestResult::from_container_result(res_b),
    )
}

fn field<T: std::str::FromStr + Default>(out: &str, key: &str) -> T {
    let prefix = format!("{key}=");
    let mut found = None;
    for token in out.split_whitespace() {
        if let Some(parsed) = token
            .strip_prefix(&prefix)
            .and_then(|v| v.parse::<T>().ok())
        {
            found = Some(parsed);
            break;
        }
    }
    if found.is_none() {
        for line in out.lines() {
            if let Some(parsed) = line
                .strip_prefix(&prefix)
                .and_then(|v| v.trim().parse::<T>().ok())
            {
                found = Some(parsed);
                break;
            }
        }
    }
    assert!(
        found.is_some(),
        "field {key} not found in guest output:\n{out}"
    );
    found.unwrap_or_default()
}

fn fault_p99(out: impl AsRef<str>) -> u64 {
    let s = out.as_ref();
    let mut found = None;
    for token in s.split_whitespace() {
        if let Some(val) = token
            .strip_prefix("p99_us=")
            .or_else(|| token.strip_prefix("p99="))
        {
            if let Ok(parsed) = val.parse::<u64>() {
                found = Some(parsed);
                break;
            }
            if let Ok(f) = val.parse::<f64>() {
                found = Some(f.round() as u64);
                break;
            }
        }
    }
    if found.is_none() {
        for line in s.lines() {
            if let Some(val) = line
                .strip_prefix("p99_us=")
                .or_else(|| line.strip_prefix("p99="))
            {
                if let Ok(parsed) = val.trim().parse::<u64>() {
                    found = Some(parsed);
                    break;
                }
                if let Ok(f) = val.trim().parse::<f64>() {
                    found = Some(f.round() as u64);
                    break;
                }
            }
        }
    }
    assert!(
        found.is_some(),
        "p99 latency not found in guest output:\n{s}"
    );
    found.unwrap_or_default()
}

#[test]
fn children_run_concurrently() {
    // 4 children x 400 ms of spinning; with 4 exposed CPUs the wall time is
    // ~400 ms when they run in parallel and ~1600 ms when serialized.
    let out = run_guest(&["/p/forkstorm", "busy", "4", "400"]);
    let wall_ms: u64 = field(&out, "wall_ms");
    assert!(
        wall_ms < 800,
        "children serialized: wall_ms={wall_ms} ({out})"
    );
}

#[test]
fn fault_latency_is_independent_of_sibling_fork() {
    // Process A: fork storm (200 forks). Process B: fault loop. B's p99
    // round latency with A running must stay within 3x of B alone.
    let alone = fault_p99(run_guest(&["/p/forkstorm", "faulter", "50"]));
    let (a, b) = run_two_guests(
        &["/p/forkstorm", "busy", "200", "5"],
        &["/p/forkstorm", "faulter", "50"],
    );
    assert!(a.exit_ok());
    let contended = fault_p99(b);
    assert!(
        contended < alone * 3,
        "fault p99 {contended}us vs alone {alone}us"
    );
}
