//! Failure evidence shared by the signed harness and VM-free regression tests.
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use carrick_kernel::kernel::debug::{self, AbortReason, PostMortem, Truncated};
use tracing_subscriber::EnvFilter;

static LOG: OnceLock<PathBuf> = OnceLock::new();

pub(super) fn filter(value: Option<&str>) -> EnvFilter {
    value
        .map(EnvFilter::new)
        .unwrap_or_else(|| EnvFilter::new("warn"))
}

pub(super) fn subscriber(
    file: std::fs::File,
    filter: EnvFilter,
) -> impl tracing::Subscriber + Send + Sync {
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(false)
        .with_writer(std::sync::Mutex::new(file))
        .finish()
}

/// Install once per test binary, before creating any carrier worker threads.
/// Synchronous warn/error writes survive panic, abort and watchdog reaping;
/// debug/info callsites stay disabled unless the operator requests them.
pub fn install(root: &Path, run_id: &str) {
    LOG.get_or_init(|| {
        let dir = root.join("target/embed-logs").join(run_id);
        std::fs::create_dir_all(&dir).expect("create embed log directory");
        let path = dir.join(format!("embed-{}.log", std::process::id()));
        let file = std::fs::File::create(&path).expect("create embed log");
        tracing::subscriber::set_global_default(subscriber(
            file,
            filter(std::env::var("RUST_LOG").ok().as_deref()),
        ))
        .expect("install embed tracing subscriber");
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            replay();
            previous(info);
        }));
        path
    });
}

/// Replay retained warnings only on failure, leaving successful runs quiet.
pub fn replay() {
    if let Some(path) = LOG.get() {
        eprintln!("embed log: {}", path.display());
        match std::fs::read_to_string(path) {
            Ok(log) => eprint!("{log}"),
            Err(error) => eprintln!("cannot read embed log: {error}"),
        }
    }
}

/// Capture independently of the runner's abort boundary: a wedged runner
/// cannot promise to service a latched abort. The existing debug client bounds
/// the exchange; PostMortem owns collection, degradation and file formats.
pub fn persist_watchdog(run_id: &str, dir: &Path) -> std::io::Result<PathBuf> {
    let mut capture = match debug::capture(run_id) {
        Ok(capture) => capture,
        Err(error) => {
            let mut capture = PostMortem::capture(
                None,
                AbortReason::LiveCapture {
                    run_id: run_id.to_owned(),
                },
                Some(run_id.to_owned()),
            );
            capture.truncated.push(Truncated {
                section: "debug_server".to_owned(),
                reason: error.to_string(),
            });
            capture
        }
    };
    // Preserve the watchdog's additional IPC / owed-host-work census in the
    // same PostMortem, rather than printing evidence which dies with stderr.
    if let Some(zone) = carrick_el1_abi::zone_tables() {
        let mut census = String::new();
        let _ = zone.write_census(&mut census);
        if let Some(region) =
            carrick_el1_abi::ipc_window_host().and_then(|window| window.attach().ok())
        {
            let _ = carrick_el1_abi::ipc::write_ipc_wait_census(zone, &region, &mut census);
            let _ = region.write_host_wake_census(&mut census);
        }
        let _ = carrick_el1_abi::write_current_task_census(&mut census);
        capture.zone_census = Some(census);
    } else if capture.zone_census.is_none() && capture.physical.is_none() {
        capture.truncated.push(Truncated {
            section: "zone_census".to_owned(),
            reason: "no zone or physical capture provider is available".to_owned(),
        });
    }
    capture.write_to_dir(dir)
}
