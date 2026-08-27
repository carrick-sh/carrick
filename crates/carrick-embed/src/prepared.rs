use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use carrick_engine::ResolveWarning;
use carrick_runtime::Runtime;
use carrick_runtime::container::{make_id, short_id};
use carrick_runtime::kernel::container::{LaunchContext, RunId};
use carrick_runtime::prepare::RuntimeExtensions;
use carrick_spec::RunSpec;

use crate::error::Phase;
use crate::result::CapturedStreams;
use crate::shared_buffer::{SharedBuffer, SharedBufferError, SharedBufferLease};
use crate::{ContainerResult, EmbedError};

/// Inspect the plan, then [`Self::execute`] it exactly once.
pub struct PreparedContainer {
    spec: RunSpec,
    warnings: Vec<ResolveWarning>,
    extensions: RuntimeExtensions,
    captured: CapturedStreams,
    launch: LaunchContext,
    generation: u64,
    retired: Arc<AtomicBool>,
    current_generation: Arc<AtomicU64>,
    shared_buffers: Vec<(String, SharedBuffer)>,
}

impl PreparedContainer {
    pub(crate) fn new(
        spec: RunSpec,
        warnings: Vec<ResolveWarning>,
        extensions: RuntimeExtensions,
        captured: CapturedStreams,
        shared_buffers: Vec<(String, SharedBuffer)>,
    ) -> Self {
        let launch = embedded_launch_context();
        let generation = 1;
        let retired = Arc::new(AtomicBool::new(false));
        let current_generation = Arc::new(AtomicU64::new(generation));
        Self {
            spec,
            warnings,
            extensions,
            captured,
            launch,
            generation,
            retired,
            current_generation,
            shared_buffers,
        }
    }

    /// The fully merged spec the runtime will execute.
    pub fn run_spec(&self) -> &RunSpec {
        &self.spec
    }

    /// Warnings emitted during request merge (e.g. named `--user` fallback).
    pub fn warnings(&self) -> &[ResolveWarning] {
        &self.warnings
    }

    /// The launch identity assigned to this container.
    pub fn launch(&self) -> &LaunchContext {
        &self.launch
    }

    /// Obtain an authenticated, generation-stamped lease for the named shared buffer.
    pub fn shared_buffer_lease(&self, name: &str) -> Result<SharedBufferLease, SharedBufferError> {
        for (n, buf) in &self.shared_buffers {
            if n == name {
                return Ok(buf.lease_with_witness(
                    self.launch.run_id.clone(),
                    self.launch.container_id,
                    self.generation,
                    Arc::clone(&self.retired),
                    Arc::clone(&self.current_generation),
                ));
            }
        }
        Err(SharedBufferError::NotFound(name.to_string()))
    }

    /// Prepare the container on the kernel graph and run it to completion on
    /// the calling thread. Blocking; see [`crate::ContainerBuilder::run`].
    pub fn execute(self) -> Result<ContainerResult, EmbedError> {
        let launch = self.launch;
        let retired = Arc::clone(&self.retired);
        let prepared = Runtime::prepare(&self.spec, launch, self.extensions).map_err(|error| {
            retired.store(true, Ordering::Release);
            EmbedError::from_runtime(error, Phase::Prepare)
        })?;
        let result = prepared.execute();
        retired.store(true, Ordering::Release);
        let result = result.map_err(crate::entitlement::classify)?;
        Ok(ContainerResult::from_run_result(result, self.captured))
    }
}

/// The run id an embedded container is scoped under: an explicit
/// `CARRICK_RUN_ID` (a caller's grouping override), else a fresh 12-hex short
/// id from the `carrick ps` id scheme. Same precedence as `carrick run`
/// (`crates/carrick-cli/src/commands.rs:979-998`, minus the `--name` rung the
/// builder does not have). The id is what `scripts/sudo/kill.sh <run-id>`
/// keys on through the carrier's proctitle; today
/// `dispatch/proctitle.rs:71` stamps that title from the ENV var itself, so an
/// explicit `CARRICK_RUN_ID` is reapable now and a generated one becomes
/// reapable once Phase B routes the stamp through `LaunchContext::run_id`.
pub(crate) fn run_id_from(explicit: Option<String>) -> String {
    match explicit.filter(|id| !id.is_empty()) {
        Some(id) => id,
        None => {
            let entropy = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0);
            // `make_id` takes two bare entropy words by design (container.rs:791-801);
            // the host pid is a SEED here, never an identity.
            short_id(&make_id(u64::from(std::process::id()), entropy)).to_string()
        }
    }
}

fn embedded_launch_context() -> LaunchContext {
    LaunchContext::unmanaged(RunId::new(run_id_from(
        std::env::var("CARRICK_RUN_ID").ok(),
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_explicit_run_id_is_used_verbatim() {
        assert_eq!(
            run_id_from(Some("embed-gate-7".to_string())),
            "embed-gate-7"
        );
    }

    #[test]
    fn an_absent_or_empty_run_id_becomes_a_twelve_hex_short_id() {
        for explicit in [None, Some(String::new())] {
            let id = run_id_from(explicit);
            assert_eq!(id.len(), 12, "{id}");
            assert!(id.chars().all(|c| c.is_ascii_hexdigit()), "{id}");
        }
    }

    #[test]
    fn generated_run_ids_are_not_constant() {
        // Two generations in the same process differ by their nanosecond
        // entropy; `make_id` avalanches both seeds into the short-id word.
        let first = run_id_from(None);
        std::thread::sleep(std::time::Duration::from_millis(2));
        let second = run_id_from(None);
        assert_ne!(first, second);
    }
}
