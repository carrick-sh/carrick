//! A resolved run, one step from execution: the merged `RunSpec` plus the
//! runtime extensions (stdio sink today; VFS mounts, observers, clock modes in
//! later phases) that `Runtime::prepare` installs and `PreparedRun::execute`
//! seals.

use std::time::{SystemTime, UNIX_EPOCH};

use carrick_engine::ResolveWarning;
use carrick_runtime::Runtime;
use carrick_runtime::container::{make_id, short_id};
use carrick_runtime::kernel::container::{LaunchContext, RunId};
use carrick_runtime::prepare::RuntimeExtensions;
use carrick_spec::RunSpec;

use crate::error::Phase;
use crate::result::CapturedStreams;
use crate::{ContainerResult, EmbedError};

/// Inspect the plan, then [`Self::execute`] it exactly once.
pub struct PreparedContainer {
    spec: RunSpec,
    warnings: Vec<ResolveWarning>,
    extensions: RuntimeExtensions,
    captured: CapturedStreams,
}

impl PreparedContainer {
    pub(crate) fn new(
        spec: RunSpec,
        warnings: Vec<ResolveWarning>,
        extensions: RuntimeExtensions,
        captured: CapturedStreams,
    ) -> Self {
        Self {
            spec,
            warnings,
            extensions,
            captured,
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

    /// Prepare the container on the kernel graph and run it to completion on
    /// the calling thread. Blocking; see [`crate::ContainerBuilder::run`].
    pub fn execute(self) -> Result<ContainerResult, EmbedError> {
        let launch = embedded_launch_context();
        let prepared = Runtime::prepare(&self.spec, launch, self.extensions)
            .map_err(|error| EmbedError::from_runtime(error, Phase::Prepare))?;
        let result = prepared.execute().map_err(crate::entitlement::classify)?;
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
