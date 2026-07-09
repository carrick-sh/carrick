//! Darwin-native execution backend boundary.
//!
//! This module is the first concrete handoff point for the no-VMM backend: the
//! runtime has already selected `--exec-backend=native`, rejected cross-ISA
//! requests, and resolved the native page profile. The actual same-ISA launch
//! machinery is still gated off, so this boundary fails explicitly rather than
//! falling back to HVF.

use crate::page_profile::ExecutionPlan;
use crate::runtime::{RunResult, RuntimeError};
use carrick_spec::RunSpec;

pub(crate) fn run(spec: &RunSpec, plan: &ExecutionPlan) -> Result<RunResult, RuntimeError> {
    let Some(geometry) = plan.page_geometry.native_geometry() else {
        return Err(RuntimeError::Unsupported(
            "native Darwin backend selected without native page geometry".to_string(),
        ));
    };

    Err(RuntimeError::Unsupported(format!(
        "native Darwin backend selected: platform={:?} profile={:?} \
         host_page_size={} linux_page_size={}; launch unsupported: same-ISA \
         native process execution is not implemented yet; no HVF fallback was attempted",
        spec.platform, geometry.profile, geometry.host_page_size, geometry.linux_page_size
    )))
}
