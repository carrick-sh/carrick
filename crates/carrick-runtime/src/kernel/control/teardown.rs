//! Receipt of one container's teardown.

use crate::kernel::container::{CarrierScopeId, ContainerId, RunId};

/// Receipt of one container's teardown.
///
/// Plain settled facts, not a handle: the kernel produces it when it retires a
/// container root, and the carrier only reads it (and fills `mounts_dropped`
/// from its own mount retirement). It therefore belongs to the kernel, which
/// is what counts the tasks and releases the pid region — a receipt the
/// carrier owned would have made the kernel name the carrier to answer its own
/// question.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContainerTeardown {
    pub id: ContainerId,
    pub carrier_scope_id: CarrierScopeId,
    pub run_id: RunId,
    pub tasks_reaped: usize,
    pub mounts_dropped: usize,
    pub pid_region_released: bool,
}
