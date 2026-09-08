//! Typed failure surface of an embedded run.

use std::sync::Arc;

use carrick_runtime::dispatch::DispatchError;
use carrick_runtime::kernel::debug::PostMortem;
use carrick_runtime::runtime::RuntimeError;
use carrick_runtime::trap::TrapError;

use crate::{ContainerId, Signal};

/// The `hv_return_t` of `HV_DENIED` as applevisor's `Display` prints it
/// (`operation not allowed by the system (error 0xfae94007)`), which
/// `carrick-vmm-hvf::trap::hvf_error` copies verbatim into
/// [`TrapError::Hypervisor`]. There is no typed variant to match on today.
const HV_DENIED_HEX: &str = "0xfae94007";

/// Why an embedded run did not produce a [`crate::ContainerResult`].
///
/// Linux outcomes delivered to the guest (errno denials, faults) are never an
/// `EmbedError`; a guest that exits non-zero is an `Ok(ContainerResult)` and
/// becomes [`EmbedError::Guest`] only through
/// [`crate::ContainerResult::ensure_success`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum EmbedError {
    /// Another explicit or implicit carrier still owns this host process.
    #[error("an independent Carrick carrier is already active in this host process")]
    CarrierAlreadyActive,
    /// The selected carrier has stopped admitting new containers.
    #[error("the Carrick carrier is closing")]
    CarrierClosing,
    /// The selected carrier has completed shutdown.
    #[error("the Carrick carrier is closed")]
    CarrierClosed,
    /// Carrier-wide ownership or teardown failed.
    #[error("the Carrick carrier failed: {reason}")]
    CarrierFailed { reason: String },
    /// Image reference parsing, pull/store resolution, or the engine's
    /// request→spec merge failed (`Engine::resolve` reports all three as one
    /// `anyhow::Error`).
    #[error("image resolution failed: {0:#}")]
    Image(anyhow::Error),
    /// The builder was given something the runtime could never honour.
    #[error("invalid container configuration: {0}")]
    Config(String),
    /// `Runtime::prepare` failed; everything it published was rolled back.
    #[error("container preparation failed: {0}")]
    Prepare(#[source] RuntimeError),
    /// The hypervisor refused the calling executable (`HV_DENIED`).
    #[error(
        "hypervisor entitlement denied (HV_DENIED 0xfae94007): the executable that embeds \
         carrick must be codesigned with scripts/entitlements.plist (AGENTS.md Rule 0)"
    )]
    Entitlement,
    /// A completed run whose guest did not succeed (see `ensure_success`).
    #[error("guest terminated unsuccessfully: exit_code={exit_code}, signal={signal:?}")]
    Guest {
        exit_code: i32,
        signal: Option<Signal>,
    },
    /// The guest hit `max_traps` without exiting.
    #[error("guest hit the trap limit without exiting")]
    TrapLimit,
    /// Runtime infrastructure failed after preparation succeeded.
    #[error("runtime failure: {0}")]
    Runtime(#[source] RuntimeError),
    /// A host syscall interceptor panicked while serving this container.
    #[error("syscall interceptor panicked in container {container_id:?}")]
    InterceptorPanicked { container_id: ContainerId },
    /// The blocking execute task panicked (`tokio::task::JoinError`).
    #[error("the execute task panicked: {0}")]
    ExecutePanicked(String),
    /// A judge proved this run could never finish, the kernel was frozen and
    /// captured in process, and every unpublished job was completed.
    ///
    /// This is the ONE fail-closed sink. Before it existed, the same states
    /// ended as a hang (`ContainerJobGroup::join` waiting on a result nobody
    /// could publish), a carrier `abort()` with no kernel-graph view, or a
    /// guest signal the guest reported as its own bug. `post_mortem` carries
    /// the kernel graph, its findings, and the event ring as of the abort — so
    /// a wedge is a returned value, not a debugging session.
    #[error("kernel aborted: {reason}")]
    KernelAborted {
        reason: String,
        post_mortem: Arc<PostMortem>,
    },
}

/// Which runtime call produced a [`RuntimeError`]; decides `Prepare` vs
/// `Runtime` for errors that are not otherwise special-cased.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Phase {
    Prepare,
    Execute,
}

impl EmbedError {
    pub(crate) fn from_runtime(error: RuntimeError, phase: Phase) -> Self {
        match error {
            RuntimeError::CarrierAlreadyActive => Self::CarrierAlreadyActive,
            RuntimeError::CarrierClosing => Self::CarrierClosing,
            RuntimeError::CarrierClosed => Self::CarrierClosed,
            RuntimeError::CarrierFailed(reason) => Self::CarrierFailed { reason },
            RuntimeError::KernelAborted {
                reason,
                post_mortem,
            } => Self::KernelAborted {
                reason,
                post_mortem,
            },
            RuntimeError::ExplicitCarrierBindingRequired => Self::Config(
                "an explicit carrier is active; use carrier.container(image)".to_owned(),
            ),
            RuntimeError::TrapLimitExceeded { .. } => Self::TrapLimit,
            RuntimeError::Dispatch(DispatchError::InterceptorPanicked { container_id }) => {
                Self::InterceptorPanicked { container_id }
            }
            RuntimeError::Trap(TrapError::Hypervisor(ref message))
                if message.contains(HV_DENIED_HEX) =>
            {
                Self::Entitlement
            }
            other if crate::entitlement::is_hv_denied(&other) => Self::Entitlement,
            other => match phase {
                Phase::Prepare => Self::Prepare(other),
                Phase::Execute => Self::Runtime(other),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use carrick_runtime::runtime::RuntimeError;
    use carrick_runtime::trap::TrapError;

    #[test]
    fn trap_limit_maps_to_trap_limit_in_both_phases() {
        for phase in [Phase::Prepare, Phase::Execute] {
            let error = RuntimeError::TrapLimitExceeded { max_traps: 5 };
            assert!(matches!(
                EmbedError::from_runtime(error, phase),
                EmbedError::TrapLimit
            ));
        }
    }

    #[test]
    fn interceptor_panic_maps_to_the_typed_container_error_in_both_phases() {
        for phase in [Phase::Prepare, Phase::Execute] {
            let expected = crate::ContainerId::allocate();
            let error = RuntimeError::Dispatch(
                carrick_runtime::dispatch::DispatchError::InterceptorPanicked {
                    container_id: expected,
                },
            );
            assert!(matches!(
                EmbedError::from_runtime(error, phase),
                EmbedError::InterceptorPanicked { container_id } if container_id == expected
            ));
        }
    }

    /// `carrick-vmm-hvf`'s `hvf_error` stringifies applevisor's Display, which
    /// prints `HV_DENIED` as `operation not allowed by the system (error 0xfae94007)`.
    #[test]
    fn hv_denied_maps_to_entitlement_regardless_of_phase() {
        for phase in [Phase::Prepare, Phase::Execute] {
            let error = RuntimeError::Trap(TrapError::Hypervisor(
                "operation not allowed by the system (error 0xfae94007)".to_string(),
            ));
            assert!(matches!(
                EmbedError::from_runtime(error, phase),
                EmbedError::Entitlement
            ));
        }
    }

    #[test]
    fn other_hypervisor_errors_keep_their_phase() {
        let make = || {
            RuntimeError::Trap(TrapError::Hypervisor(
                "hypervisor fault (error 0xfae94003)".to_string(),
            ))
        };
        assert!(matches!(
            EmbedError::from_runtime(make(), Phase::Prepare),
            EmbedError::Prepare(RuntimeError::Trap(_))
        ));
        assert!(matches!(
            EmbedError::from_runtime(make(), Phase::Execute),
            EmbedError::Runtime(RuntimeError::Trap(_))
        ));
    }

    #[test]
    fn configuration_refusals_keep_their_phase() {
        let make = || RuntimeError::Configuration("knob removed".to_string());
        assert!(matches!(
            EmbedError::from_runtime(make(), Phase::Prepare),
            EmbedError::Prepare(RuntimeError::Configuration(_))
        ));
        assert!(matches!(
            EmbedError::from_runtime(make(), Phase::Execute),
            EmbedError::Runtime(RuntimeError::Configuration(_))
        ));
    }

    #[test]
    fn entitlement_display_names_the_fix() {
        let text = EmbedError::Entitlement.to_string();
        assert!(text.contains("0xfae94007"), "{text}");
        assert!(text.contains("entitlements.plist"), "{text}");
    }
}
