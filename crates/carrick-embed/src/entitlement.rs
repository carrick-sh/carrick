//! `HV_DENIED` classification: the one runtime failure that means "this
//! EXECUTABLE is not entitled", not "the guest failed".

use crate::EmbedError;
use carrick_runtime::runtime::RuntimeError;

/// `HV_DENIED` exactly as applevisor prints it (`error {:#08x}`).
pub(crate) const HV_DENIED_MARKER: &str = "(error 0xfae94007)";

/// True when `err` is Hypervisor.framework refusing the VM because the
/// calling executable has no hypervisor entitlement.
pub(crate) fn is_hv_denied(err: &RuntimeError) -> bool {
    err.to_string().contains(HV_DENIED_MARKER) || err.to_string().contains("0xfae94007")
}

/// The single `RuntimeError` -> `EmbedError` lowering: the entitlement case
/// gets its own variant; everything else stays a runtime failure.
pub(crate) fn classify(err: RuntimeError) -> EmbedError {
    EmbedError::from_runtime(err, crate::error::Phase::Execute)
}

#[cfg(test)]
mod tests {
    use super::*;
    use carrick_runtime::trap::TrapError;

    const APPLEVISOR_DENIED: &str = "operation not allowed by the system (error 0xfae94007)";

    #[test]
    fn typed_trap_hv_denied_is_entitlement() {
        let err = RuntimeError::Trap(TrapError::Hypervisor(APPLEVISOR_DENIED.to_owned()));
        assert!(is_hv_denied(&err), "{err}");
        assert!(matches!(classify(err), EmbedError::Entitlement));
    }

    #[test]
    fn dispatcher_rewrapped_hv_denied_is_entitlement() {
        let inner = RuntimeError::Trap(TrapError::Hypervisor(APPLEVISOR_DENIED.to_owned()));
        let err = RuntimeError::FsBackend(anyhow::anyhow!(
            "failed to run ELF from dispatcher: {}",
            inner
        ));
        assert!(is_hv_denied(&err), "{err}");
        assert!(matches!(classify(err), EmbedError::Entitlement));
    }

    #[test]
    fn other_failures_stay_runtime_errors() {
        let busy = RuntimeError::Trap(TrapError::Hypervisor(
            "owning resource is busy (error 0xfae94002)".to_owned(),
        ));
        assert!(!is_hv_denied(&busy));
        assert!(matches!(classify(busy), EmbedError::Runtime(_)));
        let limit = RuntimeError::TrapLimitExceeded { max_traps: 7 };
        assert!(!is_hv_denied(&limit));
        assert!(matches!(classify(limit), EmbedError::TrapLimit));
    }
}
