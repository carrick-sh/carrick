//! Failure-only rendering through the existing bounded EL1 diagnostic crossing.

#[cfg(test)]
std::thread_local! {
    static CAPTURE: std::cell::RefCell<Option<Vec<String>>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub(crate) fn capture() {
    CAPTURE.with(|capture| assert!(capture.borrow_mut().replace(Vec::new()).is_none()));
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
pub(crate) fn take() -> Vec<String> {
    CAPTURE.with(|capture| capture.borrow_mut().take().unwrap())
}

#[inline(never)]
pub(crate) fn emit(arguments: core::fmt::Arguments<'_>) {
    #[cfg(test)]
    CAPTURE.with(|capture| {
        if let Some(lines) = capture.borrow_mut().as_mut() {
            lines.push(arguments.to_string());
        }
    });
    #[cfg(all(target_os = "none", target_arch = "aarch64"))]
    {
        let mut diagnostic = carrick_el1_abi::NativeDiagnostic::new();
        let _ = core::fmt::write(&mut diagnostic, arguments);
        carrick_el1::isa::aarch64::cross_hvc_native_diagnostic(&diagnostic);
    }
    #[cfg(not(any(test, all(target_os = "none", target_arch = "aarch64"))))]
    let _ = arguments;
}

#[cfg(any(test, all(target_os = "none", target_arch = "aarch64")))]
#[inline(never)]
pub(crate) fn signal_terminal(
    frame: &carrick_el1_abi::TrapFrame,
    control: &carrick_el1_abi::ThreadControlSlot,
    entry: (u64, u64),
) {
    if let Some((signal, code, address, true)) = control.synchronous_fault() {
        emit(format_args!(
            "signal-terminal entry-esr={:#x} pc={:#x} far={address:#x} entry-far={:#x} signal={} code={code} blocked={:#x}",
            entry.0,
            frame.elr,
            entry.1,
            signal.number(),
            control.blocked().0,
        ));
    }
}

/// The shared fault policy left an owner's fault with no supply selected:
/// the record names the deciding branch before a signal answers it (#2668).
/// Failure-only: a selected supply or an owner wait never reaches here.
#[cfg(any(test, all(target_os = "none", target_arch = "aarch64")))]
#[inline(never)]
pub(crate) fn fault_verdict(
    frame: &carrick_el1_abi::TrapFrame,
    mm: u64,
    native: bool,
    verdict: carrick_el1::fault::FaultVerdict,
) {
    emit(format_args!(
        "fault-verdict esr={:#x} pc={:#x} far={:#x} mm={mm} native={native} code={:#x} verdict={verdict:?}",
        frame.esr,
        frame.elr,
        frame.far,
        verdict.code(),
    ));
}

/// The host refused an owner fault service: the ring answers with SIGSEGV.
#[inline(never)]
pub(crate) fn fault_refused(
    fault: carrick_guest_arch::FaultInfo,
    task: carrick_sched_core::process::TaskKey,
) {
    emit(format_args!(
        "fault-refused far={:#x} present={} access={:?} {task}",
        fault.address.raw(),
        fault.present,
        fault.access,
    ));
}
