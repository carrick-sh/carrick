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
