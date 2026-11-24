//! Linux personality client of the neutral `carrick-el1` runtime: Linux ABI
//! decoding and result mapping, and the EL1 image binary (`entry.rs`).
//!
//! The same modules compile into both guest images; native operations are
//! supplied by the selected architecture backend.
#![cfg_attr(target_os = "none", no_std)]
#[cfg(target_os = "none")]
extern crate alloc as rust_alloc;
#[cfg(not(target_os = "none"))]
extern crate alloc as rust_alloc;
pub mod aarch64_process;
#[cfg(any(test, feature = "host-test"))]
pub mod aarch64_process_tests;
pub mod common_entry;
pub mod cow_resolver;
pub mod crossing_operand;
pub mod dispatch;
pub mod exec_stage;
pub mod exec_successor;
pub mod file;
pub mod file_table;
pub mod fork_loan;
pub mod inotify;
pub mod ipc;
pub mod lifecycle;
pub mod mm_portal;
mod native_diagnostic;
pub mod native_fork_refusal;
pub mod native_process_custody;
pub mod native_process_entry;
pub mod native_process_runtime;
pub mod native_process_signals;
pub mod native_run_failure;
pub mod process_owner;
pub mod retired_spaces;
pub mod sched;
pub mod signal_delivery;
pub mod thread_setup;

#[cfg(any(
    test,
    feature = "host-test",
    all(target_os = "none", target_arch = "aarch64")
))]
pub mod arm_signal;
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub mod x86_signal;

#[cfg(test)]
#[path = "reservation_decoder_tests.rs"]
mod decoder_tests;
#[cfg(test)]
mod native_ownership_tests;

/// DIAGNOSTICS ONLY (never lands): the last site that produced an invalid
/// completion route.
pub static DIAG_INVALID_SITE: core::sync::atomic::AtomicPtr<core::panic::Location<'static>> =
    core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());

#[track_caller]
pub(crate) fn diag_invalid() -> carrick_personality_linux::dispatch::CompletionRoute {
    let loc: &'static core::panic::Location<'static> = core::panic::Location::caller();
    DIAG_INVALID_SITE.store(
        loc as *const _ as *mut _,
        core::sync::atomic::Ordering::SeqCst,
    );
    carrick_personality_linux::dispatch::CompletionRoute::InvalidCompletion
}

/// DIAGNOSTICS ONLY (never lands): the error behind the last invalid route.
pub static DIAG_INVALID_ERR: core::sync::atomic::AtomicPtr<rust_alloc::string::String> =
    core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());

#[track_caller]
pub(crate) fn diag_invalid_err(
    error: &dyn core::fmt::Debug,
) -> carrick_personality_linux::dispatch::CompletionRoute {
    let text = rust_alloc::boxed::Box::new(rust_alloc::format!("{error:?}"));
    DIAG_INVALID_ERR.store(
        rust_alloc::boxed::Box::leak(text),
        core::sync::atomic::Ordering::SeqCst,
    );
    diag_invalid()
}

/// DIAGNOSTICS ONLY (never lands).
pub(crate) fn diag_note(text: &str) {
    let text = rust_alloc::boxed::Box::new(rust_alloc::string::String::from(text));
    DIAG_INVALID_ERR.store(
        rust_alloc::boxed::Box::leak(text),
        core::sync::atomic::Ordering::SeqCst,
    );
}

/// DIAGNOSTICS ONLY (never lands): stop the x86 carrier at the caller with the last note.
#[track_caller]
pub(crate) fn diag_fatal_here() {
    #[cfg(all(target_os = "none", target_arch = "x86_64"))]
    {
        let loc = core::panic::Location::caller();
        let mut report = carrick_el1_abi::PanicReport::new(loc.file(), loc.line(), loc.column());
        let e = DIAG_INVALID_ERR.load(core::sync::atomic::Ordering::SeqCst);
        {
            use core::fmt::Write;
            let mut w = report.message_writer();
            if e.is_null() {
                let _ = w.write_str("diag: no note");
            } else {
                let _ = w.write_str(unsafe { &*e });
            }
        }
        carrick_el1::isa::x86::transport::publish_fatal_report(
            carrick_el1_abi::PanicReportKind::FatalSite,
            &report,
        )
    }
}
