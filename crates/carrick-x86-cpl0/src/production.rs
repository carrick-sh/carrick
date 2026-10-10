//! Production CPL0 image entry.
#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

macro_rules! fixture_items {
    ($($item:item)*) => {};
}
#[cfg(target_os = "none")]
macro_rules! fixture_stmt {
    ($($tt:tt)*) => {};
}
#[cfg(target_os = "none")]
macro_rules! fixture_expr {
    ($($tt:tt)*) => {
        false
    };
}

#[cfg(target_os = "none")]
macro_rules! production_items { ($($item:item)*) => { $($item)* }; }
#[cfg(target_os = "none")]
fn signal_irq_return(
    frame: &mut carrick_el1::isa::x86::context::scheduler::InterruptFrame,
    xsave: &mut carrick_el1::isa::x86::context::scheduler::XsaveArea,
) {
    kernel::signal_irq_return(frame, xsave);
}

#[cfg(target_os = "none")]
fn signal_syscall_return(
    frame: &mut carrick_el1::isa::x86::context::native::NativeFrame,
    xsave: &mut carrick_el1::isa::x86::context::scheduler::XsaveArea,
) {
    kernel::signal_syscall_return(frame, xsave);
}

include!("entry.rs");
