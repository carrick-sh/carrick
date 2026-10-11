#![cfg_attr(target_os = "none", no_std)]

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
extern crate alloc as rust_alloc;

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub mod entry;
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub mod initial_boot;
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub mod native_execution;
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub mod native_irq;
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub mod personality;
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub mod table_span;

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub use personality::{
    CallContext, ControlFlow, EntryDecodeError, ExecutionContext, OwnedContinuation, Personality,
    PersonalityAbi, TerminationKind, TerminationRequest, TerminationStatus, UserCopy,
};

#[macro_export]
macro_rules! export_carrier {
    ($personality:ty) => {
        #[cfg(all(target_os = "none", target_arch = "x86_64"))]
        // SAFETY: no_mangle hardware entry called by assembly on SYSCALL.
        #[unsafe(no_mangle)]
        pub extern "C" fn carrick_x86_enter(
            frame: &mut $crate::entry::NativeFrame,
            binding: &$crate::entry::CpuBinding,
            early_xstate: &mut $crate::entry::XsaveArea,
        ) {
            $crate::entry::carrier_enter::<$personality>(frame, binding, early_xstate);
        }

        #[cfg(all(target_os = "none", target_arch = "x86_64"))]
        // SAFETY: no_mangle hardware return validator called by assembly before SYSRET/IRET.
        #[unsafe(no_mangle)]
        pub extern "C" fn carrick_x86_validate_return(
            frame: &mut $crate::entry::NativeFrame,
            xsave: &mut $crate::entry::XsaveArea,
        ) {
            $crate::entry::carrier_validate_return::<$personality>(frame, xsave);
        }

        #[cfg(all(target_os = "none", target_arch = "x86_64"))]
        // SAFETY: no_mangle hardware IRQ entry called by assembly interrupt stub.
        #[unsafe(no_mangle)]
        // SAFETY: assembly stub provides valid, non-aliased frame and xsave pointers.
        pub unsafe extern "C" fn carrick_x86_receive_irq(
            vector: u32,
            frame: *mut $crate::entry::InterruptFrame,
            xsave: *mut $crate::entry::XsaveArea,
        ) {
            // SAFETY: caller guarantees valid interrupt frame and xsave pointers.
            unsafe {
                $crate::native_irq::carrier_receive_irq::<$personality>(vector, frame, xsave);
            }
        }

        #[cfg(all(target_os = "none", target_arch = "x86_64"))]
        // SAFETY: no_mangle hardware #PF handler called by assembly on vector 14.
        #[unsafe(no_mangle)]
        pub extern "C" fn carrick_x86_handle_user_page_fault(
            frame: &mut $crate::entry::PageFaultStack,
            fpstate: &$crate::entry::XsaveArea,
        ) -> u64 {
            <$personality as $crate::personality::Personality>::handle_page_fault(frame, fpstate)
        }

        #[cfg(all(target_os = "none", target_arch = "x86_64"))]
        // SAFETY: no_mangle boot entry called by initial boot header stub.
        #[unsafe(no_mangle)]
        pub extern "C" fn carrick_x86_initial_boot(request_va: u64) -> ! {
            $crate::initial_boot::carrier_initial_boot::<$personality>(request_va)
        }

        #[cfg(all(target_os = "none", target_arch = "x86_64"))]
        // SAFETY: no_mangle peer boot entry called by initial boot header stub.
        #[unsafe(no_mangle)]
        pub extern "C" fn carrick_x86_peer_boot() -> ! {
            $crate::initial_boot::carrier_peer_boot::<$personality>()
        }

        #[cfg(all(target_os = "none", target_arch = "x86_64"))]
        // SAFETY: no_mangle fixture hold hook invoked by x86 kernel shootdown.
        #[unsafe(no_mangle)]
        pub extern "Rust" fn carrick_fixture_hold_check(
            table: &carrick_el1::isa::x86::context::native::ShootdownTable,
            target_mode: u32,
        ) -> Result<(), carrick_el1::isa::ArchError> {
            $crate::personality::Personality::fixture_hold_check(
                &<$personality as core::default::Default>::default(),
                table,
                target_mode,
            )
        }

        #[cfg(all(target_os = "none", target_arch = "x86_64"))]
        #[panic_handler]
        fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
            $crate::entry::halt()
        }
    };
}
