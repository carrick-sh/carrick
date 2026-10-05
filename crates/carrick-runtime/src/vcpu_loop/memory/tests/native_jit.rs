//! Host capability admission for the native-code test instrument.
use native_syscall_slice::native::require_jit_write_protect;

pub(super) fn available_for(test: &str) -> bool {
    match require_jit_write_protect() {
        Ok(()) => true,
        Err(refusal) => {
            use std::io::Write;
            // Direct stderr survives libtest's default capture. This is an
            // unavailable fixture precondition, not a conformance observation.
            writeln!(
                std::io::stderr().lock(),
                "PRECONDITION_UNAVAILABLE[{test}::jit_write_protect]: \
                 pthread_jit_write_protect_supported_np() returned 0 ({refusal}); \
                 native execution assertions not run"
            )
            .expect("report named JIT fixture precondition");
            false
        }
    }
}

#[test]
fn publication_enforces_host_jit_capability() {
    use native_syscall_slice::{
        Memory,
        native::{Code, JitWriteProtectUnsupported, Layout},
    };

    // SAFETY: argument-free, read-only host capability query. This test also
    // runs with the API interposed to return zero, exercising typed refusal
    // through the real publisher even on a JIT-capable development host.
    let supported = unsafe { libc::pthread_jit_write_protect_supported_np() } != 0;
    assert_eq!(require_jit_write_protect().is_ok(), supported);
    let elf = super::native_carrier_elf(&[0xd4000001], 0x800000);
    let (memory, image) = Memory::load_elf(&elf).unwrap();
    for layout in [Layout::Slots, Layout::Compact] {
        let publication = Code::publish_with_layout(&image, &memory, layout);
        if supported {
            publication.expect("capable host must publish native code");
        } else {
            let Err(error) = publication else {
                panic!("unsupported host published native code");
            };
            assert!(
                error.is::<JitWriteProtectUnsupported>(),
                "publication must retain the typed JIT refusal: {error:?}",
            );
        }
    }
}
