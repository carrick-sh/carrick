//! The old executable must refuse the retired lane and name its replacement.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
#![allow(clippy::expect_used)]

#[test]
fn standalone_x86_entry_names_shared_kernel_replacement() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_carrick-vmm-kvm"))
        .args(["run-elf", "missing.elf"])
        .output()
        .expect("run retired x86 entry");
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert_eq!(
        output.stderr,
        b"standalone x86 run-elf is retired; use carrick run --platform linux/amd64 (shared CPL0 kernel)\n"
    );
}
