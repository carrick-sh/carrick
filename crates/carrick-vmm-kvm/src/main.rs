//! `carrick-vmm-kvm` binary — the KVM MVP entry point.
//!
//! On aarch64: `carrick-vmm-kvm run-elf <freestanding-aarch64-elf>`
//! On x86_64: use `carrick run --platform linux/amd64` (shared CPL0 kernel).
//!
//! Self-contained (no `carrick-runtime` dependency) so it compiles and links
//! for `aarch64-unknown-linux-gnu` independently of the macOS dispatch layer.
//! `just kvm-smoke` builds this and runs it against the `hello-aarch64` fixture.

// aarch64 Linux: use the MMIO-sentinel KVM trap engine.
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
fn main() {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("run-elf") => {
            let Some(path) = args.next() else {
                eprintln!("usage: carrick-vmm-kvm run-elf <aarch64-elf>");
                std::process::exit(2);
            };
            match carrick_vmm_kvm::run_elf_kvm(&path) {
                Ok(code) => std::process::exit(code),
                Err(e) => {
                    eprintln!("carrick-vmm-kvm: {e}");
                    std::process::exit(127);
                }
            }
        }
        _ => {
            eprintln!("usage: carrick-vmm-kvm run-elf <aarch64-elf>");
            std::process::exit(2);
        }
    }
}

// The standalone x86 service loop is retired; guest PTEs belong to CPL0.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn main() {
    eprintln!(
        "standalone x86 run-elf is retired; use carrick run --platform linux/amd64 (shared CPL0 kernel)"
    );
    std::process::exit(1);
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("carrick-vmm-kvm is a Linux/KVM-only binary");
    std::process::exit(1);
}
