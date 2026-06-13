//! `carrick-linux` binary — the KVM MVP entry point.
//!
//! On aarch64: `carrick-linux run-elf <freestanding-aarch64-elf>`
//! On x86_64:  `carrick-linux run-elf <freestanding-x86_64-elf>` (Task 4).
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
                eprintln!("usage: carrick-linux run-elf <aarch64-elf>");
                std::process::exit(2);
            };
            match carrick_linux::run_elf_kvm(&path) {
                Ok(code) => std::process::exit(code),
                Err(e) => {
                    eprintln!("carrick-linux: {e}");
                    std::process::exit(127);
                }
            }
        }
        _ => {
            eprintln!("usage: carrick-linux run-elf <aarch64-elf>");
            std::process::exit(2);
        }
    }
}

// x86_64 Linux: run-elf entry point is wired in Task 4.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn main() {
    eprintln!("carrick-linux x86_64: run-elf not yet implemented (Task 4)");
    std::process::exit(1);
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("carrick-linux is a Linux/KVM-only binary");
    std::process::exit(1);
}
