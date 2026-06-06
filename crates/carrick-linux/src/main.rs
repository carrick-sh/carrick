//! `carrick-linux` binary — the KVM aarch64 MVP entry point.
//!
//! Usage: `carrick-linux run-elf <freestanding-aarch64-elf>`
//!
//! Self-contained (no `carrick-runtime` dependency) so it compiles and links
//! for `aarch64-unknown-linux-gnu` independently of the macOS dispatch layer.
//! `just kvm-smoke` builds this and runs it against the `hello-aarch64` fixture.

#[cfg(target_os = "linux")]
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

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("carrick-linux is a Linux/KVM-only binary");
    std::process::exit(1);
}
