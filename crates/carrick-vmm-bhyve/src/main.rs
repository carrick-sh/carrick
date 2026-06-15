//! `carrick-vmm-bhyve` binary — the bhyve x86_64 ELF runner entry point.
//!
//! Usage: `carrick-vmm-bhyve run-elf <static-x86_64-elf>`
//!
//! FreeBSD/x86_64 only (the binary is a no-op stub on all other hosts).
//! Mirrors `carrick-linux`'s `main.rs` pattern verbatim.

#[cfg(all(target_os = "freebsd", target_arch = "x86_64"))]
fn main() {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("run-elf") => {
            let Some(path) = args.next() else {
                eprintln!("usage: carrick-vmm-bhyve run-elf <x86_64-elf>");
                std::process::exit(2);
            };
            match carrick_vmm_bhyve::run_elf::run_elf_bhyve(&path) {
                Ok(code) => std::process::exit(code),
                Err(e) => {
                    eprintln!("carrick-vmm-bhyve: {e}");
                    std::process::exit(127);
                }
            }
        }
        _ => {
            eprintln!("usage: carrick-vmm-bhyve run-elf <x86_64-elf>");
            std::process::exit(2);
        }
    }
}

#[cfg(not(all(target_os = "freebsd", target_arch = "x86_64")))]
fn main() {
    eprintln!("carrick-vmm-bhyve is a FreeBSD/x86_64-only binary");
    std::process::exit(1);
}
