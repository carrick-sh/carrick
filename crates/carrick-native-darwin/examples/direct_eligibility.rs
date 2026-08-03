//! Which real guest binaries qualify for tier D today?
//!
//! Runs the fail-closed eligibility scan over ELF files named on the command
//! line and prints the verdict for each. This is the number that decides how
//! much of a container's workload direct execution can actually carry, as
//! opposed to how much it could carry in principle.
//!
//! Run: cargo run --release -p carrick-native-darwin --example direct_eligibility -- <elf>...

#[cfg(target_arch = "aarch64")]
fn main() {
    use carrick_native_darwin::direct::{DirectIneligible, scan_eligibility};

    let mut eligible = 0_usize;
    let mut refused = 0_usize;
    for path in std::env::args().skip(1) {
        let name = path.rsplit('/').next().unwrap_or(&path).to_string();
        let Ok(bytes) = std::fs::read(&path) else {
            println!("{name:<24} SKIP  unreadable");
            continue;
        };
        match scan_eligibility(&bytes) {
            Ok(Ok(sites)) => {
                eligible += 1;
                println!("{name:<24} ELIGIBLE  {sites} svc site(s) to patch");
            }
            Ok(Err(reason)) => {
                refused += 1;
                let bucket = match reason {
                    DirectIneligible::X18Access { .. } => "x18",
                    DirectIneligible::TpidrAccess { .. } => "tpidr_el0",
                    DirectIneligible::UndecodableText { .. } => "undecodable",
                    DirectIneligible::NoExecutableText => "no-text",
                    DirectIneligible::FixedLoadAddress { .. } => "ET_EXEC",
                    DirectIneligible::NeedsInterpreter { .. } => "dynamic",
                    DirectIneligible::IslandOutOfRange { .. } => "island-range",
                };
                println!("{name:<24} tier T    [{bucket}] {reason}");
            }
            Err(error) => println!("{name:<24} ERROR     {error}"),
        }
    }
    println!("\neligible {eligible}, refused {refused}");
    println!(
        "Refusals are fail-closed, not verdicts on the architecture: x18 and \
         tpidr_el0 sites are what M2's veneers exist to absorb, and \
         'undecodable' needs mapping symbols ($x/$d) to tell code from literal \
         pools."
    );
}

#[cfg(not(target_arch = "aarch64"))]
fn main() {
    eprintln!("tier D is aarch64-only: the premise is same-ISA execution");
}
