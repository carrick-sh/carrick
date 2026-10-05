use std::env;
use std::path::{Path, PathBuf};
use std::process;

use carrick_conformance_contract::{ContractRegistry, SyscallInventory};

fn parse_args() -> Result<PathBuf, String> {
    let mut args = env::args().skip(1);
    let mut root = PathBuf::from(".");
    while let Some(arg) = args.next() {
        if arg == "--root" {
            let val = args
                .next()
                .ok_or_else(|| "missing value for --root".to_string())?;
            root = PathBuf::from(val);
        } else {
            return Err(format!("unknown argument: {arg}"));
        }
    }
    Ok(root)
}

fn main() {
    let root = match parse_args() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: {e}");
            process::exit(1);
        }
    };

    if let Err(err) = run(&root) {
        eprintln!("{err}");
        process::exit(1);
    }
}

fn run(root: &Path) -> Result<(), String> {
    let registry =
        ContractRegistry::load(root).map_err(|e| format!("cannot load contract registry: {e}"))?;

    // Check each contract's bindings
    for contract in registry.contracts() {
        // Registry validation already requires every absent binding to carry a
        // non-empty unresolved reason. Once a VM-free binding is concrete,
        // additionally prove that its target crate exists.
        if let Some(vm_free) = contract.bindings.vm_free.as_deref() {
            let crate_name = vm_free.split("::").next().unwrap_or(vm_free);
            let crate_path = root.join("crates").join(crate_name);
            if !crate_path.exists() {
                return Err(format!(
                    "{}: missing vm_free target crate {}",
                    contract.id,
                    crate_path.display()
                ));
            }
        }
    }

    for surface in registry.surfaces() {
        let target = root.join(&surface.path);
        if !target.exists() {
            return Err(format!(
                "vacuous pattern: surface path {} matches no file",
                surface.path
            ));
        }
    }

    // Generate live syscall inventory from registry
    let inventory = SyscallInventory::generate(&registry);

    println!(
        "conformance contracts checked: {} contracts, {} claims, {} surfaces (inventory: {} syscalls, {} with claims)",
        registry.contracts().len(),
        registry.claims().len(),
        registry.surfaces().len(),
        inventory.summary.total_entries,
        inventory.summary.with_claims
    );
    Ok(())
}
