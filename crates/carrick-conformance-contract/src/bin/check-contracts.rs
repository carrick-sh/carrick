use std::env;
use std::path::{Path, PathBuf};
use std::process;

use carrick_conformance_contract::ContractRegistry;

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
        let vm_free = contract
            .bindings
            .vm_free
            .as_deref()
            .ok_or_else(|| format!("{}: missing vm_free binding", contract.id))?;
        let _embed = contract
            .bindings
            .embed
            .as_deref()
            .ok_or_else(|| format!("{}: missing embed binding", contract.id))?;
        let _docker = contract
            .bindings
            .docker
            .as_deref()
            .ok_or_else(|| format!("{}: missing docker binding", contract.id))?;

        // Check that the vm_free binding crate exists
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

    for surface in registry.surfaces() {
        let target = root.join(&surface.path);
        if !target.exists() {
            return Err(format!(
                "vacuous pattern: surface path {} matches no file",
                surface.path
            ));
        }
    }

    println!(
        "conformance contracts checked: {} contracts, {} surfaces",
        registry.contracts().len(),
        registry.surfaces().len()
    );
    Ok(())
}
