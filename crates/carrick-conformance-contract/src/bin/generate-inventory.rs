use std::env;
use std::fs;
use std::path::PathBuf;
use std::process;

use carrick_conformance_contract::{ContractRegistry, SyscallInventory};

struct Args {
    root: PathBuf,
    check: bool,
}

fn parse_args() -> Result<Args, String> {
    let mut args = env::args().skip(1);
    let mut root = PathBuf::from(".");
    let mut check = false;

    while let Some(arg) = args.next() {
        if arg == "--root" {
            let val = args
                .next()
                .ok_or_else(|| "missing value for --root".to_string())?;
            root = PathBuf::from(val);
        } else if arg == "--check" {
            check = true;
        } else {
            return Err(format!("unknown argument: {arg}"));
        }
    }

    Ok(Args { root, check })
}

fn main() {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: {e}");
            process::exit(1);
        }
    };

    if let Err(err) = run(&args) {
        eprintln!("{err}");
        process::exit(1);
    }
}

fn run(args: &Args) -> Result<(), String> {
    let registry = ContractRegistry::load(&args.root)
        .map_err(|e| format!("cannot load contract registry: {e}"))?;

    let inventory = SyscallInventory::generate(&registry);
    let serialized = serde_json::to_string_pretty(&inventory)
        .map_err(|e| format!("cannot serialize inventory: {e}"))?;

    let output_path = args
        .root
        .join("conformance-contracts")
        .join("inventory.json");

    if args.check {
        if !output_path.exists() {
            return Err(format!(
                "inventory file {} does not exist (run `cargo run -p carrick-conformance-contract --bin generate-inventory` to generate it)",
                output_path.display()
            ));
        }
        let existing = fs::read_to_string(&output_path).map_err(|e| {
            format!(
                "cannot read existing inventory {}: {e}",
                output_path.display()
            )
        })?;
        if existing.trim() != serialized.trim() {
            return Err(format!(
                "inventory drift detected at {} (run `cargo run -p carrick-conformance-contract --bin generate-inventory` to refresh)",
                output_path.display()
            ));
        }
        println!(
            "inventory drift check passed: {} syscalls ({} bring-up, {} deferred, {} planned; {} with claims, {} without claims)",
            inventory.summary.total_entries,
            inventory.summary.bring_up,
            inventory.summary.deferred,
            inventory.summary.planned,
            inventory.summary.with_claims,
            inventory.summary.without_claims
        );
    } else {
        fs::write(&output_path, format!("{serialized}\n"))
            .map_err(|e| format!("cannot write inventory to {}: {e}", output_path.display()))?;
        println!(
            "inventory generated at {}: {} syscalls ({} bring-up, {} deferred, {} planned; {} with claims, {} without claims)",
            output_path.display(),
            inventory.summary.total_entries,
            inventory.summary.bring_up,
            inventory.summary.deferred,
            inventory.summary.planned,
            inventory.summary.with_claims,
            inventory.summary.without_claims
        );
    }

    Ok(())
}
