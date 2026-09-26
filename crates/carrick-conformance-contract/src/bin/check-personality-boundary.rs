use std::env;
use std::path::PathBuf;
use std::process;

use carrick_conformance_contract::personality_boundary::{
    BoundaryConfig, check_substrate_boundary,
};

fn parse_args() -> Result<(PathBuf, BoundaryConfig), String> {
    let mut args = env::args().skip(1);
    let mut root = PathBuf::from(".");
    let mut config = BoundaryConfig::default();

    while let Some(arg) = args.next() {
        if arg == "--root" {
            let val = args
                .next()
                .ok_or_else(|| "missing value for --root".to_string())?;
            root = PathBuf::from(val);
        } else if arg == "--metadata-file" {
            let val = args
                .next()
                .ok_or_else(|| "missing value for --metadata-file".to_string())?;
            config.metadata_file = Some(PathBuf::from(val));
        } else if arg == "--metadata-json" {
            let val = args
                .next()
                .ok_or_else(|| "missing value for --metadata-json".to_string())?;
            config.metadata_json = Some(val);
        } else if arg == "--help" || arg == "-h" {
            println!(
                "Usage: check-personality-boundary [--root <PATH>] [--metadata-file <PATH>] [--metadata-json <JSON>]"
            );
            process::exit(0);
        } else {
            return Err(format!("unknown argument: {arg}"));
        }
    }
    Ok((root, config))
}

fn main() {
    let (root, config) = match parse_args() {
        Ok(res) => res,
        Err(e) => {
            eprintln!("error: {e}");
            process::exit(1);
        }
    };

    match check_substrate_boundary(&root, &config) {
        Ok(reports) => {
            println!(
                "personality boundary checked: {} substrate crate(s) clean",
                reports.len()
            );
            for report in &reports {
                println!(
                    "  [PASS] crate `{}` (shipped deps: {:?}, dev deps: {:?}, scanned files: {})",
                    report.crate_name,
                    report.shipped_dependency_closure,
                    report.dev_dependencies_scope,
                    report.scanned_source_files.len()
                );
            }
        }
        Err(err) => {
            eprintln!("{err}");
            process::exit(1);
        }
    }
}
