use std::env;
use std::path::{Path, PathBuf};
use std::process;

use carrick_conformance_contract::{CapabilityClass, ContractId, ExecutionLayer};
use carrick_investigation::{
    Investigation, InvestigationId, SelectedFailure, Stage, default_dir, scan_results,
};

fn print_usage() {
    eprintln!(
        "Usage:
  investigate new --id <id> --suite <suite> [--test-id <test>] [--run-id <run>] [--details <text>]
  investigate new --from-results <results.jsonl> [--suite <suite>]
  investigate prioritize --from-results <results.jsonl>
  investigate classify --id <id> --contract <contract-id> [--requires-guest <reason> | --vm-free <cap>]
  investigate reduce --id <id> --layer <layer> --mechanism <text>
  investigate diagnose --id <id> --evidence <receipt.json> [--fixture-active]
  investigate review --id <id> --package <path>
  investigate run-write-seek --output <new-directory>
  investigate status [--id <id>]
  investigate park --id <id> --reason <reason> [--resumption <condition>]
  investigate resume --id <id>
"
    );
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty()
        || args
            .iter()
            .any(|a| a == "--help" || a == "-h" || a == "help")
    {
        print_usage();
        return;
    }

    if let Err(err) = run(&args) {
        eprintln!("error: {err}");
        process::exit(1);
    }
}

fn run(args: &[String]) -> Result<(), String> {
    let command = &args[0];
    match command.as_str() {
        "run-write-seek" => handle_write_seek(&args[1..]),
        "new" => handle_new(&args[1..]),
        "prioritize" => handle_prioritize(&args[1..]),
        "classify" => handle_classify(&args[1..]),
        "reduce" => handle_reduce(&args[1..]),
        "diagnose" => handle_diagnose(&args[1..]),
        "review" => handle_review(&args[1..]),
        "status" => handle_status(&args[1..]),
        "park" => handle_park(&args[1..]),
        "resume" => handle_resume(&args[1..]),
        other => Err(format!("unknown command: {other}")),
    }
}

fn handle_new(args: &[String]) -> Result<(), String> {
    let mut id_arg = None;
    let mut suite_arg = None;
    let mut test_id_arg = None;
    let mut run_id_arg = None;
    let mut details_arg = None;
    let mut from_results_arg = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--id" if i + 1 < args.len() => {
                id_arg = Some(args[i + 1].clone());
                i += 2;
            }
            "--suite" if i + 1 < args.len() => {
                suite_arg = Some(args[i + 1].clone());
                i += 2;
            }
            "--test-id" if i + 1 < args.len() => {
                test_id_arg = Some(args[i + 1].clone());
                i += 2;
            }
            "--run-id" if i + 1 < args.len() => {
                run_id_arg = Some(args[i + 1].clone());
                i += 2;
            }
            "--details" if i + 1 < args.len() => {
                details_arg = Some(args[i + 1].clone());
                i += 2;
            }
            "--from-results" if i + 1 < args.len() => {
                from_results_arg = Some(args[i + 1].clone());
                i += 2;
            }
            other => return Err(format!("unexpected argument to 'new': {other}")),
        }
    }

    let failure = if let Some(results_file) = from_results_arg {
        let candidates = scan_results(Path::new(&results_file))
            .map_err(|e| format!("cannot scan results from {results_file}: {e}"))?;
        if candidates.is_empty() {
            return Err(format!("no failure candidates found in {results_file}"));
        }
        if let Some(target_suite) = suite_arg {
            candidates
                .into_iter()
                .find(|c| c.failure.suite == target_suite)
                .map(|c| c.failure)
                .ok_or_else(|| {
                    format!("suite {target_suite} not found among candidates in {results_file}")
                })?
        } else {
            let first = candidates
                .into_iter()
                .next()
                .ok_or_else(|| format!("no candidates found in {results_file}"))?;
            first.failure
        }
    } else {
        let suite = suite_arg.ok_or_else(|| "missing --suite".to_string())?;
        SelectedFailure {
            suite: suite.clone(),
            test_id: test_id_arg.unwrap_or(suite),
            run_id: run_id_arg.unwrap_or_else(|| "manual".to_string()),
            binary_sha256: "manual".to_string(),
            details: details_arg.unwrap_or_else(|| "manually initiated".to_string()),
        }
    };

    let id_str =
        id_arg.unwrap_or_else(|| format!("inv-{}", failure.suite.replace([':', '/', '.'], "-")));
    let id = InvestigationId::new(&id_str)
        .map_err(|e| format!("invalid investigation id {id_str}: {e}"))?;

    let inv = Investigation::new(id.clone(), failure);
    let path = default_dir().join(format!("{id}.jsonl"));
    inv.save_to_file(&path)
        .map_err(|e| format!("failed to save investigation to {}: {e}", path.display()))?;

    println!(
        "investigation created: {} at {} (stage: {})",
        id,
        path.display(),
        inv.stage.name()
    );
    Ok(())
}

fn handle_status(args: &[String]) -> Result<(), String> {
    let mut id_arg = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--id" if i + 1 < args.len() => {
                id_arg = Some(args[i + 1].clone());
                i += 2;
            }
            other => return Err(format!("unexpected argument to 'status': {other}")),
        }
    }

    if let Some(id_str) = id_arg {
        let path = default_dir().join(format!("{id_str}.jsonl"));
        let inv = Investigation::load_from_file(&path)
            .map_err(|e| format!("failed to load investigation from {}: {e}", path.display()))?;
        println!("Investigation: {}", inv.id);
        println!("  Stage:    {}", inv.stage.name());
        println!("  Suite:    {}", inv.selected_failure.suite);
        println!("  Test ID:  {}", inv.selected_failure.test_id);
        println!("  Run ID:   {}", inv.selected_failure.run_id);
        println!("  History:  {} transitions", inv.history.len());
    } else {
        let dir = default_dir();
        if !dir.exists() {
            println!("no investigations found in {}", dir.display());
            return Ok(());
        }
        let entries = std::fs::read_dir(&dir).map_err(|e| e.to_string())?;
        let mut count = 0;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("jsonl") {
                continue;
            }
            if let Ok(inv) = Investigation::load_from_file(&path) {
                println!(
                    "{:<30} {:<15} {}",
                    inv.id,
                    inv.stage.name(),
                    inv.selected_failure.suite
                );
                count += 1;
            }
        }
        if count == 0 {
            println!("no investigations found in {}", dir.display());
        }
    }
    Ok(())
}

fn handle_park(args: &[String]) -> Result<(), String> {
    let mut id_arg = None;
    let mut reason_arg = None;
    let mut resumption_arg = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--id" if i + 1 < args.len() => {
                id_arg = Some(args[i + 1].clone());
                i += 2;
            }
            "--reason" if i + 1 < args.len() => {
                reason_arg = Some(args[i + 1].clone());
                i += 2;
            }
            "--resumption" if i + 1 < args.len() => {
                resumption_arg = Some(args[i + 1].clone());
                i += 2;
            }
            other => return Err(format!("unexpected argument to 'park': {other}")),
        }
    }

    let id_str = id_arg.ok_or_else(|| "missing --id".to_string())?;
    let reason = reason_arg.ok_or_else(|| "missing --reason".to_string())?;
    let resumption = resumption_arg.unwrap_or_else(|| "Operator review completed".to_string());

    let path = default_dir().join(format!("{id_str}.jsonl"));
    let mut inv = Investigation::load_from_file(&path)
        .map_err(|e| format!("cannot load investigation {}: {e}", path.display()))?;

    inv.park(reason, resumption)
        .map_err(|e| format!("cannot park investigation: {e}"))?;

    inv.save_to_file(&path)
        .map_err(|e| format!("cannot save investigation: {e}"))?;

    println!("investigation {} parked at {}", id_str, path.display());
    Ok(())
}

fn handle_resume(args: &[String]) -> Result<(), String> {
    let mut id_arg = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--id" if i + 1 < args.len() => {
                id_arg = Some(args[i + 1].clone());
                i += 2;
            }
            other => return Err(format!("unexpected argument to 'resume': {other}")),
        }
    }

    let id_str = id_arg.ok_or_else(|| "missing --id".to_string())?;
    let path = default_dir().join(format!("{id_str}.jsonl"));
    let mut inv = Investigation::load_from_file(&path)
        .map_err(|e| format!("cannot load investigation {}: {e}", path.display()))?;

    inv.resume()
        .map_err(|e| format!("cannot resume investigation: {e}"))?;

    inv.save_to_file(&path)
        .map_err(|e| format!("cannot save investigation: {e}"))?;

    println!(
        "investigation {} resumed (stage: {})",
        id_str,
        inv.stage.name()
    );
    Ok(())
}

fn handle_prioritize(args: &[String]) -> Result<(), String> {
    let mut from_results_arg = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--from-results" if i + 1 < args.len() => {
                from_results_arg = Some(args[i + 1].clone());
                i += 2;
            }
            other => return Err(format!("unexpected argument to 'prioritize': {other}")),
        }
    }

    let results_file =
        from_results_arg.ok_or_else(|| "missing --from-results <results.jsonl>".to_string())?;
    let candidates = scan_results(Path::new(&results_file))
        .map_err(|e| format!("cannot scan results from {results_file}: {e}"))?;

    if candidates.is_empty() {
        println!("No failure candidates found in {results_file}. Conformance clean!");
        return Ok(());
    }

    println!(
        "{:<4} {:<24} {:<32} {:<20} DETAILS",
        "#", "SEVERITY", "SUITE", "TEST ID"
    );
    println!("{}", "-".repeat(105));
    for (idx, c) in candidates.iter().enumerate() {
        let sev_str = serde_json::to_string(&c.severity)
            .unwrap_or_default()
            .trim_matches('"')
            .to_string();
        println!(
            "{:<4} {:<24} {:<32} {:<20} {}",
            idx + 1,
            sev_str,
            c.failure.suite,
            c.failure.test_id,
            c.failure.details
        );
    }
    println!("\nTotal prioritized candidates: {}", candidates.len());
    Ok(())
}

fn handle_classify(args: &[String]) -> Result<(), String> {
    let mut id_arg = None;
    let mut contract_arg = None;
    let mut guest_rationale = None;
    let mut vm_free_cap = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--id" if i + 1 < args.len() => {
                id_arg = Some(args[i + 1].clone());
                i += 2;
            }
            "--contract" if i + 1 < args.len() => {
                contract_arg = Some(args[i + 1].clone());
                i += 2;
            }
            "--requires-guest" if i + 1 < args.len() => {
                guest_rationale = Some(args[i + 1].clone());
                i += 2;
            }
            "--vm-free" if i + 1 < args.len() => {
                vm_free_cap = Some(args[i + 1].clone());
                i += 2;
            }
            other => return Err(format!("unexpected argument to 'classify': {other}")),
        }
    }

    let id_str = id_arg.ok_or_else(|| "missing --id".to_string())?;
    let contract_str = contract_arg.ok_or_else(|| "missing --contract".to_string())?;
    let contract_id =
        ContractId::new(&contract_str).map_err(|e| format!("invalid contract id: {e}"))?;

    let registry = carrick_conformance_contract::ContractRegistry::load(Path::new("."))
        .map_err(|e| e.to_string())?;
    registry.require(&contract_str).map_err(|e| e.to_string())?;
    if guest_rationale.is_some() == vm_free_cap.is_some() {
        return Err("supply exactly one explicit --requires-guest or --vm-free decision".into());
    }
    let capability = if let Some(rat) = guest_rationale {
        CapabilityClass::RequiresGuest { rationale: rat }
    } else if let Some(cap) = vm_free_cap {
        CapabilityClass::VmFreeExisting { capability: cap }
    } else {
        return Err("explicit capability decision required".into());
    };

    let path = default_dir().join(format!("{id_str}.jsonl"));
    let mut inv = Investigation::load_from_file(&path)
        .map_err(|e| format!("cannot load investigation {}: {e}", path.display()))?;

    inv.transition(Stage::Classified {
        contract: contract_id,
        capability,
    })
    .map_err(|e| format!("cannot classify investigation: {e}"))?;

    inv.save_to_file(&path)
        .map_err(|e| format!("cannot save investigation: {e}"))?;

    println!("investigation {} classified at {}", id_str, path.display());
    Ok(())
}

fn handle_reduce(args: &[String]) -> Result<(), String> {
    let mut id_arg = None;
    let mut layer_arg = None;
    let mut mechanisms = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--id" if i + 1 < args.len() => {
                id_arg = Some(args[i + 1].clone());
                i += 2;
            }
            "--layer" if i + 1 < args.len() => {
                layer_arg = Some(args[i + 1].clone());
                i += 2;
            }
            "--mechanism" if i + 1 < args.len() => {
                mechanisms.push(args[i + 1].clone());
                i += 2;
            }
            other => return Err(format!("unexpected argument to 'reduce': {other}")),
        }
    }

    let id_str = id_arg.ok_or_else(|| "missing --id".to_string())?;
    let layer_str = layer_arg.ok_or_else(|| "missing --layer".to_string())?;
    let layer: ExecutionLayer = serde_json::from_value(serde_json::Value::String(layer_str))
        .map_err(|e| format!("invalid execution layer: {e}"))?;

    if mechanisms.is_empty() {
        return Err("at least one --mechanism is required".to_string());
    }

    let path = default_dir().join(format!("{id_str}.jsonl"));
    let mut inv = Investigation::load_from_file(&path)
        .map_err(|e| format!("cannot load investigation {}: {e}", path.display()))?;

    inv.transition(Stage::Reducing {
        layer,
        preserved_mechanisms: mechanisms,
    })
    .map_err(|e| format!("cannot reduce investigation: {e}"))?;

    inv.save_to_file(&path)
        .map_err(|e| format!("cannot save investigation: {e}"))?;

    println!("investigation {} reducing at {}", id_str, path.display());
    Ok(())
}

fn handle_diagnose(args: &[String]) -> Result<(), String> {
    let mut id_arg = None;
    let mut evidence = Vec::new();
    let mut fixture_active = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--id" if i + 1 < args.len() => {
                id_arg = Some(args[i + 1].clone());
                i += 2;
            }
            "--evidence" if i + 1 < args.len() => {
                evidence.push(args[i + 1].clone());
                i += 2;
            }
            "--fixture-inactive" => {
                fixture_active = false;
                i += 1;
            }
            "--fixture-active" => {
                fixture_active = true;
                i += 1;
            }
            other => return Err(format!("unexpected argument to 'diagnose': {other}")),
        }
    }

    let id_str = id_arg.ok_or_else(|| "missing --id".to_string())?;
    if evidence.is_empty() {
        return Err("at least one --evidence is required".to_string());
    }

    let path = default_dir().join(format!("{id_str}.jsonl"));
    let mut inv = Investigation::load_from_file(&path)
        .map_err(|e| format!("cannot load investigation {}: {e}", path.display()))?;

    inv.transition(Stage::Diagnosing {
        red_evidence: evidence,
        fixture_active,
    })
    .map_err(|e| format!("cannot diagnose investigation: {e}"))?;

    inv.save_to_file(&path)
        .map_err(|e| format!("cannot save investigation: {e}"))?;

    println!("investigation {} diagnosing at {}", id_str, path.display());
    Ok(())
}

fn handle_review(args: &[String]) -> Result<(), String> {
    let mut id_arg = None;
    let mut package_arg = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--id" if i + 1 < args.len() => {
                id_arg = Some(args[i + 1].clone());
                i += 2;
            }
            "--package" if i + 1 < args.len() => {
                package_arg = Some(args[i + 1].clone());
                i += 2;
            }
            other => return Err(format!("unexpected argument to 'review': {other}")),
        }
    }

    let id_str = id_arg.ok_or_else(|| "missing --id".to_string())?;
    let package_path = package_arg.ok_or_else(|| "missing --package".to_string())?;

    let path = default_dir().join(format!("{id_str}.jsonl"));
    let mut inv = Investigation::load_from_file(&path)
        .map_err(|e| format!("cannot load investigation {}: {e}", path.display()))?;

    inv.transition(Stage::ReviewReady {
        review_package_path: PathBuf::from(package_path),
    })
    .map_err(|e| format!("cannot mark investigation review-ready: {e}"))?;

    inv.save_to_file(&path)
        .map_err(|e| format!("cannot save investigation: {e}"))?;

    println!(
        "investigation {} review-ready at {}",
        id_str,
        path.display()
    );
    Ok(())
}

/// The registered VM-free pilot producer is built from the measured source
/// immediately before execution; arbitrary binaries are not accepted by this CLI.
fn handle_write_seek(args: &[String]) -> Result<(), String> {
    if args.len() != 2 || args[0] != "--output" {
        return Err("usage: investigate run-write-seek --output <new-directory>".into());
    }
    let root = std::env::current_dir().map_err(|e| e.to_string())?;
    let coordinator =
        carrick_coordinator::Coordinator::new(carrick_coordinator::Coordinator::default_dir())
            .map_err(|e| e.to_string())?;
    let _lease = coordinator
        .try_acquire(
            carrick_coordinator::ResourceClass::TimingWindow,
            carrick_coordinator::LeaseOwner {
                host: "local".into(),
                pid: std::process::id(),
                run_id: format!("write-seek-{}", std::process::id()),
                investigation_id: None,
            },
        )
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "coordinated execution window busy; queue the experiment".to_string())?;
    let before =
        carrick_investigation::evidence::source_identity(&root).map_err(|e| e.to_string())?;
    let status = std::process::Command::new("cargo")
        .args([
            "build",
            "-p",
            "carrick-kernel-example",
            "--features",
            "conformance-metrics",
            "--bin",
            "write-seek-observation",
        ])
        .env("RUSTC_WRAPPER", "")
        .status()
        .map_err(|e| e.to_string())?;
    if !status.success() {
        return Err("VM-free producer build failed".into());
    }
    if carrick_investigation::evidence::source_identity(&root).map_err(|e| e.to_string())? != before
    {
        return Err("source changed during build; no experiment admitted".into());
    }
    let receipt = carrick_investigation::evidence::capture_vm_free(
        &root,
        &root.join("target/debug/write-seek-observation"),
        &[],
        Path::new(&args[1]),
        ContractId::new("kernel.fs.write-seek").map_err(|e| e.to_string())?,
        std::time::Duration::from_secs(30),
    )
    .map_err(|e| e.to_string())?;
    println!("{}", receipt.display());
    Ok(())
}
