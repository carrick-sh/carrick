use std::env;
use std::path::Path;
use std::process;

use carrick_investigation::{
    Investigation, InvestigationId, SelectedFailure, default_dir, scan_results,
};

fn print_usage() {
    eprintln!(
        "Usage:
  investigate new --id <id> --suite <suite> [--test-id <test>] [--run-id <run>] [--details <text>]
  investigate new --from-results <results.jsonl> [--suite <suite>]
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
        "new" => handle_new(&args[1..]),
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
