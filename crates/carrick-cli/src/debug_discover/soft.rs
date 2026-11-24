//! `carrick debug discover --provider soft-a64`: each selected row's first
//! single-process command on the soft AArch64 CPU (`carrick debug soft-run`),
//! from the row's arm64 image, ranked like a hardware run. A row stage is a
//! shell script; the soft runner runs one process, so the provider takes the
//! script's first program (past `cd` and the other builtins, with its leading
//! `NAME=value` words as environment) and runs that. Diagnostics only.
//!
//! The rootfs comes from `carrick rootfs export --carrier-view --platform
//! linux/arm64`: the carrier's own digest-keyed extraction, built
//! unprivileged. The soft CPU executes natively, so the runs need a Linux
//! arm64 host.

use super::*;

/// Shell builtins a row script runs before its first program.
const BUILTINS: &[&str] = &["cd", "export", "set", "umask", ":", "true", "unset"];

/// The program a stage's first single process runs: its argv and the
/// environment words in front of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SingleCommand {
    pub(super) env: Vec<String>,
    pub(super) argv: Vec<String>,
}

/// The first program of `command`: the command itself, or, for
/// `sh -c <script>`, the script's first simple command that is not a builtin.
/// `Err` names the syntax this reader does not take (expansions,
/// redirections, globs) in the command it would have to run.
pub(super) fn first_command(command: &[String]) -> std::result::Result<SingleCommand, String> {
    let script = match command {
        [shell, flag, script]
            if flag == "-c" && (shell == "sh" || shell.ends_with("/sh") || shell == "bash") =>
        {
            script
        }
        [] => return Err("empty command".to_owned()),
        _ => {
            return Ok(SingleCommand {
                env: Vec::new(),
                argv: command.to_vec(),
            });
        }
    };
    for simple in split_simple_commands(script) {
        let words = shell_words(&simple)?;
        let split = words
            .iter()
            .position(|word| !is_assignment(word))
            .unwrap_or(words.len());
        let (env, argv) = words.split_at(split);
        let Some(program) = argv.first() else {
            continue;
        };
        if BUILTINS.contains(&program.as_str()) {
            continue;
        }
        return Ok(SingleCommand {
            env: env.to_vec(),
            argv: argv.to_vec(),
        });
    }
    Err(format!("no program in {script:?}"))
}

fn is_assignment(word: &str) -> bool {
    word.split_once('=').is_some_and(|(name, _)| {
        !name.is_empty()
            && !name.starts_with(|c: char| c.is_ascii_digit())
            && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
    })
}

/// Split a script at its unquoted `&&`, `||`, `;`, `|` and newlines.
fn split_simple_commands(script: &str) -> Vec<String> {
    let mut commands = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    let mut chars = script.chars().peekable();
    while let Some(c) = chars.next() {
        match (quote, c) {
            (Some(q), _) if c == q => {
                quote = None;
                current.push(c);
            }
            (Some('"'), '\\') => {
                current.push(c);
                if let Some(next) = chars.next() {
                    current.push(next);
                }
            }
            (Some(_), _) => current.push(c),
            (None, '\'' | '"') => {
                quote = Some(c);
                current.push(c);
            }
            (None, '\\') => {
                current.push(c);
                if let Some(next) = chars.next() {
                    current.push(next);
                }
            }
            (None, ';' | '\n') => commands.push(std::mem::take(&mut current)),
            (None, '&' | '|') => {
                if chars.peek() == Some(&c) {
                    chars.next();
                }
                commands.push(std::mem::take(&mut current));
            }
            (None, _) => current.push(c),
        }
    }
    commands.push(current);
    commands
        .into_iter()
        .map(|command| command.trim().to_owned())
        .filter(|command| !command.is_empty())
        .collect()
}

/// The words of one simple command, quotes removed.
fn shell_words(command: &str) -> std::result::Result<Vec<String>, String> {
    let mut words = Vec::new();
    let mut word: Option<String> = None;
    let mut quote: Option<char> = None;
    let mut chars = command.chars();
    let unsupported = |c: char| {
        Err(format!(
            "{command:?}: {c:?} is not taken by the soft provider"
        ))
    };
    while let Some(c) = chars.next() {
        match (quote, c) {
            (Some(q), _) if c == q => quote = None,
            (Some('"'), '$' | '`') => return unsupported(c),
            (Some('"'), '\\') => {
                if let Some(next) = chars.next() {
                    if !matches!(next, '"' | '\\' | '$' | '`') {
                        word.get_or_insert_default().push('\\');
                    }
                    word.get_or_insert_default().push(next);
                }
            }
            (Some(_), _) => word.get_or_insert_default().push(c),
            (None, '\'' | '"') => {
                quote = Some(c);
                word.get_or_insert_default();
            }
            (None, '\\') => {
                if let Some(next) = chars.next() {
                    word.get_or_insert_default().push(next);
                }
            }
            (None, ' ' | '\t') => words.extend(word.take()),
            (None, '$' | '`' | '>' | '<' | '(' | ')' | '*' | '?' | '[' | '~' | '{' | '}') => {
                return unsupported(c);
            }
            (None, _) => word.get_or_insert_default().push(c),
        }
    }
    if quote.is_some() {
        return Err(format!("{command:?}: unterminated quote"));
    }
    words.extend(word);
    Ok(words)
}

/// What `carrick rootfs export` printed for an image.
#[derive(Debug, serde::Deserialize)]
struct ExportedRootfs {
    root: PathBuf,
    #[serde(default)]
    env: Option<Vec<String>>,
}

/// Export `image` with this binary (`--carrier-view` is the harness's, not
/// necessarily the carrier's under test).
fn export_rootfs(image: &str) -> Result<ExportedRootfs> {
    let carrick = std::env::current_exe().context("locate this carrick for rootfs export")?;
    let output = std::process::Command::new(&carrick)
        .args([
            "rootfs",
            "export",
            "--carrier-view",
            "--platform",
            "linux/arm64",
        ])
        .arg(image)
        .stdin(std::process::Stdio::null())
        .output()
        .with_context(|| format!("start {} rootfs export", carrick.display()))?;
    ensure!(
        output.status.success(),
        "rootfs export {image} failed ({}): {}",
        output.status,
        String::from_utf8_lossy(&output.stderr).trim()
    );
    let line = String::from_utf8_lossy(&output.stdout);
    let line = line.lines().last().unwrap_or_default();
    serde_json::from_str(line).with_context(|| format!("parse rootfs export output {line:?}"))
}

/// Run every selected row's first single process on the soft CPU and rank it.
pub(super) fn discover(
    options: &DiscoverOptions<'_>,
    selected: &[&RowSpec],
    carrick: &Path,
    instance: &str,
) -> Result<()> {
    use std::io::Write;
    let isa = RowIsa::Arm64;
    let mut runs_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(options.out.join("runs.jsonl"))?;
    let mut run_ids = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(options.out.join("run-ids.txt"))?;
    let mut exports: BTreeMap<String, ExportedRootfs> = BTreeMap::new();
    let mut records = Vec::new();
    for run in 1..=options.runs {
        for row in selected {
            let Some(image) = row.image.get(&isa) else {
                eprintln!("discover: row {} has no arm64 image; skipped", row.name);
                continue;
            };
            let Some(stage) = row.stages.first() else {
                continue;
            };
            let single = match first_command(&stage.command) {
                Ok(single) => single,
                Err(why) => {
                    eprintln!(
                        "discover: row {} stage {}: {why}; skipped",
                        row.name, stage.name
                    );
                    continue;
                }
            };
            if !exports.contains_key(image) {
                match export_rootfs(image) {
                    Ok(export) => {
                        exports.insert(image.clone(), export);
                    }
                    Err(error) => {
                        eprintln!("discover: row {}: {error:#}; skipped", row.name);
                        continue;
                    }
                }
            }
            let export = &exports[image];
            let stage_name = format!("soft-{}", stage.name);
            let run_id = format!("discover-{}-{}-{stage_name}-{run}", options.label, row.name);
            writeln!(run_ids, "{run_id}")?;
            let base = options.out.join(format!("{}-{stage_name}-{run}", row.name));
            let census = base.with_extension("census");
            let _ = std::fs::remove_dir_all(&census);
            let stdout_path = base.with_extension("out");
            let stderr_path = base.with_extension("err");
            std::fs::write(
                base.with_extension("argv"),
                format!("env {:?}\nargv {:?}\n", single.env, single.argv),
            )?;
            let mut command = std::process::Command::new(carrick);
            command
                .args(["debug", "soft-run", "--rootfs"])
                .arg(&export.root);
            for entry in export.env.iter().flatten().chain(&single.env) {
                command.arg("--env").arg(entry);
            }
            let started = std::time::Instant::now();
            let child = command
                .arg("--")
                .args(&single.argv)
                .env("CARRICK_RUN_ID", &run_id)
                .env("CARRICK_EL1_CENSUS", &census)
                .stdin(std::process::Stdio::null())
                .stdout(std::fs::File::create(&stdout_path)?)
                .stderr(std::fs::File::create(&stderr_path)?)
                .spawn()
                .with_context(|| format!("start {}", carrick.display()))?;
            let timeout = Duration::from_secs(stage.timeout_secs.unwrap_or(row.timeout_secs));
            let ending = wait_bounded(child, timeout, &mut || {})?;
            let secs = started.elapsed().as_secs_f64();
            let stdout = String::from_utf8_lossy(&std::fs::read(&stdout_path)?).into_owned();
            let stderr = String::from_utf8_lossy(&std::fs::read(&stderr_path)?).into_owned();
            let censuses = load_censuses(&census)?;
            // The script's success marker belongs to the whole script; the
            // single process passes on exit 0.
            let judged = StageSpec {
                name: stage_name.clone(),
                command: single.argv.clone(),
                expect: None,
                timeout_secs: stage.timeout_secs,
                known_answer: BTreeMap::new(),
            };
            let (passed, findings) = judge(&judged, ending, &stdout, &stderr, &censuses);
            let record = RunRecord {
                instance: format!("{instance}-soft-a64"),
                isa,
                row: row.name.clone(),
                stage: stage_name,
                run,
                run_id,
                image: image.clone(),
                exit_code: ending.exit_code,
                signal: ending.signal,
                timed_out: ending.timed_out,
                secs,
                passed,
                findings,
            };
            eprintln!(
                "discover: soft-a64 {}/{} run {run}: {} in {secs:.1}s, {} findings",
                row.name,
                record.stage,
                if passed { "pass" } else { "FAIL" },
                record.findings.len()
            );
            writeln!(runs_file, "{}", serde_json::to_string(&record)?)?;
            runs_file.flush()?;
            records.push(record);
        }
    }
    print!(
        "{}",
        write_outputs(
            options.out,
            &records,
            &read_oracle(options.out)?,
            options.limit
        )?
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(items: &[&str]) -> Vec<String> {
        items.iter().map(|item| (*item).to_owned()).collect()
    }

    fn rows_file() -> RowsFile {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../docs/parity/parity-rows.json"
        );
        load_rows(Path::new(path)).unwrap()
    }

    fn first(row: &str) -> SingleCommand {
        let rows = rows_file();
        let row = rows.rows.iter().find(|r| r.name == row).unwrap();
        first_command(&row.stages[0].command).unwrap()
    }

    #[test]
    fn each_parity_row_has_a_first_single_process() {
        assert_eq!(first("go-hello").argv, words(&["go", "version"]));
        let go_real = first("go-real");
        assert_eq!(go_real.env, words(&["GOFLAGS=-mod=mod", "GOCACHE=/tmp/gc"]));
        assert_eq!(go_real.argv[..2], words(&["go", "install"]));
        assert_eq!(first("pip").argv, words(&["pip", "--version"]));
        assert_eq!(first("npm").argv[0], "node");
        assert_eq!(first("shell").argv, words(&["apt-get", "update"]));
        assert_eq!(first("probe-1335").argv, words(&["mkdir", "/tmp/a"]));
    }

    #[test]
    fn quotes_and_separators_split_like_a_shell() {
        let script = |s: &str| words(&["sh", "-c", s]);
        assert_eq!(
            first_command(&script("cd /x; A=1 'my prog' \"a b\" c\\ d && next")).unwrap(),
            SingleCommand {
                env: words(&["A=1"]),
                argv: words(&["my prog", "a b", "c d"]),
            }
        );
        assert_eq!(
            first_command(&script("echo 'x && y' | cat")).unwrap().argv,
            words(&["echo", "x && y"])
        );
        assert!(first_command(&script("cd /tmp && ls > out")).is_err());
        assert!(first_command(&script("echo $HOME")).is_err());
        assert!(first_command(&script("cd /tmp")).is_err());
        assert_eq!(
            first_command(&words(&["node", "-e", "x"])).unwrap().argv,
            words(&["node", "-e", "x"])
        );
    }
}
