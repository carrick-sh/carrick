use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use host_authority_escape_syntax::{Finding, scan_source};

const CHECKED_NON_SOURCE_SYMLINKS: &[(&str, &str)] = &[
    ("crates/carrick-cli/fixtures", "../../fixtures"),
    ("crates/carrick-cli/scripts", "../../scripts"),
    ("crates/carrick-runtime/fixtures", "../../fixtures"),
    ("crates/carrick-runtime/scripts", "../../scripts"),
];

#[derive(Clone, Copy)]
enum OutputFormat {
    Json,
    Text,
}

struct Options {
    root: PathBuf,
    format: OutputFormat,
}

fn parse_options() -> Result<Options, String> {
    let mut root = None;
    let mut format = OutputFormat::Text;
    let mut arguments = env::args().skip(1);
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--root" => {
                root = Some(PathBuf::from(
                    arguments
                        .next()
                        .ok_or_else(|| "--root requires a path".to_owned())?,
                ));
            }
            "--format" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| "--format requires json or text".to_owned())?;
                format = match value.as_str() {
                    "json" => OutputFormat::Json,
                    "text" => OutputFormat::Text,
                    _ => return Err(format!("unsupported output format: {value}")),
                };
            }
            "-h" | "--help" => {
                println!("usage: host-authority-escape-syntax --root PATH [--format json|text]");
                return Err(String::new());
            }
            _ => return Err(format!("unknown argument: {argument}")),
        }
    }
    Ok(Options {
        root: root.ok_or_else(|| "--root is required".to_owned())?,
        format,
    })
}

fn collect_rust_files(
    root: &Path,
    directory: &Path,
    files: &mut Vec<PathBuf>,
) -> Result<(), String> {
    let entries = fs::read_dir(directory)
        .map_err(|error| format!("cannot read {}: {error}", directory.display()))?;
    for entry in entries {
        let entry = entry.map_err(|error| {
            format!(
                "cannot read directory entry in {}: {error}",
                directory.display()
            )
        })?;
        let file_type = entry
            .file_type()
            .map_err(|error| format!("cannot stat {}: {error}", entry.path().display()))?;
        if file_type.is_symlink() {
            let relative = entry
                .path()
                .strip_prefix(root)
                .map_err(|error| format!("cannot relativize {}: {error}", entry.path().display()))?
                .to_str()
                .ok_or_else(|| format!("non-UTF-8 scan path: {}", entry.path().display()))?
                .replace(std::path::MAIN_SEPARATOR, "/");
            if let Some((_, expected_target)) = CHECKED_NON_SOURCE_SYMLINKS
                .iter()
                .find(|(checked_path, _)| *checked_path == relative)
            {
                let target = fs::read_link(entry.path())
                    .map_err(|error| format!("cannot read checked symlink {relative}: {error}"))?;
                if target == Path::new(expected_target) {
                    continue;
                }
                return Err(format!(
                    "checked symlink {relative} changed target: {}",
                    target.display()
                ));
            }
            return Err(format!(
                "refusing unchecked symlinked scan input: {relative}"
            ));
        }
        if file_type.is_dir() {
            collect_rust_files(root, &entry.path(), files)?;
        } else if file_type.is_file() && entry.path().extension().is_some_and(|ext| ext == "rs") {
            files.push(entry.path());
        }
    }
    Ok(())
}

fn scan(options: &Options) -> Result<Vec<(String, Finding)>, String> {
    let root = options
        .root
        .canonicalize()
        .map_err(|error| format!("cannot resolve {}: {error}", options.root.display()))?;
    let crates = root.join("crates");
    if !crates.is_dir() {
        return Err(format!("missing Rust scan root: {}", crates.display()));
    }
    let mut files = Vec::new();
    collect_rust_files(&root, &crates, &mut files)?;
    files.sort();
    let mut findings = Vec::new();
    for path in files {
        let relative = path
            .strip_prefix(&root)
            .map_err(|error| format!("cannot relativize {}: {error}", path.display()))?;
        let relative = relative
            .to_str()
            .ok_or_else(|| format!("non-UTF-8 scan path: {}", path.display()))?
            .replace(std::path::MAIN_SEPARATOR, "/");
        let source = fs::read_to_string(&path)
            .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
        let file_findings = scan_source(&source).map_err(|error| format!("{relative}: {error}"))?;
        findings.extend(
            file_findings
                .into_iter()
                .map(|finding| (relative.clone(), finding)),
        );
    }
    findings.sort();
    Ok(findings)
}

fn run() -> Result<(), String> {
    let options = parse_options()?;
    for (path, finding) in scan(&options)? {
        match options.format {
            OutputFormat::Json => println!("{}", finding.render_json(&path)),
            OutputFormat::Text => println!("{}", finding.render_text(&path)),
        }
    }
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) if error.is_empty() => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::from(2)
        }
    }
}
