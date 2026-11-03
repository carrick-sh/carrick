//! Host-side census evidence for acceptance runners.
//!
//! Carriers write one census file per publication into an opt-in directory
//! (`CARRICK_EL1_CENSUS`). Reading those files back is test tooling, so it
//! lives here rather than in `carrick-spec`, which ships in the CLI: the spec
//! keeps only the wire records and the pure gate (`check_log`).

use carrick_spec::syscall_census::{MARKER, check_log};

/// Load explicitly requested carrier files into the same wire transcript
/// used by gate receipts. Callers keep this evidence beside their run logs.
pub fn read_directory(directory: &std::path::Path) -> std::io::Result<String> {
    let mut paths = std::fs::read_dir(directory)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<Result<Vec<_>, _>>()?;
    paths.sort();
    let mut log = String::new();
    for path in paths {
        if path
            .extension()
            .is_some_and(|extension| extension == "json")
        {
            let body = std::fs::read_to_string(path)?;
            // Collapse the pretty-printed file into exactly one wire line.
            let body: serde_json::Value = serde_json::from_str(&body)?;
            log.push_str(MARKER);
            log.push_str(&body.to_string());
            log.push('\n');
        }
    }
    Ok(log)
}

/// Read a census directory and apply the shared refusal gate to it, with no
/// oracle shapes. Returns a readable failure for a missing, malformed or
/// refusing census.
pub fn check_directory(directory: &std::path::Path) -> Result<(), String> {
    read_directory(directory)
        .map_err(|error| error.to_string())
        .and_then(|evidence| check_log(&evidence, None))
}
