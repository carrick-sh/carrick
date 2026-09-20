use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use crate::record::Investigation;
use crate::stage::InvestigationError;

pub fn default_dir() -> PathBuf {
    PathBuf::from("target").join("investigations")
}

pub fn save(investigation: &Investigation, path: &Path) -> Result<(), InvestigationError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string(investigation)?;
    let mut file = File::create(path)?;
    writeln!(file, "{json}")?;
    Ok(())
}

pub fn load(path: &Path) -> Result<Investigation, InvestigationError> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut last_investigation: Option<Investigation> = None;

    for line in reader.lines() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let inv: Investigation = serde_json::from_str(trimmed)?;
        last_investigation = Some(inv);
    }

    last_investigation.ok_or_else(|| {
        InvestigationError::Io(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            format!("empty investigation log at {}", path.display()),
        ))
    })
}
