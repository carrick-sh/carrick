//! Fail closed on known host load generators before collecting gate evidence.
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::process::Command;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoadGenerator {
    pub pid: u32,
    pub name: String,
    pub parent_pid: u32,
    pub parent_command: String,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostLoadReport {
    pub allow_load: bool,
    pub generators: Vec<LoadGenerator>,
}

#[derive(Debug, Error)]
pub enum HostLoadError {
    #[error("cannot inspect host processes: {0}")]
    ProcessList(String),
    #[error(
        "refusing run: host load generators present:\n{0}\nStop them first, or set CARRICK_ALLOW_LOAD=1 for deliberate load characterization"
    )]
    Present(String),
}

fn ps(fields: &[&str]) -> Result<String, HostLoadError> {
    let output = Command::new("ps")
        .args(["-A", "-ww"])
        .args(fields)
        .env("LC_ALL", "C")
        .output()
        .map_err(|e| HostLoadError::ProcessList(e.to_string()))?;
    if !output.status.success() {
        return Err(HostLoadError::ProcessList(
            String::from_utf8_lossy(&output.stderr).into_owned(),
        ));
    }
    String::from_utf8(output.stdout).map_err(|e| HostLoadError::ProcessList(e.to_string()))
}

fn field(line: &str) -> Result<(&str, &str), HostLoadError> {
    let line = line.trim_start();
    let end = line.find(char::is_whitespace).unwrap_or(line.len());
    if end == 0 {
        return Err(HostLoadError::ProcessList("empty ps field".into()));
    }
    Ok((&line[..end], line[end..].trim_start()))
}

fn pid(value: &str) -> Result<u32, HostLoadError> {
    value
        .parse()
        .map_err(|_| HostLoadError::ProcessList(format!("invalid ps PID: {value}")))
}

/// Separate comm and args columns preserve paths/parent commands with spaces on
/// both BSD and GNU ps. A parent may exit between snapshots; report that fact.
pub fn detect(names: &str, commands: &str) -> Result<Vec<LoadGenerator>, HostLoadError> {
    let mut parents = HashMap::new();
    for line in commands.lines().filter(|l| !l.trim().is_empty()) {
        let (id, command) = field(line)?;
        parents.insert(pid(id)?, command.to_string());
    }
    let mut generators = Vec::new();
    for line in names.lines().filter(|l| !l.trim().is_empty()) {
        let (id, rest) = field(line)?;
        let (parent, name) = field(rest)?;
        let id = pid(id)?;
        let parent = pid(parent)?;
        let name = name.trim();
        if name.is_empty() {
            return Err(HostLoadError::ProcessList("missing ps comm field".into()));
        }
        let name = Path::new(name)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(name);
        if matches!(name, "yes" | "stress" | "stress-ng") {
            generators.push(LoadGenerator {
                pid: id,
                name: name.into(),
                parent_pid: parent,
                parent_command: parents
                    .get(&parent)
                    .cloned()
                    .unwrap_or_else(|| "<parent exited or unavailable>".into()),
            });
        }
    }
    generators.sort_by_key(|g| g.pid);
    Ok(generators)
}

fn enforce(
    generators: Vec<LoadGenerator>,
    allow_load: bool,
) -> Result<HostLoadReport, HostLoadError> {
    if !generators.is_empty() {
        let detail = generators
            .iter()
            .map(|g| {
                format!(
                    "  {} PID {}: parent PID {} command: {}",
                    g.name, g.pid, g.parent_pid, g.parent_command
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        if !allow_load {
            return Err(HostLoadError::Present(detail));
        }
        eprintln!(
            "host-load: CARRICK_ALLOW_LOAD=1; load present (deliberate characterization):\n{detail}"
        );
    } else {
        eprintln!(
            "host-load: no known load generators present (CARRICK_ALLOW_LOAD={})",
            u8::from(allow_load)
        );
    }
    Ok(HostLoadReport {
        allow_load,
        generators,
    })
}

pub fn check() -> Result<HostLoadReport, HostLoadError> {
    let names = ps(&["-o", "pid=", "-o", "ppid=", "-o", "comm="])?;
    let commands = ps(&["-o", "pid=", "-o", "args="])?;
    enforce(
        detect(&names, &commands)?,
        std::env::var("CARRICK_ALLOW_LOAD").as_deref() == Ok("1"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fake_process_list_detects_exact_names_and_parent_commands() {
        let names = " 1 0 launchd\n 10 1 /bin/bash\n 21 10 /usr/bin/yes\n 22 10 stress\n 23 99 /path with spaces/stress-ng\n 24 10 yesterday\n 25 10 stress-ng-helper\n";
        let commands = "1 launchd\n10 /bin/bash -c yes loop\n24 yesterday --mentions stress\n";
        let found = detect(names, commands).unwrap();
        assert_eq!(
            found.iter().map(|g| g.pid).collect::<Vec<_>>(),
            [21, 22, 23]
        );
        assert_eq!(found[0].parent_command, "/bin/bash -c yes loop");
        assert_eq!(found[2].parent_pid, 99);
        assert!(found[2].parent_command.contains("unavailable"));
        assert!(matches!(
            enforce(found.clone(), false),
            Err(HostLoadError::Present(_))
        ));
        let report = enforce(found.clone(), true).unwrap();
        assert!(report.allow_load);
        assert_eq!(report.generators, found);
    }

    #[test]
    fn clean_list_and_malformed_list() {
        assert!(
            detect("1 0 init\n2 1 bash\n", "1 init\n2 bash -c yes\n")
                .unwrap()
                .is_empty()
        );
        assert!(detect("not-a-pid 1 yes", "1 init").is_err());
        assert!(detect("2 1", "1 init").is_err());
        assert!(detect("2 1 yes", "invalid init").is_err());
    }
}
