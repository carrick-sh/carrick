//! `carrick debug host-stacks`: every host thread's backtrace of a live,
//! wedged or orphaned carrier, and optionally a core, taken from outside.
//!
//! `zonedump` reads the guest side of a hang through the run's debug
//! endpoint. That endpoint is gone once the carrier is in teardown (#2955:
//! a carrier that spun for hours in its `KernelContext` drop after its
//! vCPU pool had ended), so the host threads' stacks are the only evidence
//! left. This command takes them for every process whose title carries
//! the run's `carrick:<run-id>:` token (the token `scripts/sudo/kill.sh`
//! reaps by, so a reparented carrier is found too) and for each of their
//! descendants.
//!
//! The capture itself is `carrick_kernel::wedge_capture`'s, the one host
//! debugger runner the in-process wedge capture and the KVM test deadline
//! use: gdb on Linux and the BSDs, `sudo -n lldb` on macOS, each step
//! bounded, an empty artifact a named failure. The process table comes from
//! `ps -A -o pid=,ppid=,stat=,command=` (the same flags on Linux procps,
//! macOS and the BSDs). Every matched process is attempted; the command fails when none
//! matches or any capture failed.

use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};

/// One row of the host process table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HostProcess {
    pub(crate) pid: u32,
    pub(crate) ppid: u32,
    /// `ps`'s process state (`R`, `S`, `T`, ...).
    pub(crate) stat: String,
    pub(crate) title: String,
}

/// Which processes to capture, and where.
pub(crate) struct HostStacksOptions<'a> {
    /// Match processes titled `carrick:<run_id>:` and their descendants.
    pub(crate) run_id: Option<&'a str>,
    /// Or this process and its descendants.
    pub(crate) pid: Option<u32>,
    /// One private `host-stacks-<pid>/` capture directory per process goes
    /// under here (created 0700 when absent).
    pub(crate) out_dir: &'a Path,
    /// Also write a core of each matched root process.
    pub(crate) core: bool,
}

pub(crate) fn run_host_stacks(options: &HostStacksOptions<'_>) -> Result<()> {
    let table = process_table()?;
    let roots = match_roots(&table, options.run_id, options.pid)?;
    let mut failures = 0usize;
    for pid in with_descendants(&table, &roots) {
        let Some(row) = table.iter().find(|row| row.pid == pid) else {
            continue;
        };
        let Ok(host_pid) = i32::try_from(pid) else {
            continue;
        };
        let request = carrick_kernel::wedge_capture::WedgeCaptureRequest {
            label: "host-stacks".to_owned(),
            pid: host_pid,
            run_id: options.run_id.map(str::to_owned),
            budget_ms: 0,
            elapsed_ms: 0,
            out_root: options.out_dir.to_path_buf(),
        };
        let core = options.core && roots.contains(&pid);
        let line = match carrick_kernel::wedge_capture::capture_external_carrier(request, core) {
            Ok(capture) => {
                let mut artifacts = capture.backtrace.display().to_string();
                if let Some(core) = capture.core {
                    artifacts.push(' ');
                    artifacts.push_str(&core.display().to_string());
                }
                format!("pid {pid} ppid {} {}: {artifacts}", row.ppid, row.title)
            }
            Err(error) => {
                failures += 1;
                format!("pid {pid} ppid {} {}: failed: {error}", row.ppid, row.title)
            }
        };
        println!("{line}");
    }
    if failures > 0 {
        bail!("{failures} host stack capture(s) failed");
    }
    Ok(())
}

/// The matched root pids: the titled carriers of `run_id`, or `pid`. None
/// is a named failure.
fn match_roots(table: &[HostProcess], run_id: Option<&str>, pid: Option<u32>) -> Result<Vec<u32>> {
    match (run_id, pid) {
        (Some(run_id), _) => {
            let roots = titled_roots(table, run_id);
            if roots.is_empty() {
                bail!("no host process is titled `carrick:{run_id}:`");
            }
            Ok(roots)
        }
        (None, Some(pid)) => {
            if !table.iter().any(|row| row.pid == pid) {
                bail!("no host process has pid {pid}");
            }
            Ok(vec![pid])
        }
        (None, None) => bail!("host-stacks needs --run-id or --pid"),
    }
}

/// The host process table, from `ps -A -o pid=,ppid=,stat=,command=` (the
/// same flags on Linux procps, macOS and the BSDs). The one host process
/// lookup of `carrick debug`: `host-stacks` and the macOS `lldb-deadline`
/// scoped-run helpers both read it.
pub(crate) fn process_table() -> Result<Vec<HostProcess>> {
    let output = Command::new("ps")
        .args(["-A", "-o", "pid=,ppid=,stat=,command="])
        .stdin(Stdio::null())
        .output()
        .context("run ps for the host process table")?;
    if !output.status.success() {
        bail!("ps exited with {}", output.status);
    }
    Ok(parse_process_table(&String::from_utf8_lossy(
        &output.stdout,
    )))
}

/// Parse `pid ppid stat command...` rows; rows that are not are skipped.
fn parse_process_table(text: &str) -> Vec<HostProcess> {
    text.lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let pid = fields.next()?.parse().ok()?;
            let ppid = fields.next()?.parse().ok()?;
            let stat = fields.next()?.to_owned();
            Some(HostProcess {
                pid,
                ppid,
                stat,
                title: fields.collect::<Vec<_>>().join(" "),
            })
        })
        .collect()
}

/// Processes whose title carries the exact delimited `carrick:<run_id>:`
/// token, so a run id that is a prefix of another (`r-1` and `r-10`)
/// never matches the longer one.
fn titled_roots(table: &[HostProcess], run_id: &str) -> Vec<u32> {
    let token = format!("carrick:{run_id}:");
    table
        .iter()
        .filter(|row| row.title.contains(&token))
        .map(|row| row.pid)
        .collect()
}

/// `roots`, then each of their live descendants, each pid once, parents
/// before children.
fn with_descendants(table: &[HostProcess], roots: &[u32]) -> Vec<u32> {
    let mut tree: Vec<u32> = Vec::new();
    for &root in roots {
        if !tree.contains(&root) {
            tree.push(root);
        }
    }
    let mut at = 0;
    while at < tree.len() {
        let parent = tree[at];
        for row in table.iter().filter(|row| row.ppid == parent) {
            if !tree.contains(&row.pid) {
                tree.push(row.pid);
            }
        }
        at += 1;
    }
    tree
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(pid: u32, ppid: u32, title: &str) -> HostProcess {
        HostProcess {
            pid,
            ppid,
            stat: "S".to_string(),
            title: title.to_string(),
        }
    }

    #[test]
    fn the_ps_table_parses_pid_ppid_and_the_whole_title() {
        let table = parse_process_table(
            "    1     0 Ss /sbin/init\n 2207575     1 S carrick:x86-kvm-test: 0 containers\nnot a row\n",
        );
        assert_eq!(
            table,
            vec![
                HostProcess {
                    stat: "Ss".to_string(),
                    ..row(1, 0, "/sbin/init")
                },
                row(2207575, 1, "carrick:x86-kvm-test: 0 containers"),
            ]
        );
    }

    #[test]
    fn a_run_id_matches_only_its_exact_delimited_token() {
        let table = vec![
            row(10, 1, "carrick:r-1: /hello"),
            row(11, 1, "carrick:r-10: /hello"),
            row(12, 1, "carrick debug host-stacks --run-id r-1"),
        ];
        assert_eq!(titled_roots(&table, "r-1"), vec![10]);
        assert_eq!(titled_roots(&table, "r-10"), vec![11]);
        assert!(match_roots(&table, Some("r-2"), None).is_err());
        assert!(match_roots(&table, None, Some(99)).is_err());
        assert_eq!(match_roots(&table, None, Some(12)).unwrap(), vec![12]);
    }

    #[test]
    fn descendants_follow_their_roots_once_each() {
        let table = vec![
            row(10, 1, "carrick:r: a"),
            row(20, 10, "helper"),
            row(30, 20, "grandchild"),
            row(40, 1, "unrelated"),
        ];
        assert_eq!(with_descendants(&table, &[10, 10]), vec![10, 20, 30]);
    }
}
