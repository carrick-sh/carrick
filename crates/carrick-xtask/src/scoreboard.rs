//! `carrick-xtask scoreboard` (#2127): the goal scoreboard, "does carrick run
//! real programs", as a subcommand instead of a hand-run director script.
//!
//! Runs eight Python, Node and Go rows against one carrick binary, each under
//! a 120 s bound with its own `CARRICK_RUN_ID`, stdin from `/dev/null`, and the
//! row's guest reaped by run id afterwards (never `pkill -f carrick`). It
//! prints the summary table and writes a JSON receipt. The score is data, not
//! a gate: a failing row never changes the exit status.
//!
//! The glibc-vs-musl thread census the old script appended is not ported here.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::Duration;
use thiserror::Error;

pub const SCHEMA: &str = "carrick.scoreboard.v1";
const PY: &str = "docker.io/library/python:3.12-slim";
const NODE: &str = "docker.io/library/node:22-slim";
const GO: &str = "docker.io/library/golang:1.23";
const DEFAULT_BOUND_SECS: u64 = 120;
/// Exit code the old `perl -e 'alarm 120'` bound produced: 128 + SIGALRM.
/// A timed-out row reports it whatever signal actually ended it.
const TIMEOUT_EXIT: i32 = 128 + libc::SIGALRM;
/// Grace between the bound's SIGTERM and a SIGKILL of a row that ignores it.
const KILL_GRACE: Duration = Duration::from_secs(5);

#[derive(clap::Args, Debug)]
pub struct ScoreboardArgs {
    /// The signed carrick binary to score.
    #[arg(long)]
    pub carrick: PathBuf,
    /// Comma-separated row names to run (default: all rows).
    #[arg(long, value_delimiter = ',')]
    pub rows: Vec<String>,
    /// Where to write the JSON receipt.
    #[arg(long)]
    pub out: PathBuf,
    /// Main SHA the binary was built from (default: `git rev-parse HEAD`).
    #[arg(long)]
    pub sha: Option<String>,
    /// Per-row evidence directory (default: `<out>.rows`).
    #[arg(long)]
    pub evidence: Option<PathBuf>,
    /// Per-row bound in seconds.
    #[arg(long, default_value_t = DEFAULT_BOUND_SECS)]
    pub bound_secs: u64,
    /// Reaper invoked as `<reaper> <run-id>`, then `sudo -n <reaper> <run-id>`
    /// if that fails (default: `<root>/scripts/sudo/kill.sh`).
    #[arg(long)]
    pub reaper: Option<PathBuf>,
}

#[derive(Debug, Error)]
pub enum ScoreboardError {
    #[error("unknown row `{0}` (rows: {1})")]
    UnknownRow(String, String),
    #[error("{path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("cannot determine the main SHA: {0}")]
    Sha(String),
    #[error("receipt: {0}")]
    Json(#[from] serde_json::Error),
}

fn io_err(path: &Path) -> impl FnOnce(io::Error) -> ScoreboardError + '_ {
    move |source| ScoreboardError::Io {
        path: path.to_path_buf(),
        source,
    }
}

pub struct Row {
    pub name: &'static str,
    pub image: &'static str,
    pub command: &'static [&'static str],
}

pub const ROWS: &[Row] = &[
    Row {
        name: "py-version",
        image: PY,
        command: &["python3", "-c", "import sys; print(sys.version.split()[0])"],
    },
    Row {
        name: "py-thread",
        image: PY,
        command: &[
            "python3",
            "-c",
            "import threading; t=threading.Thread(target=lambda: print(\"thread-ok\")); t.start(); t.join()",
        ],
    },
    Row {
        name: "py-fork",
        image: PY,
        command: &[
            "python3",
            "-c",
            "import os; p=os.fork(); print(\"child-ok\") if p==0 else (os.waitpid(p,0), print(\"parent-ok\"))",
        ],
    },
    Row {
        name: "py-subproc",
        image: PY,
        command: &[
            "python3",
            "-c",
            "import subprocess; print(subprocess.run([\"/bin/echo\",\"sub-ok\"],capture_output=True,text=True).stdout.strip())",
        ],
    },
    Row {
        name: "node-version",
        image: NODE,
        command: &["node", "-e", "console.log(process.version)"],
    },
    Row {
        name: "node-child",
        image: NODE,
        command: &[
            "node",
            "-e",
            "console.log(require(\"child_process\").execSync(\"echo child-ok\").toString().trim())",
        ],
    },
    Row {
        name: "go-version",
        image: GO,
        command: &["go", "version"],
    },
    Row {
        name: "go-hello",
        image: GO,
        command: &[
            "sh",
            "-c",
            "cd /tmp && printf \"package main\\nimport \\\"fmt\\\"\\nfunc main(){fmt.Println(\\\"go-ok\\\")}\\n\" > h.go && go run h.go",
        ],
    },
];

/// Resolve `--rows` against [`ROWS`], keeping table order; empty means all.
pub fn select_rows(names: &[String]) -> Result<Vec<&'static Row>, ScoreboardError> {
    for name in names {
        if !ROWS.iter().any(|r| r.name == name) {
            let all: Vec<_> = ROWS.iter().map(|r| r.name).collect();
            return Err(ScoreboardError::UnknownRow(name.clone(), all.join(",")));
        }
    }
    Ok(ROWS
        .iter()
        .filter(|r| names.is_empty() || names.iter().any(|n| n == r.name))
        .collect())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RowResult {
    pub name: String,
    pub exit_code: i32,
    pub timed_out: bool,
    pub passed: bool,
    pub first_stdout_line: String,
    pub key_stderr_line: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Receipt {
    pub schema: String,
    pub main_sha: String,
    pub binary_sha256: String,
    pub rows: Vec<RowResult>,
}

fn first_line(text: &str) -> String {
    text.lines()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("")
        .to_string()
}

/// The last non-empty stderr line: where a guest or runtime reports why it died.
fn key_line(text: &str) -> String {
    text.lines()
        .rev()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("")
        .to_string()
}

pub fn row_result(
    name: &str,
    exit_code: i32,
    timed_out: bool,
    stdout: &str,
    stderr: &str,
) -> RowResult {
    RowResult {
        name: name.to_string(),
        exit_code,
        timed_out,
        passed: exit_code == 0 && !timed_out,
        first_stdout_line: first_line(stdout),
        key_stderr_line: key_line(stderr),
    }
}

/// The script's `printf "%-16s exit=%-4s %s"`: stdout newlines to spaces, cut to 60.
pub fn table_line(r: &RowResult) -> String {
    let joined: String = r.first_stdout_line.chars().take(60).collect();
    format!("{:<16} exit={:<4} {}", r.name, r.exit_code, joined)
}

pub fn render_table(rows: &[RowResult]) -> String {
    rows.iter().map(|r| table_line(r) + "\n").collect()
}

pub fn render_receipt(receipt: &Receipt) -> Result<String, ScoreboardError> {
    Ok(serde_json::to_string_pretty(receipt)? + "\n")
}

fn sha256_file(path: &Path) -> Result<String, ScoreboardError> {
    let mut file = File::open(path).map_err(io_err(path))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 1 << 16];
    loop {
        let n = file.read(&mut buf).map_err(io_err(path))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

fn read_lossy(path: &Path) -> String {
    fs::read(path)
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .unwrap_or_default()
}

struct Runner<'a> {
    carrick: &'a Path,
    evidence: &'a Path,
    bound: Duration,
    reaper: &'a Path,
}

impl Runner<'_> {
    fn run(&self, row: &Row) -> Result<RowResult, ScoreboardError> {
        let out_path = self.evidence.join(format!("{}.out", row.name));
        let err_path = self.evidence.join(format!("{}.err", row.name));
        let run_id = format!("score-{}", row.name);
        let stdout = File::create(&out_path).map_err(io_err(&out_path))?;
        let stderr = File::create(&err_path).map_err(io_err(&err_path))?;
        let mut child = Command::new(self.carrick)
            .args(["run", "--rm", "-w", "/tmp", row.image])
            .args(row.command)
            .env("CARRICK_RUN_ID", &run_id)
            .stdin(Stdio::null())
            .stdout(stdout)
            .stderr(stderr)
            // Own process group: the leader's pid is the group id, so a
            // timeout can signal every process the row spawned.
            .process_group(0)
            .spawn()
            .map_err(io_err(self.carrick))?;
        let pid = child.id() as libc::pid_t;
        let (done_tx, done_rx) = mpsc::channel::<()>();
        let (bound, grace) = (self.bound, KILL_GRACE);
        let (reaper, reap_run_id) = (self.reaper.to_path_buf(), run_id.clone());
        // The watchdog sleeps on the channel with the bound as its deadline.
        // The main thread leaves the child as a zombie (`WNOWAIT`) until the
        // watchdog is joined, so the group id stays ours and a signal can
        // never reach a recycled pid. On timeout the watchdog also reaps, so a
        // wedged guest cannot block cleanup behind the blocking wait.
        let watchdog = std::thread::spawn(move || {
            if done_rx.recv_timeout(bound) != Err(RecvTimeoutError::Timeout) {
                return false;
            }
            // SAFETY: the leader is alive or an unreaped zombie until the join,
            // so `-pid` names our row's group.
            unsafe { libc::kill(-pid, libc::SIGTERM) };
            // Returns early once the leader exits, but members that ignored
            // SIGTERM may remain, so the group is killed either way.
            let _ = done_rx.recv_timeout(grace);
            // SAFETY: as above.
            unsafe { libc::kill(-pid, libc::SIGKILL) };
            reap(&reaper, &reap_run_id);
            true
        });
        wait_without_reaping(pid).map_err(io_err(self.carrick))?;
        let _ = done_tx.send(());
        let timed_out = watchdog.join().unwrap_or(false);
        if !timed_out {
            // A row that exited by itself may still have left members behind.
            // SAFETY: the leader is still an unreaped zombie, so the group id
            // cannot have been recycled.
            unsafe { libc::kill(-pid, libc::SIGKILL) };
            reap(self.reaper, &run_id);
        }
        let status = child.wait().map_err(io_err(self.carrick))?;
        let exit_code = signal_exit(&status);
        let mut result = row_result(
            row.name,
            exit_code,
            timed_out,
            &read_lossy(&out_path),
            &read_lossy(&err_path),
        );
        if timed_out {
            result.exit_code = TIMEOUT_EXIT;
        }
        Ok(result)
    }
}

/// Upper bound on one reaper invocation.
const REAP_BOUND: Duration = Duration::from_secs(30);

/// Reap a run id's guest, the way the other harnesses do: run the reaper
/// directly first, and fall back to `sudo -n` only if that did not succeed.
/// The row is scored whether or not the reap succeeds.
fn reap(reaper: &Path, run_id: &str) {
    let direct = Command::new(reaper);
    let mut sudo = Command::new("sudo");
    sudo.arg("-n").arg(reaper);
    for command in [direct, sudo] {
        if run_bounded(command, run_id) {
            return;
        }
    }
}

/// Run `command <run-id>` in its own group under [`REAP_BOUND`]; true on exit 0.
fn run_bounded(mut command: Command, run_id: &str) -> bool {
    let Ok(mut child) = command
        .arg(run_id)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()
    else {
        return false;
    };
    let pid = child.id() as libc::pid_t;
    let (tx, rx) = mpsc::channel();
    let waiter = std::thread::spawn(move || {
        let _ = tx.send(child.wait());
    });
    let status = match rx.recv_timeout(REAP_BOUND) {
        Ok(status) => status,
        Err(_) => {
            // SAFETY: the waiter has not reaped the child yet, so `-pid` is
            // still its group.
            unsafe { libc::kill(-pid, libc::SIGKILL) };
            rx.recv()
                .unwrap_or_else(|_| Err(io::ErrorKind::TimedOut.into()))
        }
    };
    let _ = waiter.join();
    status.is_ok_and(|s| s.success())
}

/// Block until `pid` has exited, leaving it reapable.
fn wait_without_reaping(pid: libc::pid_t) -> io::Result<()> {
    loop {
        // SAFETY: an all-zero siginfo_t is a valid out-parameter for waitid.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // SAFETY: `info` is valid for writes and `pid` is our own child.
        let rc = unsafe {
            libc::waitid(
                libc::P_PID,
                pid as libc::id_t,
                &mut info,
                libc::WEXITED | libc::WNOWAIT,
            )
        };
        if rc == 0 {
            return Ok(());
        }
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
}

/// Shell-style exit code: the code, or 128 + signal.
fn signal_exit(status: &std::process::ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    status
        .code()
        .or_else(|| status.signal().map(|s| 128 + s))
        .unwrap_or(-1)
}

fn main_sha(root: &Path, given: Option<&str>) -> Result<String, ScoreboardError> {
    if let Some(sha) = given {
        return Ok(sha.to_string());
    }
    let out = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["rev-parse", "HEAD"])
        .output()
        .map_err(|e| ScoreboardError::Sha(e.to_string()))?;
    if !out.status.success() {
        return Err(ScoreboardError::Sha(
            String::from_utf8_lossy(&out.stderr).trim().to_string(),
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Run the scoreboard, printing the table to `writer` and writing the receipt.
pub fn run(
    root: &Path,
    args: ScoreboardArgs,
    writer: &mut dyn Write,
) -> Result<Receipt, ScoreboardError> {
    let rows = select_rows(&args.rows)?;
    let sha = main_sha(root, args.sha.as_deref())?;
    let binary_sha256 = sha256_file(&args.carrick)?;
    let evidence = args.evidence.clone().unwrap_or_else(|| {
        let mut name = args.out.as_os_str().to_owned();
        name.push(".rows");
        PathBuf::from(name)
    });
    fs::create_dir_all(&evidence).map_err(io_err(&evidence))?;
    let reaper = args
        .reaper
        .clone()
        .unwrap_or_else(|| root.join("scripts/sudo/kill.sh"));
    let runner = Runner {
        carrick: &args.carrick,
        evidence: &evidence,
        bound: Duration::from_secs(args.bound_secs),
        reaper: &reaper,
    };
    let short: String = sha.chars().take(10).collect();
    let _ = writeln!(writer, "main {short}  sha256={}", &binary_sha256[..16]);
    let mut results = Vec::new();
    for row in rows {
        let result = runner.run(row)?;
        let _ = writeln!(writer, "{}", table_line(&result));
        results.push(result);
    }
    let receipt = Receipt {
        schema: SCHEMA.to_string(),
        main_sha: sha,
        binary_sha256,
        rows: results,
    };
    fs::write(&args.out, render_receipt(&receipt)?).map_err(io_err(&args.out))?;
    let _ = writeln!(writer, "receipt: {}", args.out.display());
    Ok(receipt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use carrick_test_support::executable::write_executable_mode;

    #[test]
    fn row_table_matches_the_script() {
        let names: Vec<_> = ROWS.iter().map(|r| r.name).collect();
        assert_eq!(
            names,
            [
                "py-version",
                "py-thread",
                "py-fork",
                "py-subproc",
                "node-version",
                "node-child",
                "go-version",
                "go-hello"
            ]
        );
    }

    #[test]
    fn select_rows_filters_and_rejects_unknown() {
        let picked = select_rows(&["go-hello".into(), "py-fork".into()]).unwrap_or_default();
        let names: Vec<_> = picked.iter().map(|r| r.name).collect();
        assert_eq!(names, ["py-fork", "go-hello"]);
        assert!(matches!(
            select_rows(&["nope".into()]),
            Err(ScoreboardError::UnknownRow(..))
        ));
    }

    #[test]
    fn result_parsing_takes_first_stdout_and_last_stderr_line() {
        let r = row_result(
            "x",
            1,
            false,
            "\nfirst\nsecond\n",
            "warn\n\nfatal: boom\n\n",
        );
        assert_eq!(r.first_stdout_line, "first");
        assert_eq!(r.key_stderr_line, "fatal: boom");
        assert!(!r.passed);
        assert!(row_result("x", 0, false, "", "").passed);
        assert!(!row_result("x", 0, true, "", "").passed);
    }

    #[test]
    fn table_line_pads_and_truncates() {
        let r = row_result("py-fork", 0, false, &"a".repeat(80), "");
        assert_eq!(
            table_line(&r),
            format!("py-fork          exit=0    {}", "a".repeat(60))
        );
    }

    #[test]
    fn receipt_round_trips() {
        let receipt = Receipt {
            schema: SCHEMA.into(),
            main_sha: "abc".into(),
            binary_sha256: "def".into(),
            rows: vec![row_result("go-version", 0, false, "go1.23\n", "")],
        };
        let text = render_receipt(&receipt).unwrap_or_default();
        let back: Receipt = serde_json::from_str(&text).unwrap_or_else(|_| Receipt {
            schema: String::new(),
            main_sha: String::new(),
            binary_sha256: String::new(),
            rows: vec![],
        });
        assert_eq!(back.rows, receipt.rows);
        assert_eq!(back.schema, SCHEMA);
    }

    /// Fake carrick: the image argument picks the behaviour; `go` hangs, `node`
    /// fails with a stderr line, the rest print and succeed. Records reaps.
    fn fixture(dir: &Path) -> (PathBuf, PathBuf, PathBuf) {
        let carrick = dir.join("carrick");
        write_executable_mode(
            &carrick,
            "#!/bin/sh\n\
             echo \"id=$CARRICK_RUN_ID\" >> \"$0.log\"\n\
             case \"$5\" in\n\
               *golang*) sleep 30 ;;\n\
               *node*) echo v22; echo 'node: bad' >&2; exit 3 ;;\n\
               *) echo ok-$6; read x; echo extra ;;\n\
             esac\n",
            0o755,
        );
        let reaper = dir.join("reap");
        write_executable_mode(&reaper, "#!/bin/sh\necho \"$1\" >> \"$0.log\"\n", 0o755);
        (carrick, reaper, dir.join("receipt.json"))
    }

    #[test]
    fn run_scores_pass_fail_and_timeout_and_exits_ok() {
        let dir = tempfile::tempdir().unwrap_or_else(|_| std::process::abort());
        let (carrick, reaper, out) = fixture(dir.path());
        let args = ScoreboardArgs {
            carrick,
            rows: vec![
                "py-version".into(),
                "node-version".into(),
                "go-version".into(),
            ],
            out: out.clone(),
            sha: Some("0123456789abcdef".into()),
            evidence: None,
            bound_secs: 1,
            reaper: Some(reaper.clone()),
        };
        let mut table = Vec::new();
        let receipt = run(dir.path(), args, &mut table).unwrap_or_else(|_| std::process::abort());
        let by: Vec<_> = receipt
            .rows
            .iter()
            .map(|r| (r.name.as_str(), r.exit_code, r.passed))
            .collect();
        assert_eq!(
            by,
            [
                ("py-version", 0, true),
                ("node-version", 3, false),
                ("go-version", TIMEOUT_EXIT, false)
            ]
        );
        assert!(receipt.rows[2].timed_out);
        assert_eq!(receipt.rows[0].first_stdout_line, "ok-python3");
        assert_eq!(receipt.rows[1].key_stderr_line, "node: bad");
        let table = String::from_utf8_lossy(&table).into_owned();
        assert!(table.starts_with("main 0123456789  sha256="));
        assert!(table.contains("node-version     exit=3    v22"));
        let log = read_lossy(&dir.path().join("carrick.log"));
        assert_eq!(
            log.lines().collect::<Vec<_>>(),
            [
                "id=score-py-version",
                "id=score-node-version",
                "id=score-go-version"
            ]
        );
        // The reaper runs directly (no sudo) once per row, by run id.
        assert_eq!(
            read_lossy(&dir.path().join("reap.log"))
                .lines()
                .collect::<Vec<_>>(),
            ["score-py-version", "score-node-version", "score-go-version"]
        );
        let on_disk: Receipt =
            serde_json::from_str(&read_lossy(&out)).unwrap_or_else(|_| std::process::abort());
        assert_eq!(on_disk.main_sha, "0123456789abcdef");
        assert_eq!(on_disk.binary_sha256.len(), 64);
    }

    fn alive(pid: libc::pid_t) -> bool {
        match fs::read_to_string(format!("/proc/{pid}/stat")) {
            Ok(stat) => !stat.rsplit(") ").next().unwrap_or("").starts_with('Z'),
            Err(_) => false,
        }
    }

    /// A `go` row whose carrick forks a grandchild and hangs; `prelude` runs
    /// first. After the timeout nothing from the row's process group may live.
    fn assert_timeout_kills_the_group(prelude: &str) {
        let dir = tempfile::tempdir().unwrap_or_else(|_| std::process::abort());
        let carrick = dir.path().join("carrick");
        write_executable_mode(
            &carrick,
            &format!(
                "#!/bin/sh\n{prelude}echo $$ > \"$0.pid\"\n\
                 sleep 30 &\necho $! > \"$0.gc\"\nwait\n"
            ),
            0o755,
        );
        let reaper = dir.path().join("reap");
        write_executable_mode(&reaper, "#!/bin/sh\necho \"$1\" >> \"$0.log\"\n", 0o755);
        let args = ScoreboardArgs {
            carrick,
            rows: vec!["go-version".into()],
            out: dir.path().join("receipt.json"),
            sha: Some("abc".into()),
            evidence: None,
            bound_secs: 1,
            reaper: Some(reaper),
        };
        let receipt =
            run(dir.path(), args, &mut Vec::new()).unwrap_or_else(|_| std::process::abort());
        assert!(receipt.rows[0].timed_out);
        let pid_of = |name: &str| -> libc::pid_t {
            read_lossy(&dir.path().join(name))
                .trim()
                .parse()
                .unwrap_or(-1)
        };
        let (leader, grandchild) = (pid_of("carrick.pid"), pid_of("carrick.gc"));
        assert!(leader > 0 && grandchild > 0, "fixture did not record pids");
        // SAFETY: signal 0 only probes for a process group.
        let group_gone = unsafe { libc::kill(-leader, 0) } == -1;
        assert!(group_gone, "row's process group {leader} still has members");
        assert!(
            !alive(grandchild),
            "grandchild {grandchild} survived the row"
        );
    }

    #[test]
    fn timeout_kills_the_whole_row() {
        assert_timeout_kills_the_group("");
    }

    #[test]
    fn timeout_escalates_to_sigkill_when_sigterm_is_ignored() {
        assert_timeout_kills_the_group("trap '' TERM ALRM\n");
    }
}
