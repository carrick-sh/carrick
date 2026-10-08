//! Gate-host checkout lock whose liveness is the holders' own processes.
//!
//! The lock is still the `gate-worktree.lock` directory (`run_id` inside), so
//! the lock order stays: remote checkout lock -> host lease -> work. What is
//! new is `holders/<pid>`: each file names a gate-host process that holds the
//! lock and records that process's start time (`ps -o lstart=` under
//! `LC_ALL=C TZ=UTC0`). A pid plus start time names exactly one process
//! incarnation, so a recycled pid never revives a dead holder.
//!
//! - The acquiring ssh session becomes the first holder (the *keeper*): the
//!   remote shell claims the lock and then `exec`s `cat`, which lives until
//!   the local driver closes its stdin. A driver that is killed, or whose ssh
//!   connection drops, closes that pipe; the keeper exits with it.
//! - Work that outlives the driver (the detached accept job, the recapture
//!   launch shell that keeps running after an ssh drop) joins as a holder
//!   while a live sponsor holder still exists ([`build_join_cmd`]). A holder
//!   is only ever added while its sponsor is verifiably alive.
//! - A lock is stale only when every recorded holder is dead and the holder
//!   set did not change while it was being inspected. Because a new holder
//!   needs a live sponsor, a dead, unchanged holder set can never gain a live
//!   member again. Reclaimers of one stale incarnation are serialized by
//!   `reclaim.<n>` symlinks, created atomically with the reclaimer's identity
//!   as their target; a dead reclaimer's token is skipped by the next level.
//!   Each recovery appends the recovered run-id to `<lock>.recoveries`.
//! - A lock without holder records (written before liveness existed) is
//!   recovered only through the published `gate-runs/<run-id>/exit` file, as
//!   before; otherwise it is reported and left alone.
//!
//! New claims are staged privately and published with one `rename`, so a lock
//! is never visible without its holder record.
use std::io::{BufRead, BufReader};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use crate::remote_accept::{RemoteAcceptError, shell_quote};

/// Exit status of a remote join refused because the lock is not (or no longer)
/// held through a live sponsor.
pub const LOCK_LOST_STATUS: i32 = 75;

const PRELUDE: &str = r#"LC_ALL=C TZ=UTC0
export LC_ALL TZ
ident() { ps -o lstart= -p "$1" 2>/dev/null; }
"#;

const ACQUIRE_BODY: &str = r#"lock=$1 run=$2 runs=$3 me=$$
start=$(ident "$me")
[ -n "$start" ] || { echo "ERROR:cannot read the start time of process $me"; exit 70; }
holder_id() { cat "$lock/run_id" 2>/dev/null || echo unknown; }
claim() {
  stage="$lock.claim.$me"
  rm -rf "$stage"
  if ! { mkdir "$stage" && mkdir "$stage/holders" && printf '%s\n' "$start" > "$stage/holders/$me" && printf '%s\n' "$run" > "$stage/run_id"; }; then
    rm -rf "$stage"
    return 2
  fi
  [ -e "$lock" ] || mv "$stage" "$lock" 2>/dev/null
  rm -rf "$stage" "$lock/${stage##*/}"
  [ "$(cat "$lock/run_id" 2>/dev/null)" = "$run" ] && [ "$(cat "$lock/holders/$me" 2>/dev/null)" = "$start" ]
}
snapshot() {
  for f in "$lock"/holders/*; do
    [ -f "$f" ] && printf '%s=%s;' "${f##*/}" "$(cat "$f")"
  done
  return 0
}
live() {
  for f in "$lock"/holders/*; do
    [ -f "$f" ] || continue
    s=$(ident "${f##*/}")
    [ -n "$s" ] && [ "$s" = "$(cat "$f")" ] && return 0
  done
  return 1
}
held() { echo "HELD:$1:$holder"; exit 0; }
claim
rc=$?
[ "$rc" = 2 ] && { echo "ERROR:cannot stage a lock claim next to $lock"; exit 70; }
if [ "$rc" = 0 ]; then
  echo "LOCKED $me"
  exec cat >/dev/null
fi
holder=$(holder_id)
[ -d "$lock" ] || held changed
before=$(snapshot)
if [ -n "$before" ]; then
  if live || [ "$(snapshot)" != "$before" ]; then held live; fi
  reason=holder-exited
  [ "$holder" != unknown ] && [ -f "$runs/$holder/exit" ] && reason=finished
elif [ "$holder" != unknown ] && [ -f "$runs/$holder/exit" ]; then
  reason=finished-unrecorded
else
  held unrecorded
fi
n=1
while ! ln -s "$me $start" "$lock/reclaim.$n" 2>/dev/null; do
  owner=$(readlink "$lock/reclaim.$n") || held changed
  [ "$(ident "${owner%% *}")" = "${owner#* }" ] && held reclaiming
  n=$((n + 1))
done
token="$lock/reclaim.$n"
if [ "$(holder_id)" != "$holder" ] || [ "$(snapshot)" != "$before" ] || live; then
  rm -f "$token"
  held changed
fi
grave="$lock.reclaimed.$me"
rm -rf "$grave"
mv "$lock" "$grave" || { rm -f "$token"; echo "ERROR:cannot retire the stale lock $lock"; exit 70; }
printf '%s reclaimer=%s recovered=%s reason=%s holders=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$run" "$holder" "$reason" "$before" >> "$lock.recoveries"
claim
rc=$?
rm -rf "$grave"
[ "$rc" = 2 ] && { echo "ERROR:cannot stage a lock claim next to $lock"; exit 70; }
if [ "$rc" != 0 ]; then
  holder=$(holder_id)
  held live
fi
echo "RECOVERED:$reason:$holder $me"
exec cat >/dev/null
"#;

const JOIN_BODY: &str = r#"lock=$1 run=$2 sponsor=$3 pid=$4
refuse() { echo "remote checkout lock $lock: $1" >&2; exit 75; }
start=$(ident "$pid")
[ -n "$start" ] || refuse "holder $pid is not running"
[ "$(cat "$lock/run_id" 2>/dev/null)" = "$run" ] || refuse "not held by run-id $run"
printf '%s\n' "$start" > "$lock/holders/$pid" || refuse "cannot record holder $pid"
s=$(ident "$sponsor")
if [ -z "$s" ] || [ "$s" != "$(cat "$lock/holders/$sponsor" 2>/dev/null)" ] || [ "$(cat "$lock/run_id" 2>/dev/null)" != "$run" ]; then
  rm -f "$lock/holders/$pid"
  refuse "sponsor $sponsor no longer holds run-id $run"
fi
"#;

/// Where lock scripts run: the gate host over ssh, or a local shell (tests).
#[derive(Debug, Clone)]
pub enum RemoteShell {
    Ssh(String),
    Local,
}

impl RemoteShell {
    pub fn ssh(host: &str) -> Self {
        Self::Ssh(host.to_string())
    }

    fn label(&self) -> &str {
        match self {
            Self::Ssh(host) => host,
            Self::Local => "local",
        }
    }

    fn command(&self, script: &str) -> Command {
        match self {
            Self::Ssh(host) => {
                let mut command = Command::new("ssh");
                // Keepalives end a keeper whose connection silently died.
                command.args([
                    "-o",
                    "BatchMode=yes",
                    "-o",
                    "ConnectTimeout=10",
                    "-o",
                    "ServerAliveInterval=15",
                    "-o",
                    "ServerAliveCountMax=4",
                    host,
                    script,
                ]);
                command
            }
            Self::Local => {
                let mut command = Command::new("/bin/sh");
                command.args(["-c", script]);
                command
            }
        }
    }

    fn error(&self, details: String) -> RemoteAcceptError {
        RemoteAcceptError::Ssh {
            host: self.label().to_string(),
            details,
        }
    }

    /// Run a short script to completion and return its stdout.
    pub fn run(&self, script: &str) -> Result<String, RemoteAcceptError> {
        if let Self::Ssh(host) = self {
            return crate::remote_accept::run_ssh_command(host, script);
        }
        let output = self
            .command(script)
            .stdin(Stdio::null())
            .output()
            .map_err(|e| self.error(format!("failed to spawn shell: {e}")))?;
        if !output.status.success() {
            return Err(self.error(format!(
                "command failed with exit {}:\nstdout:\n{}\nstderr:\n{}",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )));
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }
}

/// The claimed lock identity remote holders join through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockClaim {
    pub lock_dir: String,
    pub run_id: String,
    /// Gate-host pid of the keeper (the acquiring session's remote process).
    pub keeper_pid: u32,
}

/// Remote script that claims the lock, or reclaims it when every recorded
/// holder is provably dead, then keeps the session alive as the keeper.
pub fn build_acquire_cmd(lock_dir: &str, run_id: &str, runs_dir: &str) -> String {
    format!(
        "exec /bin/sh -c {} carrick-gate-lock {} {} {}",
        shell_quote(&format!("{PRELUDE}{ACQUIRE_BODY}")),
        shell_quote(lock_dir),
        shell_quote(run_id),
        shell_quote(runs_dir)
    )
}

/// Shell command that records `pid` as a holder of `run_id`'s lock, refused
/// (exit [`LOCK_LOST_STATUS`]) unless `sponsor` is a live recorded holder
/// after the record is written. `sponsor` and `pid` are shell words (for
/// example `"$$"`), expanded by the shell that runs this command.
pub fn build_join_cmd(lock_dir: &str, run_id: &str, sponsor: &str, pid: &str) -> String {
    format!(
        "/bin/sh -c {} carrick-gate-lock-join {} {} {sponsor} {pid}",
        shell_quote(&format!("{PRELUDE}{JOIN_BODY}")),
        shell_quote(lock_dir),
        shell_quote(run_id)
    )
}

/// Remove the lock only while it still belongs to `run_id`.
pub fn build_release_cmd(lock_dir: &str, run_id: &str) -> String {
    let q_lock = shell_quote(lock_dir);
    format!(
        "if [ \"$(cat {q_lock}/run_id 2>/dev/null)\" = {} ]; then rm -rf {q_lock}; fi",
        shell_quote(run_id)
    )
}

#[derive(Debug, PartialEq, Eq)]
enum AcquireStatus {
    Locked {
        keeper_pid: u32,
    },
    Recovered {
        reason: String,
        holder: String,
        keeper_pid: u32,
    },
    Held {
        why: String,
        holder: String,
    },
    Error(String),
}

fn parse_acquire_line(line: &str) -> Option<AcquireStatus> {
    let line = line.trim();
    let pid = |s: &str| s.trim().parse::<u32>().ok();
    if let Some(rest) = line.strip_prefix("LOCKED ") {
        return pid(rest).map(|keeper_pid| AcquireStatus::Locked { keeper_pid });
    }
    if let Some(rest) = line.strip_prefix("RECOVERED:") {
        let (body, keeper) = rest.rsplit_once(' ')?;
        let (reason, holder) = body.split_once(':')?;
        return Some(AcquireStatus::Recovered {
            reason: reason.to_string(),
            holder: holder.to_string(),
            keeper_pid: pid(keeper)?,
        });
    }
    if let Some(rest) = line.strip_prefix("HELD:") {
        let (why, holder) = rest.split_once(':')?;
        return Some(AcquireStatus::Held {
            why: why.to_string(),
            holder: holder.to_string(),
        });
    }
    line.strip_prefix("ERROR:")
        .map(|msg| AcquireStatus::Error(msg.to_string()))
}

fn held_detail(why: &str) -> &'static str {
    match why {
        "live" => "a recorded holder process is still running",
        "reclaiming" => "another driver is reclaiming it right now; retry",
        "changed" => "the lock changed while it was inspected; retry",
        "unrecorded" => {
            "the lock has no holder records and its run published no exit file; \
             it predates holder liveness or its claim was interrupted: confirm that \
             run-id is not running on the gate host before removing the lock by hand"
        }
        _ => "unrecognized lock state",
    }
}

/// An acquired gate checkout lock, kept alive by its remote keeper session.
pub struct RemoteLock {
    shell: RemoteShell,
    claim: LockClaim,
    keeper: Option<Child>,
    keeper_stdin: Option<ChildStdin>,
    _keeper_stdout: Option<BufReader<ChildStdout>>,
    armed: bool,
}

impl RemoteLock {
    pub fn acquire(
        shell: RemoteShell,
        runs_dir: &str,
        lock_dir: &str,
        run_id: &str,
    ) -> Result<Self, RemoteAcceptError> {
        let script = build_acquire_cmd(lock_dir, run_id, runs_dir);
        let mut child = shell
            .command(&script)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| shell.error(format!("failed to spawn lock keeper: {e}")))?;
        let stdin = child.stdin.take();
        let mut stdout = child.stdout.take().map(BufReader::new);
        let mut status = None;
        let mut transcript = String::new();
        if let Some(reader) = stdout.as_mut() {
            let mut line = String::new();
            while status.is_none() {
                line.clear();
                match reader.read_line(&mut line) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {
                        transcript.push_str(&line);
                        status = parse_acquire_line(&line);
                    }
                }
            }
        }
        let keeper_pid = match status {
            Some(AcquireStatus::Locked { keeper_pid }) => keeper_pid,
            Some(AcquireStatus::Recovered {
                reason,
                holder,
                keeper_pid,
            }) => {
                println!(
                    "Notice: recovered stale worktree lock {lock_dir} from run-id '{holder}' \
                     ({reason}: no recorded holder process is alive); now held by '{run_id}'"
                );
                keeper_pid
            }
            other => {
                drop(stdin);
                let exit = child.wait();
                return Err(match other {
                    Some(AcquireStatus::Held { why, holder }) => RemoteAcceptError::LockHeld {
                        host: shell.label().to_string(),
                        run_id: holder,
                        lock_path: lock_dir.to_string(),
                        detail: held_detail(&why).to_string(),
                    },
                    Some(AcquireStatus::Error(msg)) => {
                        shell.error(format!("cannot acquire lock {lock_dir}: {msg}"))
                    }
                    _ => shell.error(format!(
                        "lock keeper for {lock_dir} ended without a status ({exit:?}): {transcript}"
                    )),
                });
            }
        };
        Ok(Self {
            shell,
            claim: LockClaim {
                lock_dir: lock_dir.to_string(),
                run_id: run_id.to_string(),
                keeper_pid,
            },
            keeper: Some(child),
            keeper_stdin: stdin,
            _keeper_stdout: stdout,
            armed: true,
        })
    }

    pub fn claim(&self) -> &LockClaim {
        &self.claim
    }

    /// A remote holder joined (or may have joined) and now owns the release;
    /// dropping this handle only ends the keeper. Liveness decides the rest.
    pub fn hand_off(&mut self) {
        self.armed = false;
    }

    pub fn is_armed(&self) -> bool {
        self.armed
    }

    /// Release while the keeper is still alive, so the lock is never seen as
    /// stale while this driver still owns it; then end the keeper.
    pub fn release(&mut self) {
        if self.armed {
            let cmd = build_release_cmd(&self.claim.lock_dir, &self.claim.run_id);
            if let Err(e) = self.shell.run(&cmd) {
                eprintln!(
                    "Warning: failed to release remote worktree lock {}: {e}",
                    self.claim.lock_dir
                );
            }
            self.armed = false;
        }
        self.end_keeper();
    }

    fn end_keeper(&mut self) {
        // EOF on the keeper's stdin ends its remote `cat`, which ends the session.
        drop(self.keeper_stdin.take());
        if let Some(mut child) = self.keeper.take() {
            let _ = child.wait();
        }
    }
}

impl Drop for RemoteLock {
    fn drop(&mut self) {
        self.release();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;

    #[test]
    fn acquire_command_text() {
        let cmd = build_acquire_cmd(
            "/Volumes/carrick/dev/gate-worktree.lock",
            "0123456789ab-20261006-120000",
            "/Volumes/carrick/dev/gate-runs",
        );
        assert!(cmd.starts_with("exec /bin/sh -c '"));
        assert!(cmd.ends_with(
            " carrick-gate-lock '/Volumes/carrick/dev/gate-worktree.lock' '0123456789ab-20261006-120000' '/Volumes/carrick/dev/gate-runs'"
        ));
        // Locale/zone-stable process identity, published by one rename.
        assert!(cmd.contains("LC_ALL=C TZ=UTC0"));
        assert!(cmd.contains("ps -o lstart= -p"));
        assert!(cmd.contains("mv \"$stage\" \"$lock\""));
        assert!(cmd.contains("echo \"LOCKED $me\""));
        assert!(cmd.contains("exec cat >/dev/null"));
        // Recovery needs dead holders, an unchanged holder set, a reclaim token
        // and a re-verification before the stale lock is retired.
        let dead = cmd
            .find("if live || [ \"$(snapshot)\" != \"$before\" ]")
            .unwrap();
        let token = cmd
            .find("ln -s \"$me $start\" \"$lock/reclaim.$n\"")
            .unwrap();
        let verify = cmd
            .find("if [ \"$(holder_id)\" != \"$holder\" ] || [ \"$(snapshot)\" != \"$before\" ] || live")
            .unwrap();
        let retire = cmd.find("mv \"$lock\" \"$grave\"").unwrap();
        assert!(dead < token && token < verify && verify < retire);
        assert!(cmd.contains(">> \"$lock.recoveries\""));
        // The exit-file path survives for holderless (pre-liveness) locks.
        assert!(cmd.contains("reason=finished-unrecorded"));
        assert!(cmd.contains("held unrecorded"));
        assert!(!cmd.contains("rm -rf \"$lock\""));
    }

    #[test]
    fn join_and_release_command_text() {
        let join = build_join_cmd("/l ock", "run-1", "'4242'", "\"$$\"");
        assert!(join.starts_with("/bin/sh -c '"));
        assert!(join.ends_with(" carrick-gate-lock-join '/l ock' 'run-1' '4242' \"$$\""));
        let record = join.find("> \"$lock/holders/$pid\"").unwrap();
        let sponsor = join.find("s=$(ident \"$sponsor\")").unwrap();
        assert!(
            record < sponsor,
            "the record must precede the sponsor check"
        );
        assert_eq!(
            build_release_cmd("/l ock", "run-1"),
            "if [ \"$(cat '/l ock'/run_id 2>/dev/null)\" = 'run-1' ]; then rm -rf '/l ock'; fi"
        );
    }

    #[test]
    fn acquire_status_lines_parse() {
        assert_eq!(
            parse_acquire_line("LOCKED 123\n"),
            Some(AcquireStatus::Locked { keeper_pid: 123 })
        );
        assert_eq!(
            parse_acquire_line("RECOVERED:holder-exited:abc-1 77"),
            Some(AcquireStatus::Recovered {
                reason: "holder-exited".into(),
                holder: "abc-1".into(),
                keeper_pid: 77
            })
        );
        assert_eq!(
            parse_acquire_line("HELD:live:abc-1"),
            Some(AcquireStatus::Held {
                why: "live".into(),
                holder: "abc-1".into()
            })
        );
        assert_eq!(parse_acquire_line("noise"), None);
    }

    /// A fake gate host: a temp remote root driven through `/bin/sh -c`.
    struct FakeRemote {
        _dir: tempfile::TempDir,
        root: String,
    }

    impl FakeRemote {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let root = dir
                .path()
                .join("remote root")
                .to_string_lossy()
                .into_owned();
            fs::create_dir_all(format!("{root}/gate-runs")).unwrap();
            Self { _dir: dir, root }
        }
        fn lock_dir(&self) -> String {
            format!("{}/gate-worktree.lock", self.root)
        }
        fn runs(&self) -> String {
            format!("{}/gate-runs", self.root)
        }
        fn acquire(&self, run_id: &str) -> Result<RemoteLock, RemoteAcceptError> {
            RemoteLock::acquire(RemoteShell::Local, &self.runs(), &self.lock_dir(), run_id)
        }
        fn run_id(&self) -> String {
            fs::read_to_string(format!("{}/run_id", self.lock_dir()))
                .unwrap()
                .trim()
                .to_string()
        }
        fn publish_exit(&self, run_id: &str) {
            let run = format!("{}/{run_id}", self.runs());
            fs::create_dir_all(&run).unwrap();
            fs::write(format!("{run}/exit"), "0\n").unwrap();
        }
        fn recoveries(&self) -> String {
            fs::read_to_string(format!("{}.recoveries", self.lock_dir())).unwrap_or_default()
        }
    }

    fn held(result: Result<RemoteLock, RemoteAcceptError>) -> (String, String) {
        match result {
            Err(RemoteAcceptError::LockHeld { run_id, detail, .. }) => (run_id, detail),
            Err(other) => panic!("expected LockHeld, got {other}"),
            Ok(_) => panic!("expected LockHeld, got the lock"),
        }
    }

    /// Simulate the local driver dying: nothing releases the lock, and the
    /// keeper's stdin pipe closes (ssh drop) or the keeper is killed outright.
    fn kill_driver(mut lock: RemoteLock, sigkill: bool) {
        lock.armed = false;
        if sigkill {
            let keeper = lock.keeper.as_mut().unwrap();
            keeper.kill().unwrap();
        }
        // end_keeper reaps it; an unreaped zombie would still look alive.
        lock.end_keeper();
    }

    #[test]
    fn live_holder_is_refused_and_release_frees_the_lock() {
        let remote = FakeRemote::new();
        let lock = remote.acquire("run-a").unwrap();
        assert_eq!(lock.claim().run_id, "run-a");
        let holder = format!("{}/holders/{}", remote.lock_dir(), lock.claim().keeper_pid);
        assert!(Path::new(&holder).is_file());
        // Even a published exit never overrides a live holder.
        remote.publish_exit("run-a");
        let (run_id, detail) = held(remote.acquire("run-b"));
        assert_eq!(run_id, "run-a");
        assert!(detail.contains("still running"), "{detail}");
        assert_eq!(remote.run_id(), "run-a");
        drop(lock);
        assert!(!Path::new(&remote.lock_dir()).exists());
        let lock = remote.acquire("run-b").unwrap();
        assert_eq!(remote.run_id(), "run-b");
        assert_eq!(remote.recoveries(), "");
        drop(lock);
    }

    #[test]
    fn killed_holder_without_exit_file_is_recovered() {
        for sigkill in [false, true] {
            let remote = FakeRemote::new();
            kill_driver(remote.acquire("run-dead").unwrap(), sigkill);
            assert_eq!(remote.run_id(), "run-dead");
            assert!(!Path::new(&format!("{}/run-dead/exit", remote.runs())).exists());
            let lock = remote.acquire("run-next").unwrap();
            assert_eq!(remote.run_id(), "run-next");
            let log = remote.recoveries();
            assert!(
                log.contains("reclaimer=run-next recovered=run-dead reason=holder-exited"),
                "{log}"
            );
            let leftovers: Vec<_> = fs::read_dir(&remote.root)
                .unwrap()
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .filter(|n| n.contains(".claim.") || n.contains(".reclaimed."))
                .collect();
            assert!(leftovers.is_empty(), "{leftovers:?}");
            drop(lock);
        }
    }

    #[test]
    fn finished_holder_with_exit_file_is_recovered() {
        // Holder records present, holder gone, exit published.
        let remote = FakeRemote::new();
        kill_driver(remote.acquire("run-done").unwrap(), false);
        remote.publish_exit("run-done");
        drop(remote.acquire("run-next").unwrap());
        assert!(
            remote
                .recoveries()
                .contains("recovered=run-done reason=finished ")
        );

        // A pre-liveness lock (no holder records) still recovers through exit.
        let remote = FakeRemote::new();
        fs::create_dir(remote.lock_dir()).unwrap();
        fs::write(format!("{}/run_id", remote.lock_dir()), "run-legacy\n").unwrap();
        let (run_id, detail) = held(remote.acquire("run-next"));
        assert_eq!(run_id, "run-legacy");
        assert!(detail.contains("no holder records"), "{detail}");
        assert!(Path::new(&remote.lock_dir()).is_dir());
        remote.publish_exit("run-legacy");
        let lock = remote.acquire("run-next").unwrap();
        assert_eq!(remote.run_id(), "run-next");
        assert!(
            remote
                .recoveries()
                .contains("recovered=run-legacy reason=finished-unrecorded")
        );
        drop(lock);
    }

    #[test]
    fn joined_holder_keeps_the_lock_after_the_driver_dies() {
        let remote = FakeRemote::new();
        let lock = remote.acquire("run-job").unwrap();
        let claim = lock.claim().clone();
        // The job joins with the keeper as sponsor, then signals readiness.
        let job = format!(
            "{} || exit 75; echo joined; exec cat >/dev/null",
            build_join_cmd(
                &claim.lock_dir,
                &claim.run_id,
                &claim.keeper_pid.to_string(),
                "\"$$\""
            )
        );
        let mut child = Command::new("/bin/sh")
            .args(["-c", &job])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut line = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        assert_eq!(line.trim(), "joined");
        kill_driver(lock, true);
        let (run_id, _) = held(remote.acquire("run-next"));
        assert_eq!(run_id, "run-job");
        // A join whose sponsor (the dead keeper) is gone is refused.
        let late = Command::new("/bin/sh")
            .args([
                "-c",
                &build_join_cmd(
                    &claim.lock_dir,
                    &claim.run_id,
                    &claim.keeper_pid.to_string(),
                    "\"$$\"",
                ),
            ])
            .output()
            .unwrap();
        assert_eq!(late.status.code(), Some(LOCK_LOST_STATUS));
        drop(child.stdin.take());
        child.wait().unwrap();
        drop(remote.acquire("run-next").unwrap());
        assert!(remote.recoveries().contains("recovered=run-job"));
    }

    #[test]
    fn reclaim_tokens_serialize_reclaimers() {
        let remote = FakeRemote::new();
        kill_driver(remote.acquire("run-dead").unwrap(), true);
        // A live reclaimer's token (this test process) blocks other reclaimers.
        let me = std::process::id();
        let start = Command::new("ps")
            .args(["-o", "lstart=", "-p", &me.to_string()])
            .env("LC_ALL", "C")
            .env("TZ", "UTC0")
            .output()
            .unwrap();
        let start = String::from_utf8(start.stdout).unwrap();
        let token = format!("{}/reclaim.1", remote.lock_dir());
        std::os::unix::fs::symlink(format!("{me} {}", start.trim_end_matches('\n')), &token)
            .unwrap();
        let (_, detail) = held(remote.acquire("run-next"));
        assert!(detail.contains("reclaiming"), "{detail}");
        // A dead reclaimer's token is skipped by the next level.
        fs::remove_file(&token).unwrap();
        std::os::unix::fs::symlink("999999 Thu Jan  1 00:00:00 1970", &token).unwrap();
        let lock = remote.acquire("run-next").unwrap();
        assert_eq!(remote.run_id(), "run-next");
        drop(lock);
    }
}
