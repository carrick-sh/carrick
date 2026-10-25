#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use serde_json::{Value, json};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::fd::{AsFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use support::wait_for_pipe_readiness;

struct Remote {
    // Field order is drop order: stop serving before removing the repos.
    server: Server,
    _dir: tempfile::TempDir,
    clients: [PathBuf; 2],
}

fn git(root: &Path, args: &[&str]) -> Output {
    let out = Command::new("git")
        .current_dir(root)
        .args(args)
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    out
}

/// A `git://` endpoint whose listening socket the test owns from bind to drop
/// (#659). Each accepted connection is served by `git daemon --inetd` with the
/// socket as its stdin and stdout, so the port is never released and rebound:
/// no other process can take it, and no readiness wait is needed because the
/// kernel queues connections on the bound listener from the start.
struct Server {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    accept: Option<JoinHandle<()>>,
    daemons: Arc<Mutex<Vec<Child>>>,
}

impl Server {
    fn bind(base_path: &Path) -> (Self, TcpListener) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let daemons = Arc::new(Mutex::new(Vec::new()));
        let accept = {
            let listener = listener.try_clone().unwrap();
            let stop = Arc::clone(&stop);
            let daemons = Arc::clone(&daemons);
            let base_path = base_path.to_owned();
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    if stop.load(Ordering::SeqCst) {
                        break;
                    }
                    let stream = stream.unwrap();
                    let input = OwnedFd::from(stream.try_clone().unwrap());
                    let output = OwnedFd::from(stream);
                    let daemon = Command::new("git")
                        .args([
                            "daemon",
                            "--inetd",
                            "--export-all",
                            "--enable=receive-pack",
                            "--init-timeout=5",
                            "--timeout=5",
                        ])
                        .arg(format!("--base-path={}", base_path.display()))
                        .stdin(Stdio::from(input))
                        .stdout(Stdio::from(output))
                        .stderr(Stdio::inherit())
                        .spawn()
                        .unwrap();
                    daemons.lock().unwrap().push(daemon);
                }
            })
        };
        let server = Self {
            address,
            stop,
            accept: Some(accept),
            daemons,
        };
        (server, listener)
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // Wake the blocked accept; the listener is still bound, so this
        // connection is queued even if the accept thread has not reached
        // `accept` yet.
        let wake = TcpStream::connect(self.address);
        if let Some(accept) = self.accept.take() {
            let _ = accept.join();
        }
        drop(wake);
        for mut daemon in self.daemons.lock().unwrap().drain(..) {
            let _ = daemon.kill();
            let _ = daemon.wait();
        }
    }
}

impl Remote {
    fn new() -> Self {
        Self::with_interloper(|_| {})
    }

    fn with_interloper(interloper: impl FnOnce(SocketAddr)) -> Self {
        let dir = tempfile::tempdir().unwrap();
        git(dir.path(), &["init", "--bare", "remote.git"]);
        let (server, listener) = Server::bind(dir.path());
        interloper(server.address);
        // The accept thread holds its own handle to the listening socket.
        drop(listener);
        let clients = [dir.path().join("a"), dir.path().join("b")];
        for client in &clients {
            std::fs::create_dir(client).unwrap();
            git(client, &["init"]);
        }
        Self {
            server,
            _dir: dir,
            clients,
        }
    }

    fn url(&self) -> String {
        format!("git://{}/remote.git", self.server.address)
    }

    fn bare_dir(&self) -> PathBuf {
        self._dir.path().join("remote.git")
    }

    fn command(&self, client: usize) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_carrick-xtask"));
        cmd.arg("--root")
            .arg(&self.clients[client])
            .arg("claims")
            .arg("--remote")
            .arg(self.url())
            .env("CARRICK_XTASK_TEST_NOW", "1");
        cmd
    }

    fn lease(&self, client: usize, until: u64) -> PathBuf {
        let path = self.clients[client].join("lease.json");
        std::fs::write(
            &path,
            serde_json::to_vec(&json!({
                "host": format!("ctb-w{}", client + 1), "slot": "author-1",
                "lane": "claims-572", "issue": "carrick-sh/carrick#572",
                "backend": "copilot", "conversation": format!("turn-{client}"),
                "lease_until": until, "workorder_sha256": "a".repeat(64), "state": "active"
            }))
            .unwrap(),
        )
        .unwrap();
        path
    }

    fn acquire(&self, client: usize, until: u64, reference: &str) -> Output {
        self.command(client)
            .args(["acquire", reference, "--lease"])
            .arg(self.lease(client, until))
            .output()
            .unwrap()
    }

    fn refs(&self) -> Value {
        let out = self.command(0).arg("list").output().unwrap();
        assert!(out.status.success(), "{out:?}");
        serde_json::from_slice(&out.stdout).unwrap()
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn sha(out: &Output) -> String {
    assert!(out.status.success(), "{out:?}");
    serde_json::from_slice::<Value>(&out.stdout).unwrap()[0]["sha"]
        .as_str()
        .unwrap()
        .to_owned()
}

const ISSUE: &str = "refs/claims/issue/carrick/572";

#[test]
fn interloper_cannot_take_the_remote_endpoint() {
    // #659: the harness used to reserve a port, drop the listener and let
    // `git daemon` rebind it, so any other process could take the port in
    // between. An interloper binding the endpoint's address at the earliest
    // point it is known must be refused, and claims must keep working while
    // other ephemeral ports are occupied.
    let squatters: Vec<TcpListener> = (0..64)
        .map(|_| TcpListener::bind("127.0.0.1:0").unwrap())
        .collect();
    let mut stolen = None;
    let remote = Remote::with_interloper(|address| {
        stolen = Some(TcpListener::bind(address));
    });
    let stolen = stolen.unwrap();
    assert!(
        matches!(&stolen, Err(e) if e.kind() == std::io::ErrorKind::AddrInUse),
        "interloper bound the remote endpoint: {stolen:?}"
    );
    sha(&remote.acquire(0, now() + 300, ISSUE));
    assert_eq!(remote.refs().as_array().unwrap().len(), 1);
    drop(squatters);
}

#[test]
fn concurrent_acquires_have_exactly_one_winner() {
    let remote = Remote::new();
    let barrier = Arc::new(Barrier::new(2));
    let results = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..2)
            .map(|client| {
                let barrier = Arc::clone(&barrier);
                let remote = &remote;
                scope.spawn(move || {
                    barrier.wait();
                    remote.acquire(client, now() + 300, ISSUE)
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(
        results.iter().filter(|out| out.status.success()).count(),
        1,
        "{results:?}"
    );
    assert_eq!(remote.refs().as_array().unwrap().len(), 1);
}

fn install_pre_push_hook(client_dir: &Path, script: &str) {
    use std::os::unix::fs::PermissionsExt;
    let hooks = client_dir.join(".git/hooks");
    std::fs::create_dir_all(&hooks).unwrap();
    let hook = hooks.join("pre-push");
    std::fs::write(&hook, script).unwrap();
    std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();
}

#[test]
fn stale_heartbeat_and_release_cannot_replace_a_successor() {
    let remote = Remote::new();
    let t0 = 1_792_260_000_u64;
    let old = sha(&remote
        .command(0)
        .args(["--now", &t0.to_string(), "acquire", ISSUE, "--lease"])
        .arg(remote.lease(0, t0 + 300))
        .output()
        .unwrap());
    let winner_out = remote.clients[1].join("winner.json");
    let hook = format!(
        "#!/usr/bin/env sh\nset -eu\nCARRICK_XTASK_TEST_NOW=1 \"{bin}\" --root \"{client1}\" claims --remote \"{url}\" --now {t0} heartbeat \"{ISSUE}\" --expected \"{old}\" --lease-until {until} > \"{winner}\"\n",
        bin = env!("CARGO_BIN_EXE_carrick-xtask"),
        client1 = remote.clients[1].display(),
        url = remote.url(),
        until = t0 + 900,
        winner = winner_out.display(),
    );
    install_pre_push_hook(&remote.clients[0], &hook);
    let raced = remote
        .command(0)
        .args([
            "--now",
            &t0.to_string(),
            "heartbeat",
            ISSUE,
            "--expected",
            &old,
            "--lease-until",
            &(t0 + 600).to_string(),
        ])
        .output()
        .unwrap();
    std::fs::remove_file(remote.clients[0].join(".git/hooks/pre-push")).unwrap();
    assert!(!raced.status.success(), "{raced:?}");
    let raced_stderr = String::from_utf8_lossy(&raced.stderr);
    assert!(
        raced_stderr.contains("[remote rejected]"),
        "expected server-side [remote rejected], got: {raced_stderr}"
    );
    let new =
        serde_json::from_slice::<Value>(&std::fs::read(&winner_out).unwrap()).unwrap()[0]["sha"]
            .as_str()
            .unwrap()
            .to_owned();
    assert_ne!(old, new);
    assert!(
        !remote
            .command(0)
            .args([
                "--now",
                &t0.to_string(),
                "heartbeat",
                ISSUE,
                "--expected",
                &old,
                "--lease-until",
                &(t0 + 1200).to_string(),
            ])
            .output()
            .unwrap()
            .status
            .success()
    );
    assert!(
        !remote
            .command(0)
            .args([
                "--now",
                &t0.to_string(),
                "release",
                ISSUE,
                "--expected",
                &old
            ])
            .output()
            .unwrap()
            .status
            .success()
    );
    assert_eq!(remote.refs()[0]["sha"], new);
}

#[test]
fn concurrent_expired_reclaimers_have_exactly_one_winner() {
    let remote = Remote::new();
    let t0 = 1_792_260_000_u64;
    let old = sha(&remote
        .command(0)
        .args(["--now", &t0.to_string(), "acquire", ISSUE, "--lease"])
        .arg(remote.lease(0, t0 + 2700))
        .output()
        .unwrap());
    let expired_now = t0 + 2701;
    let barrier = Arc::new(Barrier::new(2));
    let results = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..2)
            .map(|client| {
                let barrier = Arc::clone(&barrier);
                let remote = &remote;
                let old = &old;
                scope.spawn(move || {
                    let lease = remote.lease(client, expired_now + 300);
                    barrier.wait();
                    remote
                        .command(client)
                        .args([
                            "--now",
                            &expired_now.to_string(),
                            "reclaim",
                            ISSUE,
                            "--expected",
                            old,
                            "--lease",
                        ])
                        .arg(lease)
                        .output()
                        .unwrap()
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(
        results.iter().filter(|out| out.status.success()).count(),
        1,
        "{results:?}"
    );
    assert_ne!(remote.refs()[0]["sha"], old);
    assert!(
        !remote
            .command(0)
            .args([
                "--now",
                &expired_now.to_string(),
                "heartbeat",
                ISSUE,
                "--expected",
                &old,
                "--lease-until",
                &(expired_now + 600).to_string()
            ])
            .output()
            .unwrap()
            .status
            .success()
    );
}

struct HolderGuard(Option<Child>);

impl HolderGuard {
    fn spawn(command: &mut Command) -> Self {
        use std::os::unix::process::CommandExt;
        Self(Some(command.process_group(0).spawn().unwrap()))
    }

    fn take_stdout(&mut self) -> std::process::ChildStdout {
        self.0
            .as_mut()
            .expect("holder child present")
            .stdout
            .take()
            .expect("holder stdout")
    }

    fn kill(&mut self) -> std::io::Result<()> {
        let child = self.0.as_mut().expect("holder child present");
        if let Ok(pgid) = i32::try_from(child.id()) {
            // SAFETY: `child` was spawned with `process_group(0)` and has not
            // been waited yet, so `-pgid` targets only its process group.
            unsafe {
                libc::kill(-pgid, libc::SIGKILL);
            }
        }
        child.kill()
    }

    fn wait(&mut self) -> std::io::Result<std::process::ExitStatus> {
        self.0.take().expect("holder child present").wait()
    }
}

impl Drop for HolderGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            if let Ok(pgid) = i32::try_from(child.id()) {
                // SAFETY: `child` was spawned with `process_group(0)` and has
                // not been waited yet, so `-pgid` targets only its process group.
                unsafe {
                    libc::kill(-pgid, libc::SIGKILL);
                }
            }
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[test]
fn killed_holder_is_reclaimable_only_after_ttl() {
    let remote = Remote::new();
    let t0 = 1_792_260_000_u64;
    let ttl_end = t0 + 2700;
    // This shell is the supervisor: acquire, publish a receipt, then stay alive.
    let receipt = remote.clients[0].join("receipt.json");
    let lease = remote.lease(0, ttl_end);
    let mut holder = HolderGuard::spawn(
        Command::new("sh")
            .env("CARRICK_XTASK_TEST_NOW", "1")
            .arg("-c")
            .arg("\"$1\" --root \"$2\" claims --remote \"$3\" --now \"$4\" acquire \"$5\" --lease \"$6\" > \"$7\" && printf ready && exec sleep 30")
            .arg("holder")
            .arg(env!("CARGO_BIN_EXE_carrick-xtask"))
            .arg(&remote.clients[0])
            .arg(remote.url())
            .arg(t0.to_string())
            .arg(ISSUE)
            .arg(lease)
            .arg(&receipt)
            .stdout(Stdio::piped()),
    );
    let stdout = holder.take_stdout();
    wait_for_pipe_readiness(stdout.as_fd(), Duration::from_secs(60))
        .expect("holder failed to signal readiness");
    let bytes = std::fs::read(&receipt).expect("receipt file must exist");
    let value = serde_json::from_slice::<Value>(&bytes).expect("receipt must be valid json");
    let old = value[0]["sha"].as_str().expect("sha in receipt").to_owned();
    holder.kill().unwrap();
    holder.wait().unwrap();
    let reclaim_at = |clock: u64| {
        remote
            .command(1)
            .args([
                "--now",
                &clock.to_string(),
                "reclaim",
                ISSUE,
                "--expected",
                &old,
                "--lease",
            ])
            .arg(remote.lease(1, clock + 300))
            .output()
            .unwrap()
    };
    assert!(
        !reclaim_at(ttl_end - 1).status.success(),
        "live lease was stolen before TTL"
    );
    assert!(reclaim_at(ttl_end).status.success());
}

#[test]
fn lease_ttl_beyond_policy_cap_is_refused_and_corrupt_refs_are_skipped_by_heads_and_list() {
    let remote = Remote::new();
    let t0 = 1_792_260_000_u64;

    // `--now` without CARRICK_XTASK_TEST_NOW=1 must be refused in production.
    let unguarded_now = remote
        .command(0)
        .env_remove("CARRICK_XTASK_TEST_NOW")
        .args(["--now", &t0.to_string(), "list"])
        .output()
        .unwrap();
    assert!(
        !unguarded_now.status.success(),
        "--now was accepted without CARRICK_XTASK_TEST_NOW=1"
    );

    let over_ttl = remote
        .command(0)
        .args(["--now", &t0.to_string(), "acquire", ISSUE, "--lease"])
        .arg(remote.lease(0, t0 + 2701))
        .output()
        .unwrap();
    assert!(
        !over_ttl.status.success(),
        "accepted lease beyond 45m TTL cap"
    );

    let valid_sha = sha(&remote
        .command(0)
        .args(["--now", &t0.to_string(), "acquire", ISSUE, "--lease"])
        .arg(remote.lease(0, t0 + 2700))
        .output()
        .unwrap());
    let over_heartbeat = remote
        .command(0)
        .args([
            "--now",
            &t0.to_string(),
            "heartbeat",
            ISSUE,
            "--expected",
            &valid_sha,
            "--lease-until",
            &(t0 + 2701).to_string(),
        ])
        .output()
        .unwrap();
    assert!(!over_heartbeat.status.success());

    // Push an invalid ref namespace and a corrupt non-JSON lease commit under refs/claims/*.
    let empty_tree = String::from_utf8(
        git(
            &remote.clients[0],
            &["hash-object", "-w", "-t", "tree", "/dev/null"],
        )
        .stdout,
    )
    .unwrap();
    let bad_commit = String::from_utf8(
        git(
            &remote.clients[0],
            &[
                "-c",
                "user.name=bad",
                "-c",
                "user.email=bad@carrick.sh",
                "commit-tree",
                empty_tree.trim(),
                "-m",
                "not-json",
            ],
        )
        .stdout,
    )
    .unwrap();
    let bad_sha = bad_commit.trim();
    git(
        &remote.clients[0],
        &[
            "push",
            &remote.url(),
            &format!("{bad_sha}:refs/claims/unknown/corrupt"),
            &format!("{bad_sha}:refs/claims/issue/carrick/999"),
        ],
    );

    let list_out = remote.command(0).arg("list").output().unwrap();
    assert!(list_out.status.success(), "{list_out:?}");
    let listed: Value = serde_json::from_slice(&list_out.stdout).unwrap();
    assert_eq!(listed.as_array().unwrap().len(), 1, "{listed}");
    assert_eq!(listed[0]["reference"], ISSUE);
    let stderr = String::from_utf8_lossy(&list_out.stderr);
    assert!(stderr.contains("refs/claims/unknown/corrupt"), "{stderr}");
    assert!(stderr.contains("refs/claims/issue/carrick/999"), "{stderr}");

    // Valid claim operations still succeed alongside corrupt refs.
    let renewed_out = remote
        .command(0)
        .args([
            "--now",
            &(t0 + 600).to_string(),
            "heartbeat",
            ISSUE,
            "--expected",
            &valid_sha,
            "--lease-until",
            &(t0 + 3000).to_string(),
        ])
        .output()
        .unwrap();
    let renewed_sha = sha(&renewed_out);

    // Reclaim path must also enforce the 45-minute policy TTL cap.
    let reclaim_time = t0 + 3001;
    let over_reclaim = remote
        .command(1)
        .args([
            "--now",
            &reclaim_time.to_string(),
            "reclaim",
            ISSUE,
            "--expected",
            &renewed_sha,
            "--lease",
        ])
        .arg(remote.lease(1, reclaim_time + 2701))
        .output()
        .unwrap();
    assert!(
        !over_reclaim.status.success(),
        "reclaim accepted lease beyond 45m TTL cap"
    );
    assert_eq!(remote.refs()[0]["sha"], renewed_sha);
}

#[test]
fn sorted_hot_lock_failure_rolls_back_only_our_locks() {
    use std::os::unix::fs::PermissionsExt;
    let remote = Remote::new();
    let bare = remote.bare_dir();
    git(&bare, &["config", "core.logAllRefUpdates", "always"]);

    // 1. When `refs/claims/hot/z` is already occupied by another holder, atomic
    // push rejects the whole batch in receive-pack before `refs/claims/hot/a` is
    // ever created (so `logs/refs/claims/hot/a` is never written on the server,
    // unlike sequential push + rollback).
    let occupied = "refs/claims/hot/z";
    let old = sha(&remote.acquire(1, now() + 300, occupied));
    let out = remote
        .command(0)
        .args(["acquire", ISSUE, "--lease"])
        .arg(remote.lease(0, now() + 300))
        .args(["--hot", "z", "--hot", "a"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(
        !bare.join("logs/refs/claims/hot/a").exists(),
        "refs/claims/hot/a was created and rolled back instead of failing atomically"
    );
    let refs = remote.refs();
    assert_eq!(refs.as_array().unwrap().len(), 1, "{refs}");
    assert_eq!(refs[0]["reference"], occupied);
    assert_eq!(refs[0]["sha"], old);

    // 2. Even when `refs/claims/hot/z` does not exist yet, if a server-side
    // `update` hook rejects the second ref (`refs/claims/hot/z`), `--atomic`
    // aborts the entire transaction so the first ref (`refs/claims/hot/a`) is
    // never created on the remote.
    let update_hook = bare.join("hooks/update");
    std::fs::write(
        &update_hook,
        "#!/bin/sh\nset -eu\nif [ \"$1\" = \"refs/claims/hot/z2\" ]; then exit 1; fi\n",
    )
    .unwrap();
    std::fs::set_permissions(&update_hook, std::fs::Permissions::from_mode(0o755)).unwrap();
    let out2 = remote
        .command(0)
        .args(["acquire", ISSUE, "--lease"])
        .arg(remote.lease(0, now() + 300))
        .args(["--hot", "z2", "--hot", "a2"])
        .output()
        .unwrap();
    assert!(!out2.status.success());
    assert!(
        !bare.join("logs/refs/claims/hot/a2").exists(),
        "refs/claims/hot/a2 was created on the remote despite atomic push rejection on z2"
    );
    assert!(
        !bare.join("refs/claims/hot/a2").exists(),
        "refs/claims/hot/a2 exists on the remote"
    );
}

#[test]
fn repo_pre_push_hook_skips_claims_only_and_runs_on_branch_or_mixed_pushes() {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    let hook = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.githooks/pre-push");
    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("bin");
    std::fs::create_dir(&bin).unwrap();
    let log = dir.path().join("just.log");
    let fake_just = bin.join("just");
    std::fs::write(
        &fake_just,
        format!("#!/bin/sh\necho \"$*\" >> \"{}\"\nexit 42\n", log.display()),
    )
    .unwrap();
    std::fs::set_permissions(&fake_just, std::fs::Permissions::from_mode(0o755)).unwrap();
    let path_env = std::env::join_paths(
        std::iter::once(bin).chain(std::env::split_paths(&std::env::var_os("PATH").unwrap())),
    )
    .unwrap();

    let run_hook = |stdin_lines: &str| -> std::process::ExitStatus {
        let mut child = Command::new("sh")
            .arg(&hook)
            .args(["origin", "https://github.com/carrick-sh/carrick.git"])
            .env("PATH", &path_env)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(stdin_lines.as_bytes())
            .unwrap();
        child.wait().unwrap()
    };

    let sha1 = "1111111111111111111111111111111111111111";
    let zero = "0000000000000000000000000000000000000000";

    // Claims-only push (acquire/heartbeat/release across multiple claim refs) skips clippy.
    let status = run_hook(&format!(
        "{sha1} {sha1} refs/claims/issue/carrick/572 {zero}\n(delete) {zero} refs/claims/hot/workflows {sha1}\n"
    ));
    assert!(
        status.success(),
        "claims-only push failed pre-push hook: {status}"
    );
    assert!(!log.exists(), "claims-only push invoked just clippy");

    // Mixed push (claim ref + branch ref) must run clippy.
    let mixed = run_hook(&format!(
        "{sha1} {sha1} refs/claims/issue/carrick/572 {zero}\nrefs/heads/work/x {sha1} refs/heads/work/x {zero}\n"
    ));
    assert_eq!(mixed.code(), Some(1), "mixed push skipped clippy");
    assert_eq!(std::fs::read_to_string(&log).unwrap().trim(), "clippy");

    // Branch-only push must run clippy.
    std::fs::remove_file(&log).unwrap();
    let branch = run_hook(&format!("refs/heads/main {sha1} refs/heads/main {zero}\n"));
    assert_eq!(branch.code(), Some(1), "branch push skipped clippy");
    assert_eq!(std::fs::read_to_string(&log).unwrap().trim(), "clippy");
}

#[test]
fn hot_set_moves_and_releases_atomically() {
    let remote = Remote::new();
    let out = remote
        .command(0)
        .args(["acquire", ISSUE, "--lease"])
        .arg(remote.lease(0, now() + 300))
        .args(["--hot", "a", "--hot", "z"])
        .output()
        .unwrap();
    let old = sha(&out);
    assert_eq!(remote.refs().as_array().unwrap().len(), 3);
    let out = remote
        .command(0)
        .args([
            "heartbeat",
            ISSUE,
            "--expected",
            &old,
            "--lease-until",
            &(now() + 600).to_string(),
            "--hot",
            "z",
            "--hot",
            "a",
        ])
        .output()
        .unwrap();
    let new = sha(&out);
    assert!(
        remote
            .refs()
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r["sha"] == new)
    );
    assert!(
        remote
            .command(0)
            .args([
                "release",
                ISSUE,
                "--expected",
                &new,
                "--hot",
                "a",
                "--hot",
                "z"
            ])
            .output()
            .unwrap()
            .status
            .success()
    );
    assert_eq!(remote.refs(), json!([]));
}

struct ProbeCleanup {
    root: PathBuf,
    reference: String,
}
impl ProbeCleanup {
    fn cleanup(&self) -> bool {
        let out = Command::new("git")
            .current_dir(&self.root)
            .args(["ls-remote", "--refs", GITHUB, &self.reference])
            .output()
            .unwrap();
        if !out.status.success() {
            return false;
        }
        let text = String::from_utf8(out.stdout).unwrap();
        if text.trim().is_empty() {
            return true;
        }
        let current = text.split_whitespace().next().unwrap();
        let out = Command::new("git")
            .current_dir(&self.root)
            .args([
                "push",
                "--porcelain",
                &format!("--force-with-lease={}:{}", self.reference, current),
                GITHUB,
                &format!(":{}", self.reference),
            ])
            .output()
            .unwrap();
        if !out.status.success() {
            return false;
        }
        let out = Command::new("git")
            .current_dir(&self.root)
            .args(["ls-remote", "--refs", GITHUB, &self.reference])
            .output()
            .unwrap();
        out.status.success() && out.stdout.is_empty()
    }
}
impl Drop for ProbeCleanup {
    fn drop(&mut self) {
        if !self.cleanup() {
            eprintln!("PROBE CLEANUP FAILED: {}", self.reference);
        }
    }
}
const GITHUB: &str = "https://github.com/carrick-sh/carrick.git";

#[test]
#[ignore = "manual: creates one temporary GitHub probe ref, always CAS-deleted"]
fn github_probe_stale_force_with_lease_is_refused() {
    let temp = tempfile::tempdir().unwrap();
    let client_a = temp.path().join("a");
    let client_b = temp.path().join("b");
    std::fs::create_dir(&client_a).unwrap();
    std::fs::create_dir(&client_b).unwrap();
    git(&client_a, &["init"]);
    git(&client_b, &["init"]);
    let t0 = now();
    let reference = format!(
        "refs/claims/probe/572-{}-{}",
        t0,
        temp.path()
            .file_name()
            .unwrap()
            .to_string_lossy()
            .trim_start_matches('.')
    );
    let guard = ProbeCleanup {
        root: client_b.clone(),
        reference: reference.clone(),
    };
    let lease = client_a.join("lease.json");
    std::fs::write(
        &lease,
        serde_json::to_vec(&json!({
            "host": "ctb-w4", "slot": "probe", "lane": "claims-572", "issue": "carrick-sh/carrick#572",
            "backend": "copilot", "conversation": "phase0-live-witness",
            "lease_until": t0 + 1800, "workorder_sha256": "a".repeat(64), "state": "active"
        }))
        .unwrap(),
    )
    .unwrap();
    println!("probe={reference}");
    let first = Command::new(env!("CARGO_BIN_EXE_carrick-xtask"))
        .current_dir(&client_a)
        .args([
            "claims", "--remote", GITHUB, "acquire", &reference, "--lease",
        ])
        .arg(&lease)
        .output()
        .unwrap();
    let a = sha(&first);
    let winner_out = client_b.join("winner.json");
    // Pre-push runs in client_a AFTER git receives GitHub's ref advertisement (showing `a`)
    // and passes the client-side lease check, moving the remote ref to `b` before client_a
    // sends its pack so GitHub's receive-pack returns `[remote rejected]`.
    let hook = format!(
        "#!/usr/bin/env sh\nset -eu\n\"{bin}\" --root \"{client_b}\" claims --remote \"{GITHUB}\" heartbeat \"{reference}\" --expected \"{a}\" --lease-until {until} > \"{winner}\"\n",
        bin = env!("CARGO_BIN_EXE_carrick-xtask"),
        client_b = client_b.display(),
        until = t0 + 2400,
        winner = winner_out.display(),
    );
    install_pre_push_hook(&client_a, &hook);
    let rejected = Command::new(env!("CARGO_BIN_EXE_carrick-xtask"))
        .current_dir(&client_a)
        .args([
            "claims",
            "--remote",
            GITHUB,
            "heartbeat",
            &reference,
            "--expected",
            &a,
            "--lease-until",
            &(t0 + 2100).to_string(),
        ])
        .output()
        .unwrap();
    std::fs::remove_file(client_a.join(".git/hooks/pre-push")).unwrap();
    let b =
        serde_json::from_slice::<Value>(&std::fs::read(&winner_out).unwrap()).unwrap()[0]["sha"]
            .as_str()
            .unwrap()
            .to_owned();
    let rejected_stderr = String::from_utf8_lossy(&rejected.stderr);
    println!(
        "first={a}\nupdated={b}\nraced_push_exit={}\n{rejected_stderr}",
        rejected.status
    );
    assert!(
        !rejected.status.success(),
        "GitHub accepted stale force-with-lease"
    );
    assert!(
        rejected_stderr.contains("[remote rejected]"),
        "expected server-side [remote rejected] from GitHub, got: {rejected_stderr}"
    );
    let current = git(&client_b, &["ls-remote", "--refs", GITHUB, &reference]);
    assert_eq!(
        String::from_utf8(current.stdout)
            .unwrap()
            .split_whitespace()
            .next(),
        Some(b.as_str())
    );
    assert!(guard.cleanup(), "probe cleanup failed");
    println!("cleanup=deleted; ls-remote confirms absent");
    // Drop repeats the absence check, including on any earlier assertion failure.
}
