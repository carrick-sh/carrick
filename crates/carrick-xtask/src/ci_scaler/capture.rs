//! Scoped capture privilege on agent clones (#1621; owner decision on #231,
//! 2026-11-04, narrowed by the carrick-87 review). The dispatch worker gets
//! passwordless sudo for exactly three commands and nothing else:
//!
//! - `/usr/local/sbin/carrick-capture <name> [--seconds N]`, which runs one
//!   of the reviewed bpftrace scripts in the `carrick-capture` crate. There
//!   is no free-form program: root bpftrace with `-e PROG` can read any
//!   process's memory and files, including the loop and runner tokens and
//!   `redaction-secrets.json`, which would erase the loop/worker uid
//!   separation in `docs/ci/dispatch-worker.md`;
//! - `dmesg` with no arguments and `journalctl -k`, both under sudo's
//!   `NOEXEC` (read-only kernel log; no pager or helper can exec).
//!
//! Nothing here runs as root on a clone. This module holds the drop-in text
//! the template builder installs, the root-side checks qualification runs
//! through the guest agent ([`verify_policy`], [`verify_root_refusals`]) and
//! the worker-side check ([`verify`], `ci-scaler verify-capture`), which the
//! builder also runs while provisioning.

use super::{ScalerError, live};
use carrick_capture::{FRONT_PATH, REFUSAL, REFUSED_INSTALL, REFUSED_SHAPE, SCRIPT_DIR, SCRIPTS};
use std::io::{BufRead, BufReader, Read};
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// The drop-in the builder writes; qualification compares its bytes.
pub(crate) const SUDOERS_PATH: &str = "/etc/sudoers.d/carrick-dispatch-capture";
/// The reviewed script the live witness runs.
const WITNESS_SCRIPT: &str = "signal-kill-sender";
/// The retired design's front (a root copy of xtask named `bpftrace`); a
/// template must not carry it.
const RETIRED_FRONT: &str = "/usr/local/sbin/bpftrace";

/// Exactly three commands, full paths, no shell, no wildcards. Tags carry
/// forward in a sudoers command list: all three are `NOPASSWD`; `dmesg` and
/// `journalctl` are also `NOEXEC`. `carrick-capture` cannot be, since it
/// execs `timeout` and bpftrace; it takes only a script name and a length.
/// `""` admits bare `dmesg` only. The worker's `secure_path` puts
/// `/usr/local/sbin` first so `sudo carrick-capture ...` resolves there.
pub(crate) const SUDOERS: &str = r#"# Scoped capture privilege for dispatch workers (#1621). Written by
# scripts/ci/build-template-debian.sh from `carrick-xtask ci-scaler
# capture-sudoers`; template qualification compares these bytes. Exactly
# three commands with full paths, no shell and no wildcards.
# carrick-capture runs reviewed bpftrace scripts by name only.
Defaults:carrick-dispatch-agent secure_path="/usr/local/sbin:/usr/sbin:/usr/bin"
carrick-dispatch-agent ALL = (root) NOPASSWD: /usr/local/sbin/carrick-capture, NOEXEC: /usr/bin/dmesg "", /usr/bin/journalctl -k
"#;

fn script_path(name: &str) -> String {
    format!("{SCRIPT_DIR}/{name}.bt")
}

/// Root, through the guest agent: the whole sudoers policy and the drop-in
/// pass `visudo -c`, the drop-in holds exactly [`SUDOERS`], the front and
/// the script directory are root-owned and root-writable only, the
/// directory holds exactly the allowlisted scripts with their reviewed
/// bytes, bpftrace is installed and the retired front is gone.
pub(super) fn verify_policy(
    mut run: impl FnMut(&[&str]) -> Result<live::GuestOutput, ScalerError>,
) -> Result<(), ScalerError> {
    let mut passes = |args: &[&str]| -> Result<Option<String>, ScalerError> {
        let output = run(args)?;
        Ok((output.exit == live::GuestExit(0)).then_some(output.stdout))
    };
    if passes(&["/usr/sbin/visudo", "-c", "-q"])?.is_none() {
        return Err(ScalerError::Guard("sudoers policy fails visudo -c"));
    }
    if passes(&["/usr/sbin/visudo", "-c", "-q", "-f", SUDOERS_PATH])?.is_none() {
        return Err(ScalerError::Guard(
            "capture sudoers drop-in fails visudo -c",
        ));
    }
    if passes(&["/bin/cat", SUDOERS_PATH])?.as_deref() != Some(SUDOERS) {
        return Err(ScalerError::Guard(
            "capture sudoers drop-in differs from ci-scaler capture-sudoers",
        ));
    }
    let scripts: Vec<String> = SCRIPTS
        .iter()
        .map(|script| script_path(script.name))
        .collect();
    let mut stat = vec![
        "/usr/bin/stat",
        "-c",
        "%a %U %G %F",
        SUDOERS_PATH,
        FRONT_PATH,
        SCRIPT_DIR,
    ];
    stat.extend(scripts.iter().map(String::as_str));
    let mut modes = String::from(
        "440 root root regular file\n755 root root regular file\n755 root root directory\n",
    );
    modes.extend(scripts.iter().map(|_| "644 root root regular file\n"));
    if passes(&stat)?.as_deref() != Some(modes.as_str()) {
        return Err(ScalerError::Guard(
            "capture drop-in, front or scripts have the wrong owner, mode or type",
        ));
    }
    let listed = passes(&[
        "/usr/bin/find",
        SCRIPT_DIR,
        "-mindepth",
        "1",
        "-printf",
        "%f\n",
    ])?;
    let mut found: Vec<&str> = listed.as_deref().unwrap_or_default().lines().collect();
    found.sort_unstable();
    let mut allowed: Vec<String> = SCRIPTS
        .iter()
        .map(|script| format!("{}.bt", script.name))
        .collect();
    allowed.sort_unstable();
    if listed.is_none() || found != allowed {
        return Err(ScalerError::Guard(
            "capture script directory differs from the carrick-capture allowlist",
        ));
    }
    for (script, path) in SCRIPTS.iter().zip(&scripts) {
        if passes(&["/bin/cat", path])?.as_deref() != Some(script.source) {
            return Err(ScalerError::Guard(
                "an installed capture script differs from its reviewed source",
            ));
        }
    }
    if passes(&["/usr/bin/test", "!", "-e", RETIRED_FRONT])?.is_none() {
        return Err(ScalerError::Guard(
            "the retired bpftrace front is still installed",
        ));
    }
    if passes(&[carrick_capture::BPFTRACE, "--version"])?.is_none() {
        return Err(ScalerError::Guard("bpftrace is not installed"));
    }
    Ok(())
}

const WORKER_SUDO: [&str; 7] = [
    "/usr/sbin/runuser",
    "-u",
    "carrick-dispatch-agent",
    "--",
    "/usr/bin/sudo",
    "-n",
    "carrick-capture",
];

/// Root, through the guest agent, on the disposable qualification clone
/// only: the front refuses a root-owned script outside its allowlist (even
/// one with reviewed content) and an allowlisted script that was made
/// writable, given away or edited. Each tamper is undone before the next;
/// the restored bytes are checked here, and the worker's live capture in
/// [`verify`], run afterwards, exercises the restored script.
pub(super) fn verify_root_refusals(
    mut run: impl FnMut(&[&str]) -> Result<live::GuestOutput, ScalerError>,
) -> Result<(), ScalerError> {
    fn root(
        run: &mut impl FnMut(&[&str]) -> Result<live::GuestOutput, ScalerError>,
        args: &[&str],
    ) -> Result<(), ScalerError> {
        if run(args)?.exit != live::GuestExit(0) {
            return Err(ScalerError::External(
                "capture root refusal test setup failed",
            ));
        }
        Ok(())
    }
    let reviewed = script_path(WITNESS_SCRIPT);
    let outside = format!("{SCRIPT_DIR}/outside.bt");
    let (reviewed, outside) = (reviewed.as_str(), outside.as_str());
    let backup = "/run/carrick-capture-qualification.bt";
    // (tamper as root, script the worker names, the front's exit, undo)
    let cases: [(&[&str], &str, i32, &[&str]); 4] = [
        (
            &[
                "/usr/bin/install",
                "-m",
                "644",
                "-o",
                "root",
                "-g",
                "root",
                reviewed,
                outside,
            ],
            "outside",
            REFUSED_SHAPE,
            &["/bin/rm", "-f", outside],
        ),
        (
            &["/bin/chmod", "664", reviewed],
            WITNESS_SCRIPT,
            REFUSED_INSTALL,
            &["/bin/chmod", "644", reviewed],
        ),
        (
            &["/bin/chown", "carrick-dispatch-agent", reviewed],
            WITNESS_SCRIPT,
            REFUSED_INSTALL,
            &["/bin/chown", "root", reviewed],
        ),
        (
            &["/usr/bin/truncate", "-s", "-1", reviewed],
            WITNESS_SCRIPT,
            REFUSED_INSTALL,
            &["/bin/cp", "-p", backup, reviewed],
        ),
    ];
    root(&mut run, &["/bin/cp", "-p", reviewed, backup])?;
    for (tamper, name, expected, undo) in cases {
        root(&mut run, tamper)?;
        let mut worker = WORKER_SUDO.to_vec();
        worker.extend([name, "--seconds", "1"]);
        let exit = run(&worker)?.exit;
        root(&mut run, undo)?;
        if exit != live::GuestExit(expected) {
            return Err(ScalerError::Guard(
                "carrick-capture ran a script outside its allowlist or a tampered script",
            ));
        }
    }
    root(&mut run, &["/bin/rm", "-f", backup])?;
    let restored = run(&["/bin/cat", reviewed])?;
    let source = SCRIPTS
        .iter()
        .find(|script| script.name == WITNESS_SCRIPT)
        .map(|script| script.source);
    if restored.exit != live::GuestExit(0) || Some(restored.stdout.as_str()) != source {
        return Err(ScalerError::Guard(
            "the tampered capture script was not restored",
        ));
    }
    Ok(())
}

/// Commands sudo itself must refuse: no shell or general command, raw
/// bpftrace by any path, and the log commands with any other arguments.
const SUDO_REFUSED: [&[&str]; 8] = [
    &["true"],
    &["bash"],
    &["/usr/bin/bpftrace", "-e", "BEGIN { exit(); }"],
    &["bpftrace", "-e", "BEGIN { exit(); }"],
    &[
        "/usr/bin/timeout",
        "5",
        "/usr/bin/bpftrace",
        "-e",
        "BEGIN { exit(); }",
    ],
    &["dmesg", "-C"],
    &["journalctl"],
    &["journalctl", "-k", "-f"],
];
/// Shapes sudo admits to the front and the front must refuse before running
/// anything. `{out}` is a fresh path in a worker-owned directory that must
/// still be absent afterwards; `{script}` is a worker-written program file
/// that would read `/etc/shadow`.
const FRONT_REFUSED: [&[&str]; 12] = [
    &["carrick-capture"],
    &[
        "carrick-capture",
        "-e",
        "BEGIN { printf(\"%s\", cat(\"/etc/shadow\")); exit(); }",
    ],
    &["carrick-capture", "{script}"],
    &["carrick-capture", "-f", "{script}"],
    &["carrick-capture", WITNESS_SCRIPT, "{script}"],
    &["carrick-capture", WITNESS_SCRIPT, "-o", "{out}"],
    &["carrick-capture", WITNESS_SCRIPT, "--unsafe"],
    &["carrick-capture", WITNESS_SCRIPT, "--seconds", "0"],
    &["carrick-capture", WITNESS_SCRIPT, "--seconds", "3601"],
    &["carrick-capture", WITNESS_SCRIPT, "--seconds=5"],
    &["carrick-capture", "outside"],
    &["carrick-capture", "../../../tmp/x"],
];
const WORKER_SCRIPT: &str =
    "BEGIN { printf(\"%s\", cat(\"/etc/shadow\")); exit(); }\ninterval:s:1 { exit(); }\n";

/// `ci-scaler verify-capture`, as `carrick-dispatch-agent`.
pub(super) fn verify() -> Result<(), ScalerError> {
    verify_with(Path::new("/usr/bin/sudo"), Path::new("/proc/self/mounts"))
}

fn verify_with(sudo: &Path, mounts: &Path) -> Result<(), ScalerError> {
    let tracefs = std::fs::read_to_string(mounts)?.lines().any(|line| {
        let fields: Vec<_> = line.split_whitespace().collect();
        fields.get(1..3) == Some(&["/sys/kernel/tracing", "tracefs"][..])
    });
    if !tracefs {
        return Err(ScalerError::Guard(
            "tracefs is not mounted at /sys/kernel/tracing",
        ));
    }
    let dmesg = sudo_probe(sudo, &["dmesg"], 20)?;
    if !dmesg.status.success() || dmesg.stdout.is_empty() {
        report("sudo -n dmesg", &dmesg);
        return Err(ScalerError::Guard(
            "sudo -n dmesg did not print the kernel log",
        ));
    }
    let journal = sudo_probe(sudo, &["journalctl", "-k"], 20)?;
    if !journal.status.success() {
        report("sudo -n journalctl -k", &journal);
        return Err(ScalerError::Guard("sudo -n journalctl -k failed"));
    }
    trace_sigkill(sudo)?;
    for args in SUDO_REFUSED {
        let output = sudo_probe(sudo, args, 10)?;
        let stderr = String::from_utf8_lossy(&output.stderr);
        if output.status.success()
            || !(stderr.contains("a password is required")
                || stderr.contains("is not allowed to execute"))
        {
            report(&format!("sudo -n {}", args.join(" ")), &output);
            return Err(ScalerError::Guard(
                "sudo admitted a command outside the capture policy",
            ));
        }
    }
    let dir = tempfile::tempdir()?;
    let out = dir.path().join("written-as-root");
    let script = dir.path().join("worker.bt");
    std::fs::write(&script, WORKER_SCRIPT)?;
    let (out, script) = match (out.to_str(), script.to_str()) {
        (Some(out), Some(script)) => (out, script),
        _ => return Err(ScalerError::Guard("invalid capture probe path")),
    };
    for shape in FRONT_REFUSED {
        let args = substitute(shape, out, script);
        let output = sudo_probe(sudo, &args, 10)?;
        if output.status.code() != Some(REFUSED_SHAPE)
            || !String::from_utf8_lossy(&output.stderr).starts_with(REFUSAL)
            || !output.stdout.is_empty()
            || Path::new(out).exists()
        {
            report(&format!("sudo -n {}", args.join(" ")), &output);
            return Err(ScalerError::Guard(
                "carrick-capture admitted a shape outside its allowlist",
            ));
        }
    }
    println!("capture privilege: carrick-capture scripts, dmesg and journalctl -k only");
    Ok(())
}

fn substitute<'a>(shape: &[&'a str], out: &'a str, script: &'a str) -> Vec<&'a str> {
    shape
        .iter()
        .map(|arg| match *arg {
            "{out}" => out,
            "{script}" => script,
            other => other,
        })
        .collect()
}

/// One bounded non-interactive sudo call. coreutils `timeout` may signal
/// sudo, whose real uid stays the caller's; sudo relays it to the command.
fn sudo_probe(sudo: &Path, args: &[&str], seconds: u32) -> Result<Output, ScalerError> {
    Ok(Command::new("/usr/bin/timeout")
        .args(["-k", "2", &seconds.to_string()])
        .arg(sudo)
        .arg("-n")
        .args(args)
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .output()?)
}

fn report(label: &str, output: &Output) {
    let stderr = &output.stderr[..output.stderr.len().min(4096)];
    eprintln!(
        "{label}: {}; stderr: {}",
        output.status,
        String::from_utf8_lossy(stderr)
    );
}

/// The capture length of the live witness. The script exits on its own
/// after this many interval ticks, well inside both deadlines below.
const WITNESS_SECONDS: &str = "10";

/// The owner's acceptance shape through the reviewed script: start
/// `sudo carrick-capture signal-kill-sender`, kill one victim once the
/// script reports ready, and require the line naming this process as the
/// sender and the victim as the target. Then require the script's own
/// interval exit (status 0), not the front's hard deadline.
fn trace_sigkill(sudo: &Path) -> Result<(), ScalerError> {
    let mut victim = Command::new("/usr/bin/sleep")
        .arg("60")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let pid = victim.id();
    let result = trace_victim(sudo, pid, || victim.kill());
    let _ = victim.kill();
    let _ = victim.wait();
    result
}

fn trace_victim(
    sudo: &Path,
    pid: u32,
    kill: impl FnOnce() -> std::io::Result<()>,
) -> Result<(), ScalerError> {
    let mut child = Command::new("/usr/bin/timeout")
        .args(["-k", "2", "60"])
        .arg(sudo)
        .args([
            "-n",
            "carrick-capture",
            WITNESS_SCRIPT,
            "--seconds",
            WITNESS_SECONDS,
        ])
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let stdout = child.stdout.take().ok_or(ScalerError::External("stdout"))?;
    let stderr = child.stderr.take().ok_or(ScalerError::External("stderr"))?;
    let (lines_tx, lines) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            if lines_tx.send(line).is_err() {
                break;
            }
        }
    });
    let errors = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = stderr.take(16 * 1024).read_to_end(&mut bytes);
        bytes
    });
    let deadline = Instant::now() + Duration::from_secs(60);
    let me = std::process::id();
    let sender = format!("sender_pid={me} ");
    let target = format!(" target_pid={pid} ");
    let traced = expect_line(&lines, deadline, |line| line.starts_with("capture ready: "))
        .and_then(|()| Ok(kill()?))
        .and_then(|()| {
            expect_line(&lines, deadline, |line| {
                line.contains("sigkill ") && line.contains(&sender) && line.contains(&target)
            })
        });
    // Bounded by the script's interval exit, the front's hard deadline and
    // the outer `timeout`.
    let status = child.wait()?;
    let _ = reader.join();
    let errors = errors.join().unwrap_or_default();
    if traced.is_err() || !status.success() {
        eprintln!(
            "sudo -n carrick-capture {WITNESS_SCRIPT}: {status}; stderr: {}",
            String::from_utf8_lossy(&errors)
        );
    }
    traced?;
    if !status.success() {
        return Err(ScalerError::Guard(
            "carrick-capture did not end on the script's own interval exit",
        ));
    }
    Ok(())
}

fn expect_line(
    lines: &mpsc::Receiver<std::io::Result<String>>,
    deadline: Instant,
    want: impl Fn(&str) -> bool,
) -> Result<(), ScalerError> {
    loop {
        match lines.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(Ok(line)) if want(&line) => return Ok(()),
            Ok(Ok(_)) => {}
            Ok(Err(error)) => return Err(error.into()),
            Err(_) => {
                return Err(ScalerError::Guard(
                    "carrick-capture did not report the traced SIGKILL",
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
    use super::*;
    use std::ffi::OsString;

    #[test]
    fn qualification_front_probes_are_shapes_carrick_capture_refuses() {
        for shape in FRONT_REFUSED {
            let args: Vec<OsString> = substitute(&shape[1..], "/tmp/out", "/tmp/worker.bt")
                .into_iter()
                .map(OsString::from)
                .collect();
            assert!(carrick_capture::parse(&args).is_err(), "{shape:?}");
        }
        // The live witness's own shape is admitted, and its script exists.
        let witness: Vec<OsString> = [WITNESS_SCRIPT, "--seconds", WITNESS_SECONDS]
            .into_iter()
            .map(OsString::from)
            .collect();
        assert!(carrick_capture::parse(&witness).is_ok());
        // The root refusal test plants `outside`, which must stay unlisted.
        assert!(SCRIPTS.iter().all(|script| script.name != "outside"));
    }

    #[test]
    fn agent_template_builds_the_capture_front_from_reviewed_source() {
        let builder = include_str!("../../../../scripts/ci/build-template-debian.sh");
        let workspace = include_str!("../../../../Cargo.toml");
        // Only the std-only crate's source and scripts are staged and built,
        // with the workspace edition and the pinned toolchain's rustc.
        assert!(builder.contains(
            "cp -R \"$inputs/crates/carrick-capture/src\" \"$inputs/crates/carrick-capture/scripts\" seed/capture/"
        ));
        let edition = workspace
            .lines()
            .find_map(|line| line.strip_prefix("edition = "))
            .expect("workspace edition")
            .trim_matches('"');
        assert_eq!(
            builder
                .matches(&format!("\"$rustc\" --edition {edition} "))
                .count(),
            2
        );
        assert!(builder.contains(
            "rustc=$RUSTUP_HOME/toolchains/${channel}-x86_64-unknown-linux-gnu/bin/rustc"
        ));
        // Installed where the front and the sudoers rule expect it.
        assert!(builder.contains(&format!(
            "install -m 755 -o root -g root \"$capture_build/carrick-capture\" {FRONT_PATH}\n"
        )));
        assert!(builder.contains(&format!("install -d -m 755 -o root -g root {SCRIPT_DIR}\n")));
        assert!(builder.contains(&format!(
            "install -m 644 -o root -g root capture/scripts/*.bt {SCRIPT_DIR}/\n"
        )));
        assert!(
            builder.contains(
                "ci-scaler capture-sudoers > /etc/sudoers.d/carrick-dispatch-capture.new"
            )
        );
        // The retired xtask front is gone.
        assert!(!builder.contains(RETIRED_FRONT));
    }

    fn visudo(text: &str) -> bool {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("carrick-dispatch-capture");
        std::fs::write(&file, text).expect("drop-in");
        Command::new("/usr/sbin/visudo")
            .args(["-c", "-q", "-f"])
            .arg(&file)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("visudo (from sudo) is required to check the capture drop-in")
            .success()
    }

    #[test]
    fn sudoers_drop_in_passes_visudo_and_a_malformed_one_fails() {
        assert!(visudo(SUDOERS), "production drop-in must pass visudo -c");
        for malformed in [
            SUDOERS.replace("NOPASSWD:", "NOPASSWD"),
            SUDOERS.replace("(root)", "(root"),
            SUDOERS.replace("secure_path=\"", "secure_path=\"\""),
            format!("{SUDOERS}carrick-dispatch-agent ALL =\n"),
        ] {
            assert!(!visudo(&malformed), "visudo accepted:\n{malformed}");
        }
        // No wildcard, shell or general grant in the rule itself.
        let rule = SUDOERS
            .lines()
            .find(|line| line.starts_with("carrick-dispatch-agent "))
            .expect("rule");
        assert!(!rule.contains(['*', '?', '[', '\\']), "{rule}");
        let commands = rule.split_once("NOPASSWD:").expect("tag").1;
        assert_eq!(
            commands.split(',').map(str::trim).collect::<Vec<_>>(),
            [
                FRONT_PATH,
                "NOEXEC: /usr/bin/dmesg \"\"",
                "/usr/bin/journalctl -k"
            ]
        );
        assert!(!SUDOERS.contains("bpftrace,") && !SUDOERS.contains("/usr/bin/bpftrace"));
        assert_eq!(
            SUDOERS
                .lines()
                .filter(|line| !line.starts_with('#'))
                .count(),
            2
        );
    }

    fn guest_output(exit: i32, stdout: &str) -> live::GuestOutput {
        live::GuestOutput {
            exit: live::GuestExit(exit),
            stdout: stdout.to_owned(),
        }
    }

    /// A clone's root view for [`verify_policy`]; each field is one way an
    /// install can be wrong.
    struct Clone {
        visudo_drop_in: i32,
        installed: String,
        modes: String,
        listing: String,
        script: String,
        retired_front: bool,
    }

    impl Clone {
        fn good() -> Self {
            Self {
                visudo_drop_in: 0,
                installed: SUDOERS.to_owned(),
                modes: "440 root root regular file\n755 root root regular file\n755 root root directory\n644 root root regular file\n".to_owned(),
                listing: "signal-kill-sender.bt\n".to_owned(),
                script: SCRIPTS[0].source.to_owned(),
                retired_front: false,
            }
        }

        fn check(&self) -> Result<(), ScalerError> {
            verify_policy(|args| {
                Ok(match args {
                    ["/usr/sbin/visudo", "-c", "-q"] => guest_output(0, ""),
                    ["/usr/sbin/visudo", .., path] if *path == SUDOERS_PATH => {
                        guest_output(self.visudo_drop_in, "")
                    }
                    ["/bin/cat", path] if *path == SUDOERS_PATH => guest_output(0, &self.installed),
                    ["/bin/cat", _] => guest_output(0, &self.script),
                    ["/usr/bin/stat", ..] => guest_output(0, &self.modes),
                    ["/usr/bin/find", ..] => guest_output(0, &self.listing),
                    ["/usr/bin/test", "!", "-e", RETIRED_FRONT] => {
                        guest_output(i32::from(self.retired_front), "")
                    }
                    ["/usr/bin/bpftrace", "--version"] => guest_output(0, "bpftrace v0.23.2\n"),
                    other => panic!("unexpected guest command {other:?}"),
                })
            })
        }
    }

    #[test]
    fn policy_check_refuses_a_wrong_drop_in_front_or_script_directory() {
        Clone::good().check().expect("intended install");
        let wrong = [
            Clone {
                visudo_drop_in: 1,
                ..Clone::good()
            },
            Clone {
                installed: SUDOERS.replace("/usr/bin/journalctl -k", "ALL"),
                ..Clone::good()
            },
            Clone {
                modes: Clone::good().modes.replacen(
                    "755 root root regular",
                    "775 root root regular",
                    1,
                ),
                ..Clone::good()
            },
            Clone {
                modes: Clone::good()
                    .modes
                    .replace("755 root root directory", "777 root root directory"),
                ..Clone::good()
            },
            Clone {
                modes: Clone::good()
                    .modes
                    .replace("644 root root", "664 root root"),
                ..Clone::good()
            },
            Clone {
                listing: "signal-kill-sender.bt\nextra.bt\n".to_owned(),
                ..Clone::good()
            },
            Clone {
                listing: String::new(),
                ..Clone::good()
            },
            Clone {
                script: SCRIPTS[0].source.replace("== 9", "!= 0"),
                ..Clone::good()
            },
            Clone {
                retired_front: true,
                ..Clone::good()
            },
        ];
        for (index, clone) in wrong.iter().enumerate() {
            assert!(clone.check().is_err(), "wrong install {index} passed");
        }
    }

    /// A fake clone for [`verify_root_refusals`]: `front` decides the exit
    /// status of each worker run from the script name and the tamper state.
    fn root_refusals(front: impl Fn(&str, bool) -> i32) -> (Result<(), ScalerError>, Vec<String>) {
        let mut log = Vec::new();
        let mut tampered = false;
        let result = verify_root_refusals(|args| {
            log.push(args.join(" "));
            Ok(match args {
                ["/bin/chmod", "664", _]
                | ["/bin/chown", "carrick-dispatch-agent", _]
                | ["/usr/bin/truncate", ..] => {
                    tampered = true;
                    guest_output(0, "")
                }
                ["/bin/chmod", "644", _] | ["/bin/chown", "root", _] => {
                    tampered = false;
                    guest_output(0, "")
                }
                ["/bin/cp", "-p", from, _] if from.starts_with("/run/") => {
                    tampered = false;
                    guest_output(0, "")
                }
                ["/usr/bin/install", ..] | ["/bin/cp", ..] | ["/bin/rm", ..] => guest_output(0, ""),
                ["/bin/cat", _] => guest_output(0, if tampered { "" } else { SCRIPTS[0].source }),
                ["/usr/sbin/runuser", .., name, "--seconds", "1"] => {
                    guest_output(front(name, tampered), "")
                }
                other => panic!("unexpected guest command {other:?}"),
            })
        });
        (result, log)
    }

    #[test]
    fn root_refusal_test_passes_the_real_front_and_fails_a_permissive_one() {
        // The real front: unknown names are shape refusals; tampered
        // allowlisted scripts are install refusals.
        let real = |name: &str, tampered: bool| match (name, tampered) {
            ("outside", _) => REFUSED_SHAPE,
            (_, true) => REFUSED_INSTALL,
            _ => 0,
        };
        let (result, log) = root_refusals(real);
        result.expect("real front");
        // Four worker runs: the planted script and three tampers.
        assert_eq!(
            log.iter().filter(|line| line.contains("runuser")).count(),
            4
        );
        // A front that runs any script in its directory fails.
        let any_file = |name: &str, tampered: bool| match (name, tampered) {
            (_, true) => REFUSED_INSTALL,
            _ => 0,
        };
        assert!(root_refusals(any_file).0.is_err());
        // A front that skips the installed-script check fails.
        let unchecked = |name: &str, _: bool| if name == "outside" { REFUSED_SHAPE } else { 0 };
        assert!(root_refusals(unchecked).0.is_err());
    }

    /// A fake `sudo` (Linux: it reads `/proc`) applying `policy`: `strict`
    /// is the intended policy, `permissive` also runs anything else,
    /// `closed` is a host without the drop-in, `leaky` lets the front write
    /// `-o` files, `freeform` lets it run a worker program file, and
    /// `anonymous` misreports the sender.
    #[cfg(target_os = "linux")]
    fn fake_sudo(dir: &Path, policy: &str) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let script = format!(
            r#"#!/bin/bash
policy={policy}
[ "$1" = -n ] || exit 90
shift
refuse() {{ echo 'sudo: a password is required' >&2; exit 1; }}
[ "$policy" = closed ] && refuse
case "$*" in
  dmesg) echo '[0.000000] Linux version'; exit 0 ;;
  'journalctl -k') echo 'kernel: Linux version'; exit 0 ;;
  'carrick-capture signal-kill-sender --seconds 10')
    sender=$(cut -d' ' -f4 "/proc/$PPID/stat")
    [ "$policy" = anonymous ] && sender=1
    victim=
    for stat in /proc/[0-9]*/stat; do
      read -r p c _ pp _ < "$stat" 2>/dev/null || continue
      [ "$pp" = "$(cut -d' ' -f4 "/proc/$PPID/stat")" ] && [ "$c" = '(sleep)' ] && victim=$p
    done
    echo 'capture ready: signal-kill-sender for 10 s'
    for _ in $(seq 200); do
      state=$(cut -d' ' -f3 "/proc/$victim/stat" 2>/dev/null || echo gone)
      if [ "$state" = Z ] || [ "$state" = gone ]; then
        echo "sigkill sender_pid=$sender sender_comm=xtask target_pid=$victim target_comm=sleep result=0"
        exit 0
      fi
      sleep 0.05
    done
    exit 1 ;;
esac
if [ "$1" = carrick-capture ]; then
  if [ "$policy" = leaky ] && [ "$3" = -o ]; then : > "$4"; exit 0; fi
  if [ "$policy" = freeform ] && [ "$#" = 2 ] && [ -f "$2" ]; then exit 0; fi
  echo 'carrick-capture: refused: outside the allowlist' >&2; exit 64
fi
[ "$policy" = permissive ] && exec "$@"
refuse
"#
        );
        let path = dir.join(format!("sudo-{policy}"));
        std::fs::write(&path, script).expect("fake sudo");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("mode");
        path
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn serial_host_verify_capture_passes_the_policy_and_fails_any_other() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mounts = dir.path().join("mounts");
        std::fs::write(
            &mounts,
            "proc /proc proc rw 0 0\ntracefs /sys/kernel/tracing tracefs rw,nosuid 0 0\n",
        )
        .expect("mounts");
        // Allowed passes: the intended policy, including the live SIGKILL witness.
        verify_with(&fake_sudo(dir.path(), "strict"), &mounts).expect("strict policy");
        // Disallowed refused: a policy that also runs `true` or `bash` fails.
        assert!(verify_with(&fake_sudo(dir.path(), "permissive"), &mounts).is_err());
        // A front that writes `-o` files or runs a worker program fails.
        assert!(verify_with(&fake_sudo(dir.path(), "leaky"), &mounts).is_err());
        assert!(verify_with(&fake_sudo(dir.path(), "freeform"), &mounts).is_err());
        // A capture that does not name this process as the sender fails.
        assert!(verify_with(&fake_sudo(dir.path(), "anonymous"), &mounts).is_err());
        // A clone without the drop-in fails the allowed commands.
        assert!(verify_with(&fake_sudo(dir.path(), "closed"), &mounts).is_err());
        // So does a clone without tracefs.
        std::fs::write(&mounts, "proc /proc proc rw 0 0\n").expect("mounts");
        assert!(verify_with(&fake_sudo(dir.path(), "strict"), &mounts).is_err());
    }
}
