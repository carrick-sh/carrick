//! Scoped capture privilege on agent clones (#1621; owner decision on #231,
//! 2026-11-04). The dispatch worker gets passwordless sudo for exactly
//! `bpftrace`, `dmesg` and `journalctl -k`, so a capture round can attribute
//! SIGKILLs and OOM kills, and nothing else: no shell and no general root.
//!
//! Raw `/usr/bin/bpftrace` as root IS general root: `-o FILE` and
//! `--emit-elf`/`--emit-llvm` write any file (a sudoers drop-in, say),
//! `-c CMD` runs a command, and `--unsafe` enables `system()`. Sudoers can
//! only match whole argument strings, so the rule names [`FRONT_PATH`]
//! instead: a root-owned copy of carrick-xtask that, under that name, only
//! parses an allowlist of argument shapes and then runs `/usr/bin/bpftrace`
//! with a cleared environment and sudo's own `sudo_noexec.so` preloaded, so
//! neither bpftrace nor a child can exec. `dmesg` and `journalctl -k` take
//! sudo's `NOEXEC` tag and exact arguments.
//!
//! [`verify_policy`] (root, through the guest agent) and [`verify`] (the
//! worker account, `ci-scaler verify-capture`) are the template
//! qualification checks; the builder runs the second while provisioning too.

use super::{ScalerError, live};
use std::ffi::OsString;
use std::io::{BufRead, BufReader, Read};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// The drop-in the builder writes; qualification compares its bytes.
pub(crate) const SUDOERS_PATH: &str = "/etc/sudoers.d/carrick-dispatch-capture";
/// The bpftrace argument front, first on the worker's sudo `secure_path`, so
/// `sudo bpftrace ...` resolves here and raw `/usr/bin/bpftrace` matches no
/// rule.
pub(crate) const FRONT_PATH: &str = "/usr/local/sbin/bpftrace";
/// The installed xtask the front must be a byte copy of. A copy, not a link:
/// sudo matches a command by basename and inode, so a hard link would let a
/// user's symlink named `bpftrace` run the general xtask CLI as root.
const XTASK_PATH: &str = "/usr/local/bin/carrick-xtask";
const BPFTRACE: &str = "/usr/bin/bpftrace";
/// Sudo's `NOEXEC` mechanism: its constructor installs a seccomp filter that
/// fails `execve`/`execveat` with `EACCES` for the process and its children.
const NOEXEC_PRELOAD: &str = "/usr/libexec/sudo/sudo_noexec.so";
/// The front's refusal marker; qualification requires it on refused shapes,
/// proving sudo admitted the front and the front refused.
const FRONT_REFUSAL: &str = "bpftrace front: refused";
const FRONT_USAGE: &str = "allowed: bpftrace [-q] [-f text|json] [-B none|line|full] -e PROGRAM | bpftrace -l PATTERN | bpftrace --version";

/// Exactly three commands, full paths, no shell, no wildcards. Tags carry
/// forward in a sudoers command list: all three are `NOPASSWD`, and `dmesg`
/// and `journalctl` are also `NOEXEC` (the front applies the same preload to
/// bpftrace itself, which it must exec once). `""` admits bare `dmesg` only.
pub(crate) const SUDOERS: &str = r#"# Scoped capture privilege for dispatch workers (#1621). Written by
# scripts/ci/build-template-debian.sh from `carrick-xtask ci-scaler
# capture-sudoers`; template qualification compares these bytes. Exactly
# three commands with full paths, no shell and no wildcards. The bpftrace
# path is the carrick-xtask argument front for /usr/bin/bpftrace.
Defaults:carrick-dispatch-agent secure_path="/usr/local/sbin:/usr/sbin:/usr/bin"
carrick-dispatch-agent ALL = (root) NOPASSWD: /usr/local/sbin/bpftrace, NOEXEC: /usr/bin/dmesg "", /usr/bin/journalctl -k
"#;

/// Map the caller's bpftrace arguments to the canonical argv the front runs,
/// or the reason they fall outside the allowlist. Every option is its own
/// argument (no clusters, no `--opt=value`), option values come from fixed
/// sets, and nothing the caller passes can be read by bpftrace as an option.
fn front_argv(args: &[OsString]) -> Result<Vec<OsString>, String> {
    match args {
        [only] if only == "--version" || only == "-V" => return Ok(vec!["--version".into()]),
        [list, pattern] if list == "-l" => {
            if pattern.is_empty() || pattern.as_bytes().starts_with(b"-") {
                return Err("-l needs a probe pattern that does not start with '-'".into());
            }
            return Ok(vec!["-l".into(), pattern.clone()]);
        }
        _ => {}
    }
    let pick = |value: Option<&OsString>, option: &str, allowed: &[&'static str]| {
        value
            .and_then(|value| allowed.iter().find(|name| value == **name).copied())
            .ok_or_else(|| format!("{option} takes one of {}", allowed.join(", ")))
    };
    let (mut quiet, mut format, mut buffering, mut program) = (false, None, None, None);
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        match arg.as_bytes() {
            b"-q" if !quiet => quiet = true,
            b"-f" if format.is_none() => format = Some(pick(rest.next(), "-f", &["text", "json"])?),
            b"-B" if buffering.is_none() => {
                buffering = Some(pick(rest.next(), "-B", &["none", "line", "full"])?);
            }
            b"-e" if program.is_none() => {
                let text = rest
                    .next()
                    .filter(|text| !text.is_empty() && !text.as_bytes().starts_with(b"-"));
                program = Some(text.ok_or("-e needs a program that does not start with '-'")?);
            }
            b"-q" | b"-f" | b"-B" | b"-e" => {
                return Err(format!("{} given twice", arg.to_string_lossy()));
            }
            _ => {
                return Err(format!(
                    "{:?} is outside the capture allowlist (no output files, -c, -p, --unsafe, includes or program files)",
                    arg.to_string_lossy()
                ));
            }
        }
    }
    let program = program.ok_or("a capture needs -e PROGRAM")?;
    let mut argv: Vec<OsString> = Vec::new();
    if quiet {
        argv.push("-q".into());
    }
    for (option, value) in [("-f", format), ("-B", buffering)] {
        if let Some(value) = value {
            argv.extend([option.into(), value.into()]);
        }
    }
    argv.extend(["-e".into(), program.clone()]);
    Ok(argv)
}

/// The exec the front performs: real bpftrace, the canonical argv, a cleared
/// environment holding only a fixed `PATH` and the noexec preload.
fn front_command(argv: &[OsString]) -> Command {
    let mut command = Command::new(BPFTRACE);
    command
        .args(argv)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin")
        .env("LD_PRELOAD", NOEXEC_PRELOAD);
    command
}

/// `main` runs this, and never the general CLI, whenever the executable or
/// argv\[0\] is named `bpftrace`. Returns the exit code when it cannot exec.
pub fn bpftrace_front(args: &[OsString]) -> i32 {
    use std::os::unix::process::CommandExt;
    let argv = match front_argv(args) {
        Ok(argv) => argv,
        Err(reason) => {
            eprintln!("{FRONT_REFUSAL}: {reason}\n{FRONT_USAGE}");
            return 2;
        }
    };
    if !Path::new(NOEXEC_PRELOAD).is_file() {
        eprintln!("{FRONT_REFUSAL}: {NOEXEC_PRELOAD} is missing, so bpftrace could exec");
        return 2;
    }
    let error = front_command(&argv).exec();
    eprintln!("bpftrace front: cannot run {BPFTRACE}: {error}");
    127
}

/// Root, through the guest agent: the whole sudoers policy and the drop-in
/// pass `visudo -c`, the drop-in holds exactly [`SUDOERS`], and the front is
/// a root-owned byte copy of the installed xtask.
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
    let modes = passes(&[
        "/usr/bin/stat",
        "-c",
        "%a %U %G %F",
        SUDOERS_PATH,
        FRONT_PATH,
    ])?;
    if modes.as_deref() != Some("440 root root regular file\n755 root root regular file\n") {
        return Err(ScalerError::Guard(
            "capture drop-in or bpftrace front has the wrong owner, mode or type",
        ));
    }
    if passes(&["/usr/bin/cmp", "-s", FRONT_PATH, XTASK_PATH])?.is_none() {
        return Err(ScalerError::Guard(
            "bpftrace front is not a copy of the installed carrick-xtask",
        ));
    }
    if passes(&[BPFTRACE, "--version"])?.is_none() {
        return Err(ScalerError::Guard("bpftrace is not installed"));
    }
    Ok(())
}

/// Commands sudo itself must refuse: no shell or general command, the raw
/// bpftrace binary, and the log commands with any other arguments.
const SUDO_REFUSED: [&[&str]; 6] = [
    &["true"],
    &["bash"],
    &["/usr/bin/bpftrace", "-e", "BEGIN { exit(); }"],
    &["dmesg", "-C"],
    &["journalctl"],
    &["journalctl", "-k", "-f"],
];
/// Shapes sudo admits to the front and the front must refuse. `{out}` is a
/// fresh path in a worker-owned directory that must still be absent after.
const FRONT_REFUSED: [&[&str]; 5] = [
    &["bpftrace", "-o", "{out}", "-e", "BEGIN { exit(); }"],
    &["bpftrace", "-e", "BEGIN { exit(); }", "--emit-elf", "{out}"],
    &[
        "bpftrace",
        "--unsafe",
        "-e",
        "BEGIN { system(\"id\"); exit(); }",
    ],
    &["bpftrace", "-c", "/bin/sh", "-e", "BEGIN { exit(); }"],
    &["bpftrace", "/etc/shadow"],
];

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
    let out = out
        .to_str()
        .ok_or(ScalerError::Guard("invalid capture probe path"))?;
    for shape in FRONT_REFUSED {
        let args: Vec<&str> = shape
            .iter()
            .map(|arg| if *arg == "{out}" { out } else { arg })
            .collect();
        let output = sudo_probe(sudo, &args, 10)?;
        if output.status.success()
            || !String::from_utf8_lossy(&output.stderr).contains(FRONT_REFUSAL)
            || Path::new(out).exists()
        {
            report(&format!("sudo -n {}", args.join(" ")), &output);
            return Err(ScalerError::Guard(
                "bpftrace front admitted a refused shape",
            ));
        }
    }
    println!("capture privilege: bpftrace, dmesg and journalctl -k only");
    Ok(())
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

/// The owner's acceptance shape, made deterministic: trace SIGKILL generation
/// for one victim, kill it once bpftrace reports its probes attached (`BEGIN`
/// fires after attachment), and require the matching event.
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
    let program = format!(
        "BEGIN {{ printf(\"ready\\n\"); }} tracepoint:signal:signal_generate /args->sig == 9 && args->pid == {pid}/ {{ printf(\"sigkill %d\\n\", args->pid); exit(); }} interval:s:20 {{ exit(); }}"
    );
    let mut child = Command::new("/usr/bin/timeout")
        .args(["-k", "2", "30"])
        .arg(sudo)
        .args(["-n", "bpftrace", "-B", "line", "-q", "-e", &program])
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
    let deadline = Instant::now() + Duration::from_secs(30);
    let traced = expect_line(&lines, deadline, "ready")
        .and_then(|()| Ok(kill()?))
        .and_then(|()| expect_line(&lines, deadline, &format!("sigkill {pid}")));
    // Bounded by `timeout` and by the program's own interval exit.
    let status = child.wait()?;
    let _ = reader.join();
    let errors = errors.join().unwrap_or_default();
    if traced.is_err() || !status.success() {
        eprintln!(
            "sudo -n bpftrace: {status}; stderr: {}",
            String::from_utf8_lossy(&errors)
        );
    }
    traced?;
    if !status.success() {
        return Err(ScalerError::Guard("sudo -n bpftrace capture failed"));
    }
    Ok(())
}

fn expect_line(
    lines: &mpsc::Receiver<std::io::Result<String>>,
    deadline: Instant,
    want: &str,
) -> Result<(), ScalerError> {
    loop {
        match lines.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(Ok(line)) if line == want => return Ok(()),
            Ok(Ok(_)) => {}
            Ok(Err(error)) => return Err(error.into()),
            Err(_) => {
                return Err(ScalerError::Guard(
                    "sudo -n bpftrace did not report the traced SIGKILL",
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
    use super::*;

    fn os(args: &[&str]) -> Vec<OsString> {
        args.iter().map(OsString::from).collect()
    }

    #[test]
    fn front_admits_the_capture_shapes_in_canonical_form() {
        let acceptance =
            "tracepoint:signal:signal_generate /args->sig == 9/ { printf(\"%d\\n\", args->pid); }";
        for (given, canonical) in [
            (vec!["-e", acceptance], vec!["-e", acceptance]),
            (
                vec!["-e", acceptance, "-B", "line", "-q", "-f", "json"],
                vec!["-q", "-f", "json", "-B", "line", "-e", acceptance],
            ),
            (
                vec!["-l", "tracepoint:signal:*"],
                vec!["-l", "tracepoint:signal:*"],
            ),
            (vec!["-V"], vec!["--version"]),
            (vec!["--version"], vec!["--version"]),
        ] {
            assert_eq!(front_argv(&os(&given)), Ok(os(&canonical)), "{given:?}");
        }
    }

    #[test]
    fn front_refuses_writes_exec_unsafe_and_unknown_shapes() {
        let program = "BEGIN { exit(); }";
        for given in [
            vec![],
            vec!["-o", "/etc/sudoers.d/x", "-e", program],
            vec!["-e", program, "-o", "/etc/sudoers.d/x"],
            vec!["-e", program, "-o/etc/sudoers.d/x"],
            vec!["-e", program, "--output", "/tmp/x"],
            vec!["-e", program, "--emit-elf", "/tmp/x"],
            vec!["-e", program, "--emit-llvm", "/tmp/x"],
            vec!["-e", program, "--aot", "/tmp/x"],
            vec!["-c", "/bin/sh", "-e", program],
            vec!["-p", "1", "-e", program],
            vec!["--unsafe", "-e", program],
            vec!["-I", "/root", "-e", program],
            vec!["--include", "/etc/shadow", "-e", program],
            vec!["/etc/shadow"],
            vec!["-e", program, "/tmp/positional"],
            vec!["-e", program, "-e", program],
            vec!["-e"],
            vec!["-e", ""],
            vec!["-e", "-o/etc/sudoers.d/x"],
            vec!["-qe", program],
            vec!["--format=json", "-e", program],
            vec!["-f", "xml", "-e", program],
            vec!["-f"],
            vec!["-B", "bogus", "-e", program],
            vec!["-q", "-q", "-e", program],
            vec!["-d", "all", "-e", program],
            vec!["-v", "-e", program],
            vec!["-k", "-e", program],
            vec!["--", "-e", program],
            vec!["-l", "-o/tmp/x"],
            vec!["-l", ""],
            vec!["-l", "tracepoint:*", "-e", program],
            vec!["--version", "-e", program],
        ] {
            assert!(front_argv(&os(&given)).is_err(), "front admitted {given:?}");
        }
        // Qualification's front probes are exactly shapes the parser refuses.
        for shape in FRONT_REFUSED {
            let args: Vec<OsString> = shape[1..]
                .iter()
                .map(|arg| arg.replace("{out}", "/tmp/x").into())
                .collect();
            assert!(front_argv(&args).is_err(), "{shape:?}");
        }
    }

    #[test]
    fn front_runs_real_bpftrace_with_noexec_and_a_fixed_environment() {
        let command = front_command(&os(&["-e", "BEGIN { exit(); }"]));
        assert_eq!(command.get_program(), BPFTRACE);
        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            ["-e", "BEGIN { exit(); }"]
        );
        let mut envs: Vec<(OsString, Option<OsString>)> = command
            .get_envs()
            .map(|(name, value)| (name.to_owned(), value.map(ToOwned::to_owned)))
            .collect();
        envs.sort();
        assert_eq!(
            envs,
            [
                ("LD_PRELOAD".into(), Some(NOEXEC_PRELOAD.into())),
                ("PATH".into(), Some("/usr/sbin:/usr/bin".into())),
            ]
        );
        // A refused shape never reaches exec.
        assert_eq!(
            bpftrace_front(&os(&["-o", "/tmp/x", "-e", "BEGIN { exit(); }"])),
            2
        );
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

    #[test]
    fn policy_check_refuses_a_malformed_or_edited_drop_in() {
        let check = |visudo_drop_in: i32, installed: &str, modes: &str, cmp: i32| {
            verify_policy(|args| {
                Ok(match args {
                    ["/usr/sbin/visudo", "-c", "-q"] => guest_output(0, ""),
                    ["/usr/sbin/visudo", .., path] if *path == SUDOERS_PATH => {
                        guest_output(visudo_drop_in, "")
                    }
                    ["/bin/cat", _] => guest_output(0, installed),
                    ["/usr/bin/stat", ..] => guest_output(0, modes),
                    ["/usr/bin/cmp", ..] => guest_output(cmp, ""),
                    [BPFTRACE, "--version"] => guest_output(0, "bpftrace v0.23.2\n"),
                    other => panic!("unexpected guest command {other:?}"),
                })
            })
        };
        let modes = "440 root root regular file\n755 root root regular file\n";
        assert!(check(0, SUDOERS, modes, 0).is_ok());
        // A malformed drop-in fails visudo; an edited one fails the byte check.
        assert!(check(1, SUDOERS, modes, 0).is_err());
        let widened = SUDOERS.replace("/usr/bin/journalctl -k", "ALL");
        assert!(check(0, &widened, modes, 0).is_err());
        let writable = "644 root root regular file\n755 root root regular file\n";
        assert!(check(0, SUDOERS, writable, 0).is_err());
        assert!(check(0, SUDOERS, modes, 1).is_err());
    }

    /// A fake `sudo` (Linux: it reads `/proc`) applying `policy`: `strict`
    /// is the intended policy, `permissive` also runs anything else,
    /// `closed` is a host without the drop-in, and `leaky` lets the front
    /// write `-o` files.
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
esac
if [ "$1" = bpftrace ]; then
  if [ "$policy" = leaky ] && [ "$2" = -o ]; then : > "$3"; exit 0; fi
  case " $* " in
    *' -o '*|*' --emit-elf '*|*' --unsafe '*|*' -c '*|*' /etc/shadow '*)
      echo 'bpftrace front: refused: outside the allowlist' >&2; exit 2 ;;
  esac
  pid=$(sed -n 's/.*args->pid == \([0-9]*\)\/.*/\1/p' <<<"${{@: -1}}")
  echo ready
  for _ in $(seq 200); do
    state=$(cut -d' ' -f3 "/proc/$pid/stat" 2>/dev/null || echo gone)
    if [ "$state" = Z ] || [ "$state" = gone ]; then echo "sigkill $pid"; exit 0; fi
    sleep 0.05
  done
  exit 1
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
        // A front that writes `-o` files as root fails.
        assert!(verify_with(&fake_sudo(dir.path(), "leaky"), &mounts).is_err());
        // A clone without the drop-in fails the allowed commands.
        assert!(verify_with(&fake_sudo(dir.path(), "closed"), &mounts).is_err());
        // So does a clone without tracefs.
        std::fs::write(&mounts, "proc /proc proc rw 0 0\n").expect("mounts");
        assert!(verify_with(&fake_sudo(dir.path(), "strict"), &mounts).is_err());
    }
}
