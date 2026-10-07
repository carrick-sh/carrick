//! Shared, exact suite launch envelopes for conformance and impact.
use crate::manifest::{EnvKv, Suite};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DockerPlatform {
    LinuxArm64,
    LinuxAmd64,
}

impl DockerPlatform {
    pub fn as_str(self) -> &'static str {
        match self {
            DockerPlatform::LinuxArm64 => "linux/arm64",
            DockerPlatform::LinuxAmd64 => "linux/amd64",
        }
    }
}

fn env_args(envs: &[&[EnvKv]]) -> Vec<String> {
    let mut v = Vec::new();
    for set in envs {
        for kv in *set {
            v.push("-e".to_string());
            v.push(format!("{}={}", kv.key, kv.val));
        }
    }
    v
}

/// The command to actually launch for a suite.
///
/// LTP's `tst_test` framework forks the test body into a child and the main
/// process reaps it. When the test binary is PID 1 the kernel drops un-handled
/// signals to it, so the framework's reap/watchdog path breaks and EVERY test
/// TBROKs with "Main test process might have exit!" / "Test killed! (timeout?)".
/// This bites BOTH sides on current LTP (20260529 tightened the monitor):
/// carrick runs the binary as guest PID 1 over its host-process fork model, and
/// docker runs it as container PID 1. carrick is being *faithful* to Linux PID-1
/// semantics here — real Docker added `--init` for exactly this class of app.
///
/// Run the LTP test under `/bin/sh -c` instead, so the shell is PID 1 (a proper
/// reaper) and the test is its child — the same way `scripts/ltp-baseline.py`
/// and LTP's own runners invoke it. Applied identically to carrick AND docker so
/// the differential stays symmetric (both: sh=PID1 -> test=child). Scoped to
/// LTP; cpython/go/node keep their bare cmd.
fn effective_cmd(suite: &Suite) -> Vec<String> {
    if matches!(suite.ecosystem, crate::manifest::Ecosystem::Ltp) {
        vec!["/bin/sh".to_string(), "-c".to_string(), suite.cmd.join(" ")]
    } else {
        suite.cmd.clone()
    }
}

/// Build the carrick argv: `run --name <run-id> <envelope flags> <image> <cmd...>`.
/// `--name` gives carrick the SAME single handle docker gets — carrick derives
/// the proctitle / scoped-kill id from it (precedence: CARRICK_RUN_ID -> --name
/// -> auto), so the run-id, the container name, and the kill scope are one thing.
pub fn carrick_argv(suite: &Suite, carrick_bin: &str, run_id: &str) -> Vec<String> {
    let mut a = vec![carrick_bin.to_string(), "run".to_string()];
    a.push("--name".to_string());
    a.push(run_id.to_string());
    // Disable carrick's trap watchdog for conformance. It counts SYSCALL traps
    // as a proxy for "stuck", but that proxy is wrong: a legitimate fork- or
    // file-heavy test (fork_procs; getcwd04 creating/renaming thousands of
    // files) exceeds the 1M-trap default and is wrongly recorded CRASH before
    // it ever reaches its real verdict — verified: fork_procs PASSES with a
    // raised budget. The authoritative "stuck" guards in the gate are the
    // per-suite TIMEOUT (mac-side kill / guest-side `timeout`) and each LTP
    // test's own 30s SIGALRM watchdog, so the trap counter is pure downside.
    // A suite may still override this via its own carrick_flags (added below).
    a.push("--max-traps".to_string());
    a.push(usize::MAX.to_string());
    // NO per-run `--pull`: it defaults to `missing` (pull each image at most
    // once). Version skew (a rebuilt+repushed image — same tag, new digest) is
    // handled ONCE by the harness image-guard, which re-pulls moved images
    // before phase 1. A per-run `--pull always` re-fetches the registry manifest
    // for every one of the ~2000 suites — that pins `com.docker.backend` and the
    // Docker VM at hundreds of % CPU, the exact carrick‖docker contention the
    // two-phase gate exists to avoid, and it corrupts the timing-sensitive
    // fuzzy-sync verdicts. The one-shot image-guard gives the same skew safety
    // for free.
    a.extend(suite.carrick_flags.iter().cloned());
    // Oracle-fidelity symmetry for the launch-time syscall policy: `carrick run`
    // models Docker's default seccomp profile BY DEFAULT (matching a bare
    // `docker run` oracle), so a suite whose docker oracle is deliberately
    // UNCONFINED (`--security-opt seccomp=unconfined` in docker_flags — the
    // keyring/pidfd_getfd/fanotify/clone3 families compare real-syscall
    // capability, not container policy) must run the carrick side unconfined
    // too. Match both docker spellings (two-token `--security-opt X` and
    // one-token `--security-opt=X`) so a manifest reformat can't silently drop
    // the symmetry.
    let docker_unconfined = suite
        .docker_flags
        .iter()
        .any(|f| f == "seccomp=unconfined" || f == "--security-opt=seccomp=unconfined");
    if docker_unconfined {
        a.push("--security-opt".to_string());
        a.push("seccomp=unconfined".to_string());
    }
    if let Some(ep) = suite.entrypoint.as_ref().and_then(|e| e.for_carrick()) {
        a.push("--entrypoint".to_string());
        a.push(ep);
    }
    for m in &suite.bind_mounts {
        a.push("-v".to_string());
        a.push(m.clone());
    }
    if let Some(w) = &suite.workdir {
        a.push("-w".to_string());
        a.push(w.clone());
    }
    a.extend(env_args(&[&suite.env, &suite.env_carrick]));
    a.push(suite.image.clone());
    a.extend(effective_cmd(suite));
    a
}

/// Build the docker argv: `run --name conf-<id> --platform <platform> <flags> <image> <cmd...>`.
pub fn docker_argv(suite: &Suite, run_id: &str, platform: DockerPlatform) -> Vec<String> {
    let mut a = vec![
        "docker".to_string(),
        "run".to_string(),
        "--name".to_string(),
        run_id.to_string(), // already `conf-<pid>-<seq>` from the orchestrator
        "--platform".to_string(),
        platform.as_str().to_string(),
    ];
    a.extend(suite.docker_flags.iter().cloned());
    if let Some(ep) = suite.entrypoint.as_ref().and_then(|e| e.for_docker()) {
        a.push("--entrypoint".to_string());
        a.push(ep);
    }
    for m in &suite.bind_mounts {
        a.push("-v".to_string());
        a.push(m.clone());
    }
    if let Some(w) = &suite.workdir {
        a.push("-w".to_string());
        a.push(w.clone());
    }
    a.extend(env_args(&[&suite.env, &suite.env_docker]));
    a.push(suite.image.clone());
    a.extend(effective_cmd(suite));
    a
}

/// Native oracle launch: image defaults plus the same oracle env, entrypoint,
/// workdir and effective command as Docker. Unknown Docker policy flags fail
/// closed rather than silently measuring a different execution.
pub fn native_argv(
    suite: &Suite,
    rootfs: &crate::native::NativeRootfs,
) -> anyhow::Result<Vec<String>> {
    let mut flags = suite.docker_flags.iter();
    while let Some(flag) = flags.next() {
        match flag.as_str() {
            "--security-opt" => anyhow::ensure!(
                flags
                    .next()
                    .is_some_and(|value| value == "seccomp=unconfined"),
                "native oracle supports only seccomp=unconfined"
            ),
            "--security-opt=seccomp=unconfined" | "--rm" => {}
            other => anyhow::bail!(
                "native oracle does not support Docker flag {other:?} for {}",
                suite.name
            ),
        }
    }
    anyhow::ensure!(
        suite.bind_mounts.is_empty(),
        "native oracle bind mounts are not implemented for {}",
        suite.name
    );
    let root = rootfs
        .root
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("non-UTF8 rootfs path"))?;
    // All data is positional argv, never interpolated into a shell program.
    // PID 1 waits INSIDE the chroot: /proc/1/root must describe the image,
    // never the host. Namespace exit kills orphaned descendants.
    const SETUP: &str = r#"
root=$1
shift
read -r init_stat < /proc/self/fd/4/self/stat
exec 4<&-
printf '%s\n' "$init_stat" > "$root/../init.stat"
mount --make-rprivate /
mkdir -p "$root/proc" "$root/dev" "$root/tmp"
chmod 1777 "$root/tmp"
mount -t proc proc "$root/proc"
mount -t tmpfs -o mode=755 tmpfs "$root/dev"
for device in null zero random urandom; do
    touch "$root/dev/$device"
    mount --bind "/dev/$device" "$root/dev/$device"
done
mkdir -p "$root/dev/shm" "$root/dev/pts"
mount -t tmpfs -o mode=1777 tmpfs "$root/dev/shm"
mount -t devpts -o newinstance,ptmxmode=0666,mode=0620 devpts "$root/dev/pts"
ln -s pts/ptmx "$root/dev/ptmx"
ln -s /proc/self/fd "$root/dev/fd"
ln -s /proc/self/fd/0 "$root/dev/stdin"
ln -s /proc/self/fd/1 "$root/dev/stdout"
ln -s /proc/self/fd/2 "$root/dev/stderr"
exec 3> "$root/../init-ready"
exec "$@"
"#;
    // Retain a host-proc directory only until PID 1 records its host incarnation.
    // setsid gives init and its children ordinary positive namespace pgrp/sid.
    let mut argv: Vec<String> = [
        "sudo",
        "-n",
        "/bin/sh",
        "-eu",
        "-c",
        "exec 4< /proc; exec \"$@\"",
        "native-unshare",
        "unshare",
    ]
    .into_iter()
    .map(String::from)
    .collect();
    argv.extend(
        crate::native::UNSHARE_FLAGS
            .iter()
            .map(|flag| (*flag).into()),
    );
    argv.extend(
        [
            "setsid",
            "/bin/sh",
            "-eu",
            "-c",
            SETUP,
            "native-oracle",
            root,
            "env",
            "-i",
            "--",
        ]
        .into_iter()
        .map(String::from),
    );
    argv.push("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into());
    argv.extend(rootfs.env.iter().cloned());
    anyhow::ensure!(
        rootfs.env.iter().all(|value| value
            .split_once('=')
            .is_some_and(|(key, _)| !key.is_empty())),
        "native image environment must contain NAME=value assignments"
    );
    argv.extend(
        suite
            .env
            .iter()
            .chain(&suite.env_docker)
            .map(|kv| format!("{}={}", kv.key, kv.val)),
    );
    argv.extend(["/usr/sbin/chroot".into(), root.into()]);
    argv.extend([
        "/bin/sh".into(),
        "-c".into(),
        "printf 'ready\\n' >&3; exec 3>&-; \"$@\"; rc=$?; exit \"$rc\"".into(),
        "native-init".into(),
    ]);
    let workdir = suite
        .workdir
        .as_deref()
        .or(rootfs.workdir.as_deref())
        .unwrap_or("/");
    if workdir != "/" {
        anyhow::ensure!(workdir.starts_with('/'), "native workdir must be absolute");
        argv.extend([
            "/bin/sh".into(),
            "-eu".into(),
            "-c".into(),
            "cd -- \"$1\"; shift; exec \"$@\"".into(),
            "native-workdir".into(),
            workdir.into(),
        ]);
    }
    let entrypoint = suite.entrypoint.as_ref().and_then(|ep| ep.for_docker());
    match entrypoint {
        Some(ep) if !ep.is_empty() => argv.push(ep),
        Some(_) => {}
        None => argv.extend(rootfs.entrypoint.iter().cloned()),
    }
    argv.extend(if suite.cmd.is_empty() {
        rootfs.cmd.clone()
    } else {
        effective_cmd(suite)
    });
    Ok(argv)
}
