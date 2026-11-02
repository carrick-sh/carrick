//! Separate instrumented Docker-only pass. Its duration is never used as a
//! performance oracle. No Carrick process runs while this pass executes.
use crate::{argv, engine, lane::DockerPlatform, manifest::Suite};
use std::process::{Command, Stdio};

const CAPTURE_SOURCE: &[u8] = include_bytes!("oracle_shape.rs");
const PROGRAM: &str = include_str!("../../../scripts/bpftrace/oracle-served.bt");

pub fn source_fingerprint() -> String {
    use sha2::Digest;
    format!(
        "{:x}",
        sha2::Sha256::digest([PROGRAM.as_bytes(), CAPTURE_SOURCE].concat())
    )
}

pub fn parse(output: &str) -> Result<Vec<u64>, String> {
    if !output
        .lines()
        .any(|line| line == "CARRICK_ORACLE_SHAPE_DONE")
    {
        return Err("bpftrace syscall shape did not finish".into());
    }
    if output.contains("CARRICK_ORACLE_SHAPE_ERROR")
        || output.lines().any(|line| {
            line.starts_with("@tracked[")
                || line.starts_with("@active[")
                || line.starts_with("@nr[")
                || line.starts_with("@incomplete")
        })
    {
        return Err("incomplete bpftrace task/syscall population".into());
    }
    let mut served = std::collections::BTreeSet::new();
    for line in output.lines() {
        if let Some(rest) = line.strip_prefix("@served[") {
            let (nr, count) = rest.split_once("]: ").ok_or("malformed bpftrace shape")?;
            let nr: u64 = nr.parse().map_err(|_| "invalid syscall ordinal")?;
            let count: u64 = count.parse().map_err(|_| "invalid syscall count")?;
            if count != 0 {
                served.insert(nr);
            }
        }
    }
    if served.is_empty() {
        return Err("bpftrace shape contains no served syscall".into());
    }
    Ok(served.into_iter().collect())
}

pub fn capture(suite: &Suite, run_id: &str, platform: DockerPlatform) -> anyhow::Result<Vec<u64>> {
    let original = argv::docker_argv(suite, run_id, platform);
    let image = original
        .iter()
        .rposition(|arg| arg == &suite.image)
        .ok_or_else(|| anyhow::anyhow!("Docker argv lacks image"))?;
    anyhow::ensure!(image + 1 < original.len(), "shape requires an explicit suite command");
    let mut command = Vec::new();
    if let Some(entrypoint) = suite
        .entrypoint
        .as_ref()
        .and_then(|entry| entry.for_docker())
    {
        if !entrypoint.is_empty() { command.push(entrypoint); }
    }
    if suite
        .entrypoint
        .as_ref()
        .and_then(|entry| entry.for_docker())
        .is_none()
    {
        let config = Command::new("docker")
            .args([
                "image",
                "inspect",
                "--format",
                "{{json .Config.Entrypoint}}",
                &suite.image,
            ])
            .output()?;
        anyhow::ensure!(config.status.success(), "inspect workload entrypoint");
        let entrypoint: Option<Vec<String>> = serde_json::from_slice(&config.stdout)?;
        command.extend(entrypoint.unwrap_or_default());
    }
    command.extend_from_slice(&original[image + 1..]);
    anyhow::ensure!(
        !command.is_empty(),
        "shape requires an explicit suite command"
    );
    let control = tempfile::tempdir()?;
    std::fs::write(control.path().join("shape.bt"), PROGRAM)?;
    let fifo = format!("/tmp/carrick-census-{run_id}");
    let shape_id = format!("{run_id}-shape");
    let tracer_id = format!("{run_id}-tracer");
    struct Cleanup<'a>(&'a str, &'a str);
    impl Drop for Cleanup<'_> {
        fn drop(&mut self) {
            let _ = Command::new("docker")
                .args(["rm", "-f", self.0, self.1])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
    }
    let _cleanup = Cleanup(&shape_id, &tracer_id);
    // Preserve the workload envelope. Only its launch waits for the observer;
    // exec retains PID 1 and the ordinary suite's credentials/seccomp policy.
    let mut launch = vec!["docker".to_owned(), "run".to_owned(), "-d".to_owned()];
    let mut index = 2;
    while index < image {
        match original[index].as_str() {
            "--name" | "--entrypoint" => {
                index += 2;
            }
            _ => {
                launch.push(original[index].clone());
                index += 1;
            }
        }
    }
    launch.extend([
        "--name".into(),
        shape_id.clone(),
        "--entrypoint".into(),
        "/bin/sh".into(),
        suite.image.clone(),
        "-c".into(),
        "fifo=$1; shift; mkfifo \"$fifo\" || exit 125; read ready < \"$fifo\" || exit 125; exec \"$@\"".into(),
        "carrick-shape".into(),
        fifo.clone(),
    ]);
    launch.extend(command);
    let start = Command::new(&launch[0]).args(&launch[1..]).output()?;
    anyhow::ensure!(
        start.status.success(),
        "start shape workload: {}",
        String::from_utf8_lossy(&start.stderr)
    );
    let pid = Command::new("docker")
        .args(["inspect", "-f", "{{.State.Pid}}", &shape_id])
        .output()?;
    anyhow::ensure!(pid.status.success(), "inspect shape workload");
    let pid: u32 = String::from_utf8(pid.stdout)?.trim().parse()?;
    anyhow::ensure!(pid != 0, "shape workload did not start");
    let (exit, exit_group) = match platform {
        DockerPlatform::LinuxArm64 => (93, 94),
        DockerPlatform::LinuxAmd64 => (60, 231),
    };
    let script = format!(
        "test -r /sys/kernel/tracing/available_events || mount -t tracefs tracefs /sys/kernel/tracing || exit 125; exec bpftrace -q -B line /carrick-census/shape.bt {pid} {} {exit} {exit_group}",
        suite.timeout_s
    );
    let tracer_image = std::env::var("CARRICK_ORACLE_TRACER_IMAGE").unwrap_or_else(|_| {
        match platform {
            DockerPlatform::LinuxArm64 => "localhost:5050/ltp:arm64",
            DockerPlatform::LinuxAmd64 => "localhost:5050/ltp:amd64",
        }
        .to_owned()
    });
    let args = vec![
        "docker".into(),
        "run".into(),
        "--name".into(),
        tracer_id.clone(),
        "--platform".into(),
        platform.as_str().into(),
        "--privileged".into(),
        "--pid=host".into(),
        "--entrypoint".into(),
        "/bin/sh".into(),
        "-v".into(),
        format!("{}:/carrick-census:ro", control.path().display()),
        tracer_image,
        "-c".into(),
        script,
    ];
    let out_path = engine::raw_dir().join(format!("{tracer_id}.out"));
    let deadline = engine::CarrickDeadline {
        declared_s: suite.timeout_s,
        effective_s: suite.timeout_s,
        origin: engine::DeadlineOrigin::Declared,
    };
    std::thread::scope(|scope| {
        let trace = scope.spawn(|| {
            let mut cmd = Command::new(&args[0]);
            cmd.args(&args[1..]);
            engine::run_one(
                cmd,
                args.clone(),
                deadline,
                &tracer_id,
                engine::Engine::Docker,
                None,
            )
        });
        let ready_deadline =
            std::time::Instant::now() + std::time::Duration::from_secs(suite.timeout_s);
        loop {
            let log = std::fs::read_to_string(&out_path).unwrap_or_default();
            if log.lines().any(|line| line == "CARRICK_ORACLE_SHAPE_READY") {
                break;
            }
            anyhow::ensure!(
                !trace.is_finished() && std::time::Instant::now() < ready_deadline,
                "bpftrace did not arm; see {}",
                out_path.display()
            );
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let mut release = Command::new("docker");
        let release_args = vec![
            "docker".into(),
            "exec".into(),
            shape_id.clone(),
            "/bin/sh".into(),
            "-c".into(),
            "exec 3>\"$1\"; rm -f \"$1\" || exit 125; echo go >&3".into(),
            "carrick-shape-release".into(),
            fifo.clone(),
        ];
        release.args(&release_args[1..]);
        let released = engine::run_one(
            release,
            release_args,
            deadline,
            &format!("{shape_id}-release"),
            engine::Engine::Docker,
            None,
        )?;
        anyhow::ensure!(
            !released.timed_out && released.exit_code == 0,
            "release shape workload"
        );
        let traced = trace
            .join()
            .map_err(|_| anyhow::anyhow!("shape observer panicked"))??;
        anyhow::ensure!(
            !traced.timed_out && traced.exit_code == 0,
            "bpftrace capture failed"
        );
        let stderr = std::fs::read_to_string(traced.stderr_path)?;
        anyhow::ensure!(
            !stderr.lines().any(|line| line.contains("Lost")
                || line.contains("lost")
                || line.contains("ERROR")),
            "bpftrace capture dropped or failed: {stderr}"
        );
        let wait_args = vec!["docker".into(), "wait".into(), shape_id.clone()];
        let mut wait = Command::new("docker");
        wait.args(&wait_args[1..]);
        let waited = engine::run_one(
            wait,
            wait_args,
            deadline,
            &format!("{shape_id}-wait"),
            engine::Engine::Docker,
            None,
        )?;
        anyhow::ensure!(
            !waited.timed_out
                && waited.exit_code == 0
                && std::fs::read_to_string(waited.stdout_path)?.trim() == "0",
            "shape workload did not complete successfully"
        );
        parse(&std::fs::read_to_string(traced.stdout_path)?).map_err(anyhow::Error::msg)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_complete_nonempty_syscall_populations_are_admitted() {
        assert!(parse("@served[34]: 1").is_err());
        assert!(parse("CARRICK_ORACLE_SHAPE_DONE\n").is_err());
        assert_eq!(
            parse("@served[34]: 2\n@served[56]: 1\nCARRICK_ORACLE_SHAPE_DONE\n").unwrap(),
            vec![34, 56]
        );
        assert!(parse("@served[bad]: 1\nCARRICK_ORACLE_SHAPE_DONE\n").is_err());
    }
}
