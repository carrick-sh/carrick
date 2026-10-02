//! Per-landing measurements. Timing is observational, never a performance gate.
use carrick_conformance::{
    argv,
    manifest::{EnginePair, Manifest, Suite},
};
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Args, Debug)]
pub struct ImpactArgs {
    #[command(subcommand)]
    pub action: Action,
}
#[derive(Subcommand, Debug)]
pub enum Action {
    Carrick {
        #[arg(long)]
        artifact: PathBuf,
        #[command(flatten)]
        measurement: Measurement,
    },
    Docker {
        #[command(flatten)]
        measurement: Measurement,
    },
    Report {
        #[arg(long)]
        base: PathBuf,
        #[arg(long)]
        candidate: PathBuf,
        #[arg(long)]
        docker: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
}
#[derive(Args, Debug)]
pub struct Measurement {
    #[arg(long)]
    pub out: PathBuf,
    #[arg(long, default_value_t = 10)]
    pub samples: usize,
    /// Repeat to select workloads; defaults to all declared workloads. One excluded warm-up.
    #[arg(long)]
    pub workload: Vec<String>,
    /// Override creation count for spawn-loop and thread-spawn smoke runs.
    #[arg(long)]
    pub operations: Option<u64>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Sample {
    pub run_id: String,
    pub argv: Vec<String>,
    pub warmup: bool,
    pub wall_s: f64,
    pub child_cpu_s: Option<f64>,
    #[serde(default)]
    pub per_op_s: Option<f64>,
    #[serde(default)]
    pub guest_window_s: Option<f64>,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub cleanup_ok: bool,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct WorkloadReceipt {
    pub image: String,
    pub image_digest: String,
    pub command: Vec<String>,
    pub declaration_sha256: String,
    #[serde(default)]
    pub window: Option<Window>,
    pub samples: Vec<Sample>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Window {
    pub operations: u64,
    pub prefix: String,
}
fn parse_window(output: &str, window: &Window) -> Result<f64> {
    let values = output
        .lines()
        .filter_map(|line| line.strip_prefix(&window.prefix))
        .collect::<Vec<_>>();
    if values.len() != 1 || window.operations == 0 {
        return Err("missing or duplicate guest timing window".into());
    }
    let ns: u64 = values[0].parse()?;
    if ns == 0 {
        return Err("empty guest timing window".into());
    }
    Ok(ns as f64 / 1e9 / window.operations as f64)
}
fn output_tail(output: &str) -> String {
    let lines = output.lines().collect::<Vec<_>>();
    let tail = lines[lines.len().saturating_sub(20)..].join("\n");
    tail.chars()
        .skip(tail.chars().count().saturating_sub(4096))
        .collect()
}
fn parse_sample_window(
    output: &Output,
    window: &Window,
    workload: &str,
    index: usize,
) -> Result<f64> {
    parse_window(&output.stdout, window).map_err(|error| {
        let count = |text: &str| {
            text.lines()
                .filter(|line| line.starts_with(&window.prefix))
                .count()
        };
        format!(
            "{workload} sample {index} (warmup={}): {error}; prefix {:?} lines: stdout={}, stderr={}; exit_code={:?}, timed_out={}\nstdout tail:\n{}\nstderr tail:\n{}",
            index == 0,
            window.prefix,
            count(&output.stdout),
            count(&output.stderr),
            output.code,
            output.timed_out,
            output_tail(&output.stdout),
            output_tail(&output.stderr),
        ).into()
    })
}
fn windows(root: &Path) -> Result<BTreeMap<String, Window>> {
    Ok(serde_json::from_slice(&fs::read(
        root.join("scripts/perf/manifests/impact-windows.json"),
    )?)?)
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Artifact {
    pub path: PathBuf,
    pub sha256: String,
    pub cdhash: String,
    pub lc_uuid: String,
    pub entitlement: String,
    pub dof_present: bool,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Receipt {
    pub schema: u32,
    pub phase: String,
    pub head: String,
    pub run_id: String,
    pub measured_runs: usize,
    pub warmup_policy: String,
    pub artifact: Option<Artifact>,
    pub errors: Vec<String>,
    pub workloads: BTreeMap<String, WorkloadReceipt>,
}
#[derive(Default)]
struct Output {
    code: Option<i32>,
    stdout: String,
    stderr: String,
    wall: f64,
    cpu: Option<f64>,
    timed_out: bool,
}
trait Runner {
    fn execute(
        &mut self,
        args: &[String],
        run_id: Option<&str>,
        timeout: u64,
        env: &[(String, String)],
    ) -> Result<Output>;
}
struct SystemRunner {
    root: PathBuf,
    sequence: usize,
}
impl Runner for SystemRunner {
    fn execute(
        &mut self,
        args: &[String],
        run_id: Option<&str>,
        timeout: u64,
        env: &[(String, String)],
    ) -> Result<Output> {
        self.sequence += 1;
        let dir = self.root.join("target/impact-logs");
        fs::create_dir_all(&dir)?;
        let stem = format!("{}-{}", std::process::id(), self.sequence);
        let stdout = dir.join(format!("{stem}.out"));
        let stderr = dir.join(format!("{stem}.err"));
        let mut command = Command::new(&args[0]);
        command
            .args(&args[1..])
            .current_dir(&self.root)
            .stdin(Stdio::null())
            .stdout(fs::File::create(&stdout)?)
            .stderr(fs::File::create(&stderr)?);
        if let Some(id) = run_id {
            command.env("CARRICK_RUN_ID", id);
        }
        command.envs(env.iter().cloned());
        let cpu_before = child_cpu()?;
        let start = Instant::now();
        let mut child = command.spawn()?;
        let pid = child.id();
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let status = child.wait();
            let wall = start.elapsed().as_secs_f64();
            let cpu = child_cpu().ok().map(|after| after - cpu_before);
            let _ = sender.send((status, wall, cpu));
        });
        let (code, wall, cpu, timed_out) = match receiver.recv_timeout(Duration::from_secs(timeout))
        {
            Ok((status, wall, cpu)) => (status?.code(), wall, cpu, false),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                let pid = libc::pid_t::try_from(pid)?;
                // SAFETY: kill takes a scalar pid for our own live child; no pointers.
                unsafe {
                    libc::kill(pid, libc::SIGKILL);
                }
                let _ = receiver.recv_timeout(Duration::from_secs(5));
                (None, start.elapsed().as_secs_f64(), None, true)
            }
            Err(error) => return Err(error.into()),
        };
        let stderr = fs::read_to_string(stderr)?;
        Ok(Output {
            code,
            stdout: fs::read_to_string(stdout)?,
            stderr,
            wall,
            cpu,
            timed_out,
        })
    }
}
// The runner launches and reaps one command at a time; no other child CPU can
// enter this RUSAGE_CHILDREN delta. Mirrors the existing campaign's CPU floor.
fn child_cpu() -> std::io::Result<f64> {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
    // SAFETY: getrusage initializes a correctly sized writable rusage on success.
    if unsafe { libc::getrusage(libc::RUSAGE_CHILDREN, usage.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: the successful getrusage above initialized every field.
    let usage = unsafe { usage.assume_init() };
    Ok(usage.ru_utime.tv_sec as f64
        + usage.ru_utime.tv_usec as f64 / 1_000_000.0
        + usage.ru_stime.tv_sec as f64
        + usage.ru_stime.tv_usec as f64 / 1_000_000.0)
}
fn strings(args: &[&str]) -> Vec<String> {
    args.iter().map(|s| (*s).into()).collect()
}
fn checked(runner: &mut impl Runner, args: &[String]) -> Result<String> {
    let output = runner.execute(args, None, 30, &[])?;
    if output.code != Some(0) || output.timed_out {
        return Err(format!("{}: {}", args.join(" "), output.stderr).into());
    }
    Ok(output.stdout)
}
fn guard(runner: &mut impl Runner, phase: &str, images: &[String]) -> Result<()> {
    if phase == "docker" {
        let output = runner.execute(
            &strings(&["pgrep", "-f", "(^carrick:|^[^ ]*/carrick( |$))"]),
            None,
            30,
            &[],
        )?;
        match output.code {
            Some(1) => {}
            Some(0) => return Err("Carrick is alive; refusing Docker phase".into()),
            _ => return Err("Carrick census failed".into()),
        }
    } else {
        // No daemon means no running Docker containers. Avoid starting Docker.
        let output = runner.execute(
            &strings(&[
                "pgrep",
                "-f",
                "^([^ ]*/)?(com.docker.backend|dockerd)( |$)|^([^ ]*/)?docker run( |$)",
            ]),
            None,
            30,
            &[],
        )?;
        match output.code {
            Some(1) => {}
            Some(0) => {
                let active = checked(
                    runner,
                    &strings(&[
                        "curl",
                        "-fsS",
                        "--unix-socket",
                        "/var/run/docker.sock",
                        "http://localhost/containers/json",
                    ]),
                )?;
                let active: Vec<serde_json::Value> = serde_json::from_str(&active)?;
                for container in active {
                    let image = container["Image"]
                        .as_str()
                        .ok_or("container census missing Image")?;
                    if image.starts_with("sha256:")
                        || images
                            .iter()
                            .any(|expected| docker_repository(image) == docker_repository(expected))
                    {
                        return Err("Docker workload container alive; refusing Carrick phase (unidentified digest-only containers also fail closed)".into());
                    }
                }
            }
            _ => return Err("Docker census failed".into()),
        }
    }
    Ok(())
}
fn workloads(root: &Path) -> Result<Vec<Suite>> {
    let mut suites = Manifest::from_toml(&fs::read_to_string(
        root.join("scripts/conformance/suites.toml"),
    )?)?
    .suite;
    suites.extend(
        Manifest::from_toml(&fs::read_to_string(
            root.join("scripts/perf/manifests/el1-real-workloads-v1.toml"),
        )?)?
        .suite,
    );
    let worker = suites
        .into_iter()
        .find(|s| s.name == "node-core-worker-message-port")
        .ok_or("missing worker shard")?;
    let mut startup = worker.clone();
    // Start with a positional executable: a leading `-e` is a Carrick
    // environment option until the trailing guest command has begun.
    startup.cmd = strings(&["/opt/nodejs-conformance/bin/node24", "-e", "0"]);
    startup.timeout_s = 30;
    startup.entrypoint = Some(EnginePair {
        both: Some(String::new()),
        carrick: None,
        docker: None,
    });
    startup.env.clear();
    startup.env_carrick.clear();
    startup.env_docker.clear();
    startup.name = "node-startup".into();
    let mut trivial = startup.clone();
    trivial.image = "ubuntu:24.04".into();
    trivial.entrypoint = None;
    trivial.cmd = strings(&["/bin/true"]);
    trivial.carrick_flags.clear();
    trivial.name = "true".into();
    let mut result = vec![trivial, startup, worker];
    result.extend(
        Manifest::from_toml(&fs::read_to_string(
            root.join("scripts/perf/manifests/impact-creations.toml"),
        )?)?
        .suite,
    );
    Ok(result)
}
// Resolve an immutable native-arm64 manifest without invoking Docker. Launches
// use this digest, so a stale local tag can never substitute different bytes.
fn image_digest(runner: &mut impl Runner, image: &str) -> Result<String> {
    let (registry, repository) = match image.split_once('/') {
        Some((host, rest)) if host.contains('.') || host.contains(':') || host == "localhost" => {
            (host.to_string(), rest.to_string())
        }
        _ => (
            "registry-1.docker.io".into(),
            if image.contains('/') {
                image.into()
            } else {
                format!("library/{image}")
            },
        ),
    };
    let (repository, tag) = repository
        .rsplit_once(':')
        .map(|(r, t)| (r.to_string(), t.to_string()))
        .unwrap_or((repository.clone(), "latest".into()));
    let scheme = if registry.starts_with("localhost:") || registry.starts_with("127.0.0.1:") {
        "http"
    } else {
        "https"
    };
    let mut auth = Vec::new();
    if registry == "registry-1.docker.io" {
        let token = checked(
            runner,
            &strings(&[
                "curl",
                "-fsS",
                &format!(
                    "https://auth.docker.io/token?service=registry.docker.io&scope=repository:{repository}:pull"
                ),
            ]),
        )?;
        let token: serde_json::Value = serde_json::from_str(&token)?;
        auth = strings(&[
            "-H",
            &format!(
                "Authorization: Bearer {}",
                token["token"].as_str().ok_or("missing registry token")?
            ),
        ]);
    }
    let fetch = |runner: &mut _, reference: &str| -> Result<String> {
        let mut args = strings(&[
            "curl",
            "-fsS",
            "-H",
            "Accept: application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json",
        ]);
        args.extend(auth.clone());
        args.push(format!(
            "{scheme}://{registry}/v2/{repository}/manifests/{reference}"
        ));
        checked(runner, &args)
    };
    let body = fetch(runner, &tag)?;
    let manifest: serde_json::Value = serde_json::from_str(&body)?;
    if let Some(entries) = manifest["manifests"].as_array() {
        let digest = entries
            .iter()
            .find(|m| m["platform"]["architecture"] == "arm64" && m["platform"]["os"] == "linux")
            .and_then(|m| m["digest"].as_str())
            .ok_or("no native arm64 manifest")?;
        let body = fetch(runner, digest)?;
        let actual = format!("sha256:{:x}", Sha256::digest(body.as_bytes()));
        if digest != actual {
            return Err("registry manifest digest mismatch".into());
        }
        Ok(actual)
    } else {
        // Single-manifest images must prove architecture from their config.
        let digest = manifest["config"]["digest"]
            .as_str()
            .ok_or("missing image config")?;
        let mut args = strings(&["curl", "-fsS"]);
        args.extend(auth);
        args.push(format!(
            "{scheme}://{registry}/v2/{repository}/blobs/{digest}"
        ));
        let config = checked(runner, &args)?;
        if format!("sha256:{:x}", Sha256::digest(config.as_bytes())) != digest {
            return Err("image config digest mismatch".into());
        }
        let config: serde_json::Value = serde_json::from_str(&config)?;
        if config["architecture"] != "arm64" || config["os"] != "linux" {
            return Err("image is not native Linux arm64".into());
        }
        Ok(format!("sha256:{:x}", Sha256::digest(body.as_bytes())))
    }
}
fn image_repository(image: &str) -> &str {
    let image = image
        .split_once('@')
        .map_or(image, |(repository, _)| repository);
    image
        .rsplit_once(':')
        .filter(|(_, tag)| !tag.contains('/'))
        .map_or(image, |(repo, _)| repo)
}
fn docker_repository(image: &str) -> String {
    let repository = image_repository(image);
    let repository = repository
        .strip_prefix("docker.io/")
        .or_else(|| repository.strip_prefix("registry-1.docker.io/"))
        .or_else(|| repository.strip_prefix("index.docker.io/"))
        .unwrap_or(repository);
    let first = repository.split('/').next().unwrap_or(repository);
    if repository.contains('/')
        && (first.contains('.') || first.contains(':') || first == "localhost")
    {
        repository.into()
    } else if repository.contains('/') {
        format!("docker.io/{repository}")
    } else {
        format!("docker.io/library/{repository}")
    }
}
fn pinned(image: &str, digest: &str) -> String {
    format!("{}@{digest}", image_repository(image))
}
fn provenance(runner: &mut impl Runner, path: &Path) -> Result<Artifact> {
    let path = fs::canonicalize(path)?;
    let bin = path.to_str().ok_or("non-UTF8 artifact path")?;
    checked(
        runner,
        &strings(&["/usr/bin/codesign", "--verify", "--strict", bin]),
    )?;
    let signing = runner.execute(
        &strings(&["/usr/bin/codesign", "-d", "--verbose=4", bin]),
        None,
        30,
        &[],
    )?;
    if signing.code != Some(0) {
        return Err("codesign inspection failed".into());
    }
    let cdhash = signing
        .stderr
        .lines()
        .find_map(|l| l.strip_prefix("CDHash="))
        .ok_or("missing CDHash")?
        .into();
    let entitlement = runner.execute(
        &strings(&["/usr/bin/codesign", "-d", "--entitlements", ":-", bin]),
        None,
        30,
        &[],
    )?;
    if entitlement.code != Some(0) {
        return Err("entitlement inspection failed".into());
    }
    let entitlement = entitlement.stdout;
    if !entitlement
        .split_once("<key>com.apple.security.hypervisor</key>")
        .is_some_and(|(_, value)| value.trim_start().starts_with("<true/>"))
    {
        return Err("missing hypervisor entitlement".into());
    }
    let uuid = checked(runner, &strings(&["/usr/bin/dwarfdump", "--uuid", bin]))?;
    let lc_uuid = uuid
        .split_whitespace()
        .nth(1)
        .ok_or("missing LC_UUID")?
        .into();
    let dof_present =
        checked(runner, &strings(&["/usr/bin/otool", "-l", bin]))?.contains("__dof_carrick");
    if !dof_present {
        return Err("missing __dof_carrick".into());
    }
    Ok(Artifact {
        sha256: format!("{:x}", Sha256::digest(fs::read(&path)?)),
        path,
        cdhash,
        lc_uuid,
        entitlement,
        dof_present,
    })
}
fn save(path: &Path, receipt: &Receipt) -> Result<()> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, serde_json::to_vec_pretty(receipt)?)?;
    Ok(())
}
fn measure(
    root: &Path,
    runner: &mut impl Runner,
    phase: &str,
    artifact: Option<&Path>,
    args: &Measurement,
) -> Result<()> {
    if args.samples == 0 {
        return Err("samples must be positive".into());
    }
    let mut suites = workloads(root)?;
    let mut windows = windows(root)?;
    if let Some(n) = args.operations {
        if n == 0 {
            return Err("operations must be positive".into());
        }
        for suite in &mut suites {
            if matches!(suite.name.as_str(), "spawn-loop" | "thread-spawn") {
                for arg in &mut suite.cmd {
                    *arg = arg.replace("1000", &n.to_string());
                }
                windows
                    .get_mut(&suite.name)
                    .ok_or("missing window")?
                    .operations = n;
            }
        }
    }
    // A workload subset cannot permit another campaign's Docker phase.
    let images = suites.iter().map(|s| s.image.clone()).collect::<Vec<_>>();
    if !args.workload.is_empty() {
        for name in &args.workload {
            if !suites.iter().any(|s| &s.name == name) {
                return Err(format!("unknown workload {name}").into());
            }
        }
        suites.retain(|s| args.workload.contains(&s.name));
    }

    guard(runner, phase, &images)?;
    if phase == "docker" {
        let platform = checked(
            runner,
            &strings(&[
                "docker",
                "info",
                "--format",
                "{{.OSType}}/{{.Architecture}}",
            ]),
        )?;
        if !matches!(platform.trim(), "linux/arm64" | "linux/aarch64") {
            return Err(format!(
                "Docker engine must be native Linux arm64, got {}",
                platform.trim()
            )
            .into());
        }
    }

    let run_id = format!(
        "{}-{}-{}",
        std::env::var("CARRICK_RUN_ID").unwrap_or_else(|_| "impact".into()),
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
    );
    let mut receipt = Receipt {
        schema: 1,
        phase: phase.into(),
        head: checked(runner, &strings(&["git", "rev-parse", "HEAD"]))?
            .trim()
            .into(),
        run_id,
        measured_runs: args.samples,
        warmup_policy: "one excluded warm-up per workload; fixed measured run count".into(),
        artifact: artifact.map(|p| provenance(runner, p)).transpose()?,
        errors: vec![],
        workloads: BTreeMap::new(),
    };
    save(&args.out, &receipt)?;
    let measurement = (|| -> Result<()> {
        for mut suite in suites {
            let probe_hash = if suite.name == "fork-exec" {
                let path = root.join(
                    "conformance-probes/target/aarch64-unknown-linux-musl/release/perf_fork_exec",
                );
                suite.bind_mounts = vec![format!("{}:/tmp/impact-fork-exec:ro", path.display())];
                Some(format!("{:x}", Sha256::digest(fs::read(path)?)))
            } else {
                None
            };
            let declaration_sha256 = format!(
                "{:x}",
                Sha256::digest(serde_json::to_vec(&(
                    &suite,
                    windows.get(&suite.name),
                    probe_hash
                ))?)
            );
            let image = suite.image.clone();
            let digest = image_digest(runner, &image)?;
            suite.image = pinned(&image, &digest);
            receipt.workloads.insert(
                suite.name.clone(),
                WorkloadReceipt {
                    image: image.clone(),
                    image_digest: digest.clone(),
                    command: suite.cmd.clone(),
                    declaration_sha256,
                    window: windows.get(&suite.name).cloned(),
                    samples: vec![],
                },
            );
            for index in 0..=args.samples {
                guard(runner, phase, &images)?;
                let id = format!("{}-{}-{index}", receipt.run_id, suite.name);
                let argv = if let Some(artifact) = &receipt.artifact {
                    argv::carrick_argv(&suite, artifact.path.to_str().ok_or("non-UTF8 path")?, &id)
                } else {
                    argv::docker_argv(&suite, &id, argv::DockerPlatform::LinuxArm64)
                };
                let output = execute_workload(runner, &suite, phase, &argv, &id);
                let cleanup = if phase == "carrick" {
                    checked(
                        runner,
                        &strings(&[
                            "sudo",
                            root.join("scripts/sudo/kill.sh")
                                .to_str()
                                .ok_or("non-UTF8 root")?,
                            &id,
                        ]),
                    )
                } else {
                    checked(runner, &strings(&["docker", "rm", "-f", &id]))
                };
                let output = output?;
                let per_op = windows
                    .get(&suite.name)
                    .map(|window| parse_sample_window(&output, window, &suite.name, index))
                    .transpose();
                let sample =
                    Sample {
                        run_id: id,
                        argv,
                        warmup: index == 0,
                        wall_s: output.wall,
                        child_cpu_s: output.cpu,
                        per_op_s: per_op.as_ref().ok().copied().flatten(),
                        guest_window_s: per_op.as_ref().ok().copied().flatten().and_then(|v| {
                            windows.get(&suite.name).map(|w| v * w.operations as f64)
                        }),
                        exit_code: output.code,
                        timed_out: output.timed_out,
                        cleanup_ok: cleanup.is_ok(),
                    };
                let ok = valid_sample(&sample);
                receipt
                    .workloads
                    .get_mut(&suite.name)
                    .ok_or("missing workload")?
                    .samples
                    .push(sample);
                save(&args.out, &receipt)?;
                per_op?;
                if !ok {
                    return Err(
                        format!("{} sample failed or cleanup incomplete", suite.name).into(),
                    );
                }
            }
            if image_digest(runner, &image)? != digest {
                return Err("image tag changed during measurement".into());
            }
            if let Some(artifact) = &receipt.artifact
                && provenance(runner, &artifact.path)? != *artifact
            {
                return Err("artifact changed during measurement".into());
            }
        }
        Ok(())
    })();
    if let Err(error) = &measurement {
        receipt.errors.push(error.to_string());
    }
    save(&args.out, &receipt)?;
    measurement
}
fn execute_workload(
    runner: &mut impl Runner,
    suite: &Suite,
    phase: &str,
    argv: &[String],
    id: &str,
) -> Result<Output> {
    let env = if phase == "carrick" {
        suite
            .registry_host()
            .map(|host| vec![("CARRICK_INSECURE_REGISTRIES".into(), host.into())])
            .unwrap_or_default()
    } else {
        vec![]
    };
    runner.execute(argv, Some(id), suite.timeout_s, &env)
}
fn valid_sample(s: &Sample) -> bool {
    s.exit_code == Some(0)
        && !s.timed_out
        && s.cleanup_ok
        && s.wall_s.is_finite()
        && s.wall_s > 0.0
        && s.child_cpu_s.is_some_and(|v| v.is_finite() && v >= 0.0)
}
fn stats(r: &Receipt, w: &WorkloadReceipt) -> Option<(f64, f64, f64)> {
    if r.schema != 1
        || !r.errors.is_empty()
        || r.measured_runs == 0
        || w.samples.len() != r.measured_runs + 1
        || !w.samples.first()?.warmup
        || w.samples.iter().skip(1).any(|s| s.warmup)
        || !w.samples.iter().all(valid_sample)
        || (w.window.is_some()
            && w.samples
                .iter()
                .any(|s| !s.per_op_s.is_some_and(|v| v.is_finite() && v > 0.0)))
    {
        return None;
    }
    let mut values = w
        .samples
        .iter()
        .filter(|s| !s.warmup)
        .map(|s| s.wall_s)
        .collect::<Vec<_>>();
    values.sort_by(f64::total_cmp);
    let n = values.len();
    let median = if n % 2 == 0 {
        (values[n / 2 - 1] + values[n / 2]) / 2.0
    } else {
        values[n / 2]
    };
    Some((median, values[0], values[n - 1]))
}
fn digest_valid(d: &str) -> bool {
    d.strip_prefix("sha256:")
        .is_some_and(|v| v.len() == 64 && v.bytes().all(|b| b.is_ascii_hexdigit()))
}
/// Never returns a performance-dependent exit status; invalid evidence has no ratios.
pub fn report(base: &Receipt, candidate: &Receipt, docker: &Receipt) -> String {
    let mut text = String::from(
        "# Landing impact\n\nMedian wall seconds [min–max]; one excluded warm-up. Fixed samples, no retries. Child CPU is host child-process CPU (Docker client CPU, not container CPU). Performance is report-only. A controlled single-variable campaign on a quiet host is required for claims; this report does not prove host quietness.\n\n| workload | base | candidate | Docker | base/Docker | candidate/Docker | per-op seconds base / candidate / Docker | per-op ratios base / candidate | 2x objective |\n|---|---|---|---|---|---|---|---|---|\n",
    );
    let mut warnings = String::new();
    for name in [
        "true",
        "node-startup",
        "node-core-worker-message-port",
        "spawn-loop",
        "thread-spawn",
        "fork-exec",
    ] {
        let row = (|| {
            if base.phase != "carrick"
                || candidate.phase != "carrick"
                || docker.phase != "docker"
                || base.artifact.is_none()
                || candidate.artifact.is_none()
                || base.warmup_policy != candidate.warmup_policy
                || candidate.warmup_policy != docker.warmup_policy
            {
                return None;
            }
            let b = base.workloads.get(name)?;
            let c = candidate.workloads.get(name)?;
            let d = docker.workloads.get(name)?;
            if (matches!(name, "spawn-loop" | "thread-spawn" | "fork-exec") && c.window.is_none())
                || !digest_valid(&b.image_digest)
                || b.image_digest != c.image_digest
                || c.image_digest != d.image_digest
                || b.image != c.image
                || c.image != d.image
                || b.declaration_sha256.is_empty()
                || b.declaration_sha256 != c.declaration_sha256
                || c.declaration_sha256 != d.declaration_sha256
                || b.window != c.window
                || c.window != d.window
                || b.command != c.command
                || c.command != d.command
            {
                return None;
            }
            let wall_stats = (stats(base, b)?, stats(candidate, c)?, stats(docker, d)?);
            let per_op = if c.window.is_some() {
                let median = |w: &WorkloadReceipt| {
                    let mut values = w
                        .samples
                        .iter()
                        .skip(1)
                        .filter_map(|s| s.per_op_s)
                        .collect::<Vec<_>>();
                    values.sort_by(f64::total_cmp);
                    let n = values.len();
                    (values[(n - 1) / 2] + values[n / 2]) / 2.0
                };
                Some((median(b), median(c), median(d)))
            } else {
                None
            };
            Some((wall_stats.0, wall_stats.1, wall_stats.2, per_op))
        })();
        if let Some((b, c, d, per_op)) = row {
            let (objective, costs) = if let Some((pb, pc, pd)) = per_op {
                (
                    pc / pd,
                    format!(
                        "{pb:.9} / {pc:.9} / {pd:.9} | {:.3}x / {:.3}x",
                        pb / pd,
                        pc / pd
                    ),
                )
            } else {
                (c.0 / d.0, "— | —".into())
            };
            text.push_str(&format!("| {name} | {:.6} [{:.6}–{:.6}] | {:.6} [{:.6}–{:.6}] | {:.6} [{:.6}–{:.6}] | {:.3}x | {:.3}x | {costs} | {} |\n", b.0,b.1,b.2,c.0,c.1,c.2,d.0,d.1,d.2,b.0/d.0,c.0/d.0,if objective <= 2.0 { "met" } else { "over" }));
            if c.0 > b.0 * 1.15 {
                warnings.push_str(&format!(
                    "\nWARNING: {name} candidate median is more than 15% slower than base.\n\n"
                ));
            }
        } else {
            text.push_str(&format!("| {name} | INCOMPLETE: missing, failed, stale or mismatched evidence | — | — | — | — | — | — | INCOMPLETE |\n"));
        }
    }
    text.push_str(&warnings);
    for (label, r) in [("base", base), ("candidate", candidate), ("Docker", docker)] {
        text.push_str(&format!(
            "\n{label}: HEAD `{}`, run `{}`, samples {}.\n",
            r.head, r.run_id, r.measured_runs
        ));
        for error in &r.errors {
            text.push_str(&format!("INCOMPLETE: {error}\n"));
        }
    }
    text
}
pub fn run(root: Option<&Path>, action: Action) -> Result<()> {
    let root = crate::cli::resolve_repo_info(root)?.repository_root;
    let mut runner = SystemRunner {
        root: root.clone(),
        sequence: 0,
    };
    match action {
        Action::Carrick {
            artifact,
            measurement,
        } => {
            let _lease =
                crate::host_lease::HostLease::acquire(crate::host_lease::HostLeaseMode::Carrick)?;
            measure(&root, &mut runner, "carrick", Some(&artifact), &measurement)
        }
        Action::Docker { measurement } => {
            let _lease =
                crate::host_lease::HostLease::acquire(crate::host_lease::HostLeaseMode::Docker)?;
            measure(&root, &mut runner, "docker", None, &measurement)
        }
        Action::Report {
            base,
            candidate,
            docker,
            out,
        } => {
            let mut receipts = Vec::new();
            let mut errors = Vec::new();
            for (label, path) in [("base", base), ("candidate", candidate), ("Docker", docker)] {
                let read = || -> Result<Receipt> { Ok(serde_json::from_slice(&fs::read(&path)?)?) };
                match read() {
                    Ok(receipt) => receipts.push(receipt),
                    Err(error) => errors.push(format!(
                        "INCOMPLETE: {label} receipt {}: {error}",
                        path.display()
                    )),
                }
            }
            let text = if errors.is_empty() {
                report(&receipts[0], &receipts[1], &receipts[2])
            } else {
                format!("# Landing impact\n\n{}\n", errors.join("\n"))
            };
            fs::write(out, text)?;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    struct Fake {
        outputs: VecDeque<Output>,
        commands: Vec<Vec<String>>,
        envs: Vec<Vec<(String, String)>>,
    }
    impl Runner for Fake {
        fn execute(
            &mut self,
            args: &[String],
            _: Option<&str>,
            _: u64,
            env: &[(String, String)],
        ) -> Result<Output> {
            self.commands.push(args.to_vec());
            self.envs.push(env.to_vec());
            self.outputs
                .pop_front()
                .ok_or_else(|| "unexpected command".into())
        }
    }
    fn fake(outputs: Vec<Output>) -> Fake {
        Fake {
            outputs: outputs.into(),
            commands: vec![],
            envs: vec![],
        }
    }
    fn fixture(phase: &str, wall: f64) -> Receipt {
        let sample = Sample {
            run_id: "test".into(),
            argv: vec![],
            warmup: false,
            wall_s: wall,
            child_cpu_s: Some(0.1),
            per_op_s: None,
            guest_window_s: None,
            exit_code: Some(0),
            timed_out: false,
            cleanup_ok: true,
        };
        let mut warmup = sample.clone();
        warmup.warmup = true;
        let workload = WorkloadReceipt {
            image: "image:tag".into(),
            image_digest: format!("sha256:{}", "a".repeat(64)),
            command: vec!["cmd".into()],
            declaration_sha256: "declaration".into(),
            window: None,
            samples: vec![warmup, sample],
        };
        Receipt {
            schema: 1,
            phase: phase.into(),
            head: "head".into(),
            run_id: "test".into(),
            measured_runs: 1,
            warmup_policy: "one excluded".into(),
            artifact: (phase == "carrick").then(|| Artifact {
                path: "bin".into(),
                sha256: "hash".into(),
                cdhash: "hash".into(),
                lc_uuid: "uuid".into(),
                entitlement: "hypervisor".into(),
                dof_present: true,
            }),
            errors: vec![],
            workloads: ["true", "node-startup", "node-core-worker-message-port"]
                .into_iter()
                .map(|n| (n.into(), workload.clone()))
                .collect(),
        }
    }
    #[test]
    fn digest_launch_sets_registry_environment() -> Result<()> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let mut suite = workloads(&root)?[1].clone();
        suite.image = pinned(&suite.image, &format!("sha256:{}", "a".repeat(64)));
        let mut runner = fake(vec![
            Output::default(),
            Output::default(),
            Output::default(),
        ]);
        let argv = argv::carrick_argv(&suite, "artifact", "id");
        execute_workload(&mut runner, &suite, "carrick", &argv, "id")?;
        assert_eq!(
            runner.envs[0],
            vec![(
                "CARRICK_INSECURE_REGISTRIES".into(),
                "localhost:5005".into()
            )]
        );
        execute_workload(&mut runner, &suite, "docker", &argv, "id")?;
        assert!(runner.envs[1].is_empty());
        suite.image = "ubuntu:24.04".into();
        execute_workload(&mut runner, &suite, "carrick", &argv, "id")?;
        assert!(runner.envs[2].is_empty());
        Ok(())
    }
    #[test]
    fn fake_creation_launches_parse_declared_windows() -> Result<()> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let windows = windows(&root)?;
        for suite in workloads(&root)?
            .iter()
            .filter(|s| windows.contains_key(&s.name))
        {
            let window = &windows[&suite.name];
            let mut runner = fake(vec![Output {
                code: Some(0),
                stdout: format!("{}1000000000\n", window.prefix),
                wall: 9.0,
                cpu: Some(0.1),
                ..Output::default()
            }]);
            let argv = argv::carrick_argv(suite, "artifact", "unique-id");
            let output = execute_workload(&mut runner, suite, "carrick", &argv, "unique-id")?;
            assert_eq!(
                parse_window(&output.stdout, window)?,
                1.0 / window.operations as f64
            );
            assert_eq!(runner.commands[0], argv);
            assert_eq!(output.wall, 9.0);
        }
        Ok(())
    }
    #[test]
    fn window_diagnostics_preserve_sample_and_both_streams() {
        let window = Window {
            operations: 1000,
            prefix: "impact_window_ns=".into(),
        };
        for (stdout, stderr, count) in [
            ("guest output", "impact_window_ns=1", 0),
            ("impact_window_ns=1\nimpact_window_ns=2", "failure", 2),
            ("impact_window_ns=NaN", "failure", 1),
            ("impact_window_ns=0", "failure", 1),
        ] {
            let output = Output {
                stdout: stdout.into(),
                stderr: stderr.into(),
                code: Some(127),
                ..Output::default()
            };
            let error = parse_sample_window(&output, &window, "spawn-loop", 0)
                .expect_err("invalid window must fail closed")
                .to_string();
            assert!(error.contains("spawn-loop sample 0 (warmup=true)"));
            assert!(error.contains(&format!("stdout={count}")));
            assert!(error.contains("exit_code=Some(127)"));
            assert!(error.contains(&format!("stdout tail:\n{stdout}")));
            assert!(error.contains(&format!("stderr tail:\n{stderr}")));
            assert!(error.contains(if count == 0 { "stderr=1" } else { "stderr=0" }));
            assert!(
                parse_sample_window(&output, &window, "spawn-loop", 2)
                    .expect_err("measured sample must fail closed")
                    .to_string()
                    .contains("sample 2 (warmup=false)")
            );
        }
        assert_eq!(output_tail(&"x".repeat(5000)).len(), 4096);
        assert!(
            !output_tail(&format!("excluded\n{}", "included\n".repeat(20))).contains("excluded")
        );
    }
    #[test]
    fn guest_windows_fail_closed_and_drive_objective() -> Result<()> {
        let window = Window {
            operations: 1000,
            prefix: "impact_window_ns=".into(),
        };
        assert_eq!(
            parse_window("noise\nimpact_window_ns=2000000000\n", &window)?,
            0.002
        );
        for output in [
            "",
            "impact_window_ns=0",
            "impact_window_ns=-1",
            "impact_window_ns=NaN",
            "impact_window_ns=1\nimpact_window_ns=2",
        ] {
            assert!(parse_window(output, &window).is_err());
        }
        let mut base = fixture("carrick", 1.0);
        let mut candidate = fixture("carrick", 1.0);
        let mut docker = fixture("docker", 1.0);
        for (r, cost) in [
            (&mut base, 0.001),
            (&mut candidate, 0.003),
            (&mut docker, 0.001),
        ] {
            let mut w = r.workloads["true"].clone();
            w.window = Some(window.clone());
            for s in &mut w.samples {
                s.per_op_s = Some(cost);
            }
            r.workloads.insert("spawn-loop".into(), w);
        }
        let text = report(&base, &candidate, &docker);
        assert!(text.lines().any(|line| line.starts_with("| spawn-loop")
            && line.contains("3.000x")
            && line.contains("over")));
        candidate
            .workloads
            .get_mut("spawn-loop")
            .expect("fixture")
            .samples[1]
            .per_op_s = None;
        assert!(
            report(&base, &candidate, &docker)
                .lines()
                .any(|line| line.starts_with("| spawn-loop") && line.contains("INCOMPLETE"))
        );
        Ok(())
    }
    #[test]
    fn harness_argv_parity() -> Result<()> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let workloads = workloads(&root)?;
        for suite in workloads
            .iter()
            .filter(|s| matches!(s.name.as_str(), "node-startup" | "thread-spawn"))
        {
            assert_eq!(suite.cmd[0], "/opt/nodejs-conformance/bin/node24");
            assert_eq!(suite.cmd[1], "-e");
            assert_eq!(
                suite.entrypoint.as_ref().and_then(|e| e.for_carrick()),
                Some(String::new())
            );
            assert_eq!(
                suite.entrypoint.as_ref().and_then(|e| e.for_docker()),
                Some(String::new())
            );
        }
        let manifest = Manifest::from_toml(&fs::read_to_string(
            root.join("scripts/perf/manifests/el1-real-workloads-v1.toml"),
        )?)?;
        let suite = &manifest.suite[0];
        let worker = &workloads[2];
        let mut runner = fake(vec![Output {
            code: Some(0),
            ..Output::default()
        }]);
        let planned = argv::carrick_argv(worker, "artifact", "id");
        runner.execute(&planned, Some("id"), 300, &[])?;
        assert_eq!(
            runner.commands[0],
            argv::carrick_argv(suite, "artifact", "id")
        );
        assert_eq!(
            argv::docker_argv(worker, "id", argv::DockerPlatform::LinuxArm64),
            argv::docker_argv(suite, "id", argv::DockerPlatform::LinuxArm64)
        );
        assert!(
            argv::carrick_argv(&workloads[0], "artifact", "id")
                .ends_with(&strings(&["ubuntu:24.04", "/bin/true"]))
        );
        Ok(())
    }
    #[test]
    fn refuses_other_phase_and_census_errors() {
        let mut runner = fake(vec![Output {
            code: Some(0),
            ..Output::default()
        }]);
        assert!(guard(&mut runner, "docker", &[]).is_err());
        let mut runner = fake(vec![
            Output {
                code: Some(0),
                ..Output::default()
            },
            Output {
                code: Some(0),
                stdout: "[{\"Id\":\"live\"}]".into(),
                ..Output::default()
            },
        ]);
        assert!(guard(&mut runner, "carrick", &["image".into()]).is_err());
        let mut runner = fake(vec![Output {
            code: Some(2),
            ..Output::default()
        }]);
        assert!(guard(&mut runner, "carrick", &[]).is_err());
    }
    #[test]
    fn selecting_true_cannot_bypass_a_node_docker_phase() -> Result<()> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let mut runner = fake(vec![
            Output {
                code: Some(0),
                ..Output::default()
            },
            Output {
                code: Some(0),
                stdout: serde_json::json!([{"Image": workloads(&root)?[2].image}]).to_string(),
                ..Output::default()
            },
        ]);
        let output = tempfile::tempdir()?;
        let args = Measurement {
            out: output.path().join("receipt.json"),
            samples: 1,
            workload: vec!["true".into()],
            operations: None,
        };
        let error = measure(&root, &mut runner, "carrick", None, &args).expect_err("must refuse");
        assert!(
            error
                .to_string()
                .contains("Docker workload container alive")
        );
        assert!(!args.out.exists());
        Ok(())
    }
    #[test]
    fn rejects_emulated_docker_and_normalizes_image_aliases() -> Result<()> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let mut runner = fake(vec![
            Output {
                code: Some(1),
                ..Output::default()
            },
            Output {
                code: Some(0),
                stdout: "linux/x86_64\n".into(),
                ..Output::default()
            },
        ]);
        let output = tempfile::tempdir()?;
        let args = Measurement {
            out: output.path().join("receipt.json"),
            samples: 1,
            workload: vec!["true".into()],
            operations: None,
        };
        let error = measure(&root, &mut runner, "docker", None, &args)
            .expect_err("emulated ARM64 must be refused");
        assert!(error.to_string().contains("native Linux arm64"));
        assert_eq!(
            docker_repository("ubuntu:24.04"),
            docker_repository("docker.io/library/ubuntu:24.04")
        );
        assert_eq!(
            docker_repository("registry-1.docker.io/library/ubuntu@sha256:abc"),
            docker_repository("ubuntu")
        );
        Ok(())
    }
    #[test]
    fn incomplete_never_has_ratios() {
        let mut base = fixture("carrick", 1.0);
        let candidate = fixture("carrick", 2.0);
        let docker = fixture("docker", 1.0);
        for workload in base.workloads.values_mut() {
            workload.samples.pop();
        }
        let text = report(&base, &candidate, &docker);
        assert!(text.contains("INCOMPLETE"));
        assert!(!text.contains("2.000x"));
        let mut base = fixture("carrick", 1.0);
        base.errors.push("tag changed".into());
        assert!(!report(&base, &candidate, &docker).contains("2.000x"));
    }
    #[test]
    fn strict_warning_threshold_and_objective() {
        let base = fixture("carrick", 1.0);
        let docker = fixture("docker", 0.5);
        assert!(!report(&base, &fixture("carrick", 1.15), &docker).contains("WARNING:"));
        let text = report(&base, &fixture("carrick", 1.1501), &docker);
        assert!(text.contains("WARNING:"));
        assert!(text.contains("over"));
    }
    #[test]
    fn receipt_round_trip() -> Result<()> {
        let receipt = fixture("carrick", 1.0);
        assert_eq!(
            receipt,
            serde_json::from_str::<Receipt>(&serde_json::to_string(&receipt)?)?
        );
        Ok(())
    }
    #[test]
    fn rejects_stale_mismatched_and_missing_digests() {
        let base = fixture("carrick", 1.0);
        let candidate = fixture("carrick", 1.0);
        let mut docker = fixture("docker", 0.5);
        for w in docker.workloads.values_mut() {
            w.image_digest = format!("sha256:{}", "b".repeat(64));
        }
        assert!(!report(&base, &candidate, &docker).contains("2.000x"));
        for w in docker.workloads.values_mut() {
            w.image_digest.clear();
        }
        assert!(report(&base, &candidate, &docker).contains("INCOMPLETE"));
    }
    #[test]
    fn immutable_digest_verification_rejects_stale_registry_bytes() {
        let manifest = serde_json::json!({"manifests":[{"platform":{"architecture":"arm64","os":"linux"},"digest":format!("sha256:{}","a".repeat(64))}]});
        let mut runner = fake(vec![
            Output {
                code: Some(0),
                stdout: manifest.to_string(),
                ..Output::default()
            },
            Output {
                code: Some(0),
                stdout: "{}".into(),
                ..Output::default()
            },
        ]);
        assert!(image_digest(&mut runner, "localhost:5005/test:tag").is_err());
    }
    #[test]
    fn median_even_and_odd() {
        let mut receipt = fixture("docker", 4.0);
        receipt.measured_runs = 2;
        let w = receipt.workloads.get_mut("true").expect("fixture");
        let mut sample = w.samples[1].clone();
        sample.wall_s = 2.0;
        w.samples.push(sample.clone());
        assert_eq!(
            stats(&receipt, &receipt.workloads["true"]),
            Some((3.0, 2.0, 4.0))
        );
        receipt.measured_runs = 3;
        sample.wall_s = 9.0;
        receipt
            .workloads
            .get_mut("true")
            .expect("fixture")
            .samples
            .push(sample);
        assert_eq!(
            stats(&receipt, &receipt.workloads["true"]),
            Some((4.0, 2.0, 9.0))
        );
    }
}
