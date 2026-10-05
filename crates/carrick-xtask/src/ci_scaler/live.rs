//! Local-only PVE transport and foreground lifecycle; secrets have no Debug impl.
use super::*;
use serde_json::{Value, json};
use std::net::Ipv4Addr;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;

#[derive(Deserialize)]
struct Token {
    #[serde(rename = "full-tokenid")]
    id: String,
    #[serde(rename = "value")]
    secret: String,
}
#[derive(Copy, Clone, PartialEq, Eq)]
struct GuestExit(i32);
struct GuestOutput {
    exit: GuestExit,
    stdout: String,
}
#[derive(Deserialize)]
struct CloudStatus {
    status: String,
    errors: Vec<String>,
    recoverable_errors: std::collections::BTreeMap<String, Vec<String>>,
}
struct GuestScript {
    path: &'static str,
    source: &'static str,
}
const GUEST_SCRIPTS: [GuestScript; 2] = [
    GuestScript {
        path: "/usr/local/bin/carrick-ci-run-once",
        source: include_str!("../../../../scripts/ci/runner-once.sh"),
    },
    GuestScript {
        path: "/usr/local/bin/carrick-ci-admit-job.sh",
        source: include_str!("../../../../scripts/ci/admit-job.sh"),
    },
];
fn script_install_command(path: &str, source: &str) -> String {
    format!(
        "umask 077; printf '%s' {} > {} && chmod 755 {}",
        crate::remote_accept::shell_quote(source),
        crate::remote_accept::shell_quote(path),
        crate::remote_accept::shell_quote(path)
    )
}
fn cloud_init_complete(output: &GuestOutput) -> Result<bool, ScalerError> {
    let status: CloudStatus = serde_json::from_str(&output.stdout)?;
    const PVE_USER_DEPRECATION: &str = "'user' of type string is deprecated in 22.2 and scheduled to be removed in 27.2. Use 'users' list instead.";
    Ok(matches!(output.exit, GuestExit(0 | 2))
        && (output.exit == GuestExit(0)
            || status
                .recoverable_errors
                .values()
                .any(|warnings| !warnings.is_empty()))
        && status.status == "done"
        && status.errors.is_empty()
        && status
            .recoverable_errors
            .iter()
            .all(|(category, warnings)| {
                category == "DEPRECATED"
                    && warnings
                        .iter()
                        .all(|warning| warning == PVE_USER_DEPRECATION)
            }))
}
enum PveCall {
    Get,
    Post(Value),
    Put(Value),
    Delete,
}
impl PveCall {
    fn method(&self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post(_) => "POST",
            Self::Put(_) => "PUT",
            Self::Delete => "DELETE",
        }
    }
    fn body(&self) -> Option<Value> {
        match self {
            Self::Post(body) | Self::Put(body) => Some(body.clone()),
            Self::Get | Self::Delete => None,
        }
    }
}
fn request_config(token: &Token, call: &PveCall) -> Result<String, ScalerError> {
    let header = format!("Authorization: PVEAPIToken={}={}", token.id, token.secret);
    let mut config = format!("header = {}\n", serde_json::to_string(&header)?);
    if let Some(data) = call.body() {
        config.push_str("header = \"Content-Type: application/json\"\n");
        config.push_str(&format!(
            "data = {}\n",
            serde_json::to_string(&data.to_string())?
        ));
    }
    Ok(config)
}
fn clone_config(public_key: &str) -> Value {
    let mut encoded = String::new();
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for byte in public_key.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 15)]));
        }
    }
    json!({
        "ciuser":"runner", "sshkeys":encoded,
        "ipconfig0":"ip=dhcp", "tags":"carrick-ci;willow-pilot",
        "cores":2,"memory":4096,"balloon":0,"cpulimit":2,"cpu":"host"
    })
}
fn pve_response(bytes: &[u8]) -> Result<Value, ScalerError> {
    let end = bytes
        .iter()
        .rposition(|byte| *byte == b'\n')
        .ok_or(ScalerError::External("PVE response lacks HTTP status"))?;
    let code = &bytes[end + 1..];
    if code.len() != 3 || !code.iter().all(u8::is_ascii_digit) {
        return Err(ScalerError::External("invalid PVE HTTP status"));
    }
    let response: Value = serde_json::from_slice(&bytes[..end])?;
    if code[0] != b'2' {
        let fields = response
            .get("errors")
            .and_then(Value::as_object)
            .map(|errors| {
                errors
                    .keys()
                    .filter(|name| {
                        name.len() <= 64
                            && name
                                .bytes()
                                .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
                    })
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_default();
        return Err(ScalerError::PveRejected(format!(
            "HTTP {}; fields: {fields}",
            String::from_utf8_lossy(code)
        )));
    }
    response
        .get("data")
        .cloned()
        .ok_or(ScalerError::External("PVE response lacks data"))
}
struct Pve {
    token: Token,
    deadline: std::cell::Cell<Option<Instant>>,
}
impl Pve {
    fn local() -> Result<Self, ScalerError> {
        if std::fs::read_to_string("/etc/hostname")?.trim() != "willow" {
            return Err(ScalerError::Guard("controller must run on Willow"));
        }
        let path = Path::new("/root/carrick-ci-token.json");
        let meta = std::fs::symlink_metadata(path)?;
        if !meta.is_file() || meta.uid() != 0 || meta.mode() & 0o077 != 0 {
            return Err(ScalerError::Guard("token must be a root-only regular file"));
        }
        let token: Token = serde_json::from_slice(&std::fs::read(path)?)?;
        if token.id != "ci-scaler@pve!elastic"
            || !token
                .secret
                .bytes()
                .all(|b| b.is_ascii_hexdigit() || b == b'-')
        {
            return Err(ScalerError::Guard(
                "unexpected scoped token identity/encoding",
            ));
        }
        Ok(Self {
            token,
            deadline: std::cell::Cell::new(None),
        })
    }
    fn request(&self, call: PveCall, path: &str) -> Result<Value, ScalerError> {
        let limit = remaining(self.deadline.get(), Duration::from_secs(45))?;
        let config = request_config(&self.token, &call)?;
        let bytes = execute(
            Command::new("curl").args([
                "--silent",
                "--show-error",
                "--write-out",
                "\n%{http_code}",
                "--max-time",
                "40",
                "--resolve",
                "willow.atxconsulting.com:8006:127.0.0.1",
                "--config",
                "-",
                "--request",
                call.method(),
                &format!("https://willow.atxconsulting.com:8006/api2/json{path}"),
            ]),
            config.as_bytes(),
            limit,
        )?;
        pve_response(&bytes)
    }
    fn inventory(&self) -> Result<Vec<PoolMember>, ScalerError> {
        let pool = self.request(PveCall::Get, "/pools/carrick-ci")?;
        pool_inventory(&pool)
    }
    fn guard(&self, row: &Record) -> Result<Vm, ScalerError> {
        let inventory = self.inventory()?;
        let vm = inventory
            .into_iter()
            .find(|v| v.id == row.vm.get())
            .ok_or(ScalerError::Guard("ledger VM is absent"))?;
        let config = self.request(PveCall::Get, &format!("{}/config", base(row.vm)))?;
        authenticate_config(row, vm, &config)
    }
}
fn pool_inventory(pool: &Value) -> Result<Vec<PoolMember>, ScalerError> {
    if pool["poolid"] != POOL {
        return Err(ScalerError::Guard("PVE returned another pool"));
    }
    let members = pool["members"]
        .as_array()
        .ok_or(ScalerError::External("pool members"))?;
    let mut result = Vec::new();
    for member in members {
        if member["type"] == "qemu" {
            if member["node"] != "willow" {
                return Err(ScalerError::Guard("unexpected pool node"));
            }
            let id = member["vmid"]
                .as_u64()
                .and_then(|n| u16::try_from(n).ok())
                .ok_or(ScalerError::External("VMID"))?;
            result.push(PoolMember {
                id,
                pool: POOL.into(),
                template: member["template"].as_u64() == Some(1),
            });
        } else if member["type"] == "lxc" {
            return Err(ScalerError::Guard(
                "unknown container occupies pool; owner inspection needed",
            ));
        }
    }
    Ok(result)
}
impl Pve {
    fn task_done(&self, task: &str) -> Result<bool, ScalerError> {
        match self.task_state(task)? {
            TaskState::Succeeded => Ok(true),
            TaskState::Failed => Err(ScalerError::External("PVE task failed")),
            _ => Ok(false),
        }
    }
    fn task_state(&self, task: &str) -> Result<TaskState, ScalerError> {
        if !task.starts_with("UPID:willow:") || task.contains('/') {
            return Err(ScalerError::Guard("task belongs to another node"));
        }
        let result = self.request(PveCall::Get, &format!("/nodes/willow/tasks/{task}/status"))?;
        if result["status"] == "stopped" {
            if result["exitstatus"] != "OK" {
                return Ok(TaskState::Failed);
            }
            Ok(TaskState::Succeeded)
        } else {
            Ok(TaskState::Running)
        }
    }
    fn wait_task(&self, task: &str) -> Result<(), ScalerError> {
        let deadline = self
            .deadline
            .get()
            .unwrap_or_else(|| Instant::now() + Duration::from_secs(300));
        while Instant::now() < deadline {
            if self.task_done(task)? {
                return Ok(());
            }
            std::thread::sleep(Duration::from_secs(2));
        }
        Err(ScalerError::External("PVE task five-minute deadline"))
    }
    fn agent(&self, row: &Record, command: &[&str]) -> Result<String, ScalerError> {
        let output = self.agent_output(row, command)?;
        if output.exit != GuestExit(0) {
            return Err(ScalerError::External("guest qualification"));
        }
        Ok(output.stdout)
    }
    fn agent_output(&self, row: &Record, command: &[&str]) -> Result<GuestOutput, ScalerError> {
        self.guard(row)?;
        let response = self.request(
            PveCall::Post(json!({"command":command})),
            &format!("{}/agent/exec", base(row.vm)),
        )?;
        let pid = response["pid"]
            .as_u64()
            .ok_or(ScalerError::External("guest-agent pid"))?;
        let deadline = Instant::now() + Duration::from_secs(25);
        while Instant::now() < deadline {
            let status = self.request(
                PveCall::Get,
                &format!("{}/agent/exec-status?pid={pid}", base(row.vm)),
            )?;
            if status["exited"].as_bool() == Some(true) || status["exited"].as_u64() == Some(1) {
                let exit = status["exitcode"]
                    .as_i64()
                    .and_then(|value| i32::try_from(value).ok())
                    .ok_or(ScalerError::External("guest-agent exit status"))?;
                return Ok(GuestOutput {
                    exit: GuestExit(exit),
                    stdout: status["out-data"].as_str().unwrap_or_default().to_owned(),
                });
            }
            std::thread::sleep(Duration::from_secs(1));
        }
        Err(ScalerError::External("guest-agent exec deadline"))
    }
    fn guest_ip(&self, row: &Record) -> Result<Ipv4Addr, ScalerError> {
        self.guard(row)?;
        let data = self.request(
            PveCall::Get,
            &format!("{}/agent/network-get-interfaces", base(row.vm)),
        )?;
        let interfaces = data["result"]
            .as_array()
            .ok_or(ScalerError::External("guest interfaces"))?;
        for interface in interfaces {
            if let Some(addresses) = interface["ip-addresses"].as_array() {
                for address in addresses {
                    if address["ip-address-type"] == "ipv4"
                        && let Some(ip) = address["ip-address"]
                            .as_str()
                            .and_then(|s| s.parse::<Ipv4Addr>().ok())
                        && ip.is_private()
                        && !ip.is_loopback()
                    {
                        return Ok(ip);
                    }
                }
            }
        }
        Err(ScalerError::External("no private guest IPv4 address"))
    }
}
fn base(id: CloneId) -> String {
    format!("/nodes/willow/qemu/{}", id.get())
}
fn authenticate_config(
    row: &Record,
    member: PoolMember,
    config: &Value,
) -> Result<Vm, ScalerError> {
    // Pool membership licenses the VMID; its resource display can lag a clone.
    // Authenticate mutable identity from the live per-VM configuration.
    let name = config["name"]
        .as_str()
        .ok_or(ScalerError::Guard("live VM configuration lacks a name"))?
        .to_owned();
    let template = match config.get("template") {
        None => false,
        Some(value) if value.as_u64() == Some(0) => false,
        Some(value) if value.as_u64() == Some(1) => true,
        _ => return Err(ScalerError::Guard("unrecognized template flag")),
    };
    let vm = Vm {
        id: member.id,
        pool: member.pool,
        name,
        template,
    };
    row.guard(&vm)?;
    Ok(vm)
}
fn remaining(deadline: Option<Instant>, cap: Duration) -> Result<Duration, ScalerError> {
    let remaining = deadline
        .map(|d| d.saturating_duration_since(Instant::now()))
        .unwrap_or(cap)
        .min(cap);
    if remaining.is_zero() {
        Err(ScalerError::External("shared readiness deadline"))
    } else {
        Ok(remaining)
    }
}
struct ApiDeadline<'a>(&'a std::cell::Cell<Option<Instant>>);
impl Drop for ApiDeadline<'_> {
    fn drop(&mut self) {
        self.0.set(None);
    }
}
fn string(value: &Value, field: &str) -> Result<String, ScalerError> {
    value[field]
        .as_str()
        .map(str::to_owned)
        .ok_or(ScalerError::External("missing string field"))
}
fn task_id(value: Value) -> Result<String, ScalerError> {
    value
        .as_str()
        .map(str::to_owned)
        .ok_or(ScalerError::External("missing PVE task ID"))
}

struct Github;
impl Github {
    fn request(
        &self,
        method: &str,
        endpoint: &str,
        body: Option<Value>,
        paginate: bool,
    ) -> Result<Value, ScalerError> {
        let mut cmd = Command::new("gh");
        cmd.args(["api", "--method", method, endpoint]);
        if paginate {
            cmd.args(["--paginate", "--slurp"]);
        }
        let input = if let Some(body) = body {
            cmd.args(["--input", "-"]);
            serde_json::to_vec(&body)?
        } else {
            vec![]
        };
        let output = execute(&mut cmd, &input, Duration::from_secs(60))?;
        if method == "DELETE" {
            return Ok(Value::Null);
        }
        Ok(serde_json::from_slice(&output)?)
    }
    fn runs(&self, status: &str) -> Result<Vec<Value>, ScalerError> {
        let data = self.request(
            "GET",
            &format!("repos/{REPOSITORY}/actions/runs?status={status}&per_page=100"),
            None,
            true,
        )?;
        pages(&data, "workflow_runs")
    }
    fn jobs(&self, run: &Value) -> Result<Vec<Value>, ScalerError> {
        let id = run["id"].as_u64().ok_or(ScalerError::External("run id"))?;
        let attempt = run["run_attempt"]
            .as_u64()
            .ok_or(ScalerError::External("run attempt"))?;
        let data = self.request(
            "GET",
            &format!("repos/{REPOSITORY}/actions/runs/{id}/attempts/{attempt}/jobs?per_page=100"),
            None,
            true,
        )?;
        pages(&data, "jobs")
    }
    fn demand(&self, sha: &str) -> Result<Vec<JobKey>, ScalerError> {
        let mut demand = Vec::new();
        for status in ["queued", "in_progress"] {
            for run in self.runs(status)? {
                if !approved_run(&run, sha) {
                    continue;
                }
                for job in self.jobs(&run)? {
                    let labels: Vec<&str> = job["labels"]
                        .as_array()
                        .ok_or(ScalerError::External("job labels"))?
                        .iter()
                        .filter_map(Value::as_str)
                        .collect();
                    if job["status"] == "queued" && eligible_labels(&labels) {
                        demand.push(JobKey {
                            run: RunId(run["id"].as_u64().ok_or(ScalerError::External("run id"))?),
                            attempt: run["run_attempt"]
                                .as_u64()
                                .and_then(|n| u32::try_from(n).ok())
                                .ok_or(ScalerError::External("attempt"))?,
                            job: JobId(job["id"].as_u64().ok_or(ScalerError::External("job id"))?),
                        });
                    }
                }
            }
        }
        demand.sort_by_key(|key| key.job.0);
        demand.dedup();
        Ok(demand)
    }
    fn job(&self, id: JobId) -> Result<Value, ScalerError> {
        self.request(
            "GET",
            &format!("repos/{REPOSITORY}/actions/jobs/{}", id.0),
            None,
            false,
        )
    }
    fn assignment(&self, row: &mut Record) -> Result<Assignment, ScalerError> {
        if row.runner.is_none() {
            let data = self.request(
                "GET",
                &format!("repos/{REPOSITORY}/actions/runners?per_page=100"),
                None,
                true,
            )?;
            row.runner = recover_registration(row, &pages(&data, "runners")?)?;
        }
        let Some(runner) = row.runner else {
            return Ok(Assignment::Unassigned);
        };
        // The reservation is demand, never a job binding. Prefer the recorded
        // actual assignment; inspect all active runs if GitHub assigned another.
        let job = self.job(row.assigned.unwrap_or(row.key.job))?;
        if job["runner_id"].as_u64() == Some(runner.0) {
            row.assigned = Some(JobId(
                job["id"]
                    .as_u64()
                    .ok_or(ScalerError::External("assigned id"))?,
            ));
            return Ok(if job["status"] == "completed" {
                Assignment::Completed
            } else {
                Assignment::Busy
            });
        }
        for status in ["in_progress", "completed"] {
            for run in self.runs(status)? {
                if let Some(assignment) = observed_assignment(row, &self.jobs(&run)?) {
                    return Ok(assignment);
                }
            }
        }
        let runners = self.request(
            "GET",
            &format!("repos/{REPOSITORY}/actions/runners?per_page=100"),
            None,
            true,
        )?;
        for registered in pages(&runners, "runners")? {
            if registered["id"].as_u64() == Some(runner.0) {
                return Ok(if registered["busy"] == true {
                    Assignment::Busy
                } else {
                    Assignment::Unassigned
                });
            }
        }
        // An absent ephemeral registration can mean a completed job missed by
        // polling. Never infer unassigned from absence and destroy live work.
        Ok(Assignment::Unknown)
    }
    fn remove_runner(&self, row: &Record) -> Result<(), ScalerError> {
        let Some(id) = row.runner else {
            return Ok(());
        };
        let runners = self.request(
            "GET",
            &format!("repos/{REPOSITORY}/actions/runners?per_page=100"),
            None,
            true,
        )?;
        if let Some(runner) = pages(&runners, "runners")?
            .into_iter()
            .find(|r| r["id"].as_u64() == Some(id.0))
        {
            if runner["name"] != row.name || runner["busy"] != false {
                return Err(ScalerError::Guard(
                    "runner identity changed or still busy; defer removal",
                ));
            }
            self.request(
                "DELETE",
                &format!("repos/{REPOSITORY}/actions/runners/{}", id.0),
                None,
                false,
            )?;
        }
        Ok(())
    }
}
fn approved_run(run: &Value, sha: &str) -> bool {
    run["event"] == "workflow_dispatch"
        && run["head_sha"] == sha
        && run["head_branch"] == "work/willow-pilot"
        && run["path"] == ".github/workflows/willow-pilot.yml"
        && run["repository"]["full_name"] == REPOSITORY
}

fn recover_registration(row: &Record, runners: &[Value]) -> Result<Option<RunnerId>, ScalerError> {
    let matches: Vec<&Value> = runners.iter().filter(|r| r["name"] == row.name).collect();
    match matches.as_slice() {
        [] => Ok(None),
        [runner] => Ok(Some(RunnerId(
            runner["id"]
                .as_u64()
                .ok_or(ScalerError::External("recovered runner ID"))?,
        ))),
        _ => Err(ScalerError::Guard(
            "duplicate registration identity; quarantine",
        )),
    }
}
fn observed_assignment(row: &mut Record, jobs: &[Value]) -> Option<Assignment> {
    let runner = row.runner?;
    let job = jobs
        .iter()
        .find(|job| job["runner_id"].as_u64() == Some(runner.0))?;
    row.assigned = Some(JobId(job["id"].as_u64()?));
    Some(if job["status"] == "completed" {
        Assignment::Completed
    } else {
        Assignment::Busy
    })
}

fn pages(data: &Value, field: &str) -> Result<Vec<Value>, ScalerError> {
    let mut result = Vec::new();
    for page in data
        .as_array()
        .ok_or(ScalerError::External("API pagination"))?
    {
        result.extend(
            page[field]
                .as_array()
                .ok_or(ScalerError::External("API page"))?
                .iter()
                .cloned(),
        );
    }
    Ok(result)
}

fn enforce_cpu_ceiling(busy: f64, threads: u32) -> Result<(), ScalerError> {
    if !busy.is_finite() || busy < 0.0 || threads == 0 {
        return Err(ScalerError::Guard("CPU sample unavailable"));
    }
    let projected = busy + 2.0 / f64::from(threads);
    if projected > 0.80 {
        Err(ScalerError::CpuCeiling {
            projected: projected * 100.0,
        })
    } else {
        Ok(())
    }
}
fn resource_admission() -> Result<bool, ScalerError> {
    fn cpu() -> Result<(u64, u64), ScalerError> {
        let stat = std::fs::read_to_string("/proc/stat")?;
        let fields: Vec<u64> = stat
            .lines()
            .next()
            .ok_or(ScalerError::Guard("CPU counters"))?
            .split_whitespace()
            .skip(1)
            .take(8)
            .map(str::parse)
            .collect::<Result<_, _>>()
            .map_err(|_| ScalerError::Guard("CPU counter encoding"))?;
        if fields.len() < 5 {
            return Err(ScalerError::Guard("CPU counter count"));
        }
        Ok((fields.iter().sum(), fields[3] + fields[4]))
    }
    let a = cpu()?;
    std::thread::sleep(Duration::from_secs(5));
    let b = cpu()?;
    let total = b.0.saturating_sub(a.0);
    if total == 0 {
        return Ok(false);
    }
    let utilization = 1.0 - b.1.saturating_sub(a.1) as f64 / total as f64;
    let threads = std::thread::available_parallelism()?.get();
    let load = std::fs::read_to_string("/proc/loadavg")?
        .split_whitespace()
        .next()
        .and_then(|v| v.parse::<f64>().ok())
        .ok_or(ScalerError::Guard("load average"))?
        / threads as f64;
    let memory = std::fs::read_to_string("/proc/meminfo")?;
    let available = memory
        .lines()
        .find(|s| s.starts_with("MemAvailable:"))
        .and_then(|s| s.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u64>().ok())
        .ok_or(ScalerError::Guard("memory available"))?
        * 1024;
    let busy = utilization.max(load);
    let limiting_source = if utilization >= load {
        "/proc/stat:5s-delta"
    } else {
        "/proc/loadavg:1m-per-cpu"
    };
    println!(
        "admission utilization={utilization:.3} utilization_source=/proc/stat:5s-delta load_per_cpu={load:.3} load_source=/proc/loadavg:1m-per-cpu online_cpus={threads} limiting_source={limiting_source} busy={busy:.3} projected={:.3} reserved_vcpus=2 memory_available={available}",
        busy + 2.0 / threads as f64
    );
    enforce_cpu_ceiling(busy, u32::try_from(threads).unwrap_or(0))?;
    // No LVM mutation. Stop admission before thin data/metadata headroom runs out.
    let output = execute(
        Command::new("lvs").args([
            "--reportformat",
            "json",
            "--units",
            "b",
            "--nosuffix",
            "-o",
            "lv_size,data_percent,metadata_percent",
            "pve/data",
        ]),
        &[],
        Duration::from_secs(10),
    )?;
    let data: Value = serde_json::from_slice(&output)?;
    let lv = &data["report"][0]["lv"][0];
    let number = |field| {
        lv[field]
            .as_str()
            .and_then(|s| s.trim().parse::<f64>().ok())
            .ok_or(ScalerError::Guard("thin-pool statistics unavailable"))
    };
    let free = number("lv_size")? * (1.0 - number("data_percent")? / 100.0);
    Ok(
        admit_resources(busy, u32::try_from(threads).unwrap_or(0), available)
            && free >= (150_u64 << 30) as f64
            && number("metadata_percent")? < 80.0,
    )
}

fn key_paths(dir: &Path, row: &Record) -> (PathBuf, PathBuf) {
    (
        dir.join(format!("{}.key", row.name)),
        dir.join(format!("{}.hosts", row.name)),
    )
}
fn ssh(
    dir: &Path,
    row: &Record,
    input: &[u8],
    command: &str,
    deadline: Option<Instant>,
) -> Result<Vec<u8>, ScalerError> {
    let (key, hosts) = key_paths(dir, row);
    let ip = row
        .ip
        .ok_or(ScalerError::Guard("guest has no qualified IP"))?;
    execute(
        Command::new("ssh").args([
            "-T",
            "-o",
            "BatchMode=yes",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "ForwardAgent=no",
            "-o",
            "ClearAllForwardings=yes",
            "-o",
            "SendEnv=-*",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "ConnectTimeout=10",
            "-o",
            "ServerAliveInterval=10",
            "-o",
            "ServerAliveCountMax=1",
            "-o",
            &format!("UserKnownHostsFile={}", hosts.display()),
            "-i",
            &key.to_string_lossy(),
            &format!("runner@{ip}"),
            command,
        ]),
        input,
        remaining(deadline, Duration::from_secs(45))?,
    )
}
fn update(ledger: &mut Ledger, row: &Record, path: &Path) -> Result<(), ScalerError> {
    let target = ledger
        .rows
        .iter_mut()
        .find(|r| r.name == row.name)
        .ok_or(ScalerError::Guard("missing ledger identity"))?;
    *target = row.clone();
    ledger.save(path)
}
fn finish_destroyed(
    ledger: &mut Ledger,
    row: &mut Record,
    dir: &Path,
    path: &Path,
) -> Result<(), ScalerError> {
    let (key, hosts) = key_paths(dir, row);
    for file in [key.clone(), key.with_extension("key.pub"), hosts] {
        if file.exists() {
            std::fs::remove_file(file)?;
        }
    }
    // Release the ledger budget only after the one-use transport is removed.
    row.state = State::Destroyed;
    update(ledger, row, path)?;
    println!(
        "vm={} absent; owned transport keys removed; ledger closed",
        row.vm.get()
    );
    Ok(())
}

fn provision(
    pve: &Pve,
    gh: &Github,
    ledger: &mut Ledger,
    row: &mut Record,
    dir: &Path,
    path: &Path,
    approval: (u64, &str),
) -> Result<(), ScalerError> {
    let (key, _) = key_paths(dir, row);
    execute(
        Command::new("ssh-keygen").args([
            "-q",
            "-t",
            "ed25519",
            "-N",
            "",
            "-f",
            &key.to_string_lossy(),
        ]),
        &[],
        Duration::from_secs(10),
    )?;
    row.state = State::Cloning;
    update(ledger, row, path)?; // Write-ahead, even if POST's outcome is ambiguous.
    row.task = Some(task_id(pve.request(
        PveCall::Post(json!({
            "newid":row.vm.get(), "pool":POOL, "name":row.name, "full":false,
            "description":format!("Carrick pilot ledger identity {}", row.name)
        })),
        "/nodes/willow/qemu/300/clone",
    )?)?);
    update(ledger, row, path)?;
    pve.wait_task(
        row.task
            .as_deref()
            .ok_or(ScalerError::Guard("clone task missing"))?,
    )?;
    boot_and_register(pve, gh, ledger, row, dir, path, approval)
}

fn boot_and_register(
    pve: &Pve,
    gh: &Github,
    ledger: &mut Ledger,
    row: &mut Record,
    dir: &Path,
    path: &Path,
    approval: (u64, &str),
) -> Result<(), ScalerError> {
    let (group, sha) = approval;
    let (key, hosts) = key_paths(dir, row);
    let key_meta = std::fs::symlink_metadata(&key)?;
    if !key_meta.is_file() || key_meta.uid() != 0 || key_meta.mode() & 0o077 != 0 {
        return Err(ScalerError::Guard(
            "owned clone lacks its root-only transport key",
        ));
    }
    pve.guard(row)?;
    let status = pve.request(PveCall::Get, &format!("{}/status/current", base(row.vm)))?;
    if status["status"] != "stopped" {
        return Err(ScalerError::Guard(
            "clone preparation requires a stopped owned VM",
        ));
    }
    pve.request(
        PveCall::Put(clone_config(&std::fs::read_to_string(
            key.with_extension("key.pub"),
        )?)),
        &format!("{}/config", base(row.vm)),
    )?;
    if !resource_admission()? {
        return Err(ScalerError::Guard("host admission denied before boot"));
    }
    pve.guard(row)?;
    let deadline = Instant::now() + Duration::from_secs(300);
    pve.deadline.set(Some(deadline));
    let shared_deadline = ApiDeadline(&pve.deadline);
    row.state = State::Booting;
    row.task = None;
    update(ledger, row, path)?;
    row.task = Some(task_id(pve.request(
        PveCall::Post(json!({})),
        &format!("{}/status/start", base(row.vm)),
    )?)?);
    update(ledger, row, path)?;
    pve.wait_task(
        row.task
            .as_deref()
            .ok_or(ScalerError::Guard("start task missing"))?,
    )?;
    let mut ready = false;
    while Instant::now() < deadline {
        let qualification = (|| {
            let cloud = pve.agent_output(
                row,
                &[
                    "/usr/bin/timeout",
                    "20",
                    "/usr/bin/cloud-init",
                    "status",
                    "--wait",
                    "--format=json",
                ],
            )?;
            if !cloud_init_complete(&cloud)? {
                return Err(ScalerError::Guard("cloud-init not completely qualified"));
            }
            // cloud-final orders after multi-user.target. Starting this service
            // explicitly after completed provisioning avoids the target cycle
            // and makes removal of cloud-init sudo authority mandatory for JIT.
            pve.agent(
                row,
                &["/usr/bin/systemctl", "start", "carrick-ci-ready.service"],
            )?;
            pve.agent(
                row,
                &[
                    "/usr/bin/systemctl",
                    "is-active",
                    "carrick-ci-ready.service",
                ],
            )?;
            pve.agent(
                row,
                &[
                    "/usr/sbin/runuser",
                    "-u",
                    "runner",
                    "--",
                    "/usr/local/bin/carrick-xtask",
                    "ci-scaler",
                    "verify-kvm",
                ],
            )
        })();
        if qualification.is_ok()
            && let Ok(ip) = pve.guest_ip(row)
        {
            row.ip = Some(ip);
            let key = pve.agent(row, &["/bin/cat", "/etc/ssh/ssh_host_ed25519_key.pub"])?;
            if !key.starts_with("ssh-ed25519 ") || key.lines().count() != 1 {
                return Err(ScalerError::Guard("invalid authenticated SSH host key"));
            }
            std::fs::write(&hosts, format!("{ip} {}\n", key.trim()))?;
            std::fs::set_permissions(&hosts, std::fs::Permissions::from_mode(0o600))?;
            if ssh(
                dir,
                row,
                &[],
                "test -x /usr/local/bin/carrick-ci-run-once",
                Some(deadline),
            )
            .is_ok()
            {
                ready = true;
                break;
            }
        }
        std::thread::sleep(remaining(Some(deadline), Duration::from_secs(5))?);
    }
    if !ready {
        return Err(ScalerError::External(
            "guest five-minute readiness deadline",
        ));
    }
    // Public launch payloads are bound to the exact controller artifact. A
    // cached template must not select a stale job-start guard or launch path.
    for script in &GUEST_SCRIPTS {
        pve.agent(
            row,
            &[
                "/bin/sh",
                "-c",
                &script_install_command(script.path, script.source),
            ],
        )?;
    }
    pve.agent(
        row,
        &["/bin/sh", "-c", "rm -f /usr/local/bin/carrick-ci-admit-job"],
    )?;
    pve.agent(row, &["/bin/sh", "-c", &format!("install -d -m 755 /etc/carrick-ci; printf '%s\\n' {sha} > /etc/carrick-ci/approved-sha; chmod 644 /etc/carrick-ci/approved-sha")])?;
    println!("vm={} ready; non-root KVM API 12 verified", row.vm.get());
    drop(shared_deadline);
    // Write registration intent before asking GitHub. No JIT material in ledger.
    row.state = State::Registered;
    update(ledger, row, path)?;
    let config = gh.request(
        "POST",
        &format!("repos/{REPOSITORY}/actions/runners/generate-jitconfig"),
        Some(
            json!({"name":row.name,"runner_group_id":group,"labels":LABELS,"work_folder":"_work"}),
        ),
        false,
    )?;
    row.runner = Some(RunnerId(
        config["runner"]["id"]
            .as_u64()
            .ok_or(ScalerError::External("JIT runner ID"))?,
    ));
    update(ledger, row, path)?;
    let jit = string(&config, "encoded_jit_config")?;
    let mut input = jit.into_bytes();
    input.push(b'\n');
    ssh(dir, row, &input, "/usr/local/bin/carrick-ci-run-once", None)?;
    row.state = State::Running;
    update(ledger, row, path)?;
    println!(
        "vm={} runner={} one-job JIT delivered",
        row.vm.get(),
        row.name
    );
    Ok(())
}

fn cleanup(
    pve: &Pve,
    gh: &Github,
    ledger: &mut Ledger,
    row: &mut Record,
    dir: &Path,
    path: &Path,
    assignment: Assignment,
) -> Result<bool, ScalerError> {
    pve.guard(row)?;
    if assignment == Assignment::Unassigned && row.runner.is_some() {
        // Atomically deny further job starts, using the same guest flock as
        // the admission hook. A passed hook leaves a durable busy marker.
        let quiet = pve.agent(
            row,
            &[
                "/usr/bin/timeout",
                "15",
                "/usr/local/bin/carrick-xtask",
                "ci-scaler",
                "quiesce",
            ],
        )?;
        if quiet.trim() != "Unassigned" {
            return Ok(false);
        }
        let latest = gh.assignment(row)?;
        update(ledger, row, path)?;
        if matches!(latest, Assignment::Busy | Assignment::Unknown) {
            return Ok(false);
        }
    }
    row.state = State::Reaping;
    update(ledger, row, path)?;
    gh.remove_runner(row)?;
    // Export guest logs via the authenticated agent: bootstrap consumed its SSH
    // authorization, and no credential is recovered by this path.
    if let Ok(log) = pve.agent(
        row,
        &["/bin/sh", "-c", "tail -c 1048576 /home/runner/runner.log"],
    ) {
        std::fs::write(dir.join(format!("{}.runner.log", row.name)), log)?;
    }
    pve.guard(row)?;
    let status = pve.request(PveCall::Get, &format!("{}/status/current", base(row.vm)))?;
    if status["status"] != "stopped" {
        row.task = Some(task_id(pve.request(
            PveCall::Post(json!({})),
            &format!("{}/status/stop", base(row.vm)),
        )?)?);
        update(ledger, row, path)?;
        pve.wait_task(
            row.task
                .as_deref()
                .ok_or(ScalerError::Guard("stop task missing"))?,
        )?;
    }
    pve.guard(row)?;
    row.task = Some(task_id(pve.request(PveCall::Delete, &base(row.vm))?)?);
    update(ledger, row, path)?;
    pve.wait_task(
        row.task
            .as_deref()
            .ok_or(ScalerError::Guard("destroy task missing"))?,
    )?;
    if pve.inventory()?.iter().any(|v| v.id == row.vm.get()) {
        return Err(ScalerError::Guard("clone still exists after deletion"));
    }
    finish_destroyed(ledger, row, dir, path)?;
    Ok(true)
}

fn reconcile_one(
    pve: &Pve,
    gh: &Github,
    ledger: &mut Ledger,
    dir: &Path,
    path: &Path,
    approval: (u64, &str),
) -> Result<bool, ScalerError> {
    let Some(mut row) = ledger
        .rows
        .iter()
        .find(|r| r.state != State::Destroyed)
        .cloned()
    else {
        return Ok(false);
    };
    let present = pve.inventory()?.iter().any(|v| v.id == row.vm.get());
    let task = match &row.task {
        Some(task) => pve.task_state(task)?,
        None => TaskState::Absent,
    };
    match recovery_decision(&row, present, task, now()?) {
        Recovery::Wait => return Ok(false),
        Recovery::Quarantine => {
            eprintln!(
                "vm={} ambiguous/missing state; admission frozen, owner inspection required",
                row.vm.get()
            );
            return Ok(false);
        }
        Recovery::FinishAbsent => {
            if task == TaskState::Failed {
                row.failure = Some("recorded PVE task failed; VM absent".into());
            }
            // Recover a registration whose POST succeeded before its ID save.
            let _ = gh.assignment(&mut row)?;
            gh.remove_runner(&row)?;
            finish_destroyed(ledger, &mut row, dir, path)?;
            return Ok(true);
        }
        Recovery::ResumeClone => {
            pve.guard(&row)?;
            let job = gh.job(row.key.job)?;
            let run = gh.request(
                "GET",
                &format!("repos/{REPOSITORY}/actions/runs/{}", row.key.run.0),
                None,
                false,
            )?;
            if pending_owned_job(&row, &job, &run, approval.1) {
                println!(
                    "vm={} resuming completed clone in place; error history retained",
                    row.vm.get()
                );
                if let Err(error) =
                    boot_and_register(pve, gh, ledger, &mut row, dir, path, approval)
                {
                    row.failure = Some(match &row.failure {
                        Some(previous) => format!("{previous}; resume: {error}"),
                        None => error.to_string(),
                    });
                    if !matches!(error, ScalerError::CpuCeiling { .. }) {
                        row.state = State::Reaping;
                    }
                    update(ledger, &row, path)?;
                    return Err(error);
                }
                return Ok(false);
            }
        }
        Recovery::Inspect => {}
    }
    pve.guard(&row)?;
    if task == TaskState::Failed {
        row.failure = Some("recorded PVE task failed; owned VM retained for reap".into());
        row.task = None;
    }
    let assignment = gh.assignment(&mut row)?;
    update(ledger, &row, path)?;
    if reap_decision(&row, now()?, assignment) == Reap::Destroy {
        return cleanup(pve, gh, ledger, &mut row, dir, path, assignment);
    }
    Ok(false)
}
fn pending_owned_job(row: &Record, job: &Value, run: &Value, sha: &str) -> bool {
    let labels: Vec<&str> = job["labels"]
        .as_array()
        .map(|labels| labels.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    job["id"].as_u64() == Some(row.key.job.0)
        && job["status"] == "queued"
        && eligible_labels(&labels)
        && run["id"].as_u64() == Some(row.key.run.0)
        && run["run_attempt"].as_u64() == Some(u64::from(row.key.attempt))
        && approved_run(run, sha)
}
fn one_job_result(row: Option<&Record>) -> Result<(), ScalerError> {
    if row.is_some_and(|r| r.assigned.is_some()) {
        Ok(())
    } else {
        Err(ScalerError::External(
            "pilot finished without an assigned job; cleanup completed",
        ))
    }
}

fn qualified_template(config: &Value) -> bool {
    // PVE 9 returns memory's decimal MiB quantity as a JSON string.
    let memory_mib = config["memory"].as_u64().or_else(|| {
        config["memory"]
            .as_str()
            .and_then(|value| value.parse::<u64>().ok())
    });
    config["cpu"] == "host"
        && config["cores"] == 2
        && memory_mib == Some(4096)
        && config["scsi0"]
            .as_str()
            .is_some_and(|s| s.starts_with("local-lvm:") && s.contains("size=64G"))
        && config["net0"]
            .as_str()
            .is_some_and(|s| s.contains("bridge=vmbr0"))
}

pub(super) fn pilot(sha: &str, dir: &Path, group: u64, one_job: bool) -> Result<(), ScalerError> {
    if sha.len() != 40 || !sha.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err(ScalerError::Guard("approved SHA must be full commit hash"));
    }
    let pve = Pve::local()?;
    std::fs::create_dir_all(dir)?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o600)
        .open(dir.join("controller.lock"))?;
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(ScalerError::Guard("another controller owns this ledger"));
    }
    let inventory = pve.inventory()?;
    let template =
        inventory
            .iter()
            .find(|v| v.id == 300 && v.template)
            .ok_or(ScalerError::Guard(
                "qualified template 300 not in carrick-ci",
            ))?;
    if template.pool != POOL {
        return Err(ScalerError::Guard("template pool mismatch"));
    }
    let config = pve.request(PveCall::Get, "/nodes/willow/qemu/300/config")?;
    if !qualified_template(&config) {
        return Err(ScalerError::Guard(
            "template does not match approved size/storage/bridge",
        ));
    }
    // Read-only privilege proof. Never probe a denied destructive operation.
    let protected = pve.request(PveCall::Get, "/access/permissions?path=/vms/105")?;
    if protected.as_object().is_none_or(|map| {
        map.values()
            .any(|v| v.as_object().is_none_or(|m| !m.is_empty()))
    }) {
        return Err(ScalerError::Guard(
            "token has unexpected protected-VM rights",
        ));
    }
    let gh = Github;
    let path = dir.join("ledger.json");
    let mut ledger = Ledger::load(&path)?;
    let mut reconcile = Instant::now() - Duration::from_secs(60);
    loop {
        if reconcile.elapsed() >= Duration::from_secs(60) {
            match reconcile_one(&pve, &gh, &mut ledger, dir, &path, (group, sha)) {
                Ok(true) if one_job => {
                    return one_job_result(ledger.rows.last());
                }
                Ok(_) => {}
                Err(error @ ScalerError::CpuCeiling { .. }) => return Err(error),
                Err(error) => {
                    eprintln!("reconcile failed: {error}; admission frozen for active ledger")
                }
            }
            reconcile = Instant::now();
        }
        if !ledger.rows.iter().any(|r| r.state != State::Destroyed) {
            for job in gh.demand(sha)? {
                if ledger.rows.iter().any(|r| r.key == job) {
                    continue;
                }
                if !resource_admission()? {
                    break;
                }
                let inventory = pve.inventory()?;
                let mut row = ledger.reserve(job, &inventory, now()?)?;
                ledger.save(&path)?; // Must reach durable storage before clone.
                println!("reserved vm={} job={}", row.vm.get(), job.job.0);
                if let Err(error) =
                    provision(&pve, &gh, &mut ledger, &mut row, dir, &path, (group, sha))
                {
                    row.failure = Some(error.to_string());
                    update(&mut ledger, &row, &path)?;
                    if matches!(error, ScalerError::CpuCeiling { .. }) {
                        return Err(error);
                    }
                    eprintln!("provision failed: {error}; preserving ledger for reconciliation");
                }
                break;
            }
        }
        std::thread::sleep(Duration::from_secs(30));
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    #[test]
    fn serial_host_guest_payload_installs_exact_bytes_without_expansion() {
        let dir = tempfile::tempdir().unwrap();
        for (i, script) in GUEST_SCRIPTS.iter().enumerate() {
            let path = dir.path().join(format!("payload-{i}"));
            let status = Command::new("/bin/sh")
                .args([
                    "-c",
                    &script_install_command(path.to_str().unwrap(), script.source),
                ])
                .status()
                .unwrap();
            assert!(status.success());
            assert_eq!(std::fs::read_to_string(&path).unwrap(), script.source);
            assert_eq!(
                std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o755
            );
        }
    }
    #[test]
    fn official_runner_hook_has_a_supported_script_extension() {
        let launch = include_str!("../../../../scripts/ci/runner-once.sh");
        let hook = launch
            .lines()
            .find_map(|line| {
                line.trim()
                    .strip_prefix("export ACTIONS_RUNNER_HOOK_JOB_STARTED=")
            })
            .unwrap();
        // The live runner rejected its extensionless hook before executing it.
        assert!(hook.ends_with(".sh") || hook.ends_with(".ps1") || hook.ends_with(".js"));
    }
    #[test]
    fn completed_cloud_init_accepts_only_the_observed_pve_user_deprecation() {
        let stdout = json!({"status":"done","errors":[],"recoverable_errors":{"DEPRECATED":["'user' of type string is deprecated in 22.2 and scheduled to be removed in 27.2. Use 'users' list instead."]}}).to_string();
        let output = GuestOutput {
            exit: GuestExit(2),
            stdout: stdout.clone(),
        };
        assert!(cloud_init_complete(&output).unwrap());
        for changed in [
            json!({"status":"done","errors":[],"recoverable_errors":{}}),
            json!({"status":"done","errors":[],"recoverable_errors":{"DEPRECATED":[]}}),
            json!({"status":"running","errors":[],"recoverable_errors":{}}),
            json!({"status":"done","errors":["module failed"],"recoverable_errors":{}}),
            json!({"status":"done","errors":[],"recoverable_errors":{"WARNING":["network failed"]}}),
            json!({"status":"done","errors":[],"recoverable_errors":{"DEPRECATED":["unexpected deprecation"]}}),
        ] {
            assert!(
                !cloud_init_complete(&GuestOutput {
                    exit: GuestExit(2),
                    stdout: changed.to_string()
                })
                .unwrap()
            );
        }
        assert!(
            !cloud_init_complete(&GuestOutput {
                exit: GuestExit(1),
                stdout
            })
            .unwrap()
        );
        assert!(
            cloud_init_complete(&GuestOutput {
                exit: GuestExit(0),
                stdout: json!({"status":"done","errors":[],"recoverable_errors":{}}).to_string(),
            })
            .unwrap()
        );
    }
    #[test]
    fn pve_rejection_reports_status_and_field_names_without_echoing_values() {
        let response = b"{\"errors\":{\"sshkeys\":\"invalid secret-value\"},\"message\":\"secret-value\",\"data\":null}\n400";
        let error = pve_response(response).unwrap_err().to_string();
        assert!(error.contains("400"));
        assert!(error.contains("sshkeys"));
        assert!(!error.contains("secret-value"));
        assert_eq!(pve_response(b"{\"data\":null}\n200").unwrap(), Value::Null);
    }
    #[test]
    fn provider_http_400_requires_urlencoded_sshkeys_in_json() {
        // Exact provider response from a non-mutating cores=0 validation request.
        let rejection: Value = serde_json::from_str(r#"{"message":"Parameter verification failed.\n","errors":{"sshkeys":"invalid format - invalid urlencoded string: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIATuCezuHC3VLhCpGfe7D7WL2w2gLXdNO9LxtCCsSyhz validation-only\n\n","cores":"value must have a minimum value of 1"},"data":null}"#).unwrap();
        assert!(
            rejection["errors"]["sshkeys"]
                .as_str()
                .unwrap()
                .contains("invalid urlencoded string")
        );
        let config = clone_config("ssh-ed25519 AAAA+/= validation-only\n");
        assert_eq!(
            config["sshkeys"],
            "ssh-ed25519%20AAAA%2B%2F%3D%20validation-only%0A"
        );
        assert_eq!(config["cores"], 2);
    }
    #[test]
    fn recovered_one_job_preserves_error_history_and_requires_actual_assignment() {
        let mut row = row();
        row.failure = Some("missing cached display".into());
        assert!(one_job_result(Some(&row)).is_err());
        row.assigned = Some(row.key.job);
        assert!(one_job_result(Some(&row)).is_ok());
        assert_eq!(row.failure.as_deref(), Some("missing cached display"));
    }
    #[test]
    fn resumed_clone_requires_the_same_queued_job_attempt_labels_and_approval() {
        let row = row();
        let sha = "a".repeat(40);
        let mut job = json!({"id":row.key.job.0,"status":"queued","labels":LABELS});
        let mut run = json!({"id":row.key.run.0,"run_attempt":row.key.attempt,"event":"workflow_dispatch","head_sha":sha,"head_branch":"work/willow-pilot","path":".github/workflows/willow-pilot.yml","repository":{"full_name":REPOSITORY}});
        assert!(pending_owned_job(&row, &job, &run, &sha));
        job["status"] = json!("completed");
        assert!(!pending_owned_job(&row, &job, &run, &sha));
        job["status"] = json!("queued");
        run["run_attempt"] = json!(row.key.attempt + 1);
        assert!(!pending_owned_job(&row, &job, &run, &sha));
        run["run_attempt"] = json!(row.key.attempt);
        assert!(!pending_owned_job(&row, &job, &run, &"b".repeat(40)));
        job["labels"] = json!(["self-hosted", "Linux", "X64", "willow-kvm", "extra"]);
        assert!(!pending_owned_job(&row, &job, &run, &sha));
    }
    #[test]
    fn director_cpu_ceiling_is_a_stop_condition_above_eighty_percent() {
        assert!(enforce_cpu_ceiling(0.675, 16).is_ok());
        assert!(matches!(
            enforce_cpu_ceiling(0.676, 16),
            Err(ScalerError::CpuCeiling { .. })
        ));
    }
    #[test]
    fn pool_membership_does_not_require_a_cached_display_name() {
        let pool = json!({"poolid":POOL,"members":[
            {"type":"qemu","node":"willow","vmid":308,"template":0}
        ]});
        let members = pool_inventory(&pool).unwrap();
        assert_eq!(members[0].id, 308);
        let row = row();
        assert!(authenticate_config(&row, members[0].clone(), &json!({"name":row.name})).is_ok());
        assert!(authenticate_config(&row, members[0].clone(), &json!({})).is_err());
    }
    #[test]
    fn recovered_destruction_removes_owned_transport_credentials_and_preserves_logs() {
        let dir = tempfile::tempdir().unwrap();
        let mut row = row();
        row.state = State::Reaping;
        let mut ledger = Ledger {
            rows: vec![row.clone()],
        };
        let path = dir.path().join("ledger.json");
        ledger.save(&path).unwrap();
        let (key, hosts) = key_paths(dir.path(), &row);
        let files = [key.clone(), key.with_extension("key.pub"), hosts];
        for file in &files {
            std::fs::write(file, "fixture").unwrap();
        }
        let log = dir.path().join(format!("{}.runner.log", row.name));
        let unrelated = dir.path().join("someone-else.key");
        std::fs::write(&log, "workload log").unwrap();
        std::fs::write(&unrelated, "fixture").unwrap();
        finish_destroyed(&mut ledger, &mut row, dir.path(), &path).unwrap();
        for file in files {
            assert!(
                !file.exists(),
                "recovered deletion retained transport credentials"
            );
        }
        assert!(log.exists());
        assert!(unrelated.exists());
        assert_eq!(Ledger::load(&path).unwrap().rows[0].state, State::Destroyed);
    }
    #[test]
    fn pve_read_and_delete_have_no_body_or_global_purge() {
        let token = Token {
            id: "fixture".into(),
            secret: "not-a-credential".into(),
        };
        for call in [PveCall::Get, PveCall::Delete] {
            let config = request_config(&token, &call).unwrap();
            assert!(
                !config.contains("data ="),
                "PVE rejects GET/DELETE bodies with HTTP 501"
            );
            assert!(!config.contains("Content-Type"));
            assert!(!config.contains("purge"));
        }
        for call in [
            PveCall::Post(json!({"cores":2})),
            PveCall::Put(json!({"cores":2})),
        ] {
            let config = request_config(&token, &call).unwrap();
            assert!(config.contains("Content-Type: application/json"));
            assert!(config.contains("data ="));
        }
    }
    #[test]
    fn ownership_uses_live_config_identity_and_retains_pool_and_template_fences() {
        let row = row();
        let cached = PoolMember {
            id: row.vm.get(),
            pool: POOL.into(),
            template: false,
        };
        let live = json!({"name":row.name});
        assert!(authenticate_config(&row, cached.clone(), &live).is_ok());
        let mut stale_template = cached.clone();
        stale_template.template = true;
        assert!(authenticate_config(&row, stale_template, &live).is_ok());
        assert!(
            authenticate_config(&row, cached.clone(), &json!({"name":"someone-else"})).is_err()
        );
        assert!(
            authenticate_config(&row, cached.clone(), &json!({"name":row.name,"template":1}))
                .is_err()
        );
        assert!(
            authenticate_config(
                &row,
                cached.clone(),
                &json!({"name":row.name,"template":true})
            )
            .is_err()
        );
        let mut foreign = cached.clone();
        foreign.pool = "another-pool".into();
        assert!(authenticate_config(&row, foreign, &live).is_err());
        let mut foreign = cached;
        foreign.id += 1;
        assert!(authenticate_config(&row, foreign, &live).is_err());
    }
    #[test]
    fn template_guard_accepts_pve_string_memory_and_rejects_wrong_sizes() {
        let mut config = json!({
            "cpu":"host", "cores":2, "memory":"4096",
            "scsi0":"local-lvm:base-300-disk-0,size=64G",
            "net0":"virtio=BC:24:11:54:4F:C9,bridge=vmbr0"
        });
        assert!(qualified_template(&config));
        config["memory"] = json!(4096);
        assert!(qualified_template(&config));
        for memory in [json!(8192), json!("8192"), json!("4096MiB"), json!(null)] {
            config["memory"] = memory;
            assert!(!qualified_template(&config));
        }
    }
    #[test]
    fn shared_readiness_deadline_bounds_a_nested_external_command() {
        let deadline = Instant::now() + Duration::from_millis(100);
        let result = execute(
            Command::new("sh").args(["-c", "sleep 2"]),
            &[],
            remaining(Some(deadline), Duration::from_secs(3)).unwrap(),
        );
        assert!(
            result.is_err(),
            "nested command ran beyond the shared deadline"
        );
        assert!(
            remaining(
                Some(Instant::now() - Duration::from_millis(1)),
                Duration::from_secs(45)
            )
            .is_err()
        );
    }
    fn row() -> Record {
        Ledger::default()
            .reserve(
                JobKey {
                    run: RunId(1),
                    attempt: 1,
                    job: JobId(2),
                },
                &[],
                0,
            )
            .unwrap()
    }
    #[test]
    fn jit_post_crash_recovers_only_one_exact_registration_identity() {
        let row = row();
        let registration = json!({"id":99,"name":row.name});
        assert_eq!(
            recover_registration(&row, std::slice::from_ref(&registration)).unwrap(),
            Some(RunnerId(99))
        );
        assert!(recover_registration(&row, &[registration.clone(), registration]).is_err());
        assert_eq!(
            recover_registration(&row, &[json!({"id":99,"name":"someone-else"})]).unwrap(),
            None
        );
    }
    #[test]
    fn completed_alternate_assignment_is_recovered_by_runner_id() {
        let mut row = row();
        row.runner = Some(RunnerId(99));
        let jobs = [
            json!({"id":500,"runner_id":98,"status":"completed"}),
            json!({"id":501,"runner_id":99,"status":"completed"}),
        ];
        assert_eq!(
            observed_assignment(&mut row, &jobs),
            Some(Assignment::Completed)
        );
        assert_eq!(row.assigned, Some(JobId(501)));
    }
}
