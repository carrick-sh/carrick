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
struct Pve {
    token: Token,
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
        Ok(Self { token })
    }
    fn request(&self, method: &str, path: &str, data: Option<Value>) -> Result<Value, ScalerError> {
        let header = format!(
            "Authorization: PVEAPIToken={}={}",
            self.token.id, self.token.secret
        );
        let mut config = format!("header = {}\n", serde_json::to_string(&header)?);
        if let Some(data) = data {
            config.push_str("header = \"Content-Type: application/json\"\n");
            config.push_str(&format!(
                "data = {}\n",
                serde_json::to_string(&data.to_string())?
            ));
        }
        let bytes = execute(
            Command::new("curl").args([
                "--fail",
                "--silent",
                "--show-error",
                "--max-time",
                "40",
                "--resolve",
                "willow.atxconsulting.com:8006:127.0.0.1",
                "--config",
                "-",
                "--request",
                method,
                &format!("https://willow.atxconsulting.com:8006/api2/json{path}"),
            ]),
            config.as_bytes(),
            Duration::from_secs(45),
        )?;
        let response: Value = serde_json::from_slice(&bytes)?;
        response
            .get("data")
            .cloned()
            .ok_or(ScalerError::External("PVE response lacks data"))
    }
    fn inventory(&self) -> Result<Vec<Vm>, ScalerError> {
        let pool = self.request("GET", "/pools/carrick-ci", None)?;
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
                result.push(Vm {
                    id,
                    name: string(member, "name")?,
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
    fn guard(&self, row: &Record) -> Result<Vm, ScalerError> {
        let inventory = self.inventory()?;
        let vm = inventory
            .into_iter()
            .find(|v| v.id == row.vm.get())
            .ok_or(ScalerError::Guard("ledger VM is absent"))?;
        row.guard(&vm)?;
        let config = self.request("GET", &format!("{}/config", base(row.vm)), None)?;
        if config["name"] != row.name || config["template"].as_u64() == Some(1) {
            return Err(ScalerError::Guard("config identity mismatch"));
        }
        Ok(vm)
    }
    fn task_done(&self, task: &str) -> Result<bool, ScalerError> {
        if !task.starts_with("UPID:willow:") || task.contains('/') {
            return Err(ScalerError::Guard("task belongs to another node"));
        }
        let result = self.request("GET", &format!("/nodes/willow/tasks/{task}/status"), None)?;
        if result["status"] == "stopped" {
            if result["exitstatus"] != "OK" {
                return Err(ScalerError::External("PVE task failed"));
            }
            Ok(true)
        } else {
            Ok(false)
        }
    }
    fn wait_task(&self, task: &str) -> Result<(), ScalerError> {
        let deadline = Instant::now() + Duration::from_secs(300);
        while Instant::now() < deadline {
            if self.task_done(task)? {
                return Ok(());
            }
            std::thread::sleep(Duration::from_secs(2));
        }
        Err(ScalerError::External("PVE task five-minute deadline"))
    }
    fn agent(&self, row: &Record, command: &[&str]) -> Result<String, ScalerError> {
        self.guard(row)?;
        let response = self.request(
            "POST",
            &format!("{}/agent/exec", base(row.vm)),
            Some(json!({"command":command})),
        )?;
        let pid = response["pid"]
            .as_u64()
            .ok_or(ScalerError::External("guest-agent pid"))?;
        let deadline = Instant::now() + Duration::from_secs(25);
        while Instant::now() < deadline {
            let status = self.request(
                "GET",
                &format!("{}/agent/exec-status?pid={pid}", base(row.vm)),
                None,
            )?;
            if status["exited"].as_bool() == Some(true) || status["exited"].as_u64() == Some(1) {
                if status["exitcode"].as_u64() != Some(0) {
                    return Err(ScalerError::External("guest qualification"));
                }
                return Ok(status["out-data"].as_str().unwrap_or_default().to_owned());
            }
            std::thread::sleep(Duration::from_secs(1));
        }
        Err(ScalerError::External("guest-agent exec deadline"))
    }
    fn guest_ip(&self, row: &Record) -> Result<Ipv4Addr, ScalerError> {
        self.guard(row)?;
        let data = self.request(
            "GET",
            &format!("{}/agent/network-get-interfaces", base(row.vm)),
            None,
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
        for run in self.runs("in_progress")? {
            for job in self.jobs(&run)? {
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
    fn remove_runner(&self, id: RunnerId) -> Result<(), ScalerError> {
        let runners = self.request(
            "GET",
            &format!("repos/{REPOSITORY}/actions/runners?per_page=100"),
            None,
            true,
        )?;
        if pages(&runners, "runners")?
            .iter()
            .any(|r| r["id"].as_u64() == Some(id.0))
        {
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
    println!(
        "admission busy={busy:.3} projected={:.3} memory_available={available}",
        busy + 2.0 / threads as f64
    );
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
fn ssh(dir: &Path, row: &Record, input: &[u8], command: &str) -> Result<Vec<u8>, ScalerError> {
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
        Duration::from_secs(45),
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

fn provision(
    pve: &Pve,
    gh: &Github,
    ledger: &mut Ledger,
    row: &mut Record,
    dir: &Path,
    path: &Path,
    group: u64,
) -> Result<(), ScalerError> {
    let (key, hosts) = key_paths(dir, row);
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
        "POST",
        "/nodes/willow/qemu/300/clone",
        Some(json!({
            "newid":row.vm.get(), "pool":POOL, "name":row.name, "full":false,
            "description":format!("Carrick pilot ledger identity {}", row.name)
        })),
    )?)?);
    update(ledger, row, path)?;
    pve.wait_task(
        row.task
            .as_deref()
            .ok_or(ScalerError::Guard("clone task missing"))?,
    )?;
    pve.guard(row)?;
    pve.request(
        "PUT",
        &format!("{}/config", base(row.vm)),
        Some(json!({
            "ciuser":"runner", "sshkeys":std::fs::read_to_string(key.with_extension("key.pub"))?,
            "ipconfig0":"ip=dhcp", "tags":"carrick-ci;willow-pilot",
            "cores":2,"memory":4096,"balloon":0,"cpulimit":2,"cpu":"host"
        })),
    )?;
    if !resource_admission()? {
        return Err(ScalerError::Guard("host admission denied before boot"));
    }
    row.state = State::Booting;
    row.task = Some(task_id(pve.request(
        "POST",
        &format!("{}/status/start", base(row.vm)),
        Some(json!({})),
    )?)?);
    update(ledger, row, path)?;
    pve.wait_task(
        row.task
            .as_deref()
            .ok_or(ScalerError::Guard("start task missing"))?,
    )?;
    let deadline = Instant::now() + Duration::from_secs(300);
    let mut ready = false;
    while Instant::now() < deadline {
        let qualification = pve.agent(row, &["/usr/bin/timeout", "20", "/bin/sh", "-c",
            "cloud-init status --wait >/dev/null && systemctl is-active carrick-ci-ready >/dev/null && runuser -u runner -- /usr/local/bin/carrick-xtask ci-scaler verify-kvm"]);
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
            if ssh(dir, row, &[], "test -x /usr/local/bin/carrick-ci-run-once").is_ok() {
                ready = true;
                break;
            }
        }
        std::thread::sleep(Duration::from_secs(5));
    }
    if !ready {
        return Err(ScalerError::External(
            "guest five-minute readiness deadline",
        ));
    }
    println!("vm={} ready; non-root KVM API 12 verified", row.vm.get());
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
    ssh(dir, row, &input, "/usr/local/bin/carrick-ci-run-once")?;
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
) -> Result<(), ScalerError> {
    pve.guard(row)?;
    row.state = State::Reaping;
    update(ledger, row, path)?;
    if let Some(runner) = row.runner {
        gh.remove_runner(runner)?;
    }
    // Export guest logs via the authenticated agent: bootstrap consumed its SSH
    // authorization, and no credential is recovered by this path.
    if let Ok(log) = pve.agent(
        row,
        &["/bin/sh", "-c", "tail -c 1048576 /home/runner/runner.log"],
    ) {
        std::fs::write(dir.join(format!("{}.runner.log", row.name)), log)?;
    }
    pve.guard(row)?;
    let status = pve.request("GET", &format!("{}/status/current", base(row.vm)), None)?;
    if status["status"] != "stopped" {
        row.task = Some(task_id(pve.request(
            "POST",
            &format!("{}/status/stop", base(row.vm)),
            Some(json!({})),
        )?)?);
        update(ledger, row, path)?;
        pve.wait_task(
            row.task
                .as_deref()
                .ok_or(ScalerError::Guard("stop task missing"))?,
        )?;
    }
    pve.guard(row)?;
    row.task = Some(task_id(pve.request(
        "DELETE",
        &base(row.vm),
        Some(json!({"purge":true})),
    )?)?);
    update(ledger, row, path)?;
    pve.wait_task(
        row.task
            .as_deref()
            .ok_or(ScalerError::Guard("destroy task missing"))?,
    )?;
    if pve.inventory()?.iter().any(|v| v.id == row.vm.get()) {
        return Err(ScalerError::Guard("clone still exists after deletion"));
    }
    row.state = State::Destroyed;
    update(ledger, row, path)?;
    let (key, hosts) = key_paths(dir, row);
    for file in [key.clone(), key.with_extension("key.pub"), hosts] {
        if file.exists() {
            std::fs::remove_file(file)?;
        }
    }
    println!(
        "vm={} destroyed; pool inventory confirms absence",
        row.vm.get()
    );
    Ok(())
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
    let config = pve.request("GET", "/nodes/willow/qemu/300/config", None)?;
    if config["cpu"] != "host"
        || config["cores"] != 2
        || config["memory"] != 4096
        || !config["scsi0"]
            .as_str()
            .is_some_and(|s| s.starts_with("local-lvm:") && s.contains("size=64G"))
        || !config["net0"]
            .as_str()
            .is_some_and(|s| s.contains("bridge=vmbr0"))
    {
        return Err(ScalerError::Guard(
            "template does not match approved size/storage/bridge",
        ));
    }
    // Read-only privilege proof. Never probe a denied destructive operation.
    let protected = pve.request("GET", "/access/permissions?path=/vms/105", None)?;
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
            if let Some(mut row) = ledger
                .rows
                .iter()
                .find(|r| r.state != State::Destroyed)
                .cloned()
            {
                // Restart: wait recorded asynchronous tasks, never clone again.
                if let Some(task) = &row.task {
                    pve.wait_task(task)?;
                }
                if row.state == State::Reaping
                    && !pve.inventory()?.iter().any(|v| v.id == row.vm.get())
                {
                    row.state = State::Destroyed;
                    update(&mut ledger, &row, &path)?;
                    if one_job {
                        return Ok(());
                    }
                } else {
                    pve.guard(&row)?;
                    let assignment = gh.assignment(&mut row)?;
                    update(&mut ledger, &row, &path)?;
                    if reap_decision(&row, now()?, assignment) == Reap::Destroy {
                        cleanup(&pve, &gh, &mut ledger, &mut row, dir, &path)?;
                        if one_job {
                            return if row.failure.is_some() {
                                Err(ScalerError::External(
                                    "pilot provision failed; clone reaped",
                                ))
                            } else {
                                Ok(())
                            };
                        }
                    }
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
                if let Err(error) = provision(&pve, &gh, &mut ledger, &mut row, dir, &path, group) {
                    row.failure = Some(error.to_string());
                    update(&mut ledger, &row, &path)?;
                    eprintln!("provision failed: {error}; preserving ledger for reconciliation");
                }
                break;
            }
        }
        std::thread::sleep(Duration::from_secs(30));
    }
}
