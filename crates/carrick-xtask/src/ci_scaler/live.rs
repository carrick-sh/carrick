//! Local-only PVE transport and foreground lifecycle; secrets have no Debug impl.
use super::assignment::Revetted;
use super::github::Github;
#[cfg(test)]
use super::github::recover_registration;
use super::site::{Headroom, Site};
use super::*;
use serde_json::{Value, json};
use std::net::Ipv4Addr;
use std::os::unix::fs::MetadataExt;

#[derive(Clone, Deserialize)]
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
/// The job-start hook every clone runs (`ACTIONS_RUNNER_HOOK_JOB_STARTED`).
const HOOK_PATH: &str = "/usr/local/bin/carrick-ci-admit-job.sh";
const GUEST_SCRIPTS: [GuestScript; 2] = [
    GuestScript {
        path: "/usr/local/bin/carrick-ci-run-once",
        source: include_str!("../../../../scripts/ci/runner-once.sh"),
    },
    GuestScript {
        path: HOOK_PATH,
        source: include_str!("../../../../scripts/ci/admit-job.sh"),
    },
];
/// The bytes installed at `script.path`. A standing clone's hook falls back
/// to the controller's re-vet of the actual assignment (#333); the pilot's
/// hook admits only its approved SHA.
fn guest_script_source(script: &GuestScript, admission: &Admission) -> Result<String, ScalerError> {
    match admission {
        Admission::Standing | Admission::Agent if script.path == HOOK_PATH => {
            standing_hook_script()
        }
        _ => Ok(script.source.to_owned()),
    }
}
/// Root, under the hook's flock: report whether the rendezvous is settled
/// (approved, started or draining) and otherwise the hook's request, if any.
const GUEST_ASSIGNMENT_READ: &str = r#"cd /run/carrick-ci || exit 1
if [ -e approved-policy ] || [ -e draining ] || [ -s admission.lock ]; then echo settled; exit 0; fi
if [ -e /home/runner/runner.exit ]; then echo finished; else echo pending; fi
if [ ! -L assignment.json ] && [ -f assignment.json ]; then head -c 8193 assignment.json; fi"#;
/// Root, under the hook's flock: publish `$1` as the approved policy unless
/// draining; idempotent, and never replaces an approval with another run.
const GUEST_ASSIGNMENT_APPROVE: &str = r#"cd /run/carrick-ci || exit 1
[ ! -e draining ] || exit 3
if [ -e approved-policy ]; then [ "$(cat approved-policy)" = "$1" ] && exit 0; exit 4; fi
umask 022
printf '%s\n' "$1" > approved-policy.tmp && chmod 644 approved-policy.tmp && mv approved-policy.tmp approved-policy"#;
/// Root: print the tool server's pending token request (#1012) under the
/// request file's own lock. Exit 5 = this clone has no mint channel. The
/// runner owns the file and could hold its lock forever, so every guest mint
/// script waits at most three seconds for it (exit 6) and is killed after ten.
const GUEST_MINT_READ: &str = r#"cd /run/carrick-ci || exit 1
[ -f token-request ] && [ ! -L token-request ] || exit 5
exec 9<token-request && timeout 10 /usr/bin/flock -w 3 9 || exit 6
head -c 4097 <&9"#;
/// Root: write stdin (the answer) into the runner-owned 0600 response file
/// under its lock. The file and the root-owned directory are never replaced,
/// so the write cannot follow a planted link; the token never enters argv.
const GUEST_MINT_RESPOND: &str = r#"cd /run/carrick-ci || exit 1
[ -f token-response ] && [ ! -L token-response ] || exit 5
exec 9<token-response && timeout 10 /usr/bin/flock -w 3 9 || exit 6
timeout 10 head -c 8192 > token-response"#;
/// Root: empty the request under its lock, only while it still holds the
/// nonce `$1` (any request when `$1` is empty): a request written after the
/// controller's read is never wiped.
const GUEST_MINT_CLEAR: &str = r#"cd /run/carrick-ci || exit 1
[ -f token-request ] && [ ! -L token-request ] || exit 5
exec 9<token-request && timeout 10 /usr/bin/flock -w 3 9 || exit 6
if [ -z "$1" ] || grep -qF -- "\"$1\"" token-request; then : > token-request; fi"#;
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
fn clone_config(public_key: &str, site: &Site, vm: CloneId) -> Result<Value, ScalerError> {
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
    // `ciupgrade: 0`: PVE's cloud-init otherwise writes `package_upgrade:
    // true`, so every clone ran `apt-get update` and `dist-upgrade` against
    // the Debian mirrors on first boot (about two minutes), and a failed
    // update left cloud-init degraded and the clone never ready (#1265).
    // The template already holds its packages.
    let mut config = json!({
        "ciuser":"runner", "sshkeys":encoded, "ciupgrade":0,
        "ipconfig0":site.ipconfig(vm.get())?, "tags":"carrick-ci;willow-pilot",
        "cores":site.cores,"memory":site.memory_mib,"balloon":0,"cpulimit":site.cores,"cpu":"host"
    });
    if let Some(nameserver) = site.nameserver() {
        config["nameserver"] = json!(nameserver);
    }
    Ok(config)
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
    site: Site,
    token: Token,
    deadline: std::cell::Cell<Option<Instant>>,
}
fn pve_curl(call: &PveCall, resolve: &str, ca: Option<&str>, url: &str) -> Command {
    let mut command = Command::new("curl");
    command.args([
        "--disable",
        "--silent",
        "--show-error",
        "--write-out",
        "\n%{http_code}",
        "--max-time",
        "40",
        "--resolve",
        resolve,
    ]);
    if let Some(ca) = ca {
        command.args(["--cacert", ca]);
    }
    command.args(["--config", "-", "--request", call.method(), url]);
    command
}
impl Pve {
    fn for_lane(&self, lane: CloneLane) -> Result<Self, ScalerError> {
        Ok(Self {
            site: self.site.for_lane(lane)?,
            token: self.token.clone(),
            deadline: std::cell::Cell::new(None),
        })
    }

    fn local() -> Result<Self, ScalerError> {
        // Fails closed on any host that is not a known clone site.
        let site = Site::local()?;
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
            site,
            token,
            deadline: std::cell::Cell::new(None),
        })
    }
    fn request(&self, call: PveCall, path: &str) -> Result<Value, ScalerError> {
        let limit = remaining(self.deadline.get(), Duration::from_secs(45))?;
        let config = request_config(&self.token, &call)?;
        let bytes = execute(
            &mut pve_curl(
                &call,
                &self.site.api_resolve(),
                self.site.api_ca,
                &self.site.api_url(path),
            ),
            config.as_bytes(),
            limit,
        )?;
        pve_response(&bytes)
    }
    fn base(&self, id: CloneId) -> String {
        self.site.qemu(id.get())
    }
    fn inventory(&self) -> Result<Vec<PoolMember>, ScalerError> {
        let pool = self.request(PveCall::Get, "/pools/carrick-ci")?;
        pool_inventory(&pool, self.site.node)
    }
    fn guard(&self, row: &Record) -> Result<Vm, ScalerError> {
        let inventory = self.inventory()?;
        let vm = inventory
            .into_iter()
            .find(|v| v.id == row.vm.get())
            .ok_or(ScalerError::Guard("ledger VM is absent"))?;
        let config = self.request(PveCall::Get, &format!("{}/config", self.base(row.vm)))?;
        authenticate_config(row, vm, &config)
    }
}
fn pool_inventory(pool: &Value, node: &str) -> Result<Vec<PoolMember>, ScalerError> {
    if pool["poolid"] != POOL {
        return Err(ScalerError::Guard("PVE returned another pool"));
    }
    let members = pool["members"]
        .as_array()
        .ok_or(ScalerError::External("pool members"))?;
    let mut result = Vec::new();
    for member in members {
        if member["type"] == "qemu" {
            if member["node"] != node {
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
        if !task.starts_with(&self.site.task_prefix()) || task.contains('/') {
            return Err(ScalerError::Guard("task belongs to another node"));
        }
        let result = self.request(
            PveCall::Get,
            &format!("/nodes/{}/tasks/{task}/status", self.site.node),
        )?;
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
        self.agent_output_input(row, command, None)
    }
    /// `input` becomes the command's stdin (`input-data`): secrets passed this
    /// way travel in the PVE request body on curl's stdin, never in guest argv.
    fn agent_output_input(
        &self,
        row: &Record,
        command: &[&str],
        input: Option<&str>,
    ) -> Result<GuestOutput, ScalerError> {
        self.guard(row)?;
        let mut body = json!({"command":command});
        if let Some(input) = input {
            body["input-data"] = input.into();
        }
        let response = self.request(
            PveCall::Post(body),
            &format!("{}/agent/exec", self.base(row.vm)),
        )?;
        let pid = response["pid"]
            .as_u64()
            .ok_or(ScalerError::External("guest-agent pid"))?;
        let deadline = Instant::now() + Duration::from_secs(25);
        while Instant::now() < deadline {
            let status = self.request(
                PveCall::Get,
                &format!("{}/agent/exec-status?pid={pid}", self.base(row.vm)),
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
            &format!("{}/agent/network-get-interfaces", self.base(row.vm)),
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
fn task_id(value: Value) -> Result<String, ScalerError> {
    value
        .as_str()
        .map(str::to_owned)
        .ok_or(ScalerError::External("missing PVE task ID"))
}

fn enforce_cpu_ceiling(busy: f64, threads: u32, cores: u32) -> Result<(), ScalerError> {
    if !busy.is_finite() || busy < 0.0 || threads == 0 {
        return Err(ScalerError::Guard("CPU sample unavailable"));
    }
    let projected = busy + f64::from(cores) / f64::from(threads);
    if projected > 0.80 {
        Err(ScalerError::CpuCeiling {
            projected: projected * 100.0,
        })
    } else {
        Ok(())
    }
}
/// Nominal (cores, memory MiB) of one clone in `lane` at `pve`'s site.
fn nominal(pve: &Pve) -> impl Fn(CloneLane) -> (u32, u64) + '_ {
    move |lane| {
        pve.site
            .for_lane(lane)
            .map_or((pve.site.cores, pve.site.memory_mib), |site| {
                (site.cores, site.memory_mib)
            })
    }
}
/// One host reading: CPU busy fraction, online threads, available bytes.
struct HostSample {
    busy: f64,
    threads: u32,
    available: u64,
}
/// Whether one more clone of `(cores, memory_mib)` fits `sample` with
/// `pending` clones still booting. The fatal CPU ceiling looks at the live
/// reading only: pending charges defer a clone, they never end the
/// controller.
fn admission_verdict(
    sample: &HostSample,
    (cores, memory_mib): (u32, u64),
    pending: Pending,
) -> Result<bool, ScalerError> {
    enforce_cpu_ceiling(sample.busy, sample.threads, cores)?;
    Ok(admit_resources_with_pending(
        sample.busy,
        sample.threads,
        sample.available,
        cores,
        memory_mib,
        pending,
    ))
}
fn resource_admission(pve: &Pve, pending: Pending) -> Result<bool, ScalerError> {
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
        "admission utilization={utilization:.3} utilization_source=/proc/stat:5s-delta load_per_cpu={load:.3} load_source=/proc/loadavg:1m-per-cpu online_cpus={threads} limiting_source={limiting_source} busy={busy:.3} projected={:.3} reserved_vcpus={} memory_available={available} pending_clones={} pending_vcpus={} pending_memory_mib={}",
        busy + f64::from(pve.site.cores + pending.cores) / threads as f64,
        pve.site.cores,
        pending.clones,
        pending.cores,
        pending.memory_mib
    );
    let sample = HostSample {
        busy,
        threads: u32::try_from(threads).unwrap_or(0),
        available,
    };
    Ok(
        admission_verdict(&sample, (pve.site.cores, pve.site.memory_mib), pending)?
            && storage_headroom(pve, pending)?,
    )
}
/// Storage headroom for one more linked clone: 150 GiB free, and for an LVM
/// thin pool also metadata below 80%. Read-only; never mutates storage.
/// Free storage one more linked clone needs: 150 GiB, plus 20 GiB for each
/// clone admitted but not yet running (#1251). A freshly booted linked clone
/// has written only a few GiB, so charging each the whole floor would refuse
/// a sixth agent clone on ctb's ~780 GiB with nothing actually used.
fn storage_floor(pending: Pending) -> u64 {
    (150 << 30) + u64::from(pending.clones) * (20 << 30)
}
fn storage_headroom(pve: &Pve, pending: Pending) -> Result<bool, ScalerError> {
    let free_needed = storage_floor(pending);
    match pve.site.headroom {
        Headroom::LvmThin { pool } => {
            let output = execute(
                Command::new("lvs").args([
                    "--reportformat",
                    "json",
                    "--units",
                    "b",
                    "--nosuffix",
                    "-o",
                    "lv_size,data_percent,metadata_percent",
                    pool,
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
            Ok(free >= free_needed as f64 && number("metadata_percent")? < 80.0)
        }
        Headroom::Directory => {
            let status = pve.request(
                PveCall::Get,
                &format!(
                    "/nodes/{}/storage/{}/status",
                    pve.site.node, pve.site.storage
                ),
            )?;
            directory_headroom(&status, free_needed)
        }
    }
}
/// A directory storage admits a clone only while active, enabled and with at
/// least `free` bytes available.
fn directory_headroom(status: &Value, free: u64) -> Result<bool, ScalerError> {
    if status["active"].as_u64() != Some(1) || status["enabled"].as_u64() != Some(1) {
        return Err(ScalerError::Guard("clone storage is not active"));
    }
    let avail = status["avail"]
        .as_u64()
        .ok_or(ScalerError::Guard("storage statistics unavailable"))?;
    Ok(avail >= free)
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
    approval: (u64, &Admission),
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
        &format!("{}/clone", pve.site.qemu(row.lane.template())),
    )?)?);
    update(ledger, row, path)?;
    pve.wait_task(
        row.task
            .as_deref()
            .ok_or(ScalerError::Guard("clone task missing"))?,
    )?;
    boot_and_register(pve, gh, ledger, row, dir, path, approval, PreBoot::Defer)
}

/// What a refused pre-boot admission does. A provisioning worker owns its
/// row and may wait for other clones to run; the lifecycle loop (resuming a
/// clone in reconcile) must not, since it also reaps the clones whose exit
/// would free the host (#1251 review).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PreBoot {
    /// Wait up to ten minutes for other clones, then fail.
    Defer,
    /// Fail at once; reconciliation retries on a later pass.
    FailFast,
}
impl PreBoot {
    fn deadline(self) -> Instant {
        match self {
            Self::Defer => Instant::now() + Duration::from_secs(600),
            Self::FailFast => Instant::now(),
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn boot_and_register(
    pve: &Pve,
    gh: &Github,
    ledger: &mut Ledger,
    row: &mut Record,
    dir: &Path,
    path: &Path,
    approval: (u64, &Admission),
    pre_boot: PreBoot,
) -> Result<(), ScalerError> {
    let (group, admission) = approval;
    let (key, hosts) = key_paths(dir, row);
    let key_meta = std::fs::symlink_metadata(&key)?;
    if !key_meta.is_file() || key_meta.uid() != 0 || key_meta.mode() & 0o077 != 0 {
        return Err(ScalerError::Guard(
            "owned clone lacks its root-only transport key",
        ));
    }
    pve.guard(row)?;
    let status = pve.request(
        PveCall::Get,
        &format!("{}/status/current", pve.base(row.vm)),
    )?;
    if status["status"] != "stopped" {
        return Err(ScalerError::Guard(
            "clone preparation requires a stopped owned VM",
        ));
    }
    pve.request(
        PveCall::Put(clone_config(
            &std::fs::read_to_string(key.with_extension("key.pub"))?,
            &pve.site,
            row.vm,
        )?),
        &format!("{}/config", pve.base(row.vm)),
    )?;
    // Other clones still booting are charged at nominal size although they
    // may already use part of it, so a refusal here means "not now". A
    // worker waits for them to run (or retire); the loop fails fast.
    let admit_by = pre_boot.deadline();
    loop {
        ledger.refresh()?;
        if resource_admission(pve, ledger.pending(&row.name, nominal(pve)))? {
            break;
        }
        if Instant::now() >= admit_by {
            return Err(ScalerError::Guard("host admission denied before boot"));
        }
        std::thread::sleep(Duration::from_secs(15));
    }
    pve.guard(row)?;
    // A linked clone inherits the template's `allow-ksm: 0`; refuse one
    // that lost it before the guest runs.
    let config = pve.request(PveCall::Get, &format!("{}/config", pve.base(row.vm)))?;
    if !ksm_matches(&config, &pve.site) {
        return Err(ScalerError::Guard("clone may join KSM page merging"));
    }
    // The clone inherits 300.fw; give it its own ipfilter address, then
    // prove the whole firewall before the guest can send a packet.
    pve.set_clone_ipfilter(row.vm.get())?;
    pve.verify_vm_firewall(row.vm.get())?;
    let deadline = Instant::now() + Duration::from_secs(300);
    pve.deadline.set(Some(deadline));
    let shared_deadline = ApiDeadline(&pve.deadline);
    row.state = State::Booting;
    row.task = None;
    update(ledger, row, path)?;
    row.task = Some(task_id(pve.request(
        PveCall::Post(json!({})),
        &format!("{}/status/start", pve.base(row.vm)),
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
            for executable in ["/usr/bin/setsid", "/bin/kill"] {
                pve.agent(row, &["/usr/bin/test", "-x", executable])?;
            }
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
                &script_install_command(script.path, &guest_script_source(script, admission)?),
            ],
        )?;
    }
    pve.agent(
        row,
        &["/bin/sh", "-c", "rm -f /usr/local/bin/carrick-ci-admit-job"],
    )?;
    let standing = matches!(admission, Admission::Standing | Admission::Agent);
    if standing {
        // The re-vet half of the hook runs the template's own xtask; refuse a
        // template whose xtask predates it rather than fail a job at set-up.
        let help = pve.agent(
            row,
            &[
                "/usr/local/bin/carrick-xtask",
                "ci-scaler",
                "admit-job",
                "--help",
            ],
        )?;
        if !help.contains("--controller") {
            return Err(ScalerError::Guard(
                "template xtask lacks admit-job --controller; rebuild template 300",
            ));
        }
    }
    if matches!(admission, Admission::Agent) {
        // Agent policy parsing and assignment authorization shipped with this
        // command. Old template binaries must fail before minting a runner.
        pve.agent(
            row,
            &["/usr/local/bin/carrick-xtask", "agent-runner", "--help"],
        )?;
    }
    // Re-vet the reserved run now and bind the runner to it: the hook admits
    // this run, attempt, SHA and owner-only dispatch actors. A standing clone that
    // GitHub assigns another job asks the controller to re-vet that one.
    let policy = gh.vet(admission, row.key)?;
    // The job-start hook reads this root-owned policy; jobs cannot write it.
    // Only the runner-owned rendezvous request is writable by the hook.
    let mut rendezvous = if standing {
        format!(" && install -m 600 -o runner -g runner /dev/null {GUEST_STATE}/assignment.json")
    } else {
        String::new()
    };
    if matches!(admission, Admission::Agent) {
        // On-demand dispatch tokens (#1012): runner-owned request and
        // response files in the root-owned state directory.
        for file in [mint::REQUEST_FILE, mint::RESPONSE_FILE] {
            rendezvous.push_str(&format!(
                " && install -m 600 -o runner -g runner /dev/null {GUEST_STATE}/{file}"
            ));
        }
    }
    pve.agent(
        row,
        &[
            "/bin/sh",
            "-c",
            &format!(
                "install -d -m 755 /etc/carrick-ci; printf '%s\\n' {} > /etc/carrick-ci/policy; chmod 644 /etc/carrick-ci/policy{rendezvous}",
                crate::remote_accept::shell_quote(&policy.render())
            ),
        ],
    )?;
    println!("vm={} ready; non-root KVM API 12 verified", row.vm.get());
    drop(shared_deadline);
    // Write registration intent before asking GitHub. No JIT material in ledger.
    row.state = State::Registered;
    update(ledger, row, path)?;
    let (runner, jit) = gh.generate_jit(&row.name, group, row.lane.labels())?;
    row.runner = Some(runner);
    update(ledger, row, path)?;
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

// Reaping is durable authorization obtained after the admission/drain checks.
// Its continuation depends on owned VM state, never a surviving registration.
trait TeardownApi {
    fn present(&mut self, row: &Record) -> Result<bool, ScalerError>;
    fn stop(&mut self, row: &Record, dir: &Path) -> Result<Option<String>, ScalerError>;
    fn destroy(&mut self, row: &Record) -> Result<String, ScalerError>;
    fn wait_task(&mut self, task: &str) -> Result<(), ScalerError>;
    fn remove_runner(&mut self, row: &Record) -> Result<(), ScalerError>;
}
struct LiveTeardown<'a> {
    pve: &'a Pve,
    gh: &'a Github,
}
impl TeardownApi for LiveTeardown<'_> {
    fn present(&mut self, row: &Record) -> Result<bool, ScalerError> {
        Ok(self.pve.inventory()?.iter().any(|v| v.id == row.vm.get()))
    }
    fn stop(&mut self, row: &Record, dir: &Path) -> Result<Option<String>, ScalerError> {
        self.pve.guard(row)?;
        let status = self.pve.request(
            PveCall::Get,
            &format!("{}/status/current", self.pve.base(row.vm)),
        )?;
        if status["status"] == "stopped" {
            return Ok(None);
        }
        // A stopped guest cannot answer its agent. Preserve logs opportunistically
        // while running, without making the teardown continuation depend on them.
        if let Ok(log) = self.pve.agent(
            row,
            &["/bin/sh", "-c", "tail -c 1048576 /home/runner/runner.log"],
        ) {
            std::fs::write(dir.join(format!("{}.runner.log", row.name)), log)?;
        }
        self.pve.guard(row)?;
        Ok(Some(task_id(self.pve.request(
            PveCall::Post(json!({})),
            &format!("{}/status/stop", self.pve.base(row.vm)),
        )?)?))
    }
    fn destroy(&mut self, row: &Record) -> Result<String, ScalerError> {
        self.pve.guard(row)?;
        task_id(self.pve.request(PveCall::Delete, &self.pve.base(row.vm))?)
    }
    fn wait_task(&mut self, task: &str) -> Result<(), ScalerError> {
        self.pve.wait_task(task)
    }
    fn remove_runner(&mut self, row: &Record) -> Result<(), ScalerError> {
        self.gh.remove_runner(row)
    }
}
fn continue_teardown(
    api: &mut impl TeardownApi,
    ledger: &mut Ledger,
    row: &mut Record,
    dir: &Path,
    path: &Path,
) -> Result<bool, ScalerError> {
    if row.state != State::Reaping {
        return Err(ScalerError::Guard("teardown lacks durable authorization"));
    }
    // A failed prior fsync must not turn an in-memory state into permission for
    // side effects. Re-publish the license before every continuation attempt.
    update(ledger, row, path)?;
    if api.present(row)? {
        if let Some(task) = api.stop(row, dir)? {
            row.task = Some(task);
            update(ledger, row, path)?;
            api.wait_task(
                row.task
                    .as_deref()
                    .ok_or(ScalerError::Guard("stop task missing"))?,
            )?;
        }
        row.task = Some(api.destroy(row)?);
        update(ledger, row, path)?;
        api.wait_task(
            row.task
                .as_deref()
                .ok_or(ScalerError::Guard("destroy task missing"))?,
        )?;
        if api.present(row)? {
            return Err(ScalerError::Guard("clone still exists after deletion"));
        }
    }
    // Removing registration cannot strand a running VM: the VM is absent first.
    // If GitHub fails or this process dies, Reaping remains a resumable license.
    api.remove_runner(row)?;
    finish_destroyed(ledger, row, dir, path)?;
    Ok(true)
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
    row.task = None;
    update(ledger, row, path)?;
    continue_teardown(&mut LiveTeardown { pve, gh }, ledger, row, dir, path)
}

/// One reconciliation pass over every active clone.
struct Pass {
    finished: usize,
    /// Any row error or ambiguity freezes new admission until a clean pass.
    frozen: Option<ScalerError>,
}
/// Reconcile every active clone. One row's error does not starve the others.
/// KVM CPU-ceiling stops retain their existing policy. Agent admission
/// pressure freezes new work while reconciliation continues for live agents.
fn reconcile_all(
    pve: &Pve,
    gh: &Github,
    ledger: &mut Ledger,
    dir: &Path,
    path: &Path,
    approval: (u64, &Admission),
) -> Result<Pass, ScalerError> {
    let active: Vec<Record> = ledger
        .rows
        .iter()
        .filter(|r| r.state != State::Destroyed)
        .cloned()
        .collect();
    let mut finished = 0;
    let mut first_error = None;
    for row in active {
        let lane = row.lane;
        match reconcile_one(pve, gh, ledger, dir, path, approval, row) {
            Ok(true) => finished += 1,
            Ok(false) => {}
            Err(error @ ScalerError::CpuCeiling { .. }) if lane == CloneLane::Kvm => {
                return Err(error);
            }
            Err(error) => {
                first_error.get_or_insert(error);
            }
        }
    }
    Ok(Pass {
        finished,
        frozen: first_error,
    })
}

/// The committed copy of `name` for this reconcile step, or `None` while a
/// provisioning worker owns it (#1251 review). A pass lists its rows when it
/// starts; a worker that finishes mid-pass releases its row, and acting on
/// the pass's stale copy would write the row back to an earlier state.
/// Owned covers live and released-but-unread rows; the refresh that follows
/// drains releases with a snapshot that holds their last write.
fn reconcile_target(ledger: &mut Ledger, name: &str) -> Result<Option<Record>, ScalerError> {
    if ledger
        .publication
        .as_ref()
        .is_some_and(|publication| publication.owners().owned().contains(name))
    {
        return Ok(None);
    }
    ledger.refresh()?;
    Ok(ledger
        .rows
        .iter()
        .find(|r| r.name == name && r.state != State::Destroyed)
        .cloned())
}

#[allow(clippy::too_many_arguments)]
fn reconcile_one(
    pve: &Pve,
    gh: &Github,
    ledger: &mut Ledger,
    dir: &Path,
    path: &Path,
    approval: (u64, &Admission),
    row: Record,
) -> Result<bool, ScalerError> {
    let Some(mut row) = reconcile_target(ledger, &row.name)? else {
        return Ok(false);
    };
    let lane_pve = pve.for_lane(row.lane)?;
    let pve = &lane_pve;
    let lane_admission = row.lane.admission();
    let approval = if row.lane == CloneLane::Agent {
        (approval.0, &lane_admission)
    } else {
        approval
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
            return Err(ScalerError::Guard(
                "ambiguous clone state; admission frozen for owner inspection",
            ));
        }
        Recovery::FinishAbsent => {
            if task == TaskState::Failed {
                row.failure = Some("recorded PVE task failed; VM absent".into());
            }
            if row.state == State::Reaping {
                return continue_teardown(
                    &mut LiveTeardown { pve, gh },
                    ledger,
                    &mut row,
                    dir,
                    path,
                );
            }
            // Removal recovers a POST whose ID save was interrupted by name;
            // never query job assignment after the VM has disappeared.
            gh.remove_runner(&row)?;
            finish_destroyed(ledger, &mut row, dir, path)?;
            return Ok(true);
        }
        Recovery::ResumeReaping => {
            if task == TaskState::Failed {
                row.failure
                    .get_or_insert_with(|| "recorded PVE task failed during licensed reap".into());
            }
            return continue_teardown(&mut LiveTeardown { pve, gh }, ledger, &mut row, dir, path);
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
                if let Err(error) = boot_and_register(
                    pve,
                    gh,
                    ledger,
                    &mut row,
                    dir,
                    path,
                    approval,
                    PreBoot::FailFast,
                ) {
                    row.failure = Some(match &row.failure {
                        Some(previous) => format!("{previous}; resume: {error}"),
                        None => error.to_string(),
                    });
                    // A failed/ambiguous JIT delivery is not a licensed reap.
                    // Preserve its actual preparation state for assignment and
                    // drain checks, which may discover a job already running.
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
    ledger.refresh()?;
    if let Some(current) = ledger.rows.iter().find(|current| current.name == row.name)
        && current.assigned_key.is_some()
    {
        row.assigned = current.assigned;
        row.assigned_key = current.assigned_key;
    }
    let mut assignment = gh.assignment(&mut row)?;
    update(ledger, &row, path)?;
    if assignment == Assignment::Unknown && runner_exited(pve, &row) {
        // Registration gone, reserved job never ran here, and the guest's
        // one-use runner has written its exit status: nothing is live.
        assignment = Assignment::Completed;
    }
    if reap_decision(&row, now()?, assignment) == Reap::Destroy {
        return cleanup(pve, gh, ledger, &mut row, dir, path, assignment);
    }
    Ok(false)
}
fn runner_exited(pve: &Pve, row: &Record) -> bool {
    pve.agent_output(row, &["/usr/bin/test", "-e", "/home/runner/runner.exit"])
        .is_ok_and(|out| out.exit == GuestExit(0))
}
fn pending_owned_job(row: &Record, job: &Value, run: &Value, admission: &Admission) -> bool {
    let labels: Vec<&str> = job["labels"]
        .as_array()
        .map(|labels| labels.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    job["id"].as_u64() == Some(row.key.job.0)
        && job["status"] == "queued"
        && labels_match(row.lane.labels(), &labels)
        && run["id"].as_u64() == Some(row.key.run.0)
        && run["run_attempt"].as_u64() == Some(u64::from(row.key.attempt))
        && admission.identifies_run(run)
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

/// The datacenter firewall must be on for any VM firewall to apply. Read
/// from the root-only cluster config: the scoped token has no `/` rights.
fn cluster_firewall_enabled(cluster_fw: &str) -> bool {
    let mut options = false;
    for line in cluster_fw.lines().map(str::trim) {
        if line.starts_with('[') {
            options = line.eq_ignore_ascii_case("[OPTIONS]");
        } else if options && line.split_whitespace().collect::<Vec<_>>() == ["enable:", "1"] {
            return true;
        }
    }
    false
}
/// Exact VM firewall check for an isolating site: options and the ordered
/// rule list must equal [`Site::vm_firewall`]. Anything else fails closed.
fn vm_firewall_matches(site: &Site, options: &Value, rules: &Value) -> bool {
    let (Some(expected), Some(gateway), Some(blocked)) =
        (site.vm_firewall(), site.gateway(), site.blocked())
    else {
        return false;
    };
    let flag = |name: &str| options[name].as_u64() == Some(1);
    let text = |value: &Value, want: &str| value.as_str() == Some(want);
    if !(flag("enable")
        && flag("ipfilter")
        && options
            .get("macfilter")
            .is_none_or(|v| v.as_u64() == Some(1))
        && text(&options["policy_in"], "DROP")
        && text(&options["policy_out"], "DROP"))
    {
        return false;
    }
    let Some(mut live) = rules.as_array().cloned() else {
        return false;
    };
    live.sort_by_key(|rule| rule["pos"].as_u64().unwrap_or(u64::MAX));
    let optional = |value: &Value, want: Option<String>| match want {
        Some(want) => value.as_str() == Some(want.as_str()),
        None => value.is_null(),
    };
    live.len() == expected.len()
        && live.iter().zip(expected).all(|(rule, want)| {
            rule["enable"].as_u64() == Some(1)
                && text(&rule["type"], want.direction)
                && text(&rule["action"], want.action)
                && optional(&rule["source"], want.source(&gateway, &blocked))
                && optional(&rule["dest"], want.dest(&gateway, &blocked))
                && optional(&rule["proto"], want.proto.map(str::to_owned))
                && optional(&rule["dport"], want.dport.map(str::to_owned))
                && rule.get("iface").is_none()
                && rule.get("macro").is_none()
                && rule.get("sport").is_none()
        })
}
/// The VM's `ipfilter-net0` ipset must hold exactly its own address.
fn ipfilter_matches(set: &Value, address: &str) -> bool {
    let host = format!("{address}/32");
    set.as_array().is_some_and(|entries| {
        entries.len() == 1
            && entries.iter().all(|entry| {
                matches!(entry["cidr"].as_str(), Some(cidr) if cidr == address || cidr == host)
                    && entry.get("nomatch").is_none_or(|v| v.as_u64() == Some(0))
            })
    })
}
impl Pve {
    /// A linked clone inherits the template's `ipfilter-net0` (its
    /// address); replace it with exactly the clone's own address. Fails if
    /// the inherited set is missing, so a clone without the template's
    /// firewall never gets one invented here.
    fn set_clone_ipfilter(&self, vmid: u16) -> Result<(), ScalerError> {
        let Some(address) = self.site.static_address(vmid)? else {
            return Ok(());
        };
        let path = format!(
            "{}/firewall/ipset/{}",
            self.site.qemu(vmid),
            super::site::IPFILTER_SET
        );
        let entries = self.request(PveCall::Get, &path)?;
        let entries = entries
            .as_array()
            .ok_or(ScalerError::External("ipfilter ipset entries"))?;
        let mut present = false;
        for entry in entries {
            let cidr = entry["cidr"]
                .as_str()
                .ok_or(ScalerError::External("ipfilter ipset cidr"))?;
            if cidr == address || cidr == format!("{address}/32") {
                present = true;
                continue;
            }
            if !cidr
                .bytes()
                .all(|b| b.is_ascii_digit() || b == b'.' || b == b'/')
            {
                return Err(ScalerError::Guard("unexpected ipfilter entry"));
            }
            self.request(
                PveCall::Delete,
                &format!("{path}/{}", cidr.replace('/', "%2F")),
            )?;
        }
        if !present {
            self.request(PveCall::Post(json!({ "cidr": address })), &path)?;
        }
        Ok(())
    }
    /// On an isolating site, refuse a VM (template or clone, before boot)
    /// whose PVE firewall is not exactly the site's, or a host whose
    /// datacenter firewall is off. A no-op on other sites.
    fn verify_vm_firewall(&self, vmid: u16) -> Result<(), ScalerError> {
        if !self.site.isolates_bridge() {
            return Ok(());
        }
        if !cluster_firewall_enabled(&std::fs::read_to_string("/etc/pve/firewall/cluster.fw")?) {
            return Err(ScalerError::Guard("datacenter firewall is not enabled"));
        }
        let base = self.site.qemu(vmid);
        let options = self.request(PveCall::Get, &format!("{base}/firewall/options"))?;
        let rules = self.request(PveCall::Get, &format!("{base}/firewall/rules"))?;
        let ipset = self.request(
            PveCall::Get,
            &format!("{base}/firewall/ipset/{}", super::site::IPFILTER_SET),
        )?;
        let address = self.site.static_address(vmid)?.ok_or(ScalerError::Guard(
            "isolating site without a static address",
        ))?;
        if vm_firewall_matches(&self.site, &options, &rules) && ipfilter_matches(&ipset, &address) {
            Ok(())
        } else {
            Err(ScalerError::Guard(
                "VM firewall does not match the site's isolation rules",
            ))
        }
    }
}
fn qualified_template(config: &Value, site: &Site) -> bool {
    // PVE 9 returns memory's decimal MiB quantity as a JSON string.
    let memory_mib = config["memory"].as_u64().or_else(|| {
        config["memory"]
            .as_str()
            .and_then(|value| value.parse::<u64>().ok())
    });
    let storage = format!("{}:", site.storage);
    let size = format!("size={}G", site.disk_gib);
    let bridge = format!("bridge={}", site.bridge);
    config["cpu"] == "host"
        && config["cores"] == site.cores
        && memory_mib == Some(site.memory_mib)
        && config["scsi0"].as_str().is_some_and(|s| {
            s.starts_with(&storage)
                && (s.contains(&size)
                    || (site.lane == CloneLane::Agent
                        && s.split(',').any(|field| {
                            field
                                .strip_prefix("size=")
                                .and_then(|v| v.strip_suffix('G'))
                                .and_then(|v| v.parse::<u32>().ok())
                                .is_some_and(|gib| gib >= site.disk_gib)
                        })))
        })
        && config["net0"].as_str().is_some_and(|s| {
            s.contains(&bridge) && (!site.isolates_bridge() || s.contains("firewall=1"))
        })
        && ksm_matches(config, site)
}
/// On a site that keeps CI out of KSM, the VM config must say
/// `allow-ksm: 0` (PVE's default is 1, and absence means 1).
fn ksm_matches(config: &Value, site: &Site) -> bool {
    site.allows_ksm()
        || config["allow-ksm"].as_u64() == Some(0)
        || config["allow-ksm"].as_str() == Some("0")
}

/// What a clone reported for its assignment rendezvous.
#[derive(Debug)]
enum GuestRendezvous {
    /// Approved, started (by its reservation or an approval) or draining.
    Settled,
    Open {
        /// The one-use runner already exited.
        finished: bool,
        request: Option<JobContext>,
    },
}
fn parse_guest_rendezvous(stdout: &str) -> Result<GuestRendezvous, ScalerError> {
    let (status, request) = stdout.split_once('\n').unwrap_or((stdout, ""));
    let finished = match status {
        "settled" => return Ok(GuestRendezvous::Settled),
        "finished" => true,
        "pending" => false,
        _ => return Err(ScalerError::External("guest assignment status")),
    };
    Ok(GuestRendezvous::Open {
        finished,
        request: assignment::parse_request(request.as_bytes())?,
    })
}
/// The standing transport of the shared assignment re-vet: the scoped guest
/// agent runs as root in the clone, under the job-start hook's flock.
struct GuestExchange<'a> {
    pve: &'a Pve,
    row: Record,
    /// Nothing more to serve on this clone.
    settled: bool,
}
impl assignment::AssignmentExchange for GuestExchange<'_> {
    fn read(&mut self) -> Result<Option<assignment::AssignmentRequest>, ScalerError> {
        let lock = format!("{GUEST_STATE}/admission.lock");
        let output = self.pve.agent(
            &self.row,
            &[
                "/usr/bin/flock",
                &lock,
                "/bin/sh",
                "-c",
                GUEST_ASSIGNMENT_READ,
            ],
        )?;
        match parse_guest_rendezvous(&output)? {
            GuestRendezvous::Settled => {
                self.settled = true;
                Ok(None)
            }
            GuestRendezvous::Open { finished, request } => {
                self.settled = finished;
                Ok(request.map(|context| assignment::AssignmentRequest {
                    context,
                    approved: false,
                    finished,
                }))
            }
        }
    }
    fn approve(&mut self, policy: &JobPolicy) -> Result<(), ScalerError> {
        let lock = format!("{GUEST_STATE}/admission.lock");
        let output = self.pve.agent_output(
            &self.row,
            &[
                "/usr/bin/flock",
                &lock,
                "/bin/sh",
                "-c",
                GUEST_ASSIGNMENT_APPROVE,
                "sh",
                &policy.render(),
            ],
        )?;
        match output.exit {
            GuestExit(0) => Ok(()),
            GuestExit(3) => Err(ScalerError::Guard("runner is draining")),
            GuestExit(4) => Err(ScalerError::Guard("assignment approval changed")),
            _ => Err(ScalerError::External("guest assignment approval")),
        }
    }
}
/// The standing transport of on-demand dispatch tokens (#1012).
struct GuestMint<'a> {
    pve: &'a Pve,
    row: Record,
}
impl GuestMint<'_> {
    fn run(
        &self,
        script: &str,
        arg: &str,
        input: Option<&str>,
    ) -> Result<GuestOutput, ScalerError> {
        let output =
            self.pve
                .agent_output_input(&self.row, &["/bin/sh", "-c", script, "sh", arg], input)?;
        match output.exit {
            GuestExit(0) => Ok(output),
            GuestExit(5) => Err(ScalerError::Guard("clone has no mint channel")),
            GuestExit(6) => Err(ScalerError::External("guest mint file lock held")),
            _ => Err(ScalerError::External("guest mint exchange")),
        }
    }
}
impl mint::MintExchange for GuestMint<'_> {
    fn read(&mut self) -> Result<Option<Vec<u8>>, ScalerError> {
        let output = self.run(GUEST_MINT_READ, "", None)?;
        Ok((!output.stdout.is_empty()).then(|| output.stdout.into_bytes()))
    }
    fn respond(&mut self, response: &mint::MintResponse) -> Result<(), ScalerError> {
        self.run(
            GUEST_MINT_RESPOND,
            "",
            Some(&serde_json::to_string(response)?),
        )
        .map(drop)
    }
    fn clear(&mut self, nonce: Option<&mint::MintNonce>) -> Result<(), ScalerError> {
        // The nonce is 32 hex digits; it is safe as an argument.
        self.run(
            GUEST_MINT_CLEAR,
            nonce.map_or("", mint::MintNonce::as_str),
            None,
        )
        .map(drop)
    }
}
/// How often one agent clone's request file is polled.
const MINT_POLL: Duration = Duration::from_secs(3);
/// Serve token requests from running, approved agent clones. Failures are
/// logged; the request stays pending and the tool server's bounded wait
/// falls back to the job token.
fn serve_mints(
    pve: &Pve,
    minter: &impl mint::MintApi,
    ledger: &mut Ledger,
    path: &Path,
    polled: &mut std::collections::BTreeMap<String, Instant>,
    held: &mut mint::HeldTokens,
) {
    let revoked = held.revoke_finished(minter, ledger);
    if revoked > 0 {
        println!("revoked {revoked} dispatch token(s) of finished clones");
    }
    polled.retain(|name, _| {
        ledger
            .rows
            .iter()
            .any(|r| r.name == *name && r.state == State::Running)
    });
    let open: Vec<Record> = ledger
        .rows
        .iter()
        .filter(|r| r.lane == CloneLane::Agent && r.state == State::Running && r.approved)
        .filter(|r| {
            polled
                .get(&r.name)
                .is_none_or(|at| at.elapsed() >= MINT_POLL)
        })
        .cloned()
        .collect();
    for row in open {
        polled.insert(row.name.clone(), Instant::now());
        let vm = row.vm.get();
        let name = row.name.clone();
        let mut exchange = GuestMint { pve, row };
        match mint::serve_mint(minter, &mut exchange, &name, ledger, path, held) {
            Ok(mint::MintServed::Idle) => {}
            Ok(mint::MintServed::Ignored) => {
                println!("vm={vm} token request ignored (malformed or already answered)");
            }
            Ok(mint::MintServed::Minted(scope)) => {
                println!("vm={vm} minted a {} token", scope.label());
            }
            Ok(mint::MintServed::Refused(reason)) => {
                println!("vm={vm} token request refused: {}", reason.describe());
            }
            Err(error) => eprintln!("vm={vm} token request failed: {error}; retried next poll"),
        }
    }
}
/// Serve every standing clone's assignment rendezvous (#333): GitHub may
/// assign a clone any queued job with its labels, not the one it was minted
/// for. Runs on a dedicated worker, independent of reconciliation, provisioning
/// and admission backoff. Failures are logged and
/// retried on the next poll; they never block reconciliation or reaping.
fn revet_assignments(
    pve: &Pve,
    gh: &Github,
    ledger: &mut Ledger,
    path: &Path,
    settled: &mut Vec<String>,
) {
    settled.retain(|name| {
        ledger
            .rows
            .iter()
            .any(|r| r.name == *name && r.state != State::Destroyed)
    });
    let open: Vec<Record> = ledger
        .rows
        .iter()
        .filter(|r| {
            matches!(r.state, State::Registered | State::Running)
                && r.runner.is_some()
                && !settled.contains(&r.name)
        })
        .cloned()
        .collect();
    for mut row in open {
        let mut exchange = GuestExchange {
            pve,
            row: row.clone(),
            settled: false,
        };
        let runner = row.runner;
        let outcome = assignment::serve_assignment(
            gh,
            &mut exchange,
            row.lane.labels(),
            runner,
            ledger,
            path,
            |ledger, key| {
                row.assigned = Some(key.job);
                row.assigned_key = Some(key);
                update(ledger, &row, path)
            },
        );
        let vm = row.vm.get();
        match outcome {
            Ok(Revetted::Idle) => {
                if exchange.settled {
                    settled.push(row.name);
                }
            }
            Ok(Revetted::Approved(key, policy)) => {
                println!(
                    "vm={vm} reserved job={} assigned run={} attempt={} job={}: re-vetted; approved {}",
                    row.key.job.0,
                    key.run.0,
                    key.attempt,
                    key.job.0,
                    policy.render()
                );
                settled.push(row.name);
            }
            Ok(Revetted::Refused(key) | Revetted::Recorded(key)) => {
                println!(
                    "vm={vm} reserved job={} assigned run={} attempt={} job={}: not approved",
                    row.key.job.0, key.run.0, key.attempt, key.job.0
                );
                settled.push(row.name);
            }
            Err(error) => {
                eprintln!("vm={vm} assignment re-vet failed: {error}; retried next poll");
            }
        }
    }
}

/// Controller poll period; admission retries back off separately.
const POLL: Duration = Duration::from_secs(30);

fn verify_protected_vms(
    site: site::Site,
    mut permissions: impl FnMut(u16) -> Result<Value, ScalerError>,
) -> Result<(), ScalerError> {
    // Protection follows the site, independently of controller mode or
    // whether agent clone demand is enabled. Only the source template may
    // carry the non-mutating rights needed to inspect and clone it.
    for vm in site.protected {
        let source_template = site.node == site::CONTABO.node && *vm == 9000;
        let protected = permissions(*vm)?;
        let source_required = source_template && site.lane == CloneLane::Agent;
        if (source_required && protected != json!({"/vms/9000": {"VM.Audit": 1, "VM.Clone": 1}}))
            || protected.as_object().is_none_or(|map| {
                map.values().any(|v| {
                    v.as_object().is_none_or(|rights| {
                        rights.iter().any(|(name, value)| {
                            !source_template
                                || !matches!(name.as_str(), "VM.Audit" | "VM.Clone")
                                || value.as_u64() != Some(1)
                        })
                    })
                })
            })
        {
            return Err(ScalerError::Guard(
                "token has unexpected protected-VM rights",
            ));
        }
    }
    Ok(())
}

fn verify_startup(
    site: Site,
    lanes: &[CloneLane],
    inventory: &[PoolMember],
    mut request: impl FnMut(&str) -> Result<Value, ScalerError>,
    mut firewall: impl FnMut(u16) -> Result<(), ScalerError>,
) -> Result<(), ScalerError> {
    for lane in lanes {
        let lane_pve = site.for_lane(*lane)?;
        let template = lane.template();
        if *lane == CloneLane::Agent {
            if inventory.iter().any(|v| v.id == template && v.pool == POOL) {
                return Err(ScalerError::Guard(
                    "agent template must be outside carrick-ci",
                ));
            }
        } else if !inventory
            .iter()
            .any(|v| v.id == template && v.template && v.pool == POOL)
        {
            return Err(ScalerError::Guard(
                "qualified lane template missing from carrick-ci",
            ));
        }
        // inventory() is /pools/carrick-ci, not /cluster/resources. The
        // source is deliberately absent there; VM.Audit licenses this lookup.
        let config = request(&format!("{}/config", site.qemu(template)))?;
        if *lane == CloneLane::Agent && config["template"].as_u64() != Some(1) {
            return Err(ScalerError::Guard("agent source is not a template"));
        }
        if !qualified_template(&config, &lane_pve) {
            return Err(ScalerError::Guard(
                "template does not match approved size/storage/bridge",
            ));
        }
        firewall(template)?;
    }
    let protected_site = if lanes.contains(&CloneLane::Agent) {
        site.for_lane(CloneLane::Agent)?
    } else {
        site
    };
    verify_protected_vms(protected_site, |vm| {
        request(&format!("/access/permissions?path=/vms/{vm}"))
    })?;
    Ok(())
}

/// Foreground Willow controller. The pilot admission always runs with one
/// clone; standing mode is bounded by `limit` (at most two clones).
pub(super) fn controller(
    admission: &Admission,
    dir: &Path,
    group: u64,
    one_job: bool,
    budget: CloneBudget,
) -> Result<(), ScalerError> {
    if matches!(admission, Admission::Pilot { .. }) && budget.kvm != Concurrency::ONE {
        return Err(ScalerError::Guard("the pilot admission is one clone only"));
    }
    let pve = Pve::local()?;
    let _lock = super::acquire_controller_lock(dir)?;
    let inventory = pve.inventory()?;
    let contabo_standing =
        pve.site.node == site::CONTABO.node && matches!(admission, Admission::Standing);
    let agents = contabo_standing && std::env::var("CARRICK_AGENT_CLONES").as_deref() != Ok("0");
    let lanes = if agents {
        vec![CloneLane::Kvm, CloneLane::Agent]
    } else {
        vec![CloneLane::Kvm]
    };
    verify_startup(
        pve.site,
        &lanes,
        &inventory,
        |path| pve.request(PveCall::Get, path),
        |vm| pve.verify_vm_firewall(vm),
    )?;
    let gh = Github;
    let path = dir.join("ledger.json");
    let mut ledger = Ledger::load(&path)?;
    let mut reconcile = Instant::now() - Duration::from_secs(60);
    let mut frozen = true;
    let mut backoff = Backoff::default();
    let mut admit_after = Instant::now();
    let provisioners = Provisioners::new();
    let publication = assignment::Publication::new(ledger.clone());
    ledger.publication = Some(publication.clone());
    let _assignments = if matches!(admission, Admission::Standing) {
        let publication = publication.worker();
        let path = path.clone();
        let assignment_pve = Pve::local()?;
        let mut settled = Vec::new();
        let minter = mint::AppMinter {
            gh: &Github,
            key: mint::AppKey::load()?,
        };
        if agents && !mint::MintApi::configured(&minter) {
            eprintln!(
                "no {} credential: dispatch token requests are refused",
                mint::KEY_CREDENTIAL
            );
        }
        let mut polled = std::collections::BTreeMap::new();
        let mut held = mint::HeldTokens::default();
        Some(assignment::AssignmentService::start(move || {
            let pass = (|| -> Result<(), ScalerError> {
                let mut ledger = publication.snapshot()?;
                ledger.publication = Some(publication.clone());
                revet_assignments(&assignment_pve, &Github, &mut ledger, &path, &mut settled);
                if agents {
                    serve_mints(
                        &assignment_pve,
                        &minter,
                        &mut ledger,
                        &path,
                        &mut polled,
                        &mut held,
                    );
                }
                Ok(())
            })();
            if let Err(error) = pass {
                eprintln!("assignment worker failed: {error}");
            }
        }))
    } else {
        None
    };
    loop {
        ledger.refresh()?;
        if reconcile.elapsed() >= Duration::from_secs(60) {
            let pass = reconcile_all(&pve, &gh, &mut ledger, dir, &path, (group, admission))?;
            if pass.finished > 0 && one_job {
                ledger.refresh()?;
                return one_job_result(ledger.rows.last());
            }
            frozen = match pass.frozen {
                Some(error) => {
                    eprintln!("reconcile failed: {error}; admission frozen for active ledger");
                    true
                }
                None => false,
            };
            reconcile = Instant::now();
        }
        let demand = if matches!(admission, Admission::Standing) {
            gh.coalesced_demand(&mut ledger, &path, &LABELS)
        } else {
            gh.demand(admission, &LABELS)
        };
        if let Err(error) = &demand {
            eprintln!("queued push coalescing failed: {error}");
        }
        let active = ledger
            .rows
            .iter()
            .filter(|r| r.state != State::Destroyed)
            .count();
        // A failed provisioning worker freezes admission exactly as a failed
        // in-line provision did.
        let mut provision_failed = None;
        for result in provisioners.finished() {
            match result {
                Ok(()) => {}
                Err(error @ ScalerError::CpuCeiling { .. }) => return Err(error),
                Err(error) => {
                    provision_failed.get_or_insert(error);
                }
            }
        }
        if let Some(error) = provision_failed {
            eprintln!("provisioning failed: {error}; backing off");
            frozen = true;
            backoff.grow();
            admit_after = Instant::now() + backoff.delay();
        }
        let cap = budget.of(CloneLane::Kvm)
            + if agents {
                budget.of(CloneLane::Agent)
            } else {
                0
            };
        if !frozen && active < cap && Instant::now() >= admit_after {
            // Admit until demand or the budget runs out; each worker boots
            // its clone while the next is reserved.
            let admitted = demand.and_then(|demand| {
                let mut admitted = active;
                while admitted < cap
                    && admit_one(
                        &pve,
                        &gh,
                        &mut ledger,
                        dir,
                        &path,
                        (group, admission, demand.clone()),
                        (budget, &provisioners),
                    )?
                {
                    admitted += 1;
                }
                Ok(())
            });
            match admitted {
                Ok(()) => backoff.reset(),
                Err(error @ ScalerError::CpuCeiling { .. }) => return Err(error),
                Err(error) => {
                    // Transient GitHub/PVE failures never end the controller.
                    eprintln!("admission pass failed: {error}; backing off");
                    frozen = true;
                    backoff.grow();
                    admit_after = Instant::now() + backoff.delay();
                }
            }
        }
        std::thread::sleep(POLL);
    }
}

/// Poll delay: 30 s, doubling on consecutive failures up to 10 minutes.
#[derive(Debug, Default)]
pub(super) struct Backoff(u32);
impl Backoff {
    pub(super) fn reset(&mut self) {
        self.0 = 0;
    }
    pub(super) fn grow(&mut self) {
        self.0 = (self.0 + 1).min(5);
    }
    pub(super) fn delay(&self) -> Duration {
        Duration::from_secs((30_u64 << self.0).min(600))
    }
}

fn select_demand(
    ledger: &mut Ledger,
    path: &Path,
    demand: Vec<JobKey>,
    vet: impl FnMut(JobKey) -> Result<JobKey, ScalerError>,
) -> Result<Option<JobKey>, ScalerError> {
    ledger.refresh()?;
    assignment::admit_demand(ledger, path, demand, vet)
}

fn reserve_admitted_clone(
    ledger: &mut Ledger,
    path: &Path,
    job: JobKey,
    capacity: (CloneBudget, CloneLane),
    admit: impl FnOnce() -> Result<bool, ScalerError>,
    inventory: impl FnOnce() -> Result<Vec<PoolMember>, ScalerError>,
) -> Result<Option<Record>, ScalerError> {
    if !admit()? {
        return Ok(None);
    }
    let inventory = inventory()?;
    ledger.refresh()?;
    if ledger.served(job) {
        return Ok(None);
    }
    let row = ledger.reserve_lane(job, &inventory, now()?, capacity.0, capacity.1)?;
    ledger.save(path)?;
    Ok(Some(row))
}

fn admit_one(
    pve: &Pve,
    gh: &Github,
    ledger: &mut Ledger,
    dir: &Path,
    path: &Path,
    demand: (u64, &Admission, Vec<JobKey>),
    (budget, provisioners): (CloneBudget, &Provisioners),
) -> Result<bool, ScalerError> {
    let (group, original_admission, kvm_demand) = demand;
    let agents = pve.site.node == site::CONTABO.node
        && matches!(original_admission, Admission::Standing)
        && std::env::var("CARRICK_AGENT_CLONES").as_deref() != Ok("0");
    let mut selected = None;
    for lane in [CloneLane::Kvm, CloneLane::Agent] {
        if lane == CloneLane::Agent && !agents {
            continue;
        }
        let cap = budget.of(lane);
        if ledger
            .rows
            .iter()
            .filter(|r| r.state != State::Destroyed && r.lane == lane)
            .count()
            >= cap
        {
            continue;
        }
        let policy = if lane == CloneLane::Agent {
            Admission::Agent
        } else {
            original_admission.clone()
        };
        if let Some(job) = select_demand(
            ledger,
            path,
            if lane == CloneLane::Kvm {
                kvm_demand.clone()
            } else {
                gh.demand(&policy, lane.labels())?
            },
            |job| gh.vet(&policy, job).map(|_| job),
        )? {
            selected = Some((lane, policy, job));
            break;
        }
    }
    let Some((lane, admission, job)) = selected else {
        return Ok(false);
    };
    let lane_pve = pve.for_lane(lane)?;
    let pve = &lane_pve;
    let admission = &admission;
    // Clones admitted but not yet running are charged at their nominal size.
    let pending = ledger.pending("", nominal(pve));
    let Some(row) = reserve_admitted_clone(
        ledger,
        path,
        job,
        (budget, lane),
        || {
            gh.vet(admission, job)?;
            match resource_admission(pve, pending) {
                Err(ScalerError::CpuCeiling { .. }) if lane == CloneLane::Agent => Ok(false),
                result => result,
            }
        },
        || pve.inventory(),
    )?
    else {
        return Ok(false);
    };
    println!("reserved vm={} job={}", row.vm.get(), job.job.0);
    provisioners.start(
        ledger,
        row,
        lane_pve,
        (dir, path),
        (group, admission.clone()),
    )?;
    Ok(true)
}

/// Provisioning workers (#1251): each owns one reserved row's lifecycle
/// through its own ledger publication until the clone runs or fails, so a
/// burst of jobs boots clones side by side instead of one per pass.
pub(super) struct Provisioners {
    results: std::sync::mpsc::Sender<Result<(), ScalerError>>,
    finished: std::sync::mpsc::Receiver<Result<(), ScalerError>>,
}
impl Provisioners {
    pub(super) fn new() -> Self {
        let (results, finished) = std::sync::mpsc::channel();
        Self { results, finished }
    }
    /// Hand `row` to a new worker. The claim is taken here, before the
    /// lifecycle loop's next save, and released when the worker ends,
    /// including by panic.
    fn start(
        &self,
        ledger: &Ledger,
        mut row: Record,
        pve: Pve,
        paths: (&Path, &Path),
        approval: (u64, Admission),
    ) -> Result<(), ScalerError> {
        let (publication, claim) = ledger
            .publication
            .as_ref()
            .ok_or(ScalerError::Guard(
                "provisioning needs a ledger publication",
            ))?
            .provisioner(&row.name)?;
        let mut owned = ledger.clone();
        owned.publication = Some(publication);
        let (dir, path) = (paths.0.to_owned(), paths.1.to_owned());
        let results = self.results.clone();
        std::thread::spawn(move || {
            let _claim = claim;
            let (group, admission) = approval;
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let provisioned = provision(
                    &pve,
                    &Github,
                    &mut owned,
                    &mut row,
                    &dir,
                    &path,
                    (group, &admission),
                );
                if let Err(error) = &provisioned {
                    row.failure = Some(error.to_string());
                    // Keep the provisioning error; reconcile recovers the row
                    // even if this record is lost.
                    if let Err(record) = update(&mut owned, &row, &path) {
                        eprintln!("vm={} failure not recorded: {record}", row.vm.get());
                    }
                }
                provisioned
            }))
            .unwrap_or(Err(ScalerError::Guard("provisioning worker panicked")));
            // The receiver outlives every worker unless the controller is
            // already exiting; then reconciliation recovers the row.
            let _ = results.send(result);
        });
        Ok(())
    }
    /// Results of workers that finished since the last call.
    fn finished(&self) -> Vec<Result<(), ScalerError>> {
        self.finished.try_iter().collect()
    }
}

#[cfg(test)]
#[path = "security_tests.rs"]
mod security_tests;

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    fn provisioning_ledger(dir: &Path, rows: u64) -> (Ledger, PathBuf) {
        let path = dir.join("ledger.json");
        let budget = CloneBudget {
            kvm: Concurrency::try_from(2).unwrap(),
            agents: "6".parse().unwrap(),
        };
        let mut ledger = Ledger::default();
        for n in 0..rows {
            let key = JobKey {
                run: RunId(10),
                attempt: 1,
                job: JobId(n),
            };
            ledger
                .reserve_lane(key, &[], n, budget, CloneLane::Agent)
                .unwrap();
        }
        let publication = assignment::Publication::new(ledger.clone());
        ledger.publication = Some(publication);
        ledger.save(&path).unwrap();
        (ledger, path)
    }
    fn committed(ledger: &Ledger, name: &str) -> Record {
        let mut fresh = ledger.clone();
        fresh.publication = Some(ledger.publication.as_ref().unwrap().worker());
        fresh.refresh().unwrap();
        fresh.rows.into_iter().find(|r| r.name == name).unwrap()
    }
    /// #1251 review: two clones provision at once. Each provisioner owns only
    /// its row; the lifecycle loop's stale saves, before and after a worker
    /// finishes, never revert either row; the loop's own change to a third
    /// row survives; and a provisioner keeps the assignment worker's decision.
    #[test]
    fn two_concurrent_provisioners_keep_every_lifecycle_write() {
        let temp = tempfile::tempdir().unwrap();
        let (mut lifecycle, path) = provisioning_ledger(temp.path(), 3);
        let names: Vec<String> = lifecycle.rows.iter().map(|r| r.name.clone()).collect();
        let publication = lifecycle.publication.clone().unwrap();
        let workers: Vec<_> = names[..2]
            .iter()
            .map(|name| {
                let (owned_publication, claim) = publication.provisioner(name).unwrap();
                let mut owned = lifecycle.clone();
                owned.publication = Some(owned_publication);
                let mut row = owned.rows.iter().find(|r| &r.name == name).unwrap().clone();
                let path = path.clone();
                std::thread::spawn(move || {
                    for state in [State::Cloning, State::Booting, State::Registered] {
                        row.state = state;
                        update(&mut owned, &row, &path).unwrap();
                    }
                    (owned, row, path, claim)
                })
            })
            .collect();
        // The assignment worker records a decision for the first row.
        let mut assignments = lifecycle.clone();
        assignments.publication = Some(publication.worker());
        assignments.rows[0].assigned_key = Some(lifecycle.rows[0].key);
        assignments.rows[0].approved = true;
        assignments.save(&path).unwrap();
        // The lifecycle loop, holding its pre-provisioning snapshot, edits the
        // third row and saves while both workers write.
        lifecycle.rows[2].failure = Some("lifecycle note".into());
        lifecycle.save(&path).unwrap();
        for worker in workers {
            let (mut owned, mut row, path, claim) = worker.join().unwrap();
            row.state = State::Running;
            update(&mut owned, &row, &path).unwrap();
            drop(claim);
        }
        // Still stale: released rows stay protected until the loop re-reads.
        lifecycle.save(&path).unwrap();
        for name in &names[..2] {
            assert_eq!(committed(&lifecycle, name).state, State::Running, "{name}");
        }
        lifecycle.refresh().unwrap();
        lifecycle.save(&path).unwrap();
        let first = committed(&lifecycle, &names[0]);
        assert_eq!((first.state, first.approved), (State::Running, true));
        assert_eq!(committed(&lifecycle, &names[1]).state, State::Running);
        assert_eq!(
            committed(&lifecycle, &names[2]).failure.as_deref(),
            Some("lifecycle note")
        );
        // A row has one owner at a time.
        let (_, held) = publication.provisioner(&names[2]).unwrap();
        assert!(publication.provisioner(&names[2]).is_err());
        drop(held);
    }
    /// #1251 review: clones still booting count at their nominal size, so a
    /// host whose live reading admits one more refuses it while two boot;
    /// the charge is released when a clone runs or retires. Driven through
    /// the controller's admission verdict and its storage floor.
    #[test]
    fn admission_is_refused_while_two_clones_boot() {
        let temp = tempfile::tempdir().unwrap();
        let (mut ledger, _) = provisioning_ledger(temp.path(), 3);
        for row in &mut ledger.rows[..2] {
            row.state = State::Booting;
        }
        let nominal = |_: CloneLane| (8, 20 << 10);
        let candidate = ledger.rows[2].name.clone();
        // 50 GiB free and 10% busy on 48 threads: one 20 GiB, 8-vCPU clone fits.
        let sample = HostSample {
            busy: 0.10,
            threads: 48,
            available: 50 << 30,
        };
        let admits = |pending| admission_verdict(&sample, (8, 20 << 10), pending).unwrap();
        assert!(admits(Pending::default()));
        let pending = ledger.pending(&candidate, nominal);
        assert_eq!(
            pending,
            Pending {
                clones: 2,
                cores: 16,
                memory_mib: 40 << 10
            }
        );
        assert!(!admits(pending));
        // Storage: 150 GiB plus 20 GiB per pending clone.
        let status = |free: u64| json!({"active":1,"enabled":1,"avail":free});
        assert!(directory_headroom(&status(170 << 30), storage_floor(Pending::default())).unwrap());
        assert!(!directory_headroom(&status(170 << 30), storage_floor(pending)).unwrap());
        // A pending charge defers; it never trips the fatal CPU ceiling.
        let busy_host = HostSample {
            busy: 0.60,
            ..sample
        };
        assert!(!admission_verdict(&busy_host, (8, 20 << 10), pending).unwrap());
        // One runs, the other retires: nothing is pending any more.
        ledger.rows[0].state = State::Running;
        ledger.rows[1].state = State::Reaping;
        assert_eq!(ledger.pending(&candidate, nominal), Pending::default());
        assert!(admits(ledger.pending(&candidate, nominal)));
    }
    /// #1251 review: only a provisioning worker waits at the pre-boot
    /// re-check; reconciliation resuming a clone fails at once, so it keeps
    /// reaping the clones whose exit would free the host.
    #[test]
    fn only_a_provisioning_worker_defers_at_pre_boot() {
        let start = Instant::now();
        assert!(PreBoot::FailFast.deadline() <= Instant::now());
        assert!(PreBoot::Defer.deadline() >= start + Duration::from_secs(600));
    }
    /// #1251 review P1: a reconcile pass lists its rows when it starts. A
    /// worker that takes its row to Running and releases it mid-pass must
    /// not be reconciled from the pass's stale copy (Registered), even after
    /// another row's refresh drained the release.
    #[test]
    fn reconcile_reads_a_row_released_mid_pass_from_the_ledger() {
        let temp = tempfile::tempdir().unwrap();
        let (mut lifecycle, path) = provisioning_ledger(temp.path(), 2);
        let name = lifecycle.rows[0].name.clone();
        let other = lifecycle.rows[1].name.clone();
        let publication = lifecycle.publication.clone().unwrap();
        let (owned_publication, claim) = publication.provisioner(&name).unwrap();
        let mut owned = lifecycle.clone();
        owned.publication = Some(owned_publication);
        let mut row = owned.rows[0].clone();
        row.state = State::Registered;
        update(&mut owned, &row, &path).unwrap();
        // The pass starts: its list holds the row at Registered, and owned.
        lifecycle.refresh().unwrap();
        let pass: Vec<Record> = lifecycle.rows.clone();
        assert!(reconcile_target(&mut lifecycle, &name).unwrap().is_none());
        // Mid-pass, on its own thread, the worker finishes and releases.
        let (go, wait) = std::sync::mpsc::channel::<()>();
        let worker_path = path.clone();
        let worker = std::thread::spawn(move || {
            wait.recv().unwrap();
            row.state = State::Running;
            update(&mut owned, &row, &worker_path).unwrap();
            drop(claim);
        });
        go.send(()).unwrap();
        worker.join().unwrap();
        // Another row's reconcile step refreshes, draining the release.
        assert!(reconcile_target(&mut lifecycle, &other).unwrap().is_some());
        // The pass reaches the row: its stale copy says Registered, but the
        // step reconciles the committed Running row and keeps it Running.
        assert_eq!(pass[0].state, State::Registered);
        let current = reconcile_target(&mut lifecycle, &name).unwrap().unwrap();
        assert_eq!(current.state, State::Running);
        update(&mut lifecycle, &current, &path).unwrap();
        assert_eq!(committed(&lifecycle, &name).state, State::Running);
    }
    /// #1251 review: a provisioning worker that dies mid-boot releases its
    /// row. Reconciliation may take it over (it is no longer live), and the
    /// loop's next snapshot carries the row's last committed state.
    #[test]
    #[allow(clippy::panic)]
    fn a_provisioner_dying_mid_boot_hands_its_row_back() {
        let temp = tempfile::tempdir().unwrap();
        let (mut lifecycle, path) = provisioning_ledger(temp.path(), 1);
        let name = lifecycle.rows[0].name.clone();
        let publication = lifecycle.publication.clone().unwrap();
        let (owned_publication, claim) = publication.provisioner(&name).unwrap();
        let mut owned = lifecycle.clone();
        owned.publication = Some(owned_publication);
        let mut row = owned.rows[0].clone();
        let worker_path = path.clone();
        let died = std::thread::spawn(move || {
            let _claim = claim;
            row.state = State::Booting;
            update(&mut owned, &row, &worker_path).unwrap();
            panic!("worker died mid-boot");
        })
        .join();
        assert!(died.is_err());
        // Until the loop re-reads, its stale copy (Reserved) can't win.
        lifecycle.save(&path).unwrap();
        assert_eq!(committed(&lifecycle, &name).state, State::Booting);
        // Released but not yet re-read: still skipped this step.
        let pass_list = reconcile_target(&mut lifecycle, &name).unwrap();
        assert!(pass_list.is_none(), "released, not yet re-read");
        // The next step re-reads and reconciles it at its last state.
        lifecycle.refresh().unwrap();
        assert!(publication.owners().owned().is_empty());
        let reclaimed = reconcile_target(&mut lifecycle, &name).unwrap().unwrap();
        assert_eq!(reclaimed.state, State::Booting);
    }
    /// #1251: the agent lane reserves up to `--max-agent-clones`, then
    /// refuses; the KVM lane keeps its own budget; out-of-range caps fail.
    #[test]
    fn the_agent_clone_budget_is_the_configured_cap() {
        assert!("0".parse::<AgentClones>().is_err());
        assert!("9".parse::<AgentClones>().is_err());
        assert_eq!("6".parse::<AgentClones>().unwrap().get(), 6);
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("ledger.json");
        let budget = CloneBudget {
            kvm: Concurrency::try_from(2).unwrap(),
            agents: "6".parse().unwrap(),
        };
        let mut ledger = Ledger::default();
        let job = |n: u64| JobKey {
            run: RunId(10),
            attempt: 1,
            job: JobId(n),
        };
        for n in 0..6 {
            let row = reserve_admitted_clone(
                &mut ledger,
                &path,
                job(n),
                (budget, CloneLane::Agent),
                || Ok(true),
                || Ok(Vec::new()),
            )
            .unwrap()
            .unwrap();
            assert_eq!(row.lane, CloneLane::Agent);
        }
        let seventh = reserve_admitted_clone(
            &mut ledger,
            &path,
            job(6),
            (budget, CloneLane::Agent),
            || Ok(true),
            || Ok(Vec::new()),
        );
        assert!(matches!(
            seventh,
            Err(ScalerError::Guard("clone concurrency budget occupied"))
        ));
        // The KVM lane is budgeted on its own.
        for n in 7..9 {
            reserve_admitted_clone(
                &mut ledger,
                &path,
                job(n),
                (budget, CloneLane::Kvm),
                || Ok(true),
                || Ok(Vec::new()),
            )
            .unwrap()
            .unwrap();
        }
        assert!(
            reserve_admitted_clone(
                &mut ledger,
                &path,
                job(9),
                (budget, CloneLane::Kvm),
                || Ok(true),
                || Ok(Vec::new()),
            )
            .is_err()
        );
    }
    #[test]
    fn admit_early_returns_never_reserve() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("ledger.json");
        let job = JobKey {
            run: RunId(10),
            attempt: 1,
            job: JobId(20),
        };

        // 1. Early return when resource_admission is false: inventory is
        // never queried and nothing is reserved.
        let mut ledger = Ledger::default();
        let reserved = reserve_admitted_clone(
            &mut ledger,
            &path,
            job,
            (
                CloneBudget {
                    kvm: Concurrency::ONE,
                    agents: AgentClones::DEFAULT,
                },
                CloneLane::Kvm,
            ),
            || Ok(false),
            || panic!("inventory must not be queried when resource_admission is false"),
        )
        .unwrap();
        assert!(reserved.is_none());

        // 2. Early return when ledger.served(job) is true.
        ledger.refused.push(job);
        let reserved = reserve_admitted_clone(
            &mut ledger,
            &path,
            job,
            (
                CloneBudget {
                    kvm: Concurrency::ONE,
                    agents: AgentClones::DEFAULT,
                },
                CloneLane::Kvm,
            ),
            || Ok(true),
            || Ok(Vec::new()),
        )
        .unwrap();
        assert!(reserved.is_none());

        // 3. Admitted, unserved demand is reserved.
        ledger.refused.clear();
        let reserved = reserve_admitted_clone(
            &mut ledger,
            &path,
            job,
            (
                CloneBudget {
                    kvm: Concurrency::ONE,
                    agents: AgentClones::DEFAULT,
                },
                CloneLane::Kvm,
            ),
            || Ok(true),
            || Ok(Vec::new()),
        )
        .unwrap();
        assert!(reserved.is_some());
    }

    #[test]
    fn ci_scaler_standing_inadmissible_demand_is_refused_before_reservation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ledger.json");
        let mut ledger = Ledger::default();
        let stale = JobKey {
            run: RunId(1),
            attempt: 1,
            job: JobId(1),
        };
        let live = JobKey {
            run: RunId(2),
            attempt: 1,
            job: JobId(2),
        };
        let selected = select_demand(&mut ledger, &path, vec![stale, live], |key| {
            if key == stale {
                Err(ScalerError::Guard("event is not admitted"))
            } else {
                Ok(key)
            }
        });
        assert_eq!(selected.unwrap(), Some(live));
        assert!(ledger.rows.is_empty());
        assert!(Ledger::load(&path).unwrap().served(stale));
    }

    #[test]
    fn serial_host_guest_payload_installs_exact_bytes_without_expansion() {
        let dir = tempfile::tempdir().unwrap();
        let pilot = Admission::pilot(&"a".repeat(40)).unwrap();
        for admission in [pilot, Admission::Standing, Admission::Agent] {
            for (i, script) in GUEST_SCRIPTS.iter().enumerate() {
                let source = guest_script_source(script, &admission).unwrap();
                let path = dir.path().join(format!("payload-{i}"));
                let status = Command::new("/bin/sh")
                    .args([
                        "-c",
                        &script_install_command(path.to_str().unwrap(), &source),
                    ])
                    .status()
                    .unwrap();
                assert!(status.success());
                assert_eq!(std::fs::read_to_string(&path).unwrap(), source);
                assert_eq!(
                    std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
                    0o755
                );
                // Only a standing clone's hook may fall back to a re-vet.
                let revet = script.path == HOOK_PATH
                    && matches!(admission, Admission::Standing | Admission::Agent);
                assert_eq!(source.contains("admit-job --controller"), revet);
            }
        }
    }
    /// Run a guest rendezvous script in `state` (standing in for
    /// `/run/carrick-ci`), as the guest agent does under the hook's flock.
    fn guest_script(state: &Path, script: &str, arg: &str) -> std::process::Output {
        let script = script.replace("/run/carrick-ci", state.to_str().unwrap());
        Command::new("/bin/sh")
            .args(["-c", &script, "sh", arg])
            .output()
            .unwrap()
    }
    /// A guest mint script in `state`, with `input` on stdin as `input-data`.
    /// Hosts without util-linux `flock` (macOS) run it unlocked.
    fn guest_mint(state: &Path, script: &str, input: &str) -> std::process::Output {
        guest_mint_arg(state, script, "", input)
    }
    fn guest_mint_arg(state: &Path, script: &str, arg: &str, input: &str) -> std::process::Output {
        let mut script = script.replace("/run/carrick-ci", state.to_str().unwrap());
        if !Path::new("/usr/bin/flock").exists() {
            script = script
                .replace("timeout 10 /usr/bin/flock -w 3 9", "true")
                .replace("timeout 10 head", "head");
        }
        let mut child = Command::new("/bin/sh")
            .args(["-c", &script, "sh", arg])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        // A refusing script exits before reading stdin, so the write may race
        // its exit and see EPIPE; the caller's status and file checks decide.
        match child.stdin.take().unwrap().write_all(input.as_bytes()) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => {}
            Err(error) => panic!("write guest mint input: {error}"),
        }
        child.wait_with_output().unwrap()
    }
    #[test]
    fn serial_host_guest_mint_scripts_round_trip_with_the_tool_server() {
        let state = tempfile::tempdir().unwrap();
        let state = state.path().to_owned();
        std::fs::write(
            state.join("approved-policy"),
            format!("agent run=41 attempt=2 sha={}\n", "a".repeat(40)),
        )
        .unwrap();
        // `read_policy` refuses a group-writable policy; don't inherit umask.
        std::fs::set_permissions(
            state.join("approved-policy"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        for file in [mint::REQUEST_FILE, mint::RESPONSE_FILE] {
            std::fs::write(state.join(file), "").unwrap();
        }
        // No channel files: the controller sees exit 5, never a created file.
        let empty = tempfile::tempdir().unwrap();
        assert_eq!(
            guest_mint(empty.path(), GUEST_MINT_READ, "").status.code(),
            Some(5)
        );
        assert!(!empty.path().join(mint::REQUEST_FILE).exists());
        let client_state = state.clone();
        let client = std::thread::spawn(move || {
            crate::dispatch_mint::request(
                &client_state,
                mint::MintScope::Board,
                Duration::from_secs(10),
                None,
            )
            .ok()
            .map(|token| token.secret().to_owned())
        });
        let deadline = Instant::now() + Duration::from_secs(5);
        let request: Value = loop {
            let output = guest_mint(&state, GUEST_MINT_READ, "");
            assert!(output.status.success());
            if let Ok(request) = serde_json::from_slice(&output.stdout) {
                break request;
            }
            assert!(Instant::now() < deadline, "no token request");
            std::thread::sleep(Duration::from_millis(20));
        };
        assert_eq!(request["scope"], "board");
        let response = json!({"status":"minted","nonce":request["nonce"],
            "token":"ghs_guestScriptFixture0123456789"});
        assert!(
            guest_mint(&state, GUEST_MINT_RESPOND, &response.to_string())
                .status
                .success()
        );
        // A clear for another nonce leaves the request in place.
        assert!(
            guest_mint_arg(&state, GUEST_MINT_CLEAR, &"0".repeat(32), "")
                .status
                .success()
        );
        assert!(
            !std::fs::read(state.join(mint::REQUEST_FILE))
                .unwrap()
                .is_empty()
        );
        assert!(
            guest_mint_arg(
                &state,
                GUEST_MINT_CLEAR,
                request["nonce"].as_str().unwrap(),
                ""
            )
            .status
            .success()
        );
        assert_eq!(
            client.join().unwrap().as_deref(),
            Some("ghs_guestScriptFixture0123456789")
        );
        for file in [mint::REQUEST_FILE, mint::RESPONSE_FILE] {
            assert!(
                std::fs::read(state.join(file)).unwrap().is_empty(),
                "{file}"
            );
        }
        // A planted link is refused, not written through.
        std::fs::remove_file(state.join(mint::RESPONSE_FILE)).unwrap();
        std::os::unix::fs::symlink(
            state.join("approved-policy"),
            state.join(mint::RESPONSE_FILE),
        )
        .unwrap();
        assert_eq!(
            guest_mint(&state, GUEST_MINT_RESPOND, &"overwrite".repeat(16 * 1024))
                .status
                .code(),
            Some(5)
        );
        assert!(
            std::fs::read_to_string(state.join("approved-policy"))
                .unwrap()
                .starts_with("agent ")
        );
    }
    /// A runner holding the request lock cannot stall the controller.
    #[cfg(target_os = "linux")]
    #[test]
    fn serial_host_guest_mint_scripts_fail_fast_on_a_held_lock() {
        use std::os::unix::io::AsRawFd;
        let state = tempfile::tempdir().unwrap();
        for file in [mint::REQUEST_FILE, mint::RESPONSE_FILE] {
            std::fs::write(state.path().join(file), "{}").unwrap();
        }
        let held = File::open(state.path().join(mint::REQUEST_FILE)).unwrap();
        // SAFETY: flock on a descriptor this test owns.
        assert_eq!(unsafe { libc::flock(held.as_raw_fd(), libc::LOCK_EX) }, 0);
        for script in [GUEST_MINT_READ, GUEST_MINT_CLEAR] {
            let start = Instant::now();
            let output = guest_mint(state.path(), script, "");
            assert_eq!(output.status.code(), Some(6));
            assert!(start.elapsed() < Duration::from_secs(8));
        }
        assert_eq!(
            std::fs::read_to_string(state.path().join(mint::REQUEST_FILE)).unwrap(),
            "{}"
        );
    }
    #[test]
    fn serial_host_guest_rendezvous_does_not_follow_assignment_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        let secret = dir.path().join("secret");
        std::fs::write(&secret, "must-not-read").unwrap();
        std::os::unix::fs::symlink(&secret, dir.path().join("assignment.json")).unwrap();
        let output = guest_script(dir.path(), GUEST_ASSIGNMENT_READ, "");
        assert!(!String::from_utf8_lossy(&output.stdout).contains("must-not-read"));
    }

    #[test]
    fn serial_host_guest_rendezvous_reads_requests_and_publishes_one_approval() {
        // The shell halves use the same state directory and request bound.
        for script in [GUEST_ASSIGNMENT_READ, GUEST_ASSIGNMENT_APPROVE] {
            assert!(script.starts_with(&format!("cd {GUEST_STATE} ")));
        }
        assert!(GUEST_ASSIGNMENT_READ.contains(&format!(
            "head -c {} assignment.json",
            assignment::REQUEST_LIMIT + 1
        )));
        let state = tempfile::tempdir().unwrap();
        let state = state.path();
        std::fs::set_permissions(state, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(state.join("admission.lock"), "").unwrap();
        std::fs::write(state.join("assignment.json"), "").unwrap();
        let read = |state: &Path| {
            let output = guest_script(state, GUEST_ASSIGNMENT_READ, "");
            assert!(output.status.success());
            parse_guest_rendezvous(std::str::from_utf8(&output.stdout).unwrap()).unwrap()
        };
        // Before the hook asks: open, no request.
        assert!(matches!(
            read(state),
            GuestRendezvous::Open {
                finished: false,
                request: None
            }
        ));
        // The real hook rendezvous writes run B's request (and then waits).
        let b = JobContext {
            repository: REPOSITORY.into(),
            actor: "tjfontaine".into(),
            triggering_actor: "tjfontaine".into(),
            event: "workflow_dispatch".into(),
            workflow_ref: format!("{REPOSITORY}/{KERNEL_RUNTIME_WORKFLOW}@refs/heads/main"),
            git_ref: "refs/heads/main".into(),
            sha: "b".repeat(40),
            run_id: 20,
            run_attempt: 1,
        };
        let uid = unsafe { libc::geteuid() };
        assert!(admit_assigned(state, &b, uid, Duration::ZERO).is_err());
        let GuestRendezvous::Open {
            finished: false,
            request: Some(request),
        } = read(state)
        else {
            panic!("hook request not visible to the controller");
        };
        assert_eq!((request.run_id, request.sha.as_str()), (20, b.sha.as_str()));
        // Approval for B: published once, idempotent, never replaced.
        let policy = JobPolicy::Bound(RunBinding {
            run: RunId(20),
            attempt: 1,
            sha: b.sha.clone(),
        });
        assert_eq!(approve_in(state, &policy), Some(0));
        assert_eq!(approve_in(state, &policy), Some(0));
        let other = JobPolicy::Bound(RunBinding {
            run: RunId(10),
            attempt: 1,
            sha: "a".repeat(40),
        });
        assert_eq!(approve_in(state, &other), Some(4));
        // The hook accepts exactly that root-owned (here: owner-owned) policy.
        assert_eq!(
            read_policy(&state.join("approved-policy"), Some(uid)).unwrap(),
            policy
        );
        assert!(admit_assigned(state, &b, uid, Duration::ZERO).is_ok());
        assert!(matches!(read(state), GuestRendezvous::Settled));
        // A draining clone never receives an approval.
        let drained = tempfile::tempdir().unwrap();
        std::fs::write(drained.path().join("admission.lock"), "").unwrap();
        std::fs::write(drained.path().join("draining"), "").unwrap();
        assert_eq!(approve_in(drained.path(), &policy), Some(3));
        assert!(!drained.path().join("approved-policy").exists());
        assert!(matches!(read(drained.path()), GuestRendezvous::Settled));
        assert!(parse_guest_rendezvous("bogus\n").is_err());
    }
    fn approve_in(state: &Path, policy: &JobPolicy) -> Option<i32> {
        guest_script(state, GUEST_ASSIGNMENT_APPROVE, &policy.render())
            .status
            .code()
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
        let vm = CloneId::try_from(308).unwrap();
        let config = clone_config(
            "ssh-ed25519 AAAA+/= validation-only\n",
            &super::site::WILLOW,
            vm,
        )
        .unwrap();
        assert_eq!(
            config["sshkeys"],
            "ssh-ed25519%20AAAA%2B%2F%3D%20validation-only%0A"
        );
        assert_eq!(config["cores"], 2);
        assert_eq!(config["cpulimit"], 2);
        assert_eq!(config["memory"], 4096);
        // Willow's clone configuration is unchanged: DHCP, no nameserver key.
        assert_eq!(config["ipconfig0"], "ip=dhcp");
        assert!(config.get("nameserver").is_none());
        let config = clone_config("ssh-ed25519 AAAA\n", &super::site::CONTABO, vm).unwrap();
        assert_eq!(config["cores"], 8);
        assert_eq!(config["cpulimit"], 8);
        assert_eq!(config["memory"], 16384);
        assert_eq!(config["ipconfig0"], "ip=10.77.0.108/24,gw=10.77.0.1");
        assert_eq!(config["nameserver"], "1.1.1.1");
        // #1265: no clone upgrades its packages at boot, on any site.
        for site in [&super::site::WILLOW, &super::site::CONTABO] {
            let config = clone_config("ssh-ed25519 AAAA\n", site, vm).unwrap();
            assert_eq!(config["ciupgrade"], 0);
        }
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
        let approved = Admission::pilot(&sha).unwrap();
        assert!(pending_owned_job(&row, &job, &run, &approved));
        job["status"] = json!("completed");
        assert!(!pending_owned_job(&row, &job, &run, &approved));
        job["status"] = json!("queued");
        run["run_attempt"] = json!(row.key.attempt + 1);
        assert!(!pending_owned_job(&row, &job, &run, &approved));
        run["run_attempt"] = json!(row.key.attempt);
        assert!(!pending_owned_job(
            &row,
            &job,
            &run,
            &Admission::pilot(&"b".repeat(40)).unwrap()
        ));
        // A standing controller never resumes a pilot clone's job.
        assert!(!pending_owned_job(&row, &job, &run, &Admission::Standing));
        job["labels"] = json!(["self-hosted", "Linux", "X64", "willow-kvm", "extra"]);
        assert!(!pending_owned_job(&row, &job, &run, &approved));
    }
    #[test]
    fn director_cpu_ceiling_is_a_stop_condition_above_eighty_percent() {
        assert!(enforce_cpu_ceiling(0.675, 16, 2).is_ok());
        assert!(matches!(
            enforce_cpu_ceiling(0.676, 16, 2),
            Err(ScalerError::CpuCeiling { .. })
        ));
    }
    #[test]
    fn pool_membership_does_not_require_a_cached_display_name() {
        let pool = json!({"poolid":POOL,"members":[
            {"type":"qemu","node":"willow","vmid":308,"template":0}
        ]});
        let members = pool_inventory(&pool, "willow").unwrap();
        // Membership on another site's node is foreign, never adopted.
        assert!(pool_inventory(&pool, "carrick-ctb").is_err());
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
            ..Ledger::default()
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
        let willow = &super::site::WILLOW;
        let contabo = &super::site::CONTABO;
        assert!(qualified_template(&config, willow));
        // A Willow-shaped template never qualifies on another site.
        assert!(!qualified_template(&config, contabo));
        config["memory"] = json!(4096);
        assert!(qualified_template(&config, willow));
        for memory in [json!(8192), json!("8192"), json!("4096MiB"), json!(null)] {
            config["memory"] = memory;
            assert!(!qualified_template(&config, willow));
        }
        let mut config = json!({
            "cpu":"host", "cores":8, "memory":"16384",
            "scsi0":"local:300/base-300-disk-0.qcow2,size=100G",
            "net0":"virtio=BC:24:11:00:00:01,bridge=vmbr1,firewall=1",
            "allow-ksm":0
        });
        assert!(qualified_template(&config, contabo));
        // Without `allow-ksm: 0` (PVE default 1) a Contabo template is refused.
        config.as_object_mut().unwrap().remove("allow-ksm");
        assert!(!qualified_template(&config, contabo));
        config["allow-ksm"] = json!(0);
        assert!(!qualified_template(&config, willow));
        config["net0"] = json!("virtio=BC:24:11:00:00:01,bridge=vmbr0,firewall=1");
        assert!(!qualified_template(&config, contabo));
        // On a shared private bridge the PVE VM firewall is mandatory.
        config["net0"] = json!("virtio=BC:24:11:00:00:01,bridge=vmbr1");
        assert!(!qualified_template(&config, contabo));
    }
    #[test]
    fn vm_firewall_check_is_exact_and_fails_closed() {
        let site = &super::site::CONTABO;
        let blocked = site.blocked().unwrap();
        assert!(blocked.ends_with(",100.64.0.0/10,154.38.161.112"));
        let options =
            json!({"enable":1,"ipfilter":1,"macfilter":1,"policy_in":"DROP","policy_out":"DROP"});
        let rules = json!([
            {"pos":2,"type":"out","action":"ACCEPT","dest":"0.0.0.0/0","enable":1,"log":"nolog"},
            {"pos":0,"type":"in","action":"ACCEPT","source":"10.77.0.1","proto":"tcp","dport":"22","enable":1},
            {"pos":1,"type":"out","action":"DROP","dest":blocked,"enable":1}
        ]);
        assert!(vm_firewall_matches(site, &options, &rules));
        // Willow has no VM firewall to match.
        assert!(!vm_firewall_matches(&super::site::WILLOW, &options, &rules));
        for (field, value) in [
            ("enable", json!(0)),
            ("ipfilter", json!(0)),
            ("macfilter", json!(0)),
            ("policy_out", json!("ACCEPT")),
            ("policy_in", json!("ACCEPT")),
        ] {
            let mut weakened = options.clone();
            weakened[field] = value;
            assert!(!vm_firewall_matches(site, &weakened, &rules), "{field}");
        }
        let mut missing = options.clone();
        missing.as_object_mut().unwrap().remove("policy_out");
        assert!(!vm_firewall_matches(site, &missing, &rules));
        let mutate = |index: usize, field: &str, value: Value| {
            let mut changed = rules.clone();
            changed[index][field] = value;
            changed
        };
        for changed in [
            mutate(0, "enable", json!(0)),
            mutate(0, "dest", json!(super::site::PRIVATE_V4)),
            mutate(2, "dest", json!(super::site::PRIVATE_V4)),
            mutate(1, "source", json!("10.77.0.0/24")),
            mutate(1, "dport", json!("1:65535")),
            mutate(2, "dest", json!("10.77.0.0/24")),
            mutate(2, "iface", json!("net0")),
        ] {
            assert!(!vm_firewall_matches(site, &options, &changed));
        }
        let mut extra = rules.clone();
        extra
            .as_array_mut()
            .unwrap()
            .push(json!({"pos":3,"type":"out","action":"ACCEPT","enable":1}));
        assert!(!vm_firewall_matches(site, &options, &extra));
        assert!(!vm_firewall_matches(site, &options, &json!([])));
        // Order matters: ACCEPT any before DROP private would open the subnet.
        let reordered = json!([
            {"pos":0,"type":"in","action":"ACCEPT","source":"10.77.0.1","proto":"tcp","dport":"22","enable":1},
            {"pos":1,"type":"out","action":"ACCEPT","dest":"0.0.0.0/0","enable":1},
            {"pos":2,"type":"out","action":"DROP","dest":blocked,"enable":1}
        ]);
        assert!(!vm_firewall_matches(site, &options, &reordered));
    }
    #[test]
    fn ksm_is_refused_only_where_the_site_keeps_ci_out() {
        let contabo = &super::site::CONTABO;
        let willow = &super::site::WILLOW;
        for config in [json!({"allow-ksm":0}), json!({"allow-ksm":"0"})] {
            assert!(ksm_matches(&config, contabo));
        }
        // Absent means PVE's default, 1: refused on Contabo.
        for config in [json!({}), json!({"allow-ksm":1}), json!({"allow-ksm":"1"})] {
            assert!(!ksm_matches(&config, contabo), "{config}");
            // Willow keeps the default and needs nothing.
            assert!(ksm_matches(&config, willow));
        }
    }
    #[test]
    fn ipfilter_holds_exactly_the_vms_own_address() {
        let ip = "10.77.0.108";
        assert!(ipfilter_matches(&json!([{"cidr":ip}]), ip));
        assert!(ipfilter_matches(
            &json!([{"cidr":"10.77.0.108/32","nomatch":0}]),
            ip
        ));
        for set in [
            json!([]),
            json!([{"cidr":"10.77.0.100"}]),
            json!([{"cidr":ip},{"cidr":"10.77.0.11"}]),
            json!([{"cidr":"10.77.0.0/24"}]),
            json!([{"cidr":ip,"nomatch":1}]),
            json!(null),
        ] {
            assert!(!ipfilter_matches(&set, ip), "{set}");
        }
    }
    #[test]
    fn cluster_firewall_must_be_enabled_in_options() {
        assert!(cluster_firewall_enabled(
            "[OPTIONS]\nenable: 1\npolicy_in: DROP\n\n[RULES]\nIN SSH(ACCEPT)\n"
        ));
        assert!(!cluster_firewall_enabled("[OPTIONS]\nenable: 0\n"));
        assert!(!cluster_firewall_enabled("[OPTIONS]\npolicy_in: DROP\n"));
        assert!(!cluster_firewall_enabled("[RULES]\nenable: 1\n"));
        assert!(!cluster_firewall_enabled(""));
    }
    #[test]
    fn directory_storage_admits_only_active_storage_with_free_space() {
        let free = 150_u64 << 30;
        let status = |active: u64, avail: u64| json!({"active":active,"enabled":1,"avail":avail});
        assert!(directory_headroom(&status(1, free), free).unwrap());
        assert!(!directory_headroom(&status(1, free - 1), free).unwrap());
        assert!(directory_headroom(&status(0, free * 4), free).is_err());
        assert!(directory_headroom(&json!({"active":1,"enabled":1}), free).is_err());
        assert!(directory_headroom(&json!({"active":1,"enabled":0,"avail":free}), free).is_err());
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
                Concurrency::ONE,
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
}
