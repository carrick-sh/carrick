//! Root-only qualification on the template's PVE node. Never uses controller
//! identities, VMIDs, registration credentials, or the runner pool.
use super::{CloneLane, ScalerError, execute, live, site};
use serde_json::Value;
use std::{
    path::Path,
    process::Command,
    time::{Duration, Instant},
};

const VM: &str = "9501";
// Restrict empty-file checks to executable/configuration authority. Empty
// machine-id and authorized_keys after cloud-init clean are intentional.
const HEALTH: &str = r#"set -eu
for file in /etc/systemd/system/carrick-ci-ready.service /usr/local/bin/carrick-ci-ready /usr/local/bin/carrick-ci-run-once /usr/local/bin/carrick-ci-admit-job.sh /var/lib/carrick-ci/qualification.json; do
  test -s "$file" || { echo "empty or missing critical file: $file" >&2; exit 1; }
done
empty=$(find /etc/systemd/system /usr/local/bin -type f -size 0 -print)
test -z "$empty" || { printf 'empty critical files:\n%s\n' "$empty" >&2; exit 1; }
journalctl -k -b --no-pager > /run/carrick-qualification-kernel.log
test -s /run/carrick-qualification-kernel.log
if grep -Ei 'EXT4-fs.*(recovery|recovering)' /run/carrick-qualification-kernel.log; then
  echo 'template filesystem required journal recovery' >&2; exit 1
fi
"#;

fn command(args: &[&str], deadline: Instant) -> Result<String, ScalerError> {
    bounded(args, deadline, Duration::from_secs(300))
}
/// [`command`] with its own per-command cap.
fn bounded(args: &[&str], deadline: Instant, cap: Duration) -> Result<String, ScalerError> {
    let (program, args) = args
        .split_first()
        .ok_or(ScalerError::Guard("empty command"))?;
    let duration = deadline.saturating_duration_since(Instant::now()).min(cap);
    if duration.is_zero() {
        return Err(ScalerError::External("clone qualification deadline"));
    }
    String::from_utf8(execute(Command::new(program).args(args), &[], duration)?)
        .map_err(|_| ScalerError::Guard("non UTF-8 qualification output"))
}
fn guest(args: &[&str], deadline: Instant) -> Result<live::GuestOutput, ScalerError> {
    let mut cmd = vec!["qm", "guest", "exec", VM, "--timeout", "25", "--"];
    cmd.extend_from_slice(args);
    let value: Value = serde_json::from_str(&command(&cmd, deadline)?)?;
    if value["exited"] != 1 && value["exited"] != true {
        return Err(ScalerError::External(
            "qualification guest command unfinished",
        ));
    }
    if value["exitcode"] != 0 {
        eprintln!(
            "qualification guest command failed: {}\n{}",
            args.join(" "),
            value["err-data"].as_str().unwrap_or_default()
        );
    }
    Ok(live::GuestOutput {
        exit: live::GuestExit(
            value["exitcode"]
                .as_i64()
                .and_then(|n| i32::try_from(n).ok())
                .ok_or(ScalerError::External("missing guest exit code"))?,
        ),
        stdout: value["out-data"].as_str().unwrap_or_default().to_owned(),
    })
}
fn checked_guest(args: &[&str], deadline: Instant) -> Result<String, ScalerError> {
    let output = guest(args, deadline)?;
    if output.exit != live::GuestExit(0) {
        return Err(ScalerError::External("clone health check failed"));
    }
    Ok(output.stdout)
}

pub(super) fn run(template: u16) -> Result<(), ScalerError> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(ScalerError::Guard(
            "clone qualification requires root on PVE",
        ));
    }
    let site = site::Site::local()?
        .for_lane(CloneLane::Agent)?
        .with_template(Some(template))?;
    let template = template.to_string();
    let prepare = Instant::now() + Duration::from_secs(300);
    // Listing must succeed; a failed status call is not proof of absence.
    let inventory: Value = serde_json::from_str(&command(
        &[
            "pvesh",
            "get",
            "/cluster/resources",
            "--type",
            "vm",
            "--output-format",
            "json",
        ],
        prepare,
    )?)?;
    let rows = inventory
        .as_array()
        .ok_or(ScalerError::Guard("invalid VM inventory"))?;
    if rows.iter().any(|row| row["vmid"].as_u64() == Some(9501))
        || Path::new("/etc/pve/firewall/9501.fw").exists()
    {
        return Err(ScalerError::Guard(
            "qualification slot 9501 is occupied; inspect before retry",
        ));
    }
    let config = command(&["qm", "config", &template], prepare)?;
    if !config.lines().any(|line| line == "template: 1") {
        return Err(ScalerError::Guard("qualification source is not a template"));
    }
    let net = config
        .lines()
        .find_map(|line| line.strip_prefix("net0: "))
        .ok_or(ScalerError::Guard("qualification template lacks net0"))?;
    if !net.split(',').any(|field| field == "firewall=1")
        || !net
            .split(',')
            .any(|field| field == format!("bridge={}", site.bridge))
    {
        return Err(ScalerError::Guard(
            "qualification template lacks isolating NIC",
        ));
    }
    let dir = tempfile::tempdir()?;
    let key = dir.path().join("key");
    let key = key.to_str().ok_or(ScalerError::Guard("invalid key path"))?;
    command(
        &["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key],
        prepare,
    )?;
    // No --pool, and a name the standing controller cannot adopt.
    command(
        &[
            "qm",
            "clone",
            &template,
            VM,
            "--full",
            "0",
            "--name",
            "template-qualification-9501",
        ],
        prepare,
    )?;
    let result = (|| {
        let pubkey = format!("{key}.pub");
        command(
            &[
                "qm",
                "set",
                VM,
                "--ciuser",
                "runner",
                "--ciupgrade",
                "0",
                "--sshkeys",
                &pubkey,
                "--ipconfig0",
                &site.ipconfig(9501)?,
                "--nameserver",
                site.nameserver()
                    .ok_or(ScalerError::Guard("qualification needs static site"))?,
            ],
            prepare,
        )?;
        let firewall = site
            .vm_firewall_file(9501)?
            .ok_or(ScalerError::Guard("qualification needs isolating firewall"))?;
        std::fs::write("/etc/pve/firewall/9501.fw", firewall)?;
        let deadline = Instant::now() + Duration::from_secs(300);
        command(&["qm", "start", VM], deadline)?;
        live::wait_for_readiness(deadline, || {
            live::qualify_guest(super::RunnerKind::Vm, |args| guest(args, deadline))?;
            // Pin the key through the authenticated guest agent, exactly as the
            // controller does; prove the SSH readiness path without registering JIT.
            let hostkey =
                checked_guest(&["/bin/cat", "/etc/ssh/ssh_host_ed25519_key.pub"], deadline)?;
            if !hostkey.starts_with("ssh-ed25519 ") || hostkey.lines().count() != 1 {
                return Err(ScalerError::Guard("invalid clone host key"));
            }
            let ip = site
                .static_address(9501)?
                .ok_or(ScalerError::Guard("missing qualification IP"))?;
            let hosts = dir.path().join("known_hosts");
            std::fs::write(&hosts, format!("{ip} {}\n", hostkey.trim()))?;
            live::ssh_transport(
                Path::new(key),
                &hosts,
                ip.parse()
                    .map_err(|_| ScalerError::Guard("invalid qualification address"))?,
                &[],
                "test -x /usr/local/bin/carrick-ci-run-once",
                Some(deadline),
            )?;
            Ok(())
        })?;
        checked_guest(&["/bin/sh", "-c", HEALTH], deadline)?;
        checked_guest(
            &[
                "/usr/sbin/runuser",
                "-u",
                "carrick-dispatch-agent",
                "--",
                "/usr/local/bin/carrick-xtask",
                "ci-scaler",
                "verify-kvm",
            ],
            deadline,
        )?;
        let manifest: Value = serde_json::from_str(&checked_guest(
            &["/bin/cat", "/var/lib/carrick-ci/qualification.json"],
            deadline,
        )?)?;
        if manifest["kvm_api"] != 12 || manifest["runner_registered"] != false {
            return Err(ScalerError::Guard("invalid clone qualification manifest"));
        }
        Ok(manifest)
    })();
    if let Err(error) = &result {
        eprintln!("clone qualification failed: {error}");
        let diagnostic_deadline = Instant::now() + Duration::from_secs(30);
        match guest(
            &[
                "/bin/sh",
                "-c",
                "cloud-init status --long; ip -4 address; ip route; systemctl status carrick-ci-ready.service --no-pager; journalctl -b -u cloud-final -u ssh -u carrick-ci-ready --no-pager -n 100; tail -c 16384 /var/log/cloud-init-output.log",
            ],
            diagnostic_deadline,
        ) {
            Ok(output) => eprintln!("clone diagnosis:\n{}", output.stdout),
            Err(error) => eprintln!("clone diagnostics unavailable: {error}"),
        }
    }
    // Cleanup has its own bounded deadline, including when readiness expired.
    let cleanup = Instant::now() + Duration::from_secs(360);
    let stop = command(&["qm", "stop", VM], cleanup);
    let destroy = stop.and_then(|_| command(&["qm", "destroy", VM, "--purge", "1"], cleanup));
    if let Err(error) = destroy {
        eprintln!(
            "qualification cleanup failed for VM 9501: {error}; inspect VM and firewall before retry"
        );
        return Err(error);
    }
    let manifest = result?;
    println!(
        "{}",
        serde_json::json!({"template":template,"clone":9501,"ready":true,"qualification":manifest})
    );
    Ok(())
}

/// The checks of [`HEALTH`] that hold in a container. An unprivileged
/// container cannot read the kernel journal, and its rootfs has no journal
/// replay of its own to detect; instead it proves the agent-retirement
/// census can read `/proc` and enumerate processes by uid.
const CONTAINER_HEALTH: &str = r#"set -eu
for file in /etc/systemd/system/carrick-ci-ready.service /usr/local/bin/carrick-ci-ready /usr/local/bin/carrick-ci-run-once /usr/local/bin/carrick-ci-admit-job.sh /var/lib/carrick-ci/qualification.json; do
  test -s "$file" || { echo "empty or missing critical file: $file" >&2; exit 1; }
done
empty=$(find /etc/systemd/system /usr/local/bin -type f -size 0 -print)
test -z "$empty" || { printf 'empty critical files:\n%s\n' "$empty" >&2; exit 1; }
test -r /proc/self/stat
for account in runner carrick-dispatch-agent carrick-dispatch-loop; do id -u "$account" >/dev/null; done
pgrep -u root >/dev/null
test -c /dev/kvm
"#;

/// Remove container 9501 whatever state qualification left it in: a copy
/// interrupted mid-clone stays locked (`create`) and owns a volume its
/// configuration does not list yet, so `pct destroy` alone would leak it.
fn destroy_container(site: &site::Site) -> Result<(), ScalerError> {
    let cleanup = Instant::now() + Duration::from_secs(360);
    if command(&["pct", "status", VM], cleanup).is_ok() {
        // Stop fails on a container that never started and unlock on one
        // that holds no lock; destroy decides.
        let _ = command(&["pct", "stop", VM], cleanup);
        let _ = command(&["pct", "unlock", VM], cleanup);
        command(&["pct", "destroy", VM, "--purge", "1"], cleanup)?;
    }
    // `pct destroy` exits 0 with only a task warning when it cannot take the
    // storage lock to delete the rootfs (live on ctb, where clone traffic
    // holds `local`'s lock), so prove the volumes are gone, retrying frees
    // across lock timeouts, and fail loudly instead of leaking 5.5 GB.
    let mut leaked = Vec::new();
    while Instant::now() < cleanup {
        leaked = container_volumes(site, cleanup)?;
        if leaked.is_empty() {
            return Ok(());
        }
        for volid in &leaked {
            if let Err(error) = command(&["pvesm", "free", volid], cleanup) {
                eprintln!("qualification volume {volid} not freed yet: {error}");
            }
        }
        std::thread::sleep(Duration::from_secs(5));
    }
    eprintln!("qualification volumes leaked: {}", leaked.join(", "));
    Err(ScalerError::External(
        "qualification container volume leaked",
    ))
}
/// Volumes the clone storage still lists for slot 9501.
fn container_volumes(site: &site::Site, deadline: Instant) -> Result<Vec<String>, ScalerError> {
    let volumes: Value = serde_json::from_str(&command(
        &[
            "pvesh",
            "get",
            &format!("/nodes/{}/storage/{}/content", site.node, site.storage),
            "--vmid",
            VM,
            "--output-format",
            "json",
        ],
        deadline,
    )?)?;
    volumes
        .as_array()
        .ok_or(ScalerError::Guard("invalid storage content listing"))?
        .iter()
        .map(|volume| {
            volume["volid"]
                .as_str()
                .filter(|id| id.starts_with(&format!("{}:{VM}/", site.storage)))
                .map(str::to_owned)
                .ok_or(ScalerError::Guard("unexpected qualification volume"))
        })
        .collect()
}

/// [`run`] for the gated container template: full-clone it into reserved
/// slot 9501, boot it with its own address and the site firewall, reach it
/// exactly as the controller would (root `pct exec`, then SSH with a pinned
/// host key), prove non-root KVM for the runner and agent accounts and the
/// census prerequisites, then destroy it.
pub(super) fn run_container(template: u16) -> Result<(), ScalerError> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(ScalerError::Guard(
            "clone qualification requires root on PVE",
        ));
    }
    if template != site::CONTAINER_TEMPLATE {
        return Err(ScalerError::Guard("unapproved container template VMID"));
    }
    let site = site::Site::local()?
        .with_agent_kind(super::RunnerKind::Lxc)?
        .for_lane(CloneLane::Agent)?;
    let template = template.to_string();
    let prepare = Instant::now() + Duration::from_secs(900);
    let inventory: Value = serde_json::from_str(&command(
        &[
            "pvesh",
            "get",
            "/cluster/resources",
            "--type",
            "vm",
            "--output-format",
            "json",
        ],
        prepare,
    )?)?;
    let rows = inventory
        .as_array()
        .ok_or(ScalerError::Guard("invalid VM inventory"))?;
    if rows.iter().any(|row| row["vmid"].as_u64() == Some(9501))
        || Path::new("/etc/pve/firewall/9501.fw").exists()
    {
        return Err(ScalerError::Guard(
            "qualification slot 9501 is occupied; inspect before retry",
        ));
    }
    let config: Value = serde_json::from_str(&command(
        &[
            "pvesh",
            "get",
            &format!(
                "{}/config",
                site.guest(super::RunnerKind::Lxc, site::CONTAINER_TEMPLATE)
            ),
            "--output-format",
            "json",
        ],
        prepare,
    )?)?;
    if config["template"].as_u64() != Some(1) {
        return Err(ScalerError::Guard("qualification source is not a template"));
    }
    if !live::qualified_template(&config, &site) {
        return Err(ScalerError::Guard(
            "container template does not match the agent lane's shape",
        ));
    }
    let dir = tempfile::tempdir()?;
    let key = dir.path().join("key");
    let key = key.to_str().ok_or(ScalerError::Guard("invalid key path"))?;
    command(
        &["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key],
        prepare,
    )?;
    // No --pool, and a hostname the standing controller cannot adopt. A
    // directory storage permits only a full container copy, which can take
    // longer than one ordinary command; a failed copy is still cleaned up.
    let cloned = bounded(
        &[
            "pct",
            "clone",
            &template,
            VM,
            "--full",
            "1",
            "--hostname",
            "template-qualification-9501",
        ],
        prepare,
        live::CONTAINER_CLONE_WAIT,
    );
    let result = cloned.and_then(|_| {
        command(
            &[
                "pct",
                "set",
                VM,
                "--net0",
                &format!(
                    "name=eth0,bridge={},firewall=1,{}",
                    site.bridge,
                    site.ipconfig(9501)?
                ),
            ],
            prepare,
        )?;
        let firewall = site
            .vm_firewall_file(9501)?
            .ok_or(ScalerError::Guard("qualification needs isolating firewall"))?;
        std::fs::write("/etc/pve/firewall/9501.fw", firewall)?;
        let deadline = Instant::now() + Duration::from_secs(300);
        command(&["pct", "start", VM], deadline)?;
        let public_key = std::fs::read_to_string(format!("{key}.pub"))?;
        let exec = |args: &[&str]| live::container_exec(9501, args, None);
        live::wait_for_readiness(deadline, || {
            let transport = live::container_exec(
                9501,
                &["/bin/sh", "-c", live::CONTAINER_TRANSPORT],
                Some(&public_key),
            )?;
            if transport.exit != live::GuestExit(0) {
                return Err(ScalerError::External("container transport setup"));
            }
            live::qualify_guest(super::RunnerKind::Lxc, exec)?;
            let hostkey = exec(&["/bin/cat", "/etc/ssh/ssh_host_ed25519_key.pub"])?.stdout;
            if !hostkey.starts_with("ssh-ed25519 ") || hostkey.lines().count() != 1 {
                return Err(ScalerError::Guard("invalid clone host key"));
            }
            let ip = site
                .static_address(9501)?
                .ok_or(ScalerError::Guard("missing qualification IP"))?;
            let hosts = dir.path().join("known_hosts");
            std::fs::write(&hosts, format!("{ip} {}\n", hostkey.trim()))?;
            live::ssh_transport(
                Path::new(key),
                &hosts,
                ip.parse()
                    .map_err(|_| ScalerError::Guard("invalid qualification address"))?,
                &[],
                "test -x /usr/local/bin/carrick-ci-run-once",
                Some(deadline),
            )?;
            Ok(())
        })?;
        let checked = |args: &[&str]| -> Result<String, ScalerError> {
            let output = exec(args)?;
            if output.exit != live::GuestExit(0) {
                eprintln!("qualification container command failed: {}", args.join(" "));
                return Err(ScalerError::External("clone health check failed"));
            }
            Ok(output.stdout)
        };
        checked(&["/bin/sh", "-c", CONTAINER_HEALTH])?;
        checked(&[
            "/usr/sbin/runuser",
            "-u",
            "carrick-dispatch-agent",
            "--",
            "/usr/local/bin/carrick-xtask",
            "ci-scaler",
            "verify-kvm",
        ])?;
        let manifest: Value = serde_json::from_str(&checked(&[
            "/bin/cat",
            "/var/lib/carrick-ci/qualification.json",
        ])?)?;
        if manifest["kvm_api"] != 12 || manifest["runner_registered"] != false {
            return Err(ScalerError::Guard("invalid clone qualification manifest"));
        }
        Ok(manifest)
    });
    if let Err(error) = &result {
        eprintln!("container qualification failed: {error}");
        match live::container_exec(
            9501,
            &[
                "/bin/sh",
                "-c",
                "systemctl is-system-running; systemctl --failed --no-pager; ip -4 address; ip route; journalctl -b -u ssh -u carrick-ci-ready --no-pager -n 100",
            ],
            None,
        ) {
            Ok(output) => eprintln!("container diagnosis:\n{}", output.stdout),
            Err(error) => eprintln!("container diagnostics unavailable: {error}"),
        }
    }
    let destroy = destroy_container(&site);
    let firewall = std::fs::remove_file("/etc/pve/firewall/9501.fw");
    if let Err(error) = destroy {
        eprintln!(
            "qualification cleanup failed for container 9501: {error}; inspect it and its firewall before retry"
        );
        return Err(error);
    }
    match firewall {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => return Err(error.into()),
        _ => {}
    }
    let manifest = result?;
    println!(
        "{}",
        serde_json::json!({"template":template,"clone":9501,"kind":"lxc","ready":true,"qualification":manifest})
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    use super::*;
    #[test]
    fn qualification_refuses_empty_unit_files_and_journal_recovery() {
        let dir = tempfile::tempdir().expect("fixture");
        let paths = [
            "/etc/systemd/system/carrick-ci-ready.service",
            "/usr/local/bin/carrick-ci-ready",
            "/usr/local/bin/carrick-ci-run-once",
            "/usr/local/bin/carrick-ci-admit-job.sh",
            "/var/lib/carrick-ci/qualification.json",
        ];
        for path in paths {
            let file = dir.path().join(&path[1..]);
            std::fs::create_dir_all(file.parent().expect("parent")).expect("directory");
            std::fs::write(file, "fixture").expect("file");
        }
        std::fs::create_dir(dir.path().join("run")).expect("run");
        for (contents, kernel, passes) in [
            ("", "EXT4-fs: mounted filesystem", false),
            ("[Unit]", "EXT4-fs: mounted filesystem", true),
            ("[Unit]", "EXT4-fs (sda1): recovery complete", false),
        ] {
            std::fs::write(dir.path().join(&paths[0][1..]), contents).expect("unit");
            let mut script = format!("journalctl() {{ echo '{kernel}'; }}\n{HEALTH}");
            // Two passes: on macOS the tempdir itself lives under /var/, so a
            // sequential rewrite would re-prefix paths an earlier pass inserted.
            let prefixes = ["/etc/", "/usr/", "/var/", "/run/"];
            for (index, prefix) in prefixes.iter().enumerate() {
                script = script.replace(prefix, &format!("\u{0}PREFIX{index}\u{0}"));
            }
            for (index, prefix) in prefixes.iter().enumerate() {
                script = script.replace(
                    &format!("\u{0}PREFIX{index}\u{0}"),
                    &format!("{}{prefix}", dir.path().display()),
                );
            }
            assert_eq!(
                Command::new("sh")
                    .arg("-c")
                    .arg(script)
                    .status()
                    .expect("shell")
                    .success(),
                passes
            );
        }
    }
}
