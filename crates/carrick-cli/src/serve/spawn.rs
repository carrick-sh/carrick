//! The bridge from the API server to the existing CLI lifecycle and on-disk
//! registry. Containers are spawned by shelling out to the `carrick` binary,
//! which performs its own single-threaded fork — so the server's multi-thread
//! tokio runtime never forks a guest in-process.

use carrick_runtime::container;
use std::process::Command;

/// Persist a `Created` entry by invoking `carrick create --name <name> <image>
/// <cmd...>` and return the 64-hex container id `carrick create` prints on
/// stdout. The id (not the name) is the Docker-API `Id`; the name is stored as a
/// label so the container is later resolvable by either, via
/// `carrick_runtime::container::resolve`.
/// Options for `create_container` beyond the required `image` and `cmd`.
pub(crate) struct CreateContainerOpts<'a> {
    pub name: Option<&'a str>,
    pub env: &'a [String],
    pub workdir: Option<&'a str>,
    pub tty: bool,
    pub interactive: bool,
    pub user: Option<&'a str>,
    pub entrypoint: Option<&'a [String]>,
    pub auto_remove: bool,
    pub binds: &'a [String],
    pub mount_specs: &'a [String],
    pub publish_specs: &'a [String],
    pub network: Option<&'a str>,
    pub network_aliases: &'a [String],
    pub extra_hosts: &'a [String],
    pub dns_servers: &'a [String],
    pub dns_search: &'a [String],
    pub dns_options: &'a [String],
    pub volumes_from: &'a [String],
}

pub(crate) fn create_container(
    image: &str,
    cmd: &[String],
    opts: &CreateContainerOpts<'_>,
) -> anyhow::Result<String> {
    // nosemgrep: rust.lang.security.args.command-injection -- the server spawns
    // itself (current_exe) with operator-controlled API inputs as separate argv
    // entries, never a shell; a CLI that re-execs itself is expected here.
    let exe = std::env::current_exe()?;
    let mut c = Command::new(exe);
    c.arg("create");
    c.arg("--fs").arg("host");
    // No `?name=` → omit `--name`, letting `carrick create` auto-name (matching
    // Docker, which auto-generates a name when none is supplied).
    if let Some(n) = opts.name {
        c.arg("--name").arg(n);
    }
    for e in opts.env {
        c.arg("-e").arg(e);
    }
    if let Some(w) = opts.workdir {
        c.arg("-w").arg(w);
    }
    if opts.tty {
        c.arg("-t");
    }
    if opts.interactive {
        c.arg("-i");
    }
    if let Some(u) = opts.user {
        c.arg("-u").arg(u);
    }
    if let Some(ep) = opts.entrypoint
        && let Some(first) = ep.first()
    {
        c.arg("--entrypoint").arg(first);
    }
    if opts.auto_remove {
        c.arg("--rm");
    }
    for b in opts.binds {
        c.arg("-v").arg(b);
    }
    for m in opts.mount_specs {
        c.arg("--mount").arg(m);
    }
    for p in opts.publish_specs {
        c.arg("-p").arg(p);
    }
    if let Some(network) = opts.network {
        c.arg("--network").arg(network);
    }
    for alias in opts.network_aliases {
        c.arg("--network-alias").arg(alias);
    }
    for host in opts.extra_hosts {
        c.arg("--add-host").arg(host);
    }
    for server in opts.dns_servers {
        c.arg("--dns").arg(server);
    }
    for search in opts.dns_search {
        c.arg("--dns-search").arg(search);
    }
    for option in opts.dns_options {
        c.arg("--dns-option").arg(option);
    }
    for source in opts.volumes_from {
        c.arg("--volumes-from").arg(source);
    }
    c.arg(image);
    for a in cmd {
        c.arg(a);
    }

    let out = c.output()?;
    if !out.status.success() {
        anyhow::bail!(
            "carrick create failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    // `carrick create` prints the generated 64-hex id (and nothing else) on
    // stdout; the last non-empty line is that id.
    let stdout = String::from_utf8_lossy(&out.stdout);
    let id = stdout
        .lines()
        .rev()
        .find(|l| !l.trim().is_empty())
        .map(str::trim)
        .unwrap_or_default()
        .to_string();
    if id.is_empty() {
        anyhow::bail!("carrick create produced no container id");
    }
    Ok(id)
}

/// Block until the container exits, returning its exit code. Polls the on-disk
/// registry's reconciled status (no daemon push exists). Bounded by `timeout`.
pub(crate) fn wait_container(id: &str, timeout: std::time::Duration) -> anyhow::Result<i32> {
    let real = container::resolve(id).map_err(|e| anyhow::anyhow!(e))?;
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let Ok(state) = container::ContainerState::load(&real) else {
            return Ok(0);
        };
        if matches!(
            container::reconciled_status(&state),
            container::ContainerStatus::Exited
        ) {
            return Ok(state.exit_code.unwrap_or(0));
        }
        if std::time::Instant::now() >= deadline {
            anyhow::bail!("wait timed out for {id}");
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

/// Remove a container: `carrick rm [-f] <id>`. Reused rather than reimplemented
/// so kill/grace/cleanup stay identical to the CLI.
pub(crate) fn remove_container(id: &str, force: bool) -> anyhow::Result<()> {
    let real = container::resolve(id).map_err(|e| anyhow::anyhow!(e))?;
    // nosemgrep: rust.lang.security.args.command-injection -- the server spawns
    // itself (current_exe) with operator-controlled API inputs as separate argv
    // entries, never a shell; a CLI that re-execs itself is expected here.
    let exe = std::env::current_exe()?;
    let mut command = Command::new(exe);
    command.arg("rm");
    if force {
        command.arg("-f");
    }
    let out = command.arg(&real).output()?;
    if !out.status.success() {
        anyhow::bail!(
            "carrick rm failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(())
}

/// Start a previously-created container by relaunching it: `carrick start <id>`.
/// Resolves the server-facing id/name to carrick's internal id first.
pub(crate) fn start_container(id: &str) -> anyhow::Result<()> {
    let real = container::resolve(id).map_err(|e| anyhow::anyhow!(e))?;
    // nosemgrep: rust.lang.security.args.command-injection -- the server spawns
    // itself (current_exe) with operator-controlled API inputs as separate argv
    // entries, never a shell; a CLI that re-execs itself is expected here.
    let exe = std::env::current_exe()?;
    let out = Command::new(exe).arg("start").arg(&real).output()?;
    if !out.status.success() {
        anyhow::bail!(
            "carrick start failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(())
}
