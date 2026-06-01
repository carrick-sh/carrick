//! `carrick run -d` (detached) and the container lifecycle subcommands
//! (`ps`, `stop`, `kill`, `rm`). Daemonless: a detached container is its own
//! process tree under a per-container NsSupervisor; these subcommands are pure
//! reads/signals over the on-disk registry in `carrick_runtime::container`.
//! There is no `carrickd`.

use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, bail};
use carrick_runtime::container::{self, ContainerState, ContainerStatus};

/// Detach into the background and run the container under its own supervisor,
/// printing the container id and returning. Mirrors `docker run -d`.
///
/// Flow (daemonless, podman-style):
///  1. Generate the id and write a `Created` registry entry.
///  2. `fork()`. The PARENT prints the id and returns (the user's shell is
///     freed). The CHILD `setsid()`s, redirects stdio (stdin←/dev/null,
///     stdout/stderr→the container log), exports `CARRICK_CONTAINER_ID`, and
///     runs the engine — which forks the NsSupervisor + guest-init. The child
///     becomes the supervisor, records the live pids (status → Running), and
///     blocks until the container exits, then marks the entry Exited (or
///     removes it for `--rm`).
pub(crate) fn run_detached(
    req: carrick_engine::CliRunRequest,
    store: carrick_image::ImageStore,
    name: Option<String>,
) -> anyhow::Result<()> {
    let created_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Seed the id from this (pre-fork) pid + the creation time so it is unique
    // per launch; container::make_id formats it as a 64-hex docker-like id.
    let id = container::make_id(std::process::id() as u64, created_secs);

    let state = ContainerState {
        id: id.clone(),
        name: name.clone(),
        image: req.image_ref.clone(),
        command: req.args.clone(),
        status: ContainerStatus::Created,
        supervisor_pid: 0,
        init_pid: 0,
        created_secs,
        exit_code: None,
        auto_remove: req.rm,
    };
    state
        .create()
        .with_context(|| format!("failed to create container registry entry for {id}"))?;

    let log = container::log_path(&id)?;

    // SAFETY: fork(2). The CLI is single-threaded here (no tokio runtime is
    // live at this point — block_on_oci builds its own per-call runtime, and we
    // have not entered it yet), so fork is safe.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        let _ = ContainerState::remove(&id);
        bail!("fork failed for detached run");
    }
    if pid > 0 {
        // PARENT: print the container id (docker prints the full id) and return.
        // The detached child is reparented to launchd and lives on.
        println!("{id}");
        return Ok(());
    }

    // CHILD: become a session leader so we are not killed when the invoking
    // shell exits, and detach from the controlling terminal.
    // SAFETY: setsid on a fresh fork child that is not a process-group leader.
    unsafe {
        libc::setsid();
    }
    // Redirect stdio: stdin from /dev/null, stdout+stderr to the container log,
    // so the guest's streamed output is captured for `carrick logs` and nothing
    // touches the user's terminal.
    redirect_detached_stdio(&log);

    // Tell the runtime which container this is, so its supervisor records the
    // live pids + final status into the registry (see runtime::
    // maybe_fork_ns_supervisor).
    // SAFETY: single-threaded child, pre-runtime.
    unsafe {
        std::env::set_var("CARRICK_CONTAINER_ID", &id);
    }

    let engine = carrick_engine::Engine::new(store);
    let result = crate::runtime_util::block_on_oci(async { engine.run(req).await });
    // The supervisor already marked the registry entry Exited; just exit with
    // the container's code. (If the run errored before the supervisor took
    // over, reflect that as a non-zero exit + Exited state.)
    match result {
        Ok(r) => {
            std::process::exit(r.exit_code);
        }
        Err(_) => {
            container::mark_exited(&id, 1);
            std::process::exit(1);
        }
    }
}

/// Point fd 0 at /dev/null and fds 1/2 at the container log file (append).
fn redirect_detached_stdio(log: &std::path::Path) {
    use std::os::fd::IntoRawFd;
    // /dev/null for stdin.
    if let Ok(devnull) = std::fs::OpenOptions::new().read(true).open("/dev/null") {
        let fd = devnull.into_raw_fd();
        // SAFETY: dup2 onto fd 0, then close the temp fd.
        unsafe {
            libc::dup2(fd, 0);
            libc::close(fd);
        }
    }
    if let Ok(out) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log)
    {
        let fd = out.into_raw_fd();
        // SAFETY: dup2 onto fds 1 and 2, then close the temp fd.
        unsafe {
            libc::dup2(fd, 1);
            libc::dup2(fd, 2);
            libc::close(fd);
        }
    }
}

/// `carrick ps` — list containers. Running only by default; `--all` includes
/// exited. `--quiet` prints just ids.
pub(crate) fn ps(all: bool, quiet: bool) -> anyhow::Result<()> {
    let mut containers = container::list();
    // Stable, newest-first by creation time.
    containers.sort_by(|a, b| b.created_secs.cmp(&a.created_secs));

    let rows: Vec<(&ContainerState, ContainerStatus)> = containers
        .iter()
        .map(|c| (c, container::reconciled_status(c)))
        .filter(|(_, st)| all || *st == ContainerStatus::Running)
        .collect();

    if quiet {
        for (c, _) in &rows {
            println!("{}", container::short_id(&c.id));
        }
        return Ok(());
    }

    println!(
        "{:<14}{:<24}{:<12}{:<10}{}",
        "CONTAINER ID", "IMAGE", "STATUS", "PID", "NAMES"
    );
    for (c, st) in &rows {
        let status = match st {
            ContainerStatus::Created => "created".to_string(),
            ContainerStatus::Running => "running".to_string(),
            ContainerStatus::Exited => {
                format!("exited ({})", c.exit_code.unwrap_or(0))
            }
        };
        let pid = if *st == ContainerStatus::Running {
            c.init_pid.to_string()
        } else {
            "-".to_string()
        };
        println!(
            "{:<14}{:<24}{:<12}{:<10}{}",
            container::short_id(&c.id),
            truncate(&c.image, 22),
            status,
            pid,
            c.name.as_deref().unwrap_or("")
        );
    }
    Ok(())
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max.saturating_sub(1)])
    }
}

/// `carrick stop` — SIGTERM the container's init, wait up to `secs`, then
/// SIGKILL. Prints the id of each stopped container (docker behavior).
pub(crate) fn stop(secs: u64, containers: &[String]) -> anyhow::Result<()> {
    let mut had_err = false;
    for spec in containers {
        match stop_one(spec, secs) {
            Ok(id) => println!("{id}"),
            Err(e) => {
                eprintln!("Error: {e}");
                had_err = true;
            }
        }
    }
    if had_err {
        bail!("one or more containers failed to stop");
    }
    Ok(())
}

fn stop_one(spec: &str, secs: u64) -> anyhow::Result<String> {
    let id = container::resolve(spec).map_err(anyhow::Error::msg)?;
    let state = ContainerState::load(&id)?;
    if !state.init_alive() {
        // Already stopped — docker treats `stop` of a stopped container as a
        // no-op success and echoes the id.
        return Ok(id);
    }
    let init = state.init_pid;
    // SIGTERM, then poll for exit up to `secs`, then SIGKILL.
    // SAFETY: kill on the recorded host init pid.
    unsafe {
        libc::kill(init, libc::SIGTERM);
    }
    let deadline_ticks = secs.saturating_mul(10); // 100ms ticks
    for _ in 0..deadline_ticks {
        if !container::pid_alive(init) {
            return Ok(id);
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    // Grace expired: SIGKILL.
    // SAFETY: kill on the recorded host init pid.
    unsafe {
        libc::kill(init, libc::SIGKILL);
    }
    Ok(id)
}

/// `carrick kill` — send `signal` to the container's init.
pub(crate) fn kill(signal: &str, containers: &[String]) -> anyhow::Result<()> {
    let signum = parse_signal(signal).with_context(|| format!("invalid signal: {signal}"))?;
    let mut had_err = false;
    for spec in containers {
        match kill_one(spec, signum) {
            Ok(id) => println!("{id}"),
            Err(e) => {
                eprintln!("Error: {e}");
                had_err = true;
            }
        }
    }
    if had_err {
        bail!("one or more containers failed to receive the signal");
    }
    Ok(())
}

fn kill_one(spec: &str, signum: i32) -> anyhow::Result<String> {
    let id = container::resolve(spec).map_err(anyhow::Error::msg)?;
    let state = ContainerState::load(&id)?;
    if !state.init_alive() {
        bail!("container {} is not running", container::short_id(&id));
    }
    // SAFETY: kill on the recorded host init pid.
    let rc = unsafe { libc::kill(state.init_pid, signum) };
    if rc != 0 {
        bail!("failed to signal container {}", container::short_id(&id));
    }
    Ok(id)
}

/// `carrick rm` — remove a container's registry entry. Refuses a running
/// container unless `force` (which SIGKILLs it first).
pub(crate) fn rm(force: bool, containers: &[String]) -> anyhow::Result<()> {
    let mut had_err = false;
    for spec in containers {
        match rm_one(spec, force) {
            Ok(id) => println!("{id}"),
            Err(e) => {
                eprintln!("Error: {e}");
                had_err = true;
            }
        }
    }
    if had_err {
        bail!("one or more containers failed to be removed");
    }
    Ok(())
}

fn rm_one(spec: &str, force: bool) -> anyhow::Result<String> {
    let id = container::resolve(spec).map_err(anyhow::Error::msg)?;
    let state = ContainerState::load(&id)?;
    if state.init_alive() {
        if !force {
            bail!(
                "container {} is running; stop it first or use --force",
                container::short_id(&id)
            );
        }
        // SAFETY: SIGKILL the running init before removing its entry.
        unsafe {
            libc::kill(state.init_pid, libc::SIGKILL);
        }
        // Give teardown a brief moment so the supervisor cleans up too.
        for _ in 0..20 {
            if !container::pid_alive(state.init_pid) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }
    ContainerState::remove(&id)?;
    Ok(id)
}

/// Parse a signal name (`TERM`, `SIGTERM`, `9`, `KILL`, …) to a number.
fn parse_signal(s: &str) -> Option<i32> {
    let t = s.trim();
    if let Ok(n) = t.parse::<i32>() {
        return (n > 0 && n <= 64).then_some(n);
    }
    let name = t.strip_prefix("SIG").unwrap_or(t).to_ascii_uppercase();
    let n = match name.as_str() {
        "HUP" => libc::SIGHUP,
        "INT" => libc::SIGINT,
        "QUIT" => libc::SIGQUIT,
        "KILL" => libc::SIGKILL,
        "USR1" => libc::SIGUSR1,
        "USR2" => libc::SIGUSR2,
        "TERM" => libc::SIGTERM,
        "STOP" => libc::SIGSTOP,
        "CONT" => libc::SIGCONT,
        _ => return None,
    };
    Some(n)
}

/// `carrick logs` would replay `container::log_path(id)`; wired separately. The
/// import keeps the surface explicit for that follow-up.
#[allow(dead_code)]
fn _logs_marker() {
    let _ = std::io::stdout().flush();
}
