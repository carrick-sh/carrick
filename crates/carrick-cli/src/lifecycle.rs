//! `carrick run -d` (detached) and the container lifecycle subcommands
//! (`ps`, `stop`, `kill`, `rm`). Daemonless: a detached container is its own
//! process tree under a per-container NsSupervisor; these subcommands are pure
//! reads/signals over the on-disk registry in `carrick_runtime::container`.
//! There is no `carrickd`.

use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, bail};
use carrick_runtime::container::{self, ContainerState, ContainerStatus, RunConfig};

use crate::runtime_util::{human_age, human_size, truncate_str};

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
    let created_secs = now_secs();
    let id = container::make_id(std::process::id() as u64, created_secs);
    let name = resolve_name(name, &id)?;
    // Resolve the image in the FOREGROUND (before forking) so pull errors reach
    // the user's terminal — and so the effective stop signal (flag > image
    // STOPSIGNAL) is baked into the persisted RunConfig for a later `stop`.
    let resolved = resolve_request_image(&req, &store)?;
    let stop_signal =
        resolve_stop_signal(req.stop_signal.as_deref(), resolved.config.stop_signal.as_deref())?;
    build_created_state(&req, &id, name, created_secs, stop_signal)
        .create()
        .with_context(|| format!("failed to create container registry entry for {id}"))?;

    let log = container::log_path(&id)?;
    // SAFETY: fork(2). The CLI is single-threaded here (no tokio runtime is live
    // — block_on_oci builds its own per-call runtime and we have not entered it).
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        let _ = ContainerState::remove(&id);
        bail!("fork failed for detached run");
    }
    if pid > 0 {
        // PARENT: print the id and return; the child lives on under launchd.
        println!("{id}");
        return Ok(());
    }
    // CHILD: first launch — extract the rootfs (attach_overlay = None).
    run_supervised_child(req, store, &id, &log, None);
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Resolve the container's name: reject a user-supplied `--name` that collides
/// with an existing container (docker `Conflict`); auto-generate one otherwise.
fn resolve_name(name: Option<String>, id: &str) -> anyhow::Result<Option<String>> {
    match name {
        Some(n) => {
            if container::resolve(&n).is_ok() {
                bail!("Conflict. The container name {n:?} is already in use");
            }
            Ok(Some(n))
        }
        None => Ok(Some(gen_name(id))),
    }
}

/// Build the `Created` registry entry for a detached run, persisting the full
/// relaunch inputs into RunConfig. scratch_path/region_path are filled in by the
/// runtime once the launched child sets up its overlay + region.
fn build_created_state(
    req: &carrick_engine::CliRunRequest,
    id: &str,
    name: Option<String>,
    created_secs: u64,
    stop_signal: Option<i32>,
) -> ContainerState {
    ContainerState {
        id: id.to_string(),
        name,
        image: req.image_ref.clone(),
        command: req.args.clone(),
        status: ContainerStatus::Created,
        supervisor_pid: 0,
        init_pid: 0,
        created_secs,
        exit_code: None,
        auto_remove: req.rm,
        config: RunConfig {
            platform: req.platform.clone(),
            env: req.env_overrides.clone(),
            workdir: req.workdir.clone(),
            user: req.user.clone(),
            pid: req.pid,
            scratch_path: None,
            region_path: None,
            entrypoint: req.entrypoint_override.clone(),
            mounts: req.mounts.clone(),
            fs: req.fs,
            tty: req.tty,
            interactive: req.interactive,
            max_traps: req.max_traps,
            stop_signal,
            stop_timeout: req.stop_timeout,
        },
    }
}

/// Pull/warm the request's image and return the resolved config (so image errors
/// surface eagerly, like `docker create`/`run -d`). Shared by `create` and
/// `run_detached`, which both need the image's `STOPSIGNAL` before forking.
fn resolve_request_image(
    req: &carrick_engine::CliRunRequest,
    store: &carrick_image::ImageStore,
) -> anyhow::Result<carrick_image::ResolvedImage> {
    let image_ref = carrick_image::ImageReference::parse(&req.image_ref)?;
    let target = req
        .platform
        .as_deref()
        .and_then(carrick_image::PlatformTarget::parse)
        .unwrap_or_else(carrick_image::PlatformTarget::default_target);
    Ok(crate::runtime_util::block_on_oci(
        store.resolve_with_platform(&image_ref, &target),
    )?)
}

/// The post-fork CHILD body shared by `run -d` and `start`: become a session
/// leader, redirect stdio to the container log, point the runtime at this
/// container (`CARRICK_CONTAINER_ID`), optionally attach an already-extracted
/// overlay (`attach_overlay` — set on `start`/`restart` to skip re-extraction),
/// run the engine, and exit with the container's code. Never returns.
fn run_supervised_child(
    req: carrick_engine::CliRunRequest,
    store: carrick_image::ImageStore,
    id: &str,
    log: &std::path::Path,
    attach_overlay: Option<&str>,
) -> ! {
    // SAFETY: setsid on a fresh fork child that is not a process-group leader.
    unsafe {
        libc::setsid();
    }
    redirect_detached_stdio(log);
    // SAFETY: single-threaded child, pre-runtime.
    unsafe {
        std::env::set_var("CARRICK_CONTAINER_ID", id);
        if let Some(scratch) = attach_overlay {
            // Reuse the existing overlay (already holds the rootfs + prior
            // writes); the runtime attaches it and skips layer extraction.
            std::env::set_var("CARRICK_EXEC_OVERLAY", scratch);
        }
    }
    let engine = carrick_engine::Engine::new(store);
    match crate::runtime_util::block_on_oci(async { engine.run(req).await }) {
        Ok(r) => std::process::exit(r.exit_code),
        Err(_) => {
            container::mark_exited(id, 1);
            std::process::exit(1);
        }
    }
}

/// `carrick create` — build a container (and warm/pull its image so image errors
/// surface now, like `docker create`) WITHOUT starting it; print its id. The
/// rootfs overlay is extracted lazily on the first `start`.
pub(crate) fn create(
    req: carrick_engine::CliRunRequest,
    store: carrick_image::ImageStore,
    name: Option<String>,
) -> anyhow::Result<()> {
    let created_secs = now_secs();
    let id = container::make_id(std::process::id() as u64, created_secs);
    let name = resolve_name(name, &id)?;
    // Warm the image cache + surface image errors at create time, and capture
    // the image's STOPSIGNAL so a later `stop` honors it (flag > image > TERM).
    let resolved = resolve_request_image(&req, &store)?;
    let stop_signal =
        resolve_stop_signal(req.stop_signal.as_deref(), resolved.config.stop_signal.as_deref())?;
    build_created_state(&req, &id, name, created_secs, stop_signal)
        .create()
        .with_context(|| format!("failed to create container registry entry for {id}"))?;
    println!("{id}");
    Ok(())
}

/// Reconstruct a `CliRunRequest` from a persisted container so `start` can
/// relaunch it. The command is persisted SPLIT (state.command = cmd args,
/// config.entrypoint = the override) so the engine re-merges entrypoint+cmd
/// instead of double-applying the image entrypoint.
fn rebuild_request_from_state(state: &ContainerState) -> carrick_engine::CliRunRequest {
    let c = &state.config;
    carrick_engine::CliRunRequest {
        image_ref: state.image.clone(),
        platform: c.platform.clone(),
        args: state.command.clone(),
        env_overrides: c.env.clone(),
        mounts: c.mounts.clone(),
        workdir: c.workdir.clone(),
        user: c.user.clone(),
        entrypoint_override: c.entrypoint.clone(),
        tty: c.tty,
        interactive: c.interactive,
        rm: state.auto_remove,
        name: None,
        max_traps: c.max_traps,
        debug_state_path: None,
        fs: c.fs,
        pid: c.pid,
        // The effective host stop signum is already persisted in RunConfig and
        // preserved across relaunch; engine.run ignores these, so leave unset.
        stop_signal: None,
        stop_timeout: None,
    }
}

/// `carrick start` — (re)launch one or more created/stopped containers, reusing
/// their persisted config + overlay. Daemonless restart = a fresh fork +
/// supervisor + region over the SAME overlay.
pub(crate) fn start(
    store: &carrick_image::ImageStore,
    _attach: bool,
    specs: &[String],
) -> anyhow::Result<()> {
    let mut had_err = false;
    for spec in specs {
        match start_one(store, spec) {
            Ok(id) => println!("{id}"),
            Err(e) => {
                eprintln!("Error: {e}");
                had_err = true;
            }
        }
    }
    if had_err {
        bail!("one or more containers failed to start");
    }
    Ok(())
}

fn start_one(store: &carrick_image::ImageStore, spec: &str) -> anyhow::Result<String> {
    let id = container::resolve(spec).map_err(anyhow::Error::msg)?;
    let mut state = ContainerState::load(&id)?;
    if container::reconciled_status(&state) == ContainerStatus::Running {
        // docker: starting an already-running container is a no-op success.
        return Ok(id);
    }
    if state.auto_remove {
        bail!(
            "container {} was created with --rm and cannot be started/restarted",
            container::short_id(&id)
        );
    }
    if matches!(state.config.fs, Some(carrick_spec::FsBackendKind::Memory)) {
        bail!("start requires a container created with --fs host");
    }
    // If a prior run populated the overlay (scratch_path set), attach it (skip
    // re-extraction, preserving the container's writes); otherwise this is the
    // first start and the runtime extracts the rootfs.
    let attach_overlay = state.config.scratch_path.clone();
    // A relaunch forks a FRESH supervisor + region; unlink the stale region file
    // so alloc_region maps a clean, seeded one (a reused file keeps dead members).
    if let Some(region) = &state.config.region_path {
        let _ = std::fs::remove_file(region);
    }
    reset_for_relaunch(&mut state);
    state.persist()?;

    let req = rebuild_request_from_state(&state);
    let log = container::log_path(&id)?;
    // SAFETY: fork(2); single-threaded (no live tokio runtime).
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        bail!("fork failed for start");
    }
    if pid > 0 {
        return Ok(id);
    }
    run_supervised_child(req, store.clone(), &id, &log, attach_overlay.as_deref());
}

/// Reset a container's volatile state for a relaunch. The supervisor overwrites
/// status/supervisor_pid/init_pid on takeover but NOT exit_code, so a stale
/// `Some(code)` would otherwise persist into the new Running entry; region_path
/// is cleared because the relaunch maps a fresh region.
fn reset_for_relaunch(state: &mut ContainerState) {
    state.status = ContainerStatus::Created;
    state.exit_code = None;
    state.init_pid = 0;
    state.supervisor_pid = 0;
    state.config.region_path = None;
}

/// `carrick restart` — stop (if running) then start, reusing the overlay.
/// `time` is `None` when `-t` is not given (the container's `--stop-timeout`,
/// else 10s, applies).
pub(crate) fn restart(
    store: &carrick_image::ImageStore,
    time: Option<u64>,
    specs: &[String],
) -> anyhow::Result<()> {
    let mut had_err = false;
    for spec in specs {
        let result = stop_one(spec, time).and_then(|_| start_one(store, spec));
        match result {
            Ok(id) => println!("{id}"),
            Err(e) => {
                eprintln!("Error: {e}");
                had_err = true;
            }
        }
    }
    if had_err {
        bail!("one or more containers failed to restart");
    }
    Ok(())
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

/// `carrick ps` — list containers, docker-shaped. Running only by default;
/// `--all` includes exited. `--quiet` prints just ids; `--format` renders a
/// Go-template-style expression per row; `--no-trunc` keeps full ids/commands.
pub(crate) fn ps(
    all: bool,
    quiet: bool,
    no_trunc: bool,
    format: Option<&str>,
) -> anyhow::Result<()> {
    let mut containers = container::list();
    // Stable, newest-first by creation time.
    containers.sort_by(|a, b| b.created_secs.cmp(&a.created_secs));

    let rows: Vec<(&ContainerState, ContainerStatus)> = containers
        .iter()
        .map(|c| (c, container::reconciled_status(c)))
        .filter(|(_, st)| all || *st == ContainerStatus::Running)
        .collect();

    if let Some(fmt) = format {
        for (c, st) in &rows {
            println!("{}", render_format(fmt, &ps_row_json(c, *st, no_trunc)));
        }
        return Ok(());
    }
    if quiet {
        for (c, _) in &rows {
            println!("{}", ps_id(&c.id, no_trunc));
        }
        return Ok(());
    }

    println!(
        "{:<14}{:<22}{:<26}{:<22}{:<20}{:<8}{}",
        "CONTAINER ID", "IMAGE", "COMMAND", "CREATED", "STATUS", "PORTS", "NAMES"
    );
    for (c, st) in &rows {
        println!(
            "{:<14}{:<22}{:<26}{:<22}{:<20}{:<8}{}",
            ps_id(&c.id, no_trunc),
            truncate_str(&c.image, 20),
            ps_command(&c.command, no_trunc),
            human_age(c.created_secs),
            ps_status(c, *st),
            "", // PORTS — carrick is host-networked; no published ports.
            c.name.as_deref().unwrap_or("")
        );
    }
    Ok(())
}

/// `carrick system df` — disk-usage summary for images and containers.
pub(crate) fn system_df(store: &carrick_image::ImageStore) -> anyhow::Result<()> {
    let images = store.list_images();
    let (blob_total, blob_reclaimable) = store.blob_disk_usage();
    let containers = container::list();
    let running = containers
        .iter()
        .filter(|c| container::reconciled_status(c) == ContainerStatus::Running)
        .count();
    let (mut cont_total, mut cont_reclaimable) = (0u64, 0u64);
    for c in &containers {
        let sz = c
            .config
            .scratch_path
            .as_deref()
            .map(|p| dir_size(std::path::Path::new(p)))
            .unwrap_or(0);
        cont_total += sz;
        if container::reconciled_status(c) != ContainerStatus::Running {
            cont_reclaimable += sz;
        }
    }
    println!(
        "{:<16}{:<8}{:<8}{:<12}{}",
        "TYPE", "TOTAL", "ACTIVE", "SIZE", "RECLAIMABLE"
    );
    println!(
        "{:<16}{:<8}{:<8}{:<12}{}",
        "Images",
        images.len(),
        images.len(),
        human_size(blob_total),
        human_size(blob_reclaimable)
    );
    println!(
        "{:<16}{:<8}{:<8}{:<12}{}",
        "Containers",
        containers.len(),
        running,
        human_size(cont_total),
        human_size(cont_reclaimable)
    );
    Ok(())
}

/// `carrick system prune` — remove stopped containers and unreferenced image
/// layers, reporting reclaimed space.
pub(crate) fn system_prune(store: &carrick_image::ImageStore) -> anyhow::Result<()> {
    let (mut removed, mut cont_bytes) = (0usize, 0u64);
    for c in container::list() {
        if container::reconciled_status(&c) != ContainerStatus::Running {
            if let Some(p) = c.config.scratch_path.as_deref() {
                cont_bytes += dir_size(std::path::Path::new(p));
            }
            if ContainerState::remove(&c.id).is_ok() {
                removed += 1;
            }
        }
    }
    let (blob_count, blob_bytes) = store.gc_blobs();
    println!("Deleted {removed} stopped container(s)");
    println!(
        "Total reclaimed space: {} ({blob_count} unreferenced layer(s))",
        human_size(cont_bytes + blob_bytes)
    );
    Ok(())
}

/// Recursively sum the byte sizes of regular files under `path`.
fn dir_size(path: &std::path::Path) -> u64 {
    let mut total = 0u64;
    let mut stack = vec![path.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            match entry.metadata() {
                Ok(m) if m.is_dir() => stack.push(entry.path()),
                Ok(m) => total += m.len(),
                Err(_) => {}
            }
        }
    }
    total
}

/// Generate a docker-style `adjective_surname` container name seeded by the id,
/// appending a short id suffix if it collides with an existing container (so
/// by-name `stop`/`kill`/`rm`/`logs` stay unambiguous).
fn gen_name(id: &str) -> String {
    const ADJ: &[&str] = &[
        "bold", "calm", "eager", "brave", "clever", "gentle", "jolly", "keen", "lucid", "merry",
        "nifty", "proud", "quirky", "serene", "witty", "amber", "cosmic", "mellow", "vivid",
        "stoic",
    ];
    const SUR: &[&str] = &[
        "turing", "hopper", "lovelace", "ritchie", "torvalds", "knuth", "dijkstra", "hamilton",
        "babbage", "liskov", "carmack", "thompson", "kernighan", "shannon", "noether", "euler",
        "gauss", "tesla", "curie", "bohr",
    ];
    let b = id.as_bytes();
    let a = ADJ[b.first().copied().unwrap_or(0) as usize % ADJ.len()];
    let s = SUR[b.get(1).copied().unwrap_or(0) as usize % SUR.len()];
    let base = format!("{a}_{s}");
    if container::resolve(&base).is_ok() {
        format!("{base}_{}", id.get(..4).unwrap_or("0000"))
    } else {
        base
    }
}

fn ps_id(id: &str, no_trunc: bool) -> String {
    if no_trunc {
        id.to_string()
    } else {
        container::short_id(id).to_string()
    }
}

/// docker COMMAND column: the argv joined + quoted, truncated unless `no_trunc`.
fn ps_command(command: &[String], no_trunc: bool) -> String {
    let quoted = format!("\"{}\"", command.join(" "));
    if no_trunc {
        quoted
    } else {
        truncate_str(&quoted, 22)
    }
}

/// docker STATUS column: `Created` / `Up <age>` / `Exited (N) <age>`.
fn ps_status(c: &ContainerState, st: ContainerStatus) -> String {
    match st {
        ContainerStatus::Created => "Created".to_string(),
        ContainerStatus::Running => {
            format!("Up {}", human_age(c.created_secs).trim_end_matches(" ago"))
        }
        ContainerStatus::Exited => format!(
            "Exited ({}) {}",
            c.exit_code.unwrap_or(0),
            human_age(c.created_secs)
        ),
    }
}

/// A docker-ps-shaped JSON row for `--format` (`.ID`, `.Image`, `.Command`,
/// `.CreatedAt`, `.Status`, `.State`, `.Ports`, `.Names`).
fn ps_row_json(c: &ContainerState, st: ContainerStatus, no_trunc: bool) -> serde_json::Value {
    serde_json::json!({
        "ID": ps_id(&c.id, no_trunc),
        "Image": c.image,
        "Command": ps_command(&c.command, no_trunc),
        "CreatedAt": human_age(c.created_secs),
        "RunningFor": human_age(c.created_secs),
        "Status": ps_status(c, st),
        "Ports": "",
        "Names": c.name.as_deref().unwrap_or(""),
        "State": match st {
            ContainerStatus::Created => "created",
            ContainerStatus::Running => "running",
            ContainerStatus::Exited => "exited",
        },
    })
}

/// `carrick stop` — send the container's stop signal (its `--stop-signal` /
/// image `STOPSIGNAL`, else SIGTERM) to init, wait out the grace window (`-t`
/// flag > the container's `--stop-timeout` > 10s), then SIGKILL. Prints the id
/// of each stopped container (docker behavior). `time` is `None` when `-t` is
/// not given.
pub(crate) fn stop(time: Option<u64>, containers: &[String]) -> anyhow::Result<()> {
    let mut had_err = false;
    for spec in containers {
        match stop_one(spec, time) {
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

fn stop_one(spec: &str, time: Option<u64>) -> anyhow::Result<String> {
    let id = container::resolve(spec).map_err(anyhow::Error::msg)?;
    let state = ContainerState::load(&id)?;
    if !state.init_alive() {
        // Already stopped — docker treats `stop` of a stopped container as a
        // no-op success and echoes the id.
        return Ok(id);
    }
    let init = state.init_pid;
    // The container's configured stop signal (image STOPSIGNAL / --stop-signal),
    // else SIGTERM; then the grace window (flag > config --stop-timeout > 10s).
    let signum = state.config.stop_signal.unwrap_or(libc::SIGTERM);
    let secs = stop_grace_secs(time, state.config.stop_timeout);
    // Configured stop signal, then poll for exit up to `secs`, then SIGKILL.
    // SAFETY: kill on the recorded host init pid.
    unsafe {
        libc::kill(init, signum);
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

/// Parse a signal name (`TERM`, `SIGTERM`, `9`, `KILL`, …) to its HOST (macOS)
/// signal number. The result is sent via host `kill(2)` (and persisted as the
/// container's stop signum), so names MUST resolve to the host's numbering, not
/// the guest's Linux ABI.
pub(crate) fn parse_signal(s: &str) -> Option<i32> {
    let t = s.trim();
    if let Ok(n) = t.parse::<i32>() {
        return (n > 0 && n <= 64).then_some(n);
    }
    let name = t.strip_prefix("SIG").unwrap_or(t).to_ascii_uppercase();
    let n = match name.as_str() {
        "HUP" => libc::SIGHUP,
        "INT" => libc::SIGINT,
        "QUIT" => libc::SIGQUIT,
        "ABRT" => libc::SIGABRT,
        "KILL" => libc::SIGKILL,
        "USR1" => libc::SIGUSR1,
        "USR2" => libc::SIGUSR2,
        "TERM" => libc::SIGTERM,
        "STOP" => libc::SIGSTOP,
        "CONT" => libc::SIGCONT,
        "WINCH" => libc::SIGWINCH,
        _ => return None,
    };
    Some(n)
}

/// Resolve a container's effective HOST stop signum from the `--stop-signal`
/// flag and the image's OCI `STOPSIGNAL`: an explicit flag wins; else the image
/// value; else `None` (stop falls back to `SIGTERM`). An invalid *explicit*
/// flag is a hard error (docker rejects it at run time); an unparseable *image*
/// value is ignored with a warning rather than failing the run.
pub(crate) fn resolve_stop_signal(
    flag: Option<&str>,
    image_stop_signal: Option<&str>,
) -> anyhow::Result<Option<i32>> {
    if let Some(f) = flag {
        let n =
            parse_signal(f).with_context(|| format!("invalid stop signal: {f}"))?;
        return Ok(Some(n));
    }
    if let Some(img) = image_stop_signal {
        match parse_signal(img) {
            Some(n) => return Ok(Some(n)),
            None => eprintln!("carrick: ignoring unrecognized image STOPSIGNAL {img:?}"),
        }
    }
    Ok(None)
}

/// The graceful-stop window in seconds: an explicit `stop -t` flag wins, then
/// the container's configured `--stop-timeout`, else docker's 10s default.
/// `Some(0)` (immediate SIGKILL) is honored — only an *absent* value defaults.
pub(crate) fn stop_grace_secs(flag: Option<u64>, config_timeout: Option<u64>) -> u64 {
    flag.or(config_timeout).unwrap_or(10)
}

/// `carrick exec [-i] [-t] [-u] [-w] [-e] <container> <cmd>...` — run a command
/// in a running container, sharing its filesystem (the persisted overlay) and
/// PID namespace (the file-backed region). Requires the container to have been
/// started with `--fs host`. Runs in this process (no supervisor fork — the
/// container already has one) and exits with the command's code.
#[allow(clippy::too_many_arguments)]
pub(crate) fn exec(
    store: carrick_image::ImageStore,
    spec: &str,
    command: Vec<String>,
    interactive: bool,
    tty: bool,
    user: Option<String>,
    workdir: Option<String>,
    env: Vec<String>,
) -> anyhow::Result<()> {
    let id = container::resolve(spec).map_err(anyhow::Error::msg)?;
    let state = ContainerState::load(&id)?;
    if !state.init_alive() {
        bail!("container {} is not running", container::short_id(&id));
    }
    let Some(scratch) = state.config.scratch_path.clone() else {
        bail!("exec requires a container started with --fs host");
    };
    let Some(region) = state.config.region_path.clone() else {
        bail!(
            "container {} has no joinable namespace (it was started with --pid host)",
            container::short_id(&id)
        );
    };
    // Tell the runtime to ATTACH this container's overlay + JOIN its pid region
    // (instead of creating a new overlay / forking a supervisor).
    // SAFETY: single-threaded CLI, before any runtime/fork.
    unsafe {
        std::env::set_var("CARRICK_EXEC_OVERLAY", &scratch);
        std::env::set_var("CARRICK_JOIN_REGION", &region);
    }

    // exec inherits the container's env (image ENV + its `-e`) plus exec's `-e`.
    let mut env_overrides = state.config.env.clone();
    env_overrides.extend(env);

    let req = carrick_engine::CliRunRequest {
        image_ref: state.image.clone(),
        platform: state.config.platform.clone(),
        args: command,
        env_overrides,
        // Reapply the container's bind mounts so exec sees the same mounted dirs.
        mounts: state.config.mounts.clone(),
        workdir: workdir.or_else(|| state.config.workdir.clone()),
        user: user.or_else(|| state.config.user.clone()),
        // exec runs the command directly — no image ENTRYPOINT prepended.
        entrypoint_override: Some(vec![]),
        tty,
        interactive,
        rm: false,
        name: None,
        max_traps: carrick_runtime::runtime::DEFAULT_MAX_TRAPS,
        debug_state_path: None,
        fs: Some(carrick_spec::FsBackendKind::Host),
        pid: state.config.pid,
        // exec is a transient command, not a managed container — it is never
        // `stop`ped, so it carries no stop config.
        stop_signal: None,
        stop_timeout: None,
    };

    let engine = carrick_engine::Engine::new(store);
    let result = match crate::runtime_util::block_on_oci(async { engine.run(req).await }) {
        Ok(r) => r,
        Err(e) => {
            // The command couldn't be started (e.g. not found / not executable
            // surfaces inside as 126/127; this is the engine/setup-failure case).
            eprintln!("carrick: exec failed: {e:#}");
            std::process::exit(126);
        }
    };
    let status = if result.trap_limit_hit {
        1
    } else {
        result.exit_code
    };
    if !(tty || interactive) {
        crate::runtime_util::emit_raw(&result);
    }
    std::process::exit(status);
}

/// `carrick wait <container>...` — block until each container stops, then print
/// its exit code (like `docker wait`). An already-exited container returns
/// immediately; a `--rm` container that was auto-removed reports 0.
pub(crate) fn wait(containers: &[String]) -> anyhow::Result<()> {
    let mut had_err = false;
    for spec in containers {
        match wait_one(spec) {
            Ok(code) => println!("{code}"),
            Err(e) => {
                eprintln!("Error: {e}");
                had_err = true;
            }
        }
    }
    if had_err {
        bail!("one or more containers failed to wait");
    }
    Ok(())
}

fn wait_one(spec: &str) -> anyhow::Result<i32> {
    let id = container::resolve(spec).map_err(anyhow::Error::msg)?;
    loop {
        let Ok(state) = ContainerState::load(&id) else {
            // Gone (e.g. a `--rm` container removed on exit): nothing to wait on.
            return Ok(0);
        };
        if state.status == ContainerStatus::Exited {
            return Ok(state.exit_code.unwrap_or(0));
        }
        if container::reconciled_status(&state) == ContainerStatus::Exited {
            // The init died but the supervisor hasn't recorded the code yet;
            // give it a brief window, then fall back to whatever is on disk.
            for _ in 0..50 {
                std::thread::sleep(std::time::Duration::from_millis(20));
                if let Ok(s) = ContainerState::load(&id)
                    && s.status == ContainerStatus::Exited
                {
                    return Ok(s.exit_code.unwrap_or(0));
                }
            }
            return Ok(state.exit_code.unwrap_or(0));
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

/// `carrick inspect <container>... [-f FORMAT]` — render the persisted container
/// state, docker-shaped. Without `--format`, prints a JSON array; with it,
/// renders the Go-template-style expression per container (one line each).
pub(crate) fn inspect(format: Option<&str>, containers: &[String]) -> anyhow::Result<()> {
    let mut objs = Vec::new();
    let mut had_err = false;
    for spec in containers {
        let loaded = container::resolve(spec)
            .map_err(anyhow::Error::msg)
            .and_then(|id| ContainerState::load(&id).map_err(Into::into));
        match loaded {
            Ok(state) => {
                let status = container::reconciled_status(&state);
                objs.push(container_to_json(&state, status));
            }
            Err(e) => {
                eprintln!("Error: {e}");
                had_err = true;
            }
        }
    }
    match format {
        Some(fmt) => {
            for obj in &objs {
                println!("{}", render_format(fmt, obj));
            }
        }
        None => {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::Value::Array(objs))?
            );
        }
    }
    if had_err {
        bail!("one or more containers not found");
    }
    Ok(())
}

/// Build the docker-shaped inspect object for a container. A subset of docker's
/// schema covering the commonly-scripted fields (`.Id`, `.Name`, `.Image`,
/// `.State.{Status,Running,Pid,ExitCode}`, `.Path`, `.Args`, `.Config.Cmd`).
fn container_to_json(c: &ContainerState, status: ContainerStatus) -> serde_json::Value {
    let running = status == ContainerStatus::Running;
    let status_str = match status {
        ContainerStatus::Created => "created",
        ContainerStatus::Running => "running",
        ContainerStatus::Exited => "exited",
    };
    let (path, args) = c
        .command
        .split_first()
        .map(|(p, a)| (p.clone(), a.to_vec()))
        .unwrap_or_default();
    serde_json::json!({
        "Id": c.id,
        "Name": format!("/{}", c.name.as_deref().unwrap_or("")),
        "Image": c.image,
        "Created": c.created_secs,
        "Path": path,
        "Args": args,
        "State": {
            "Status": status_str,
            "Running": running,
            "Pid": if running { c.init_pid } else { 0 },
            "ExitCode": c.exit_code.unwrap_or(0),
        },
        "Config": {
            "Cmd": c.command,
            "Env": c.config.env,
            "WorkingDir": c.config.workdir,
            "User": c.config.user,
        },
    })
}

/// Render a docker `--format` expression against `value`: literal text is kept,
/// `{{ .Path.To.Field }}` is replaced by the JSON value at that dotted path
/// (`<no value>` if absent), and `{{json .}}` dumps the whole object. A minimal
/// subset of Go's text/template — enough for the common `-f '{{.State.X}}'`.
fn render_format(fmt: &str, value: &serde_json::Value) -> String {
    let mut out = String::new();
    let mut rest = fmt;
    while let Some(start) = rest.find("{{") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let Some(end) = after.find("}}") else {
            out.push_str("{{");
            rest = after;
            continue;
        };
        let expr = after[..end].trim();
        rest = &after[end + 2..];
        if expr == "json ." || expr == "json." {
            out.push_str(&serde_json::to_string(value).unwrap_or_default());
        } else if let Some(path) = expr.strip_prefix('.') {
            match lookup_path(value, path) {
                Some(s) => out.push_str(&s),
                None => out.push_str("<no value>"),
            }
        }
        // Other expressions are unsupported and render to nothing.
    }
    out.push_str(rest);
    out
}

/// Follow a dotted `A.B.C` path into a JSON value, returning the leaf rendered
/// as a plain string (`None` if any segment is missing). An empty path is the
/// value itself.
fn lookup_path(value: &serde_json::Value, path: &str) -> Option<String> {
    let mut cur = value;
    if !path.is_empty() {
        for key in path.split('.') {
            cur = cur.get(key)?;
        }
    }
    Some(match cur {
        serde_json::Value::String(s) => s.clone(),
        other => other.to_string(),
    })
}

/// `carrick logs <container> [-f] [--tail N]` — replay (and optionally follow)
/// the captured stdout/stderr of a container. Detached runs redirect the
/// guest's inherited stdio to `output.log` (see [`redirect_detached_stdio`]);
/// this reads it back, mirroring `docker logs`.
pub(crate) fn logs(spec: &str, follow: bool, tail: Option<usize>) -> anyhow::Result<()> {
    let id = container::resolve(spec).map_err(anyhow::Error::msg)?;
    // `id` is a real registered id (resolve only returns existing ids), and
    // log_path runs it through the is_safe_id guard (container_dir_checked), so
    // `path` is under the registry root by construction — not traversable.
    let path = container::log_path(&id)?;

    // Dump what's already on disk (the last `tail` lines, or everything).
    let data = std::fs::read(&path).unwrap_or_default(); // nosemgrep
    let mut out = std::io::stdout();
    out.write_all(select_tail(&data, tail))?;
    out.flush()?;

    if !follow {
        return Ok(());
    }

    // `-f`/--follow: stream appended bytes until the container's init exits,
    // then drain whatever was written after the last poll. Best-effort polling
    // (no inotify on macOS); 100ms cadence matches `stop`'s grace ticks.
    let mut offset = data.len() as u64;
    let state = ContainerState::load(&id).ok();
    loop {
        offset = emit_appended(&path, offset, &mut out)?;
        let alive = state.as_ref().is_some_and(|s| s.init_alive());
        if !alive {
            // Final drain: catch bytes written between the last read and exit.
            emit_appended(&path, offset, &mut out)?;
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

/// Write any bytes in `path` past `offset` to `out`; return the new offset.
fn emit_appended(
    path: &std::path::Path,
    offset: u64,
    out: &mut impl Write,
) -> anyhow::Result<u64> {
    use std::io::{Read, Seek};
    // `path` is the registry log_path built from an allowlisted id (see `logs`);
    // it is under the registry root by construction, not user-traversable.
    let opened = std::fs::File::open(path); // nosemgrep
    let Ok(mut f) = opened else {
        return Ok(offset);
    };
    let len = f.metadata().map(|m| m.len()).unwrap_or(offset);
    if len <= offset {
        return Ok(offset);
    }
    f.seek(std::io::SeekFrom::Start(offset))?;
    let mut buf = Vec::with_capacity((len - offset) as usize);
    f.read_to_end(&mut buf)?;
    out.write_all(&buf)?;
    out.flush()?;
    Ok(len)
}

/// Return the suffix of `data` covering its last `tail` newline-delimited lines
/// (`None` ⇒ all of it, `Some(0)` ⇒ empty). A final line without a trailing
/// newline still counts. Mirrors `docker logs --tail N`.
fn select_tail(data: &[u8], tail: Option<usize>) -> &[u8] {
    let Some(n) = tail else {
        return data;
    };
    if n == 0 {
        return &data[data.len()..];
    }
    // Ignore a single trailing newline so it doesn't introduce a phantom empty
    // last line when counting boundaries from the end.
    let search_end = if data.last() == Some(&b'\n') {
        data.len() - 1
    } else {
        data.len()
    };
    let mut count = 0;
    let mut i = search_end;
    while i > 0 {
        i -= 1;
        if data[i] == b'\n' {
            count += 1;
            if count == n {
                return &data[i + 1..];
            }
        }
    }
    // Fewer than `n` lines present → return everything.
    data
}

#[cfg(test)]
mod tests {
    use super::{
        ContainerState, ContainerStatus, RunConfig, parse_signal, rebuild_request_from_state,
        render_format, reset_for_relaunch, resolve_stop_signal, select_tail, stop_grace_secs,
    };

    fn sample_state() -> ContainerState {
        ContainerState {
            id: "a".repeat(64),
            name: Some("c".into()),
            image: "ubuntu:24.04".into(),
            command: vec!["echo".into(), "hi".into()],
            status: ContainerStatus::Exited,
            supervisor_pid: 5,
            init_pid: 6,
            created_secs: 1,
            exit_code: Some(3),
            auto_remove: false,
            config: RunConfig {
                platform: Some("linux/arm64".into()),
                env: vec!["A=1".into()],
                workdir: Some("/w".into()),
                user: Some("1000".into()),
                pid: carrick_spec::PidMode::Private,
                scratch_path: Some("/s".into()),
                region_path: Some("/r".into()),
                entrypoint: Some(vec!["/bin/sh".into(), "-c".into()]),
                mounts: vec![carrick_spec::Mount {
                    source: "/h".into(),
                    target: "/g".into(),
                    readonly: true,
                }],
                fs: Some(carrick_spec::FsBackendKind::Host),
                tty: true,
                interactive: false,
                max_traps: 4242,
                stop_signal: Some(libc::SIGQUIT),
                stop_timeout: Some(15),
            },
        }
    }

    #[test]
    fn rebuild_request_reproduces_run_inputs_split_not_merged() {
        let req = rebuild_request_from_state(&sample_state());
        assert_eq!(req.image_ref, "ubuntu:24.04");
        assert_eq!(req.platform.as_deref(), Some("linux/arm64"));
        // D1: persisted SPLIT — args is the cmd, entrypoint is the override; the
        // engine re-merges (storing the merged argv would double-apply the image
        // entrypoint).
        assert_eq!(req.args, vec!["echo".to_string(), "hi".to_string()]);
        assert_eq!(
            req.entrypoint_override,
            Some(vec!["/bin/sh".to_string(), "-c".to_string()])
        );
        assert_eq!(req.env_overrides, vec!["A=1".to_string()]);
        assert_eq!(req.workdir.as_deref(), Some("/w"));
        assert_eq!(req.user.as_deref(), Some("1000"));
        assert_eq!(req.mounts.len(), 1);
        assert_eq!(req.fs, Some(carrick_spec::FsBackendKind::Host));
        assert!(req.tty);
        assert_eq!(req.max_traps, 4242);
        assert_eq!(req.pid, carrick_spec::PidMode::Private);
        assert!(!req.rm);
    }

    #[test]
    fn reset_for_relaunch_clears_volatile_state() {
        let mut s = sample_state();
        reset_for_relaunch(&mut s);
        assert_eq!(s.status, ContainerStatus::Created);
        assert_eq!(s.exit_code, None); // D5: stale exit code MUST be cleared
        assert_eq!(s.init_pid, 0);
        assert_eq!(s.supervisor_pid, 0);
        assert_eq!(s.config.region_path, None);
        // The overlay path is preserved (the relaunch reuses it).
        assert_eq!(s.config.scratch_path.as_deref(), Some("/s"));
        // The container's stop config survives a relaunch (docker keeps the
        // configured --stop-signal / --stop-timeout across `restart`/`start`).
        assert_eq!(s.config.stop_signal, Some(libc::SIGQUIT));
        assert_eq!(s.config.stop_timeout, Some(15));
    }

    #[test]
    fn parse_signal_pins_host_numbers_and_new_aliases() {
        // Signal NAMES resolve to the HOST (macOS) signal numbers — the stop
        // signum is persisted and later passed to host kill(2), so it must be a
        // host number, not Linux's (e.g. SIGUSR1 is 10 on macOS, 30 on Linux).
        assert_eq!(parse_signal("SIGUSR1"), Some(libc::SIGUSR1));
        assert_eq!(parse_signal("USR1"), Some(libc::SIGUSR1));
        assert_eq!(parse_signal("SIGSTOP"), Some(libc::SIGSTOP));
        assert_eq!(parse_signal("term"), Some(libc::SIGTERM));
        // Aliases added for stop-signal coverage.
        assert_eq!(parse_signal("SIGABRT"), Some(libc::SIGABRT));
        assert_eq!(parse_signal("WINCH"), Some(libc::SIGWINCH));
        // Numeric form + bounds (1..=64).
        assert_eq!(parse_signal("9"), Some(9));
        assert_eq!(parse_signal("0"), None);
        assert_eq!(parse_signal("65"), None);
        assert_eq!(parse_signal("NOPE"), None);
    }

    #[test]
    fn resolve_stop_signal_precedence_flag_over_image_over_none() {
        // An explicit --stop-signal wins over the image's STOPSIGNAL.
        assert_eq!(
            resolve_stop_signal(Some("SIGUSR1"), Some("SIGQUIT")).unwrap(),
            Some(libc::SIGUSR1)
        );
        // No flag → the image's STOPSIGNAL.
        assert_eq!(resolve_stop_signal(None, Some("SIGQUIT")).unwrap(), Some(libc::SIGQUIT));
        // Neither → None (stop falls back to SIGTERM at stop time).
        assert_eq!(resolve_stop_signal(None, None).unwrap(), None);
        // An invalid EXPLICIT flag is a hard error (docker rejects it at run).
        assert!(resolve_stop_signal(Some("BOGUS"), None).is_err());
        // An unparseable IMAGE STOPSIGNAL is ignored (→ None), never an error —
        // we don't fail a run over a weird value baked into someone's image.
        assert_eq!(resolve_stop_signal(None, Some("BOGUS")).unwrap(), None);
    }

    #[test]
    fn stop_grace_uses_flag_then_config_then_default() {
        // An explicit `-t` wins over the container's configured timeout.
        assert_eq!(stop_grace_secs(Some(3), Some(20)), 3);
        // No `-t` → the container's --stop-timeout.
        assert_eq!(stop_grace_secs(None, Some(20)), 20);
        // Neither → docker's 10s default.
        assert_eq!(stop_grace_secs(None, None), 10);
        // `-t 0` is honored (immediate SIGKILL), not treated as "unset".
        assert_eq!(stop_grace_secs(Some(0), Some(20)), 0);
    }

    #[test]
    fn render_format_field_access() {
        let v = serde_json::json!({
            "Id": "abc",
            "State": { "Status": "exited", "ExitCode": 7, "Running": false },
        });
        assert_eq!(render_format("{{.State.ExitCode}}", &v), "7");
        assert_eq!(render_format("{{.State.Status}}", &v), "exited");
        assert_eq!(render_format("{{.Id}}", &v), "abc");
        assert_eq!(
            render_format("s={{.State.Status}} c={{.State.ExitCode}}", &v),
            "s=exited c=7"
        );
        assert_eq!(render_format("{{.State.Running}}", &v), "false");
    }

    #[test]
    fn render_format_missing_field_is_no_value() {
        let v = serde_json::json!({ "Id": "abc" });
        assert_eq!(render_format("{{.Nope.Here}}", &v), "<no value>");
    }

    #[test]
    fn render_format_json_dot_dumps_object() {
        let v = serde_json::json!({ "Id": "abc" });
        assert_eq!(render_format("{{json .}}", &v), "{\"Id\":\"abc\"}");
    }

    #[test]
    fn select_tail_none_returns_all() {
        assert_eq!(select_tail(b"a\nb\nc\n", None), b"a\nb\nc\n");
    }

    #[test]
    fn select_tail_returns_last_n_lines_with_trailing_newline() {
        // tail=2 over three trailing-newline-terminated lines → last two.
        assert_eq!(select_tail(b"line1\nline2\nline3\n", Some(2)), b"line2\nline3\n");
    }

    #[test]
    fn select_tail_returns_last_line_without_trailing_newline() {
        // A final partial line (no trailing \n) still counts as one line.
        assert_eq!(select_tail(b"a\nb", Some(1)), b"b");
    }

    #[test]
    fn select_tail_zero_is_empty() {
        assert_eq!(select_tail(b"a\nb\n", Some(0)), b"");
    }

    #[test]
    fn select_tail_more_than_available_returns_all() {
        assert_eq!(select_tail(b"only\n", Some(10)), b"only\n");
    }
}
