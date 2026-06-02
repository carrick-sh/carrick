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
        "Config": { "Cmd": c.command },
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
    use super::{render_format, select_tail};

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
