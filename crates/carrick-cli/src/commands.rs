//! Command dispatch implementation for the CLI.

use anyhow::{Context, bail};
use carrick_image::{ImageReference, ImageStore};
use carrick_runtime::compat::{CompatReporter, SyscallArgs};
use carrick_runtime::dispatch::{LinearMemory, SyscallDispatcher, SyscallRequest};
#[cfg(target_os = "macos")]
use carrick_runtime::dtrace_consumer::join_ids;
use carrick_runtime::elf::{inspect_elf, plan_elf_load};
use carrick_runtime::memory::AddressSpace;
use carrick_runtime::rootfs::RootFs;
use carrick_runtime::runtime::{
    DEFAULT_MAX_TRAPS, run_static_elf_with_hvf_args_and_dispatcher_debug,
};
use carrick_runtime::syscall::{aarch64_table, lookup_aarch64};
use carrick_runtime::trap::hvf_capabilities;

use crate::args::{Cli, Commands, RootfsCommand, SystemCommand};
use crate::debug::run_debug;
use crate::fs_setup::install_fs_backend;
use crate::runtime_util::{
    block_on_oci, emit_raw, human_age, human_size, parse_env_file, parse_mount_flag,
    parse_volume_mount, truncate_str, validate_publish,
};
#[cfg(target_os = "macos")]
use crate::trace_cli::{current_supplementary_groups, trace_drop_credentials};

pub(crate) fn run_cli(cli: Cli) -> anyhow::Result<()> {
    let Cli { store, command } = cli;
    let store = store
        .map(ImageStore::new)
        .unwrap_or_else(ImageStore::default_for_user);

    // `carrick shell [image]` is a convenience for an interactive run of
    // /bin/sh: normalise it to `Run` with a pty when stdin is a terminal (raw
    // streaming otherwise, so piped input still works). This reuses the entire
    // run path (image pull, fs backend, pty relay) with zero duplication.
    let command = match command {
        Commands::Shell { image } => {
            // SAFETY: isatty on fd 0 is a simple syscall returning 0/1.
            let interactive = unsafe { libc::isatty(0) } == 1;
            Commands::Run {
                image,
                platform: None,
                max_traps: DEFAULT_MAX_TRAPS,
                debug_state_path: None,
                raw: !interactive,
                json: false,
                tty: interactive,
                interactive,
                fs: None,
                env: vec![],
                env_file: vec![],
                workdir: None,
                user: None,
                entrypoint: None,
                volume: vec![],
                mount: vec![],
                name: None,
                rm: false,
                publish: vec![],
                pid: carrick_spec::PidMode::Private,
                detach: false,
                forward_env: vec![],
                command: vec!["/bin/sh".to_owned()],
            }
        }
        other => other,
    };

    match command {
        Commands::InspectElf { path } => {
            let metadata = inspect_elf(&path)
                .with_context(|| format!("failed to inspect {}", path.display()))?;
            println!("{}", serde_json::to_string_pretty(&metadata)?);
        }
        Commands::PlanElfLoad { path } => {
            let plan = plan_elf_load(&path)
                .with_context(|| format!("failed to plan ELF load for {}", path.display()))?;
            println!("{}", serde_json::to_string_pretty(&plan)?);
        }
        Commands::LoadElf { path, find_text } => {
            let image = AddressSpace::load_elf(&path)
                .with_context(|| format!("failed to load ELF image for {}", path.display()))?;
            let found_address = find_text
                .as_ref()
                .and_then(|needle| image.find_bytes(needle.as_bytes()));
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "entry": image.entry(),
                    "region_count": image.regions().len(),
                    "regions": image.regions(),
                    "found_address": found_address,
                }))?
            );
        }
        Commands::RunElf {
            path,
            rootfs_layers,
            max_traps,
            debug_state_path,
            raw,
            fs,
            volume,
            workdir,
            forward_env,
            args,
        } => {
            // Apply forwarded env BEFORE anything reads it (host_facts caches the
            // CPU count on first query). CLI args survive sudo's env_reset where
            // a bare `sudo VAR=val` is rejected without SETENV in sudoers.
            for kv in &forward_env {
                if let Some((k, v)) = kv.split_once('=') {
                    // SAFETY: single-threaded at this point (pre-runtime).
                    unsafe { std::env::set_var(k, v) };
                }
            }
            let mut dispatcher = if rootfs_layers.is_empty() {
                SyscallDispatcher::new()
            } else {
                SyscallDispatcher::with_rootfs(
                    RootFs::from_layer_paths(&rootfs_layers)
                        .context("failed to compose rootfs layers")?,
                )
            };
            install_fs_backend(&mut dispatcher, fs)?;
            // Bind-mount host paths into the guest. `--fs host` is a sandboxed
            // scratch (NOT the real host FS), so this is the only way to expose a
            // host directory — e.g. a conformance test's `testdata/`. `HOST:GUEST[:ro]`.
            for v in &volume {
                let parts: Vec<&str> = v.splitn(3, ':').collect();
                if parts.len() < 2 {
                    anyhow::bail!("invalid -v/--volume {v:?}: expected HOST:GUEST[:ro]");
                }
                let (host_src, guest_dst) = (parts[0], parts[1]);
                let readonly = parts.get(2).is_some_and(|m| *m == "ro");
                let bind = carrick_runtime::vfs::BindVfs::new(
                    guest_dst,
                    std::path::PathBuf::from(host_src),
                    readonly,
                );
                dispatcher.register_mount(std::path::PathBuf::from(guest_dst), Box::new(bind));
            }
            // Set the guest's initial CWD from -w (so a test's relative
            // `testdata/...`/`../testdata/...` resolves against a bind-mounted dir).
            if let Some(dir) = &workdir {
                dispatcher.set_cwd(dir);
            }
            if raw {
                dispatcher.set_stream_stdio(true);
            }
            let executable_path = path
                .canonicalize()
                .unwrap_or_else(|_| path.clone())
                .to_string_lossy()
                .into_owned();
            // Make the guest's own executable openable at its /proc/self/exe path.
            // run-elf loads the ELF directly from a host path, so the guest fs (the
            // --fs host scratch / rootfs) doesn't contain it; without this a guest
            // that does os.Executable()+open, or re-execs /proc/self/exe (Go os
            // TestOpenFileNonBlocking, TestPidfdLeak; glibc's _dl_get_origin), hits
            // ENOENT on its own binary. Bind the host ELF read-only at the
            // executable path so the readlink target resolves to real, openable
            // bytes — matching `carrick run <image>` and Docker, where the binary
            // is a real file in the guest fs.
            {
                let exe_bind =
                    carrick_runtime::vfs::BindVfs::new(executable_path.clone(), path.clone(), true);
                dispatcher.register_mount(
                    std::path::PathBuf::from(&executable_path),
                    Box::new(exe_bind),
                );
            }
            let mut argv = vec![executable_path];
            argv.extend(args);
            let mut elf_env: Vec<String> = Vec::new();
            for key in [
                "GODEBUG",
                "GOMAXPROCS",
                "GOTRACEBACK",
                "GOGC",
                "GODEBUGFLAGS",
            ] {
                if let Ok(val) = std::env::var(key) {
                    elf_env.push(format!("{key}={val}"));
                }
            }
            let result = run_static_elf_with_hvf_args_and_dispatcher_debug(
                &path,
                dispatcher,
                argv,
                elf_env.into_iter(),
                max_traps,
                debug_state_path.as_ref(),
            )
            .with_context(|| format!("failed to run static ELF {}", path.display()))?;
            if raw {
                emit_raw(&result);
                std::process::exit(if result.trap_limit_hit {
                    1
                } else {
                    result.exit_code
                });
            }
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "path": path,
                    "rootfs_layers": rootfs_layers,
                    "exit_code": result.exit_code,
                    "stdout": String::from_utf8_lossy(&result.stdout),
                    "stderr": String::from_utf8_lossy(&result.stderr),
                    "traps": result.traps,
                    "trap_limit_hit": result.trap_limit_hit,
                    "report": result.report,
                }))?
            );
            if result.trap_limit_hit {
                bail!(
                    "guest did not exit after {} traps (compat report above)",
                    result.traps
                );
            }
        }
        Commands::Pull { image, platform } => {
            let image = ImageReference::parse(&image)?;
            let target = platform
                .as_deref()
                .and_then(carrick_image::PlatformTarget::parse)
                .unwrap_or_else(carrick_image::PlatformTarget::default_target);
            // Cache short-circuit: if the image is already in the store for this
            // platform, don't re-download (docker prints "Image is up to date").
            // Note: this trusts the local cache and does not re-check the registry
            // for a newer digest on a moving tag — a force/`--pull` follow-up.
            if block_on_oci(store.load_pull_summary_for(&image, &target)).is_ok() {
                println!("Status: Image is up to date for {}", image.canonical());
            } else {
                block_on_oci(carrick_image::pull_image_with_platform(
                    &image, &store, &target,
                ))?;
                println!("Status: Downloaded newer image for {}", image.canonical());
            }
        }
        Commands::Images { quiet } => {
            let images = store.list_images();
            if quiet {
                for img in &images {
                    println!("{}", img.id);
                }
            } else {
                println!(
                    "{:<28}{:<14}{:<16}{:<24}{}",
                    "REPOSITORY", "TAG", "IMAGE ID", "CREATED", "SIZE"
                );
                for img in &images {
                    println!(
                        "{:<28}{:<14}{:<16}{:<24}{}",
                        truncate_str(&img.repository, 26),
                        truncate_str(&img.tag, 12),
                        img.id,
                        human_age(img.created_secs),
                        human_size(img.size),
                    );
                }
            }
        }
        Commands::Rmi { images } => {
            let mut had_err = false;
            for spec in &images {
                match ImageReference::parse(spec).and_then(|image| {
                    store
                        .remove_image(&image)
                        .map(|removed| (image, removed))
                        .map_err(|e| {
                            carrick_image::OciBootstrapError::Io(std::io::Error::other(e))
                        })
                }) {
                    Ok((image, true)) => println!("Untagged: {}", image.canonical()),
                    Ok((_, false)) => {
                        eprintln!("Error: no such image: {spec}");
                        had_err = true;
                    }
                    Err(e) => {
                        eprintln!("Error: {spec}: {e}");
                        had_err = true;
                    }
                }
            }
            let (count, bytes) = store.gc_blobs();
            if count > 0 {
                println!("Deleted {count} layer(s), reclaimed {}", human_size(bytes));
            }
            if had_err {
                bail!("one or more images failed to be removed");
            }
        }
        Commands::Prune => {
            let (count, bytes) = store.gc_blobs();
            println!(
                "Total reclaimed space: {} ({count} unreferenced layer(s))",
                human_size(bytes)
            );
        }
        Commands::System { command } => match command {
            SystemCommand::Df => crate::lifecycle::system_df(&store)?,
            SystemCommand::Prune { force: _ } => crate::lifecycle::system_prune(&store)?,
        },
        Commands::Tag { source, target } => {
            let src = ImageReference::parse(&source)
                .with_context(|| format!("invalid source image {source:?}"))?;
            let dst = ImageReference::parse(&target)
                .with_context(|| format!("invalid target image {target:?}"))?;
            store
                .tag_image(&src, &dst)
                .with_context(|| format!("failed to tag {source} as {target}"))?;
        }
        Commands::Run {
            image,
            platform,
            max_traps,
            debug_state_path,
            raw,
            json,
            tty,
            interactive,
            fs,
            env,
            env_file,
            workdir,
            user,
            entrypoint,
            volume,
            mount,
            name,
            rm,
            publish,
            pid,
            detach,
            forward_env,
            command,
        } => {
            // Apply forwarded env BEFORE anything reads it (e.g. host_facts'
            // CPU-count cache). CLI args survive sudo's env_reset where a bare
            // `sudo VAR=val` is rejected without SETENV in sudoers.
            for kv in &forward_env {
                if let Some((k, v)) = kv.split_once('=') {
                    // SAFETY: single-threaded at this point (pre-runtime).
                    unsafe { std::env::set_var(k, v) };
                }
            }
            // Reject `-p` maps that can't work under host-only networking
            // (port remap / random host port) before doing any work — hybrid policy.
            validate_publish(&publish)?;

            let mut env_overrides = env.clone();
            // `--env-file` may repeat (docker allows it); later files win.
            for file_path in &env_file {
                env_overrides.extend(parse_env_file(file_path)?);
            }

            let mut mounts = Vec::new();
            for v_str in &volume {
                mounts.push(parse_volume_mount(v_str)?);
            }
            for m_str in &mount {
                mounts.push(parse_mount_flag(m_str)?);
            }

            // `--entrypoint ""` clears the image ENTRYPOINT (run the command
            // alone), like docker — an empty value maps to an empty vec, not a
            // one-element [""] that would become an empty argv[0].
            let entrypoint_override =
                entrypoint.map(|ep| if ep.is_empty() { Vec::new() } else { vec![ep] });

            let req = carrick_engine::CliRunRequest {
                image_ref: image,
                platform,
                args: command,
                env_overrides,
                mounts,
                workdir,
                user,
                entrypoint_override,
                tty,
                interactive,
                rm,
                name,
                max_traps,
                debug_state_path: debug_state_path.map(|p| p.to_string_lossy().into_owned()),
                fs,
                pid,
            };

            // Detached (`carrick run -d`): pull the image, then fork into the
            // background under a per-container supervisor, print the id, and
            // return. Manage it with `carrick ps|stop|kill|rm`. We pull BEFORE
            // forking so an image-resolution error surfaces to the user's
            // terminal (not the detached log).
            if detach {
                // Resolve/pull the image in the foreground so failures are
                // visible; the detached child re-resolves from the warm store.
                let _ = block_on_oci(async {
                    carrick_image::ImageReference::parse(&req.image_ref)
                        .map_err(|e| anyhow::anyhow!("invalid image reference: {e}"))
                });
                let name_for_state = req.name.clone();
                return crate::lifecycle::run_detached(req, store.clone(), name_for_state);
            }

            let engine = carrick_engine::Engine::new(store.clone());
            // Docker exits 125 when `run` itself fails *before/at* container
            // start — image resolve/pull, an invalid reference, no command, or
            // VM setup. (The container's OWN exit code is the Ok path below;
            // 126/127 for a bad entrypoint are produced inside the runtime.)
            let result = match block_on_oci(async { engine.run(req.clone()).await }) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("carrick: {e:#}");
                    // This arm can run in the forked guest-init child (under
                    // `--pid private` the supervisor fork happens inside
                    // engine.run, and an HVF/setup failure surfaces here in the
                    // child). `std::process::exit` runs atexit/Drop cleanup,
                    // which is unsafe after fork and double-closes an inherited
                    // fd (IO-safety abort → SIGABRT). `_exit` terminates without
                    // that cleanup, like the runtime's other forked-child exits.
                    // stderr is already flushed (eprintln is unbuffered).
                    // SAFETY: _exit is async-signal-safe; no cleanup to skip on
                    // this error path (no buffered stdout; the report isn't emitted).
                    unsafe { libc::_exit(125) };
                }
            };

            // The container's host exit status: its real exit code, or 1 when
            // the guest hit the trap limit without exiting. Docker propagates
            // the container's exit code as its own; carrick now does the same on
            // every non-interactive path (previously the default path returned
            // Ok and exited 0 regardless — the inverse of docker for `false`).
            let status = if result.trap_limit_hit {
                1
            } else {
                result.exit_code
            };

            // Interactive / tty: the guest's stdio already went straight to the
            // terminal; nothing to emit, just take the exit code.
            if tty || interactive {
                std::process::exit(status);
            }

            // `--json`: opt into the legacy compat-report envelope on stdout.
            // Output already streamed live during the run (the engine runs every
            // container with raw/streaming stdio), so the envelope's stdout/
            // stderr fields are informational only.
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "image": req.image_ref,
                        "command": req.args,
                        "store": store.root(),
                        "exit_code": result.exit_code,
                        "stdout": String::from_utf8_lossy(&result.stdout),
                        "stderr": String::from_utf8_lossy(&result.stderr),
                        "traps": result.traps,
                        "trap_limit_hit": result.trap_limit_hit,
                        "report": result.report,
                    }))?
                );
                std::process::exit(status);
            }

            // Default (and the back-compat `--raw`): behave like `docker run`.
            // The guest's stdout/stderr already streamed byte-exact; flush any
            // residual buffered bytes, surface a trap-limit failure on stderr
            // (never polluting stdout), and exit with the container's code.
            let _ = raw; // `--raw` is now the default behavior; accepted for compat.
            emit_raw(&result);
            if result.trap_limit_hit {
                eprintln!(
                    "carrick: guest did not exit after {} traps (re-run with --json for the compat report)",
                    result.traps
                );
            }
            std::process::exit(status);
        }
        // `Shell` is normalised to `Run` (interactive /bin/sh) before this
        // match, so it is never reached here.
        Commands::Shell { .. } => bail!("internal error: shell command was not normalized to run"),
        Commands::Logs {
            follow,
            tail,
            container,
        } => crate::lifecycle::logs(&container, follow, tail)?,
        Commands::Wait { containers } => crate::lifecycle::wait(&containers)?,
        Commands::Inspect {
            format,
            containers,
        } => crate::lifecycle::inspect(format.as_deref(), &containers)?,
        Commands::Ps {
            all,
            quiet,
            no_trunc,
            format,
        } => crate::lifecycle::ps(all, quiet, no_trunc, format.as_deref())?,
        Commands::Stop { time, containers } => crate::lifecycle::stop(time, &containers)?,
        Commands::Kill { signal, containers } => crate::lifecycle::kill(&signal, &containers)?,
        Commands::Rm { force, containers } => crate::lifecycle::rm(force, &containers)?,
        Commands::Exec {
            interactive,
            tty,
            user,
            workdir,
            env,
            container,
            command,
        } => crate::lifecycle::exec(
            store.clone(),
            &container,
            command,
            interactive,
            tty,
            user,
            workdir,
            env,
        )?,
        Commands::CompatReport { format, command } => {
            if command.is_empty() {
                bail!("compat-report needs a command after --");
            }
            tracing::warn!(
                "compat-report runtime hooks are scaffolded; returning an empty report for {:?}",
                command
            );
            let report = CompatReporter::default().finish();
            println!("{}", report.render(format)?);
        }
        Commands::DispatchSyscall {
            number,
            args,
            memory_base,
            memory_text,
        } => {
            if args.len() != 6 {
                bail!("dispatch-syscall requires exactly six --args values");
            }
            let mut memory = LinearMemory::new(memory_base, memory_text.into_bytes());
            let mut dispatcher = SyscallDispatcher::new();
            let reporter = CompatReporter::default();
            let outcome = dispatcher.dispatch(
                SyscallRequest::new(
                    number,
                    SyscallArgs::from([args[0], args[1], args[2], args[3], args[4], args[5]]),
                ),
                &mut memory,
                &reporter,
            )?;
            println!("{}", {
                let stdout = dispatcher.stdout();
                let stderr = dispatcher.stderr();
                serde_json::to_string_pretty(&serde_json::json!({
                    "outcome": outcome,
                    "stdout": String::from_utf8_lossy(&stdout),
                    "stderr": String::from_utf8_lossy(&stderr),
                    "report": reporter.finish(),
                }))?
            });
        }
        Commands::Rootfs { layers, command } => {
            let rootfs = RootFs::from_layer_paths(&layers)?;
            match command {
                RootfsCommand::Summary => {
                    println!("{}", serde_json::to_string_pretty(&rootfs.summary())?);
                }
                RootfsCommand::Ls { path } => {
                    for name in rootfs.list_dir(path)? {
                        println!("{name}");
                    }
                }
                RootfsCommand::Cat { path } => {
                    use std::io::Write;
                    let bytes = rootfs.read(path)?;
                    std::io::stdout().write_all(&bytes)?;
                }
            }
        }
        Commands::Syscalls { number } => {
            if let Some(number) = number {
                let syscall = lookup_aarch64(number)
                    .with_context(|| format!("unknown Linux/aarch64 syscall {}", number))?;
                println!("{}", serde_json::to_string_pretty(syscall)?);
            } else {
                println!("{}", serde_json::to_string_pretty(aarch64_table())?);
            }
        }
        Commands::TrapCapabilities => {
            println!("{}", serde_json::to_string_pretty(&hvf_capabilities())?);
        }
        Commands::Debug { command } => run_debug(command)?,
        Commands::TraceChild {
            trace_uid,
            trace_gid,
            trace_groups,
            command,
        } => {
            #[cfg(target_os = "macos")]
            {
                crate::trace_cli::exec_trace_child(trace_uid, trace_gid, &trace_groups, &command)?;
            }
            #[cfg(not(target_os = "macos"))]
            {
                let _ = (trace_uid, trace_gid, trace_groups, command);
                bail!("trace child execution is only available on macOS.");
            }
        }
        Commands::Trace {
            flowindent,
            script,
            trace_out,
            command,
            forward_env,
            trace_uid,
            trace_gid,
            trace_groups,
        } => {
            #[cfg(target_os = "macos")]
            {
                // Apply env vars carried across the sudo re-exec as CLI args.
                for kv in &forward_env {
                    if let Some((k, v)) = kv.split_once('=') {
                        // SAFETY: single-threaded at this point (pre-runtime).
                        unsafe { std::env::set_var(k, v) };
                    }
                }
                if command.is_empty() {
                    bail!(
                        "trace needs a carrick subcommand to forward (e.g. `carrick trace run alpine:latest /bin/busybox echo hi`)"
                    );
                }
                let me = std::env::current_exe()
                    .context("failed to resolve current carrick binary path")?;
                if unsafe { libc::geteuid() } != 0 {
                    // libdtrace needs root to open /dev/dtrace. Re-exec the
                    // whole `carrick trace ...` invocation under sudo so the
                    // caller doesn't have to remember the prefix.
                    use std::os::unix::process::CommandExt;
                    tracing::warn!("carrick trace: not root; re-executing under sudo");
                    // Plain `sudo` resets the environment (env_reset), which
                    // would drop the CARRICK_* knobs the trace'd run needs
                    // (CARRICK_INSECURE_REGISTRIES, CARRICK_WATCH_ADDR,
                    // CARRICK_PULL_PLATFORM, CARRICK_HOME, ...). Carry those and
                    // the user identity env (`HOME`, `USER`, `LOGNAME`, `SHELL`)
                    // across as `--forward-env KEY=VAL` CLI args (which survive
                    // sudo, unlike env vars, and don't need SETENV in sudoers);
                    // the re-exec'd carrick sets them before spawning the child.
                    let mut forwarded: Vec<std::ffi::OsString> =
                        vec![me.as_os_str().to_owned(), std::ffi::OsString::from("trace")];
                    if flowindent {
                        forwarded.push(std::ffi::OsString::from("--flowindent"));
                    }
                    if let Some(ref s) = script {
                        forwarded.push(std::ffi::OsString::from("--script"));
                        forwarded.push(s.as_os_str().to_owned());
                    }
                    if let Some(ref o) = trace_out {
                        forwarded.push(std::ffi::OsString::from("--trace-out"));
                        forwarded.push(o.as_os_str().to_owned());
                    }
                    forwarded.push(std::ffi::OsString::from("--trace-uid"));
                    forwarded.push(unsafe { libc::getuid() }.to_string().into());
                    forwarded.push(std::ffi::OsString::from("--trace-gid"));
                    forwarded.push(unsafe { libc::getgid() }.to_string().into());
                    let groups = current_supplementary_groups();
                    if !groups.is_empty() {
                        forwarded.push(std::ffi::OsString::from("--trace-groups"));
                        forwarded.push(join_ids(&groups).into());
                    }
                    for (k, v) in std::env::vars_os() {
                        let key = k.to_string_lossy();
                        if key.starts_with("CARRICK_")
                            || matches!(key.as_ref(), "HOME" | "USER" | "LOGNAME" | "SHELL")
                        {
                            forwarded.push(std::ffi::OsString::from("--forward-env"));
                            let mut kv = k;
                            kv.push("=");
                            kv.push(v);
                            forwarded.push(kv);
                        }
                    }
                    forwarded.push(std::ffi::OsString::from("--"));
                    forwarded.extend(command.iter().map(std::ffi::OsString::from));
                    let err = std::process::Command::new("sudo").args(&forwarded).exec();
                    bail!("carrick trace: failed to re-exec under sudo: {}", err);
                }
                let script_src =
                    match &script {
                        Some(path) => Some(std::fs::read_to_string(path).with_context(|| {
                            format!("failed to read D script {}", path.display())
                        })?),
                        None => None,
                    };
                let opts = carrick_runtime::dtrace_consumer::TraceOptions {
                    flowindent,
                    script: script_src,
                    out_path: trace_out.as_ref().map(|p| p.to_string_lossy().into_owned()),
                    drop_credentials: trace_drop_credentials(trace_uid, trace_gid, &trace_groups),
                };
                carrick_runtime::dtrace_consumer::run_child_under_dtrace(&me, &command, &opts)
                    .map_err(|e| anyhow::anyhow!("trace failed: {}", e))?;
            }
            #[cfg(not(target_os = "macos"))]
            {
                let _ = (
                    flowindent,
                    script,
                    trace_out,
                    command,
                    forward_env,
                    trace_uid,
                    trace_gid,
                    trace_groups,
                );
                bail!("carrick trace is only available on macOS (libdtrace).");
            }
        }
        #[cfg(target_os = "macos")]
        Commands::Volume { command } => match command {
            crate::args::VolumeCommand::Create { quota } => {
                let v = carrick_runtime::apfs::create_carrick_volume(quota)
                    .context("failed to create carrick scratch volume")?;
                println!(
                    "{} {} {} case-sensitive={}",
                    v.device,
                    v.name,
                    v.mount_point
                        .as_deref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| "Not Mounted".to_owned()),
                    v.case_sensitive,
                );
            }
            crate::args::VolumeCommand::Info => {
                match carrick_runtime::apfs::find_carrick_volume()
                    .context("failed to query carrick scratch volume")?
                {
                    Some(v) => {
                        println!(
                            "{} {} {} case-sensitive={}",
                            v.device,
                            v.name,
                            v.mount_point
                                .as_deref()
                                .map(|p| p.display().to_string())
                                .unwrap_or_else(|| "Not Mounted".to_owned()),
                            v.case_sensitive,
                        );
                    }
                    None => {
                        bail!(
                            "no carrick scratch volume found; run `carrick volume create` to lay one down"
                        );
                    }
                }
            }
            crate::args::VolumeCommand::Delete { yes } => {
                let Some(v) = carrick_runtime::apfs::find_carrick_volume()
                    .context("failed to query carrick scratch volume")?
                else {
                    println!("no carrick scratch volume to delete");
                    return Ok(());
                };
                if !yes {
                    println!(
                        "would delete {} ({}); pass --yes to confirm",
                        v.device, v.name,
                    );
                    return Ok(());
                }
                carrick_runtime::apfs::delete_carrick_volume()
                    .context("failed to delete carrick scratch volume")?;
                println!("deleted {} ({})", v.device, v.name);
            }
        },
    }

    Ok(())
}

