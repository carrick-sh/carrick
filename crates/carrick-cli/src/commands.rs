//! Command dispatch — the single `match` that turns a parsed [`Cli`] into an
//! action against the lower crates.
//!
//! # Theory of operation
//!
//! [`run_cli`] is one big dispatch over [`Commands`]. There is no command-object
//! indirection on purpose: every arm is short because the real work lives below
//! the request boundary, and keeping the wiring flat makes the "what does this
//! flag actually do" question answerable by reading one arm. Three structural
//! patterns recur and are worth internalising before editing:
//!
//! 1. **`shell` is sugar for `run`.** Before the dispatch, `Commands::Shell` is
//!    rewritten into an interactive `Commands::Run` of `/bin/sh` (with a pty iff
//!    stdin is a tty). This reuses the *entire* run path — image pull, fs
//!    backend, pty relay — with zero duplication; the `Shell` arm in the match
//!    is therefore unreachable and only exists to satisfy exhaustiveness.
//!
//! 2. **The two run pipelines.** There are deliberately two entry points to a
//!    guest, and they share almost nothing:
//!    - `Run`/`Create`/`Exec` build a [`carrick_engine::CliRunRequest`] and go
//!      through `carrick_engine::Engine::resolve` — i.e. resolve+pull an OCI
//!      image and compose its rootfs — then call `Runtime::execute` separately,
//!      once the async pull is torn down (no tokio runtime live across the fork).
//!      This is the docker path.
//!    - `RunElf`/`DispatchSyscall` bypass the engine and the image store
//!      entirely, loading a *host* ELF (or a single synthetic syscall) straight
//!      through `carrick-runtime`. This is the fixture path used by Go/CPython/
//!      libuv conformance and unit tests, where there is no container image —
//!      hence the manual rootfs-layer composition, `--fs` install,
//!      `-v`/`--volume` bind-mounts, and the read-only self-bind of the host ELF
//!      at its own `/proc/self/exe` path (so `os.Executable()` + re-exec
//!      resolve), all of which the engine would otherwise do from the image.
//!
//! 3. **Exit-code parity with docker.** The CLI, not the runtime, owns the
//!    *process* exit code. Docker's convention is encoded explicitly here: `125`
//!    when `run` itself fails before/at container start (image resolve/pull, bad
//!    reference, VM setup — the `Err` arm of `engine.run`); the container's own
//!    code on success; `1` when the guest never exited and hit the trap limit.
//!    `126`/`127` for a bad entrypoint are produced *inside* the runtime and
//!    flow through as the container code. The default output is docker-shaped
//!    (stdio already streamed live by the engine; the CLI just flushes residual
//!    bytes and adopts the code); `--json` opts into the legacy compat-report
//!    envelope; `--raw` is now a no-op alias for the default.
//!
//! ## Fork-safety on the engine error path
//!
//! Under `--pid private` the supervisor fork happens *inside* `engine.run`, so
//! an HVF/setup failure can surface in the `Err` arm while already in a forked
//! guest-init child. That arm therefore exits with `libc::_exit(125)`, never
//! `std::process::exit`: the latter runs atexit/Drop cleanup, which after a fork
//! double-closes an inherited fd and trips an IO-safety abort. This mirrors how
//! the runtime exits all its other forked children.
//!
//! ## `trace`: the auto-sudo re-exec
//!
//! `Commands::Trace` is the one arm with real control-flow weight, because
//! libdtrace needs root to open `/dev/dtrace` but the *traced guest* must run as
//! the original user. When invoked non-root, the arm re-execs the whole
//! `carrick trace …` invocation under `sudo` and returns. The non-obvious part
//! is environment survival: plain `sudo` does `env_reset`, which would strip the
//! `CARRICK_*` knobs (and `HOME`/`USER`/…) the traced run needs. Those are
//! re-encoded as `--forward-env KEY=VAL` *CLI args* — which survive `sudo`
//! where env vars don't, and need no `SETENV` in sudoers — and re-applied via
//! `std::env::set_var` before the child runs. The original uid/gid/groups ride
//! along as hidden `--trace-uid/--trace-gid/--trace-groups` args so the trace
//! parent can keep root for libdtrace while the spawned child (see
//! [`crate::trace_cli`]) drops back to the caller's identity. The same
//! `--forward-env` idiom is reused by `run`/`run-elf` for sudo-launched runs.

use anyhow::{Context, bail};
use carrick_image::{ImageReference, ImageStore};
use carrick_runtime::compat::{CompatReporter, SyscallArgs};
use carrick_runtime::dispatch::{LinearMemory, SyscallDispatcher, SyscallRequest};
#[cfg(target_os = "macos")]
use carrick_runtime::dtrace_consumer::join_ids;
use carrick_runtime::elf::{inspect_elf, plan_elf_load};
use carrick_runtime::memory::AddressSpace;
use carrick_runtime::rootfs::RootFs;
use carrick_runtime::runtime::DEFAULT_MAX_TRAPS;
// HVF-only diagnostics — the `run-elf`, `trap-capabilities`, and full
// `syscalls`-table subcommands are macOS-only for now (Linux uses `carrick run
// <oci>` / `carrick-kvm run-elf`; per-number `syscalls <n>` works on both).
#[cfg(feature = "platform-macos")]
use carrick_runtime::runtime::run_static_elf_with_hvf_args_and_dispatcher_debug;
#[cfg(feature = "platform-macos")]
use carrick_runtime::syscall::aarch64_table;
use carrick_runtime::syscall::lookup_aarch64;
#[cfg(feature = "platform-macos")]
use carrick_runtime::trap::hvf_capabilities;

use crate::args::{Cli, Commands, NetworkCommand, RootfsCommand, SystemCommand, VolumeCommand};
#[cfg(feature = "platform-macos")]
use crate::debug::run_debug;
// Used only by the macOS-only `run-elf` arm.
#[cfg(feature = "platform-macos")]
use crate::fs_setup::install_fs_backend;
use crate::runtime_util::{
    block_on_oci, emit_raw, human_age, human_size, parse_env_file, parse_mount_flag,
    parse_publish_specs, parse_volume_mount, resolve_volumes_from_specs, truncate_str,
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
                pull: crate::args::PullArg::Missing,
                tty: interactive,
                interactive,
                fs: None,
                network: "host".to_string(),
                network_alias: vec![],
                ip: None,
                add_host: vec![],
                dns: vec![],
                dns_search: vec![],
                dns_option: vec![],
                env: vec![],
                env_file: vec![],
                workdir: None,
                user: None,
                entrypoint: None,
                volume: vec![],
                volumes_from: vec![],
                mount: vec![],
                name: None,
                rm: false,
                stop_signal: None,
                stop_timeout: None,
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
        #[cfg(feature = "platform-macos")]
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
            // Fork-shared alias-IPA counter, before any guest fork (see the Run
            // handler / alloc_alias_ipa — prevents cross-process alias-IPA reuse
            // in the unflushable shared stage-2 TLB).
            carrick_runtime::memory::init_alias_ipa_allocator();
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
                elf_env,
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
            // Cache short-circuit: skip the re-download only if the image is
            // cached for this platform AND its tag has not MOVED in the registry
            // (same tag, new digest). Re-checking the registry digest is what
            // stops a rebuilt+repushed image from being silently served stale —
            // the LTP-oracle version-skew that manufactured 278 false regressions.
            // If the registry is unreachable, we keep trusting the cache so an
            // offline `pull` still succeeds (see `tag_moved_since_pull`).
            let cached = block_on_oci(store.load_pull_summary_for(&image, &target)).ok();
            let up_to_date = cached.as_ref().is_some_and(|summary| {
                let registry = block_on_oci(carrick_image::resolve_registry_tag_digest(
                    &image, &store, &target,
                ));
                !carrick_image::tag_moved_since_pull(summary.digest.as_deref(), registry.as_deref())
            });
            if up_to_date {
                println!("Status: Image is up to date for {}", image.canonical());
            } else {
                block_on_oci(carrick_image::pull_image_with_platform(
                    &image, &store, &target,
                ))?;
                println!("Status: Downloaded newer image for {}", image.canonical());
            }
        }
        Commands::Load { input, platform } => {
            let target = platform
                .as_deref()
                .and_then(carrick_image::PlatformTarget::parse)
                .unwrap_or_else(carrick_image::PlatformTarget::default_target);
            let summaries = store
                .load_docker_archive_for_platform(&input, &target)
                .with_context(|| format!("failed to load image from {}", input.display()))?;
            // docker prints `Loaded image: <tag>` per tag loaded.
            for summary in &summaries {
                println!("Loaded image: {}", summary.image);
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
                    "{:<28}{:<14}{:<16}{:<24}SIZE",
                    "REPOSITORY", "TAG", "IMAGE ID", "CREATED"
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
                match store.remove_image_by_spec(spec) {
                    Ok(Some(name)) => println!("Untagged: {name}"),
                    Ok(None) => {
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
        Commands::Network { command } => run_network_command(command)?,
        Commands::Login {
            registry,
            username,
            password,
            password_stdin,
        } => {
            let registry = registry.unwrap_or_else(|| "docker.io".to_string());
            let username = username.context("a username is required (-u/--username)")?;
            let password = if password_stdin {
                use std::io::Read;
                let mut s = String::new();
                std::io::stdin().read_to_string(&mut s)?;
                s.trim_end_matches(['\n', '\r']).to_string()
            } else {
                password.context("a password is required (-p/--password or --password-stdin)")?
            };
            // Verify against the registry (like docker login), then persist.
            block_on_oci(carrick_image::verify_login(&registry, &username, &password))?;
            carrick_image::auth::write_login(store.root(), &registry, &username, &password)?;
            println!("Login Succeeded");
        }
        Commands::Logout { registry } => {
            let registry = registry.unwrap_or_else(|| "docker.io".to_string());
            if carrick_image::auth::remove_login(store.root(), &registry)? {
                println!("Removing login credentials for {registry}");
            } else {
                println!("Not logged in to {registry}");
            }
        }
        Commands::Tag { source, target } => {
            let src = ImageReference::parse(&source)
                .with_context(|| format!("invalid source image {source:?}"))?;
            let dst = ImageReference::parse(&target)
                .with_context(|| format!("invalid target image {target:?}"))?;
            store
                .tag_image(&src, &dst)
                .with_context(|| format!("failed to tag {source} as {target}"))?;
        }
        Commands::Build {
            tag,
            file,
            build_arg,
            no_cache,
            cache,
            cache_repo,
            platform,
            push,
            context,
        } => {
            run_build(
                &store, tag, file, build_arg, no_cache, cache, cache_repo, platform, push, context,
            )?;
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
            network,
            network_alias,
            ip,
            add_host,
            dns,
            dns_search,
            dns_option,
            env,
            env_file,
            workdir,
            user,
            entrypoint,
            volume,
            volumes_from,
            mount,
            name,
            rm,
            stop_signal,
            stop_timeout,
            publish,
            pid,
            detach,
            forward_env,
            pull,
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
            let parsed_network = parse_network_mode_arg(&network)?;
            let published_ports = parse_publish_specs(parsed_network.mode, &publish)?;

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
            mounts.extend(resolve_volumes_from_specs(&volumes_from)?);

            // `--entrypoint ""` clears the image ENTRYPOINT (run the command
            // alone), like docker — an empty value maps to an empty vec, not a
            // one-element [""] that would become an empty argv[0].
            let entrypoint_override =
                entrypoint.map(|ep| if ep.is_empty() { Vec::new() } else { vec![ep] });

            let req = carrick_engine::CliRunRequest {
                image_ref: image,
                pull: pull.into(),
                platform,
                args: command,
                env_overrides,
                mounts,
                workdir,
                user,
                hostname: None,
                entrypoint_override,
                tty,
                interactive,
                rm,
                name,
                max_traps,
                debug_state_path: debug_state_path.map(|p| p.to_string_lossy().into_owned()),
                fs,
                pid,
                network: parsed_network.mode,
                network_bridge: parsed_network.bridge,
                network_container: parsed_network.container,
                network_namespace_id: None,
                network_attachments: Vec::new(),
                network_ipv4: ip,
                network_aliases: network_alias,
                extra_hosts: add_host,
                dns_servers: dns,
                dns_search,
                dns_options: dns_option,
                volumes_from,
                published_ports,
                stop_signal,
                stop_timeout,
            };

            // Stand up the fork-shared alias-IPA counter NOW, in the root process,
            // before any guest (or the --pid-private supervisor) forks — every
            // host-forked descendant must inherit the one MAP_SHARED counter so no
            // two guest processes ever reuse an alias IPA in the shared hv_vm
            // (a latent cross-process stage-2 coherence hazard). See alloc_alias_ipa.
            carrick_runtime::memory::init_alias_ipa_allocator();

            // Detached (`carrick run -d`): fork into the background under a
            // per-container supervisor, print the id, and return. Manage it with
            // `carrick ps|stop|kill|rm`. `run_detached` resolves/pulls the image
            // in the foreground first, so a resolution error surfaces to the
            // user's terminal (not the detached log) and the effective stop
            // signal is baked into the persisted config.
            if detach {
                let name_for_state = req.name.clone();
                return crate::lifecycle::run_detached(req, store.clone(), name_for_state);
            }

            // Sensible-default run identity. A foreground `carrick run` is not a
            // registered container (like foreground `docker run`), but it should
            // still carry a stable id used for the proctitle + the scoped reaper
            // (`scripts/sudo/kill.sh`), drawn from the SAME id space as
            // `carrick ps` / `run -d`. Precedence:
            //   explicit CARRICK_RUN_ID (a caller's grouping override)
            //     -> the container `--name`
            //       -> an auto 12-hex short id (`make_id`/`short_id`, the ps scheme).
            // So every run is scoped + reapable by default with no env var to
            // remember, and the prefix-collision class of bug disappears (ids are
            // random 12-hex, never a prefix of one another). `proctitle.rs` reads
            // CARRICK_RUN_ID; we resolve the default here and stamp it.
            if std::env::var_os("CARRICK_RUN_ID").is_none() {
                let scope = req.name.clone().unwrap_or_else(|| {
                    let entropy = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_nanos() as u64)
                        .unwrap_or(0);
                    let id =
                        carrick_runtime::container::make_id(std::process::id() as u64, entropy);
                    carrick_runtime::container::short_id(&id).to_string()
                });
                // SAFETY: single-threaded here (pre-runtime), like the
                // forward-env `set_var` later in this function.
                unsafe { std::env::set_var("CARRICK_RUN_ID", scope) };
            }

            let engine = carrick_engine::Engine::new(store.clone());
            // Docker exits 125 when `run` itself fails *before/at* container
            // start — image resolve/pull, an invalid reference, no command, or
            // VM setup. (The container's OWN exit code is the Ok path below;
            // 126/127 for a bad entrypoint are produced inside the runtime.)
            // Resolve (pull + build the spec) under the tokio runtime, then DROP
            // the runtime before executing — so no tokio thread is alive across
            // the fork in Runtime::execute. (Forking with a live tokio runtime
            // deadlocks the child in BlockingPool::shutdown.)
            let spec = match block_on_oci(engine.resolve(req.clone())) {
                Ok(s) => s,
                // resolve runs in the PARENT (no fork yet) → normal exit is safe.
                Err(e) => {
                    eprintln!("carrick: {e:#}");
                    std::process::exit(125);
                }
            };
            let result = match carrick_runtime::Runtime::execute(&spec) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("carrick: {e:#}");
                    // execute() forks (interactive supervisor / `--pid private`
                    // NsSupervisor); a setup failure can surface in the forked
                    // guest-init child, where `std::process::exit`'s atexit/Drop
                    // is unsafe after fork and double-closes an inherited fd
                    // (IO-safety abort → SIGABRT). `_exit` terminates without that
                    // cleanup, like the runtime's other forked-child exits.
                    // SAFETY: _exit is async-signal-safe; stderr already flushed
                    // (eprintln is unbuffered); no buffered stdout to lose.
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
        Commands::Inspect { format, containers } => {
            crate::lifecycle::inspect(format.as_deref(), &containers)?
        }
        Commands::Ps {
            all,
            quiet,
            no_trunc,
            format,
        } => crate::lifecycle::ps(all, quiet, no_trunc, format.as_deref())?,
        Commands::Stop { time, containers } => crate::lifecycle::stop(time, &containers)?,
        Commands::Kill { signal, containers } => crate::lifecycle::kill(&signal, &containers)?,
        Commands::Rm { force, containers } => crate::lifecycle::rm(force, &containers)?,
        Commands::Create {
            image,
            platform,
            fs,
            pid,
            network,
            network_alias,
            ip,
            add_host,
            dns,
            dns_search,
            dns_option,
            env,
            env_file,
            workdir,
            user,
            entrypoint,
            volume,
            volumes_from,
            mount,
            name,
            rm,
            tty,
            interactive,
            publish,
            stop_signal,
            stop_timeout,
            pull,
            command,
        } => {
            let mut env_overrides = env;
            for file_path in &env_file {
                env_overrides.extend(parse_env_file(file_path)?);
            }
            let mut mounts = Vec::new();
            for v in &volume {
                mounts.push(parse_volume_mount(v)?);
            }
            for m in &mount {
                mounts.push(parse_mount_flag(m)?);
            }
            mounts.extend(resolve_volumes_from_specs(&volumes_from)?);
            let entrypoint_override =
                entrypoint.map(|ep| if ep.is_empty() { Vec::new() } else { vec![ep] });
            let parsed_network = parse_network_mode_arg(&network)?;
            let req = carrick_engine::CliRunRequest {
                image_ref: image,
                pull: pull.into(),
                platform,
                args: command,
                env_overrides,
                mounts,
                workdir,
                user,
                hostname: None,
                entrypoint_override,
                tty,
                interactive,
                rm,
                name: None,
                max_traps: DEFAULT_MAX_TRAPS,
                debug_state_path: None,
                fs,
                pid,
                network: parsed_network.mode,
                network_bridge: parsed_network.bridge,
                network_container: parsed_network.container,
                network_namespace_id: None,
                network_attachments: Vec::new(),
                network_ipv4: ip,
                network_aliases: network_alias,
                extra_hosts: add_host,
                dns_servers: dns,
                dns_search,
                dns_options: dns_option,
                volumes_from,
                published_ports: parse_publish_specs(parsed_network.mode, &publish)?,
                stop_signal,
                stop_timeout,
            };
            crate::lifecycle::create(req, store.clone(), name)?;
        }
        Commands::Start { attach, containers } => {
            crate::lifecycle::start(&store, attach, &containers)?
        }
        Commands::Restart { time, containers } => {
            crate::lifecycle::restart(&store, time, &containers)?
        }
        Commands::Serve { docker_api, host } => crate::serve::serve(docker_api, host)?,
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
        #[cfg(feature = "platform-macos")]
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
            // `CompatReporter` is a fielded struct on macOS (carrick-vmm-hvf) but a
            // unit struct in the non-macOS fallback, so `.default()` only trips
            // `default_constructed_unit_structs` off-macOS. Keep the lint strict
            // on macOS.
            #[cfg_attr(
                not(target_os = "macos"),
                allow(clippy::default_constructed_unit_structs)
            )]
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
                // The full-table dump comes from the HVF syscall table; macOS-only.
                // The per-number lookup above works on both backends.
                #[cfg(feature = "platform-macos")]
                println!("{}", serde_json::to_string_pretty(aarch64_table())?);
                #[cfg(any(
                    feature = "platform-linux",
                    feature = "platform-freebsd",
                    feature = "platform-netbsd"
                ))]
                bail!(
                    "the full syscall-table dump is HVF-only on this build; pass a syscall number"
                );
            }
        }
        Commands::TrapCapabilities => {
            #[cfg(feature = "platform-macos")]
            println!("{}", serde_json::to_string_pretty(&hvf_capabilities())?);
            #[cfg(any(
                feature = "platform-linux",
                feature = "platform-freebsd",
                feature = "platform-netbsd"
            ))]
            bail!("trap-capabilities is HVF-only; not available on this backend");
        }
        #[cfg(feature = "platform-macos")]
        Commands::Debug { command } => run_debug(command)?,
        #[cfg(any(
            feature = "platform-linux",
            feature = "platform-freebsd",
            feature = "platform-netbsd"
        ))]
        Commands::Debug { command } => {
            let _ = command;
            bail!("debug (guest address-space inspection) is HVF-only on this build");
        }
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
        Commands::Volume { command } => run_volume_command(command)?,
    }

    Ok(())
}

fn run_volume_command(command: VolumeCommand) -> anyhow::Result<()> {
    match command {
        VolumeCommand::Create {
            driver,
            label,
            opt,
            quota,
            name,
        } => {
            if let Some(name) = name {
                if quota.is_some() {
                    bail!("--quota applies only to the legacy scratch volume create path");
                }
                let labels = parse_key_value_args(label, "--label")?;
                let driver_opts = parse_key_value_args(opt, "--opt")?;
                let body = serde_json::to_vec(&serde_json::json!({
                    "Name": name,
                    "Driver": driver,
                    "Labels": labels,
                    "DriverOpts": driver_opts,
                }))?;
                let (status, body) = crate::serve::resources::create_volume(&body);
                ensure_resource_status(status, &body, &[201])?;
                let value: serde_json::Value = serde_json::from_str(&body)?;
                let Some(name) = value.get("Name").and_then(serde_json::Value::as_str) else {
                    bail!("volume create response missing Name");
                };
                println!("{name}");
            } else {
                run_scratch_volume_create(quota)?;
            }
        }
        VolumeCommand::Ls {
            filter,
            format,
            quiet,
        } => {
            let query = resource_filter_query(filter)?;
            let (status, body) = crate::serve::resources::list_volumes(&query);
            ensure_resource_status(status, &body, &[200])?;
            let value: serde_json::Value = serde_json::from_str(&body)?;
            let volumes = value
                .get("Volumes")
                .and_then(serde_json::Value::as_array)
                .cloned()
                .unwrap_or_default();
            print_volume_list(volumes, format.as_deref(), quiet)?;
        }
        VolumeCommand::Prune {
            all,
            force: _,
            mut filter,
        } => {
            if all {
                filter.push("all=true".to_string());
            }
            let query = resource_filter_query(filter)?;
            let (status, body) = crate::serve::resources::prune_volumes(&query);
            ensure_resource_status(status, &body, &[200])?;
            let value: serde_json::Value = serde_json::from_str(&body)?;
            println!("Deleted Volumes:");
            if let Some(volumes) = value
                .get("VolumesDeleted")
                .and_then(serde_json::Value::as_array)
            {
                for volume in volumes.iter().filter_map(serde_json::Value::as_str) {
                    println!("{volume}");
                }
            }
            let reclaimed = value
                .get("SpaceReclaimed")
                .and_then(serde_json::Value::as_i64)
                .unwrap_or_default();
            println!(
                "Total reclaimed space: {}",
                human_size(reclaimed.max(0) as u64)
            );
        }
        VolumeCommand::Inspect { names } => {
            let mut volumes = Vec::new();
            for name in names {
                let (status, body) = crate::serve::resources::inspect_volume(&name);
                ensure_resource_status(status, &body, &[200])?;
                volumes.push(serde_json::from_str::<serde_json::Value>(&body)?);
            }
            println!("{}", serde_json::to_string(&volumes)?);
        }
        VolumeCommand::Rm { force, names } => {
            let mut had_err = false;
            for name in names {
                let (status, body) = crate::serve::resources::remove_volume(&name, force);
                if status == 204 {
                    println!("{name}");
                } else {
                    had_err = true;
                    eprintln!("{}", resource_error_message(&body));
                }
            }
            if had_err {
                bail!("one or more volumes failed to be removed");
            }
        }
        #[cfg(target_os = "macos")]
        VolumeCommand::Info => run_scratch_volume_info()?,
        #[cfg(target_os = "macos")]
        VolumeCommand::Delete { yes } => run_scratch_volume_delete(yes)?,
    }
    Ok(())
}

fn print_volume_list(
    volumes: Vec<serde_json::Value>,
    format: Option<&str>,
    quiet: bool,
) -> anyhow::Result<()> {
    if quiet {
        for volume in volumes {
            println!("{}", volume_field(&volume, "Name"));
        }
        return Ok(());
    }

    match format {
        Some("json") => {
            for volume in volumes {
                println!("{}", serde_json::to_string(&volume)?);
            }
        }
        Some("table") | None => {
            println!("DRIVER\tVOLUME NAME");
            for volume in volumes {
                println!(
                    "{}\t{}",
                    volume_field(&volume, "Driver"),
                    volume_field(&volume, "Name")
                );
            }
        }
        Some(template) => {
            let template = template.strip_prefix("table ").unwrap_or(template);
            for volume in volumes {
                println!("{}", render_volume_template(&volume, template));
            }
        }
    }
    Ok(())
}

fn render_volume_template(volume: &serde_json::Value, template: &str) -> String {
    ["Name", "Driver", "Mountpoint", "Scope"].into_iter().fold(
        template.to_string(),
        |rendered, field| {
            rendered.replace(&format!("{{{{.{field}}}}}"), &volume_field(volume, field))
        },
    )
}

fn volume_field(volume: &serde_json::Value, field: &str) -> String {
    volume
        .get(field)
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_string()
}

#[cfg(target_os = "macos")]
fn run_scratch_volume_create(quota: Option<u64>) -> anyhow::Result<()> {
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
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn run_scratch_volume_create(_quota: Option<u64>) -> anyhow::Result<()> {
    bail!("unnamed scratch volume creation is only available on macOS");
}

#[cfg(target_os = "macos")]
fn run_scratch_volume_info() -> anyhow::Result<()> {
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
            bail!("no carrick scratch volume found; run `carrick volume create` to lay one down");
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn run_scratch_volume_delete(yes: bool) -> anyhow::Result<()> {
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
    Ok(())
}

fn run_network_command(command: NetworkCommand) -> anyhow::Result<()> {
    match command {
        NetworkCommand::Create {
            driver,
            label,
            subnet,
            gateway,
            ip_range,
            aux_address,
            ipam_driver,
            ipam_opt,
            scope,
            internal,
            attachable,
            ingress,
            config_from,
            config_only,
            ipv4,
            ipv6,
            opt,
            name,
        } => {
            let labels = parse_key_value_args(label, "--label")?;
            let options = parse_key_value_args(opt, "--opt")?;
            let ipam = network_ipam_config(
                &ipam_driver,
                ipam_opt,
                &subnet,
                &gateway,
                &ip_range,
                aux_address,
            )?;
            let body = serde_json::to_vec(&serde_json::json!({
                "Name": name,
                "Driver": driver,
                "Scope": scope,
                "Internal": internal,
                "Attachable": attachable,
                "Ingress": ingress,
                "ConfigFrom": config_from.map(|network| serde_json::json!({ "Network": network })),
                "ConfigOnly": config_only,
                "EnableIPv4": ipv4.unwrap_or(true),
                "EnableIPv6": ipv6,
                "IPAM": ipam,
                "Options": options,
                "Labels": labels,
            }))?;
            let (status, body) = crate::serve::resources::create_network(&body);
            ensure_resource_status(status, &body, &[201])?;
            let value: serde_json::Value = serde_json::from_str(&body)?;
            let Some(id) = value.get("Id").and_then(serde_json::Value::as_str) else {
                bail!("network create response missing Id");
            };
            println!("{id}");
        }
        NetworkCommand::Connect {
            alias,
            link,
            ip,
            ip6,
            link_local_ip,
            driver_opt,
            gw_priority,
            network,
            container,
        } => {
            let ipam_config =
                network_connect_ipam_config(ip.as_deref(), ip6.as_deref(), &link_local_ip);
            let driver_opts = parse_key_value_args(driver_opt, "--driver-opt")?;
            let body = serde_json::to_vec(&serde_json::json!({
                "Container": container,
                "EndpointConfig": {
                    "Aliases": alias,
                    "Links": link,
                    "IPAMConfig": ipam_config,
                    "DriverOpts": driver_opts,
                    "GwPriority": gw_priority,
                },
            }))?;
            let (status, body) = crate::serve::resources::connect_network(&network, &body);
            ensure_resource_status(status, &body, &[200])?;
        }
        NetworkCommand::Disconnect {
            force,
            network,
            container,
        } => {
            let body = serde_json::to_vec(&serde_json::json!({
                "Container": container,
                "Force": force,
            }))?;
            let (status, body) = crate::serve::resources::disconnect_network(&network, &body);
            ensure_resource_status(status, &body, &[200])?;
        }
        NetworkCommand::Ls => {
            let (status, body) = crate::serve::resources::list_networks("");
            ensure_resource_status(status, &body, &[200])?;
            let networks: Vec<serde_json::Value> = serde_json::from_str(&body)?;
            println!("NETWORK ID\tNAME\tDRIVER\tSCOPE");
            for network in networks {
                let id = network
                    .get("Id")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default();
                let short_id = id.get(..12).unwrap_or(id);
                let name = network
                    .get("Name")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default();
                let driver = network
                    .get("Driver")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default();
                let scope = network
                    .get("Scope")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default();
                println!("{short_id}\t{name}\t{driver}\t{scope}");
            }
        }
        NetworkCommand::Prune { force: _, filter } => {
            let query = resource_filter_query(filter)?;
            let (status, body) = crate::serve::resources::prune_networks(&query);
            ensure_resource_status(status, &body, &[200])?;
            let value: serde_json::Value = serde_json::from_str(&body)?;
            println!("Deleted Networks:");
            if let Some(networks) = value
                .get("NetworksDeleted")
                .and_then(serde_json::Value::as_array)
            {
                for network in networks.iter().filter_map(serde_json::Value::as_str) {
                    println!("{network}");
                }
            }
        }
        NetworkCommand::Inspect { names } => {
            let mut networks = Vec::new();
            for name in names {
                let (status, body) = crate::serve::resources::inspect_network(&name);
                ensure_resource_status(status, &body, &[200])?;
                networks.push(serde_json::from_str::<serde_json::Value>(&body)?);
            }
            println!("{}", serde_json::to_string(&networks)?);
        }
        NetworkCommand::Rm { names } => {
            let mut had_err = false;
            for name in names {
                let (status, body) = crate::serve::resources::remove_network(&name);
                if status == 204 {
                    println!("{name}");
                } else {
                    had_err = true;
                    eprintln!("{}", resource_error_message(&body));
                }
            }
            if had_err {
                bail!("one or more networks failed to be removed");
            }
        }
    }
    Ok(())
}

fn network_connect_ipam_config(
    ipv4: Option<&str>,
    ipv6: Option<&str>,
    link_local_ips: &[String],
) -> Option<serde_json::Value> {
    if ipv4.is_none() && ipv6.is_none() && link_local_ips.is_empty() {
        return None;
    }
    let mut ipam = serde_json::Map::new();
    if let Some(ipv4) = ipv4 {
        ipam.insert("IPv4Address".to_string(), serde_json::json!(ipv4));
    }
    if let Some(ipv6) = ipv6 {
        ipam.insert("IPv6Address".to_string(), serde_json::json!(ipv6));
    }
    if !link_local_ips.is_empty() {
        ipam.insert(
            "LinkLocalIPs".to_string(),
            serde_json::json!(link_local_ips),
        );
    }
    Some(serde_json::Value::Object(ipam))
}

fn network_ipam_config(
    driver: &str,
    options: Vec<String>,
    subnets: &[String],
    gateways: &[String],
    ip_ranges: &[String],
    aux_addresses: Vec<String>,
) -> anyhow::Result<serde_json::Value> {
    let options = parse_key_value_args(options, "--ipam-opt")?;
    if driver == "default"
        && options.is_empty()
        && subnets.is_empty()
        && gateways.is_empty()
        && ip_ranges.is_empty()
        && aux_addresses.is_empty()
    {
        return Ok(serde_json::Value::Null);
    }
    if !gateways.is_empty() && gateways.len() != subnets.len() {
        bail!("--gateway must be specified once per --subnet");
    }
    if !ip_ranges.is_empty() && ip_ranges.len() != subnets.len() {
        bail!("--ip-range must be specified once per --subnet");
    }
    if !aux_addresses.is_empty() && subnets.is_empty() {
        bail!("--aux-address requires at least one --subnet");
    }
    let aux_addresses = parse_key_value_args(aux_addresses, "--aux-address")?;
    let config: Vec<serde_json::Value> = subnets
        .iter()
        .enumerate()
        .map(|(index, subnet)| {
            let mut entry = serde_json::Map::new();
            entry.insert("Subnet".to_string(), serde_json::json!(subnet));
            if let Some(gateway) = gateways.get(index) {
                entry.insert("Gateway".to_string(), serde_json::json!(gateway));
            }
            if let Some(ip_range) = ip_ranges.get(index) {
                entry.insert("IPRange".to_string(), serde_json::json!(ip_range));
            }
            if index == 0 && !aux_addresses.is_empty() {
                entry.insert(
                    "AuxiliaryAddresses".to_string(),
                    serde_json::json!(aux_addresses),
                );
            }
            serde_json::Value::Object(entry)
        })
        .collect();
    Ok(serde_json::json!({
        "Driver": driver,
        "Options": options,
        "Config": config,
    }))
}

fn parse_key_value_args(
    pairs: Vec<String>,
    flag_name: &str,
) -> anyhow::Result<std::collections::HashMap<String, String>> {
    let mut parsed = std::collections::HashMap::new();
    for pair in pairs {
        let Some((key, value)) = pair.split_once('=') else {
            bail!("{flag_name} expects KEY=VALUE");
        };
        if key.is_empty() {
            bail!("{flag_name} key cannot be empty");
        }
        parsed.insert(key.to_string(), value.to_string());
    }
    Ok(parsed)
}

fn resource_filter_query(filters: Vec<String>) -> anyhow::Result<String> {
    if filters.is_empty() {
        return Ok(String::new());
    }
    let mut parsed: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();
    for filter in filters {
        let Some((key, value)) = filter.split_once('=') else {
            bail!("--filter expects KEY=VALUE");
        };
        if key.is_empty() {
            bail!("--filter key cannot be empty");
        }
        parsed
            .entry(key.to_string())
            .or_default()
            .push(value.to_string());
    }
    let json = serde_json::to_string(&parsed)?;
    Ok(format!("filters={}", percent_encode_query_value(&json)))
}

fn percent_encode_query_value(value: &str) -> String {
    let mut out = String::new();
    for b in value.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(char::from(b))
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn ensure_resource_status(status: u16, body: &str, expected: &[u16]) -> anyhow::Result<()> {
    if expected.contains(&status) {
        return Ok(());
    }
    bail!("{}", resource_error_message(body));
}

fn resource_error_message(body: &str) -> String {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|value| {
            value
                .get("message")
                .and_then(serde_json::Value::as_str)
                .map(ToOwned::to_owned)
        })
        .unwrap_or_else(|| body.to_string())
}

/// The kaniko executor image, pinned to the spike-validated version. The build
/// wrapper runs this exact image as a carrick guest; bumping it is a deliberate
/// re-validation step, not an incidental dependency update.
const KANIKO_IMAGE: &str = "gcr.io/kaniko-project/executor:v1.24.0";

/// The destination used when no `-t/--tag` is given. kaniko requires a
/// `--destination` even for a `--no-push` build (it stamps the image's
/// `RepoTags`, which is what `carrick load` then tags the image as).
const DEFAULT_BUILD_TAG: &str = "carrick-build:latest";

/// `carrick build` — a thin wrapper that builds a Dockerfile by running the real
/// kaniko executor as a carrick guest, then loads the result into the store.
///
/// This reimplements nothing: it composes the already-proven loop of
/// `carrick run --fs host -v <context>:/workspace [-v <out>:/out] <kaniko> …`
/// (the server-as-translator pattern: shell out to our own binary, inheriting
/// stdio so kaniko's progress streams live) and then either lets kaniko push or
/// ingests the resulting tar with [`ImageStore::load_docker_archive`].
#[allow(clippy::too_many_arguments)]
fn run_build(
    store: &ImageStore,
    tag: Option<String>,
    file: std::path::PathBuf,
    build_arg: Vec<String>,
    no_cache: bool,
    cache: bool,
    cache_repo: Option<String>,
    platform: Option<String>,
    push: bool,
    context: std::path::PathBuf,
) -> anyhow::Result<()> {
    // The build context must exist and be a directory. Canonicalise it so the
    // `-v` bind mount gets an absolute host path (carrick run resolves the mount
    // source against its launch dir otherwise).
    let context_abs = context.canonicalize().with_context(|| {
        format!(
            "build context {} does not exist or is not accessible",
            context.display()
        )
    })?;
    if !context_abs.is_dir() {
        bail!("build context {} is not a directory", context_abs.display());
    }

    // The Dockerfile path is RELATIVE to the context; reject an absolute `-f`
    // (it would not resolve inside the guest's /workspace mount) so the failure
    // is a clear CLI error rather than an opaque kaniko ENOENT.
    if file.is_absolute() {
        bail!(
            "-f/--file {} must be relative to the build context",
            file.display()
        );
    }
    let dockerfile_rel = file.to_string_lossy().into_owned();

    // kaniko's `--destination` is required even for `--no-push`; default it.
    let destination = tag.unwrap_or_else(|| DEFAULT_BUILD_TAG.to_owned());

    let me = std::env::current_exe().context("failed to resolve current carrick binary path")?;

    // DATA-LOSS GUARD: never bind-mount the user's context directory directly.
    //
    // kaniko's between-stage filesystem reset calls `os.RemoveAll("/workspace")`
    // which, through the bind mount, would delete the user's real source files
    // on the host. Docker avoids this by sending the context as a tar stream (a
    // copy, never the original). We mirror that by copying the context into a
    // fresh temp dir and mounting the COPY — kaniko then deletes/mutates the
    // copy, and the user's context is never touched.
    //
    // Keep the TempDir handle alive across the entire build so the copy isn't
    // cleaned up until after the kaniko run and the image ingest both finish.
    let context_tmp =
        tempfile::tempdir().context("failed to create temp directory for build context copy")?;
    let context_copy = context_tmp.path().join("context");
    copy_dir_recursive(&context_abs, &context_copy).with_context(|| {
        format!(
            "failed to copy build context {} to temp dir",
            context_abs.display()
        )
    })?;

    // The output dir for the built tar is only needed on the `--no-push` path.
    // Keep the TempDir alive for the duration of the build + ingest.
    let out_dir = if push {
        None
    } else {
        Some(tempfile::tempdir().context("failed to create temp output directory for image tar")?)
    };
    let out_path = out_dir.as_ref().map(|d| d.path().to_path_buf());

    let argv = kaniko_run_argv(
        &me.to_string_lossy(),
        &context_copy.to_string_lossy(),
        out_path.as_ref().map(|p| p.to_string_lossy().into_owned()),
        &dockerfile_rel,
        &destination,
        &build_arg,
        no_cache,
        cache,
        cache_repo.as_deref(),
        platform.as_deref(),
    );

    // Shell out to ourselves, inheriting stdio so kaniko's build progress
    // streams straight to the user (same translator pattern as `carrick serve`
    // / `carrick trace`). argv[0] is the carrick binary path.
    let (program, args) = argv
        .split_first()
        .context("internal error: empty kaniko run argv")?;
    let status = std::process::Command::new(program)
        .args(args)
        .status()
        .with_context(|| format!("failed to spawn {program} for the kaniko build"))?;
    if !status.success() {
        // kaniko's own diagnostics already streamed to the user's terminal.
        bail!("build failed (kaniko exited with {status})");
    }

    if push {
        // kaniko already pushed to the registry; nothing to ingest.
        println!("Successfully built {destination}");
        println!("Successfully pushed {destination}");
        return Ok(());
    }

    // `--no-push`: ingest the tar kaniko wrote into the store, directly via the
    // store method (no third process). kaniko tags the image per the tar's
    // RepoTags (our `--destination`).
    let tar = out_path
        .as_ref()
        .context("internal error: missing output tar path for --no-push build")?
        .join("image.tar");
    let summaries = store
        .load_docker_archive(&tar)
        .with_context(|| format!("failed to load built image from {}", tar.display()))?;

    println!("Successfully built {destination}");
    for summary in &summaries {
        println!("Successfully tagged {}", summary.image);
    }
    Ok(())
}

/// Recursively copy `src` (a directory) to `dst` (which must not yet exist).
///
/// Files are copied byte-for-byte. Symlinks are reproduced as symlinks
/// (pointing to the same target they did in the source tree) rather than
/// followed — this preserves the context faithfully and avoids following a
/// dangling or loop-creating link. Permissions on files and directories are
/// preserved via `std::fs::copy` (which copies the permission bits on Unix).
///
/// This is intentionally simple: no `.dockerignore` filtering (kaniko applies
/// its own ignore rules from the copy), no hardlink deduplication. The goal is
/// a faithful, safe copy so kaniko's `os.RemoveAll("/workspace")` cannot touch
/// the user's source tree.
fn copy_dir_recursive(src: &std::path::Path, dst: &std::path::Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(dst)
        .with_context(|| format!("failed to create directory {}", dst.display()))?;

    // `src` is a canonicalized directory the user explicitly supplied as their
    // build context; `dst` is a fresh tempdir owned by this process.
    // `entry.file_name()` is always a bare filename with no separators, so no
    // traversal into the temp tree is possible.
    for entry in std::fs::read_dir(src) // nosemgrep: rust.actix.path-traversal.tainted-path.tainted-path
        .with_context(|| format!("failed to read directory {}", src.display()))?
    {
        let entry = entry.with_context(|| format!("failed to read entry in {}", src.display()))?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());

        let file_type = entry
            .file_type()
            .with_context(|| format!("failed to get file type of {}", src_path.display()))?;

        if file_type.is_symlink() {
            // Reproduce the symlink rather than following it.
            let target = std::fs::read_link(&src_path)
                .with_context(|| format!("failed to read symlink {}", src_path.display()))?;
            std::os::unix::fs::symlink(&target, &dst_path).with_context(|| {
                format!(
                    "failed to create symlink {} -> {}",
                    dst_path.display(),
                    target.display()
                )
            })?;
        } else if file_type.is_dir() {
            copy_dir_recursive(&src_path, &dst_path)?;
        } else {
            // Regular file (or other non-symlink non-dir special file that
            // std::fs::copy handles gracefully on the platforms we care about).
            std::fs::copy(&src_path, &dst_path).with_context(|| {
                format!(
                    "failed to copy {} to {}",
                    src_path.display(),
                    dst_path.display()
                )
            })?;
        }
    }
    Ok(())
}

/// Build the `carrick run` argv that runs kaniko over the build context. Pure
/// (no IO) so the flag mapping is unit-testable. `argv[0]` is the carrick
/// binary path; the rest is `run --fs host …` followed by the kaniko image and
/// its executor flags.
///
/// `out_dir` is `Some` for the `--no-push` path (kaniko writes `image.tar`
/// there via a `/out` bind mount); `None` for `--push` (kaniko pushes directly,
/// so there is no `/out` mount, no `--tar-path`, and no `--no-push`).
///
/// Cache flag priority: `no_cache` wins over `cache`. Only one of
/// `--cache=false` or `--cache=true` is ever emitted. `cache_repo` is only
/// meaningful (and only emitted) when `cache` is set and `no_cache` is not.
#[allow(clippy::too_many_arguments)]
fn kaniko_run_argv(
    carrick_bin: &str,
    context_abs: &str,
    out_dir: Option<String>,
    dockerfile_rel: &str,
    destination: &str,
    build_args: &[String],
    no_cache: bool,
    cache: bool,
    cache_repo: Option<&str>,
    platform: Option<&str>,
) -> Vec<String> {
    let mut argv: Vec<String> = vec![
        carrick_bin.to_owned(),
        "run".to_owned(),
        "--fs".to_owned(),
        "host".to_owned(),
        // A long build must never be killed by the trap budget: run effectively
        // uncapped. `--max-traps` takes a usize; usize::MAX is the largest value.
        "--max-traps".to_owned(),
        usize::MAX.to_string(),
        "-v".to_owned(),
        format!("{context_abs}:/workspace"),
    ];
    if let Some(out) = &out_dir {
        argv.push("-v".to_owned());
        argv.push(format!("{out}:/out"));
    }
    // The kaniko image, then its executor args (everything after this is parsed
    // by kaniko, not carrick — `carrick run`'s trailing_var_arg captures it).
    argv.push(KANIKO_IMAGE.to_owned());
    argv.push("--context".to_owned());
    argv.push("dir:///workspace".to_owned());
    argv.push("--dockerfile".to_owned());
    argv.push(format!("/workspace/{dockerfile_rel}"));
    // kaniko runs in its DEFAULT full-filesystem snapshot mode (no
    // `--use-new-run`). That mode is the most faithful — it captures every
    // per-RUN change, including modifications to files brought in by
    // `COPY --from=<stage>` — which `--use-new-run` does NOT.
    //
    // `--use-new-run` was previously forced here to work around a carrick bug:
    // a writable `-v` bind mount let kaniko's between-stage "Deleting
    // filesystem" (`os.RemoveAll("/workspace")`) delete the host source dir,
    // leaving a dangling mount that made the next full-FS snapshot walk abort
    // at /workspace and emit a spurious `.wh.lib` (deleting /lib → broken
    // image). That is now fixed at the source (BindVfs treats removing the
    // mount point as a no-op — see crates/carrick-runtime/src/vfs/bind.rs), so
    // the default snapshot produces a correct multi-stage image under carrick
    // and the workaround (and its COPY --from fidelity loss) is gone.
    if out_dir.is_some() {
        // No-push: build to a tar that carrick then loads.
        argv.push("--no-push".to_owned());
        argv.push("--tar-path".to_owned());
        argv.push("/out/image.tar".to_owned());
    }
    argv.push("--destination".to_owned());
    argv.push(destination.to_owned());
    for ba in build_args {
        argv.push("--build-arg".to_owned());
        argv.push(ba.clone());
    }
    if no_cache {
        // kaniko has no `--no-cache` flag (that name errors with "unknown
        // flag"); its caching is opt-in via `--cache` (off by default). Express
        // "no cache" with the valid, explicit `--cache=false`.
        // `--no-cache` wins over `--cache` when both are given.
        argv.push("--cache=false".to_owned());
    } else if cache {
        // Explicitly enable kaniko's registry-backed layer cache.
        argv.push("--cache=true".to_owned());
        if let Some(repo) = cache_repo {
            argv.push("--cache-repo".to_owned());
            argv.push(repo.to_owned());
        }
    }
    if let Some(p) = platform {
        argv.push("--customPlatform".to_owned());
        argv.push(p.to_owned());
    }
    argv
}

#[cfg(test)]
mod build_tests {
    use super::*;

    #[test]
    fn parse_network_mode_accepts_custom_bridge_name() {
        let parsed = parse_network_mode_arg("compose_default").unwrap();
        assert_eq!(parsed.mode, carrick_spec::NetworkMode::Bridge);
        assert_eq!(parsed.bridge.as_deref(), Some("compose_default"));
        assert_eq!(parsed.container, None);
    }

    #[test]
    fn parse_network_mode_accepts_container_target_name() {
        let entropy = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        let id = carrick_runtime::container::make_id(std::process::id() as u64, entropy);
        let name = format!("m0_cli_net_target_{}", &id[..12]);
        let config = carrick_runtime::container::RunConfig {
            network: carrick_spec::NetworkMode::Bridge,
            network_attachments: vec![carrick_runtime::container::NetworkAttachment {
                name: "compose_default".to_string(),
                aliases: Vec::new(),
                links: Vec::new(),
                mac_address: None,
                gw_priority: 0,
                ipv4_address: None,
                ipv6_address: None,
                link_local_ips: Vec::new(),
                driver_opts: std::collections::HashMap::new(),
            }],
            ..Default::default()
        };
        let state = carrick_runtime::container::ContainerState {
            id: id.clone(),
            name: Some(name.clone()),
            image: "ubuntu:24.04".to_string(),
            command: vec!["/bin/true".to_string()],
            status: carrick_runtime::container::ContainerStatus::Created,
            supervisor_pid: 0,
            init_pid: 0,
            created_secs: 0,
            exit_code: None,
            auto_remove: false,
            api_auto_remove: false,
            labels: std::collections::HashMap::new(),
            config,
        };
        let _ = carrick_runtime::container::ContainerState::remove(&id);
        state.create().unwrap();

        let parsed = parse_network_mode_arg(&format!("container:{name}")).unwrap();

        let _ = carrick_runtime::container::ContainerState::remove(&id);
        assert_eq!(parsed.mode, carrick_spec::NetworkMode::Bridge);
        assert_eq!(parsed.bridge.as_deref(), Some("compose_default"));
        assert_eq!(parsed.container.as_deref(), Some(id.as_str()));
    }

    #[test]
    fn network_ipam_config_preserves_docker_cli_metadata() {
        let ipam = network_ipam_config(
            "carrick-ipam",
            vec!["mode=test".to_string()],
            &["172.29.0.0/16".to_string()],
            &["172.29.0.1".to_string()],
            &["172.29.8.0/24".to_string()],
            vec!["router=172.29.0.254".to_string()],
        )
        .unwrap();

        assert_eq!(
            ipam,
            serde_json::json!({
                "Driver": "carrick-ipam",
                "Options": {
                    "mode": "test",
                },
                "Config": [{
                    "Subnet": "172.29.0.0/16",
                    "Gateway": "172.29.0.1",
                    "IPRange": "172.29.8.0/24",
                    "AuxiliaryAddresses": {
                        "router": "172.29.0.254",
                    },
                }],
            })
        );
    }

    #[test]
    fn network_connect_ipam_config_preserves_ipv4_and_ipv6() {
        let ipam = network_connect_ipam_config(
            Some("172.31.44.11"),
            Some("fd00:carrick::11"),
            &["169.254.44.11".to_string()],
        )
        .unwrap();

        assert_eq!(
            ipam,
            serde_json::json!({
                "IPv4Address": "172.31.44.11",
                "IPv6Address": "fd00:carrick::11",
                "LinkLocalIPs": ["169.254.44.11"],
            })
        );
    }

    #[test]
    fn kaniko_argv_no_push_maps_flags() {
        let argv = kaniko_run_argv(
            "/usr/local/bin/carrick",
            "/abs/context",
            Some("/tmp/out".to_owned()),
            "Dockerfile",
            "app",
            &["X=1".to_owned()],
            false,
            false,
            None,
            None,
        );
        assert_eq!(
            argv,
            vec![
                "/usr/local/bin/carrick",
                "run",
                "--fs",
                "host",
                "--max-traps",
                &usize::MAX.to_string(),
                "-v",
                "/abs/context:/workspace",
                "-v",
                "/tmp/out:/out",
                "gcr.io/kaniko-project/executor:v1.24.0",
                "--context",
                "dir:///workspace",
                "--dockerfile",
                "/workspace/Dockerfile",
                // No --use-new-run: kaniko runs its faithful default full-FS
                // snapshot (the BindVfs mount-point fix makes multi-stage builds
                // correct under carrick — see kaniko_run_argv).
                "--no-push",
                "--tar-path",
                "/out/image.tar",
                "--destination",
                "app",
                "--build-arg",
                "X=1",
            ]
        );
    }

    #[test]
    fn kaniko_argv_push_omits_out_mount_and_no_push() {
        let argv = kaniko_run_argv(
            "carrick",
            "/ctx",
            None,
            "docker/Dockerfile.prod",
            "registry.example.com/app:v2",
            &[],
            true,
            false,
            None,
            Some("linux/amd64"),
        );
        // No /out mount, no --no-push, no --tar-path on the push path.
        assert!(!argv.iter().any(|a| a == "--no-push"));
        assert!(!argv.iter().any(|a| a == "--tar-path"));
        assert!(!argv.iter().any(|a| a == "/out"));
        assert!(
            argv.windows(2)
                .any(|w| w[0] == "-v" && w[1] == "/ctx:/workspace")
        );
        // Dockerfile path is joined under /workspace.
        assert!(
            argv.windows(2)
                .any(|w| w[0] == "--dockerfile" && w[1] == "/workspace/docker/Dockerfile.prod")
        );
        // Destination, no-cache (kaniko's valid --cache=false, not the
        // nonexistent --no-cache), and customPlatform all pass through.
        assert!(
            argv.windows(2)
                .any(|w| w[0] == "--destination" && w[1] == "registry.example.com/app:v2")
        );
        assert!(argv.iter().any(|a| a == "--cache=false"));
        assert!(!argv.iter().any(|a| a == "--no-cache"));
        assert!(
            argv.windows(2)
                .any(|w| w[0] == "--customPlatform" && w[1] == "linux/amd64")
        );
        // The kaniko image is always present.
        assert!(argv.iter().any(|a| a == KANIKO_IMAGE));
        // --use-new-run is NOT emitted: kaniko uses its faithful default
        // full-FS snapshot now that the BindVfs mount-point fix keeps
        // multi-stage builds correct under carrick.
        assert!(!argv.iter().any(|a| a == "--use-new-run"));
    }

    /// `--use-new-run` must NOT be emitted on EITHER path. Forcing it was a
    /// workaround for the bind-mount /workspace whiteout bug (now fixed in
    /// BindVfs); it also silently dropped `COPY --from`+RUN modifications, so
    /// dropping it both restores full fidelity and lets the default
    /// full-filesystem snapshot run.
    #[test]
    fn kaniko_argv_never_uses_new_run() {
        // no-push path
        let no_push = kaniko_run_argv(
            "carrick",
            "/ctx",
            Some("/tmp/out".to_owned()),
            "Dockerfile",
            "app",
            &[],
            false,
            false,
            None,
            None,
        );
        // push path
        let push = kaniko_run_argv(
            "carrick",
            "/ctx",
            None,
            "Dockerfile",
            "app",
            &[],
            false,
            false,
            None,
            None,
        );
        for argv in [&no_push, &push] {
            assert!(
                !argv.iter().any(|a| a == "--use-new-run"),
                "--use-new-run must not be present in {argv:?}",
            );
        }
    }

    /// `--cache` (no repo) → `--cache=true` in argv; no `--cache-repo`; no
    /// `--cache=false`.
    #[test]
    fn kaniko_argv_cache_no_repo() {
        let argv = kaniko_run_argv(
            "carrick",
            "/ctx",
            None,
            "Dockerfile",
            "app:latest",
            &[],
            false, // no_cache
            true,  // cache
            None,  // cache_repo
            None,
        );
        assert!(
            argv.iter().any(|a| a == "--cache=true"),
            "expected --cache=true in {argv:?}"
        );
        assert!(
            !argv.iter().any(|a| a == "--cache-repo"),
            "unexpected --cache-repo in {argv:?}"
        );
        assert!(
            !argv.iter().any(|a| a == "--cache=false"),
            "unexpected --cache=false in {argv:?}"
        );
    }

    /// `--cache --cache-repo localhost:5000/cache` → both `--cache=true` and
    /// `--cache-repo localhost:5000/cache` appear in argv.
    #[test]
    fn kaniko_argv_cache_with_repo() {
        let argv = kaniko_run_argv(
            "carrick",
            "/ctx",
            None,
            "Dockerfile",
            "app:latest",
            &[],
            false,                        // no_cache
            true,                         // cache
            Some("localhost:5000/cache"), // cache_repo
            None,
        );
        assert!(
            argv.iter().any(|a| a == "--cache=true"),
            "expected --cache=true in {argv:?}"
        );
        assert!(
            argv.windows(2)
                .any(|w| w[0] == "--cache-repo" && w[1] == "localhost:5000/cache"),
            "expected --cache-repo localhost:5000/cache in {argv:?}",
        );
        assert!(
            !argv.iter().any(|a| a == "--cache=false"),
            "unexpected --cache=false in {argv:?}"
        );
    }

    /// `--no-cache --cache` (both) → `--cache=false` wins; no `--cache=true`.
    #[test]
    fn kaniko_argv_no_cache_wins_over_cache() {
        let argv = kaniko_run_argv(
            "carrick",
            "/ctx",
            None,
            "Dockerfile",
            "app:latest",
            &[],
            true, // no_cache
            true, // cache
            Some("localhost:5000/cache"),
            None,
        );
        assert!(
            argv.iter().any(|a| a == "--cache=false"),
            "expected --cache=false in {argv:?}"
        );
        assert!(
            !argv.iter().any(|a| a == "--cache=true"),
            "unexpected --cache=true in {argv:?}"
        );
    }

    /// Default (no cache flags) → no `--cache=*` emitted at all.
    #[test]
    fn kaniko_argv_default_no_cache_flags() {
        let argv = kaniko_run_argv(
            "carrick",
            "/ctx",
            None,
            "Dockerfile",
            "app:latest",
            &[],
            false, // no_cache
            false, // cache
            None,
            None,
        );
        assert!(
            !argv.iter().any(|a| a.starts_with("--cache")),
            "unexpected cache flag in {argv:?}"
        );
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedNetworkMode {
    mode: carrick_spec::NetworkMode,
    bridge: Option<String>,
    container: Option<String>,
}

fn parse_network_mode_arg(value: &str) -> anyhow::Result<ParsedNetworkMode> {
    match value {
        "host" => Ok(ParsedNetworkMode {
            mode: carrick_spec::NetworkMode::Host,
            bridge: None,
            container: None,
        }),
        "bridge" => Ok(ParsedNetworkMode {
            mode: carrick_spec::NetworkMode::Bridge,
            bridge: None,
            container: None,
        }),
        "none" => Ok(ParsedNetworkMode {
            mode: carrick_spec::NetworkMode::None,
            bridge: None,
            container: None,
        }),
        mode if mode.starts_with("container:") => parse_container_network_mode(mode),
        "" => anyhow::bail!("network mode cannot be empty"),
        custom_bridge => Ok(ParsedNetworkMode {
            mode: carrick_spec::NetworkMode::Bridge,
            bridge: Some(custom_bridge.to_string()),
            container: None,
        }),
    }
}

fn parse_container_network_mode(value: &str) -> anyhow::Result<ParsedNetworkMode> {
    let target = value
        .strip_prefix("container:")
        .filter(|target| !target.is_empty())
        .ok_or_else(|| anyhow::anyhow!("network mode \"container\" requires a target"))?;
    let target_id = carrick_runtime::container::resolve(target)
        .map_err(|_| anyhow::anyhow!("No such container: {target}"))?;
    let target_state = carrick_runtime::container::ContainerState::load(&target_id)?;
    let bridge = if target_state.config.network == carrick_spec::NetworkMode::Bridge {
        target_state
            .config
            .network_attachments
            .iter()
            .find(|attachment| attachment.name != "bridge")
            .map(|attachment| attachment.name.clone())
    } else {
        None
    };
    Ok(ParsedNetworkMode {
        mode: target_state.config.network,
        bridge,
        container: Some(target_id),
    })
}
