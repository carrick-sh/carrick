//! Container orchestration: lowering a docker-style run request into a
//! [`carrick_spec::RunSpec`] the runtime can execute.
//!
//! # Theory of operation
//!
//! Three crates sit between the CLI and the HVF runtime, each owning one
//! transform. `carrick-image` answers *what bytes make up this image*
//! (ordered layer blobs + the OCI config). `carrick-runtime` answers *how do I
//! run this exact process* (it consumes a fully resolved [`RunSpec`] and knows
//! nothing about images, registries, or docker flags). This crate is the seam
//! between them: it takes a [`CliRunRequest`] — the loosely-typed, docker-CLI-
//! shaped bundle of flags and overrides the user typed — resolves the image,
//! and *merges* the two into a single, fully-specified `RunSpec`. The runtime
//! never sees a `CliRunRequest`; the CLI never builds a `RunSpec`. All
//! docker-compatibility merge semantics — the rules for which of image-config
//! vs. command-line wins — live in exactly one place: [`resolve_run_spec`].
//!
//! ## The merge is the whole job, and order matters
//!
//! [`resolve_run_spec`] is a deterministic, side-effect-light function (its only
//! reads of ambient state are `std::env` for bare-`-e KEY` import and the APFS
//! case-sensitivity probe). It reproduces docker's precedence rules:
//!
//! * **argv** = effective entrypoint ++ effective command. `--entrypoint`
//!   overrides the image `Entrypoint` (and `--entrypoint ""`, lowered by the CLI
//!   to `Some(vec![])`, *clears* it); positional `args` override the image
//!   `Cmd`. An empty result is an error — there is nothing to exec. This is the
//!   subtle docker rule that a cmd override does *not* clear the entrypoint, so
//!   `run img /bin/ls` against an `ENTRYPOINT ["/bin/sh"]` image execs
//!   `/bin/sh /bin/ls`, not `/bin/ls`.
//! * **env** is layered lowest-to-highest: image `Env`, then carrick's baseline
//!   defaults (`PATH`, `HOME`, `TERM`, `LANG`/`LC_ALL`, `DEBIAN_FRONTEND`,
//!   `PAGER`) added only where the image left a key *unset*, then `--env`
//!   overrides last-wins. A bare `-e KEY` (no `=`) imports `KEY` from the *host*
//!   environment and contributes nothing if the host has it unset — matching
//!   docker's `-e KEY` / env-file passthrough. The result is sorted for a
//!   stable, reproducible `envp`.
//! * **cwd** = `--workdir`, else image `WorkingDir`, else `/`.
//! * **user** = `--user`, else image `User`. Only *numeric* `uid[:gid]` is
//!   honored; a user/group **name** would require reading the in-image
//!   `/etc/passwd` (which this layer cannot do — the rootfs is not mounted yet),
//!   so a name resolves to root with a warning rather than a silent
//!   mis-mapping. `gid` defaults to `0` when only a uid is given, per docker.
//!
//! ## Filesystem backend: explicit, else probed
//!
//! The runtime can back the guest rootfs either in host memory or on the host's
//! APFS via cap-std. The host backend requires a **case-sensitive** volume
//! (Linux rootfs paths collide otherwise), so when `--fs` is not given,
//! [`resolve_run_spec`] probes the preferred scratch root for case sensitivity
//! and picks [`FsBackendKind::Host`] only if the probe passes, falling back to
//! [`FsBackendKind::Memory`]. This is the one place the function touches the
//! filesystem.
//!
//! ## Platform and the image read-through
//!
//! [`request_platform`] canonicalises `--platform` (or the host default,
//! arm64) into a [`Platform`]. [`Engine::resolve`] maps that to a
//! [`carrick_image::PlatformTarget`] and calls `resolve_with_platform`, so an
//! amd64 (Rosetta) run pulls and caches the amd64 manifest without disturbing
//! the native arm64 cache (see the `carrick-image` BTS), then returns the merged
//! [`RunSpec`] to the caller. Resolving the spec is deliberately kept separate
//! from executing it: the CLI calls [`carrick_runtime::Runtime::execute`] only
//! after `resolve` has returned and the async (tokio) image-pull machinery has
//! been torn down, so no tokio runtime is ever live across the `execute` fork.
//!
//! ## What this layer does *not* own
//!
//! Several `CliRunRequest` fields are carried but not consumed here. `rm`,
//! `name`, `stop_signal`, and `stop_timeout` are container-lifecycle concerns
//! resolved and persisted by the CLI/registry at create time, not run-merge
//! inputs — they are part of the request shape for a single source of truth, but
//! [`resolve_run_spec`] ignores them. `interactive`/`tty`/`pid`/`mounts` flow
//! straight through into the `RunSpec` unchanged. Keeping the merge function
//! pure of lifecycle bookkeeping is what makes it exhaustively unit-testable
//! (see the `tests` module: argv/env/workdir/user precedence are pinned there).

use camino::Utf8PathBuf;
use std::collections::HashMap;

pub use carrick_image::{ImageStore, ResolvedImage};
pub use carrick_runtime::runtime::RunResult;
pub use carrick_spec::{FsBackendKind, ImageConfig, Mount, PidMode, Platform, RunSpec};

#[derive(Debug, Clone)]
pub struct CliRunRequest {
    pub image_ref: String,
    /// Raw OCI platform string from the CLI (`--platform linux/amd64`), or
    /// `None` to default to the host architecture (arm64).
    pub platform: Option<String>,
    pub args: Vec<String>,
    pub env_overrides: Vec<String>,
    pub mounts: Vec<Mount>,
    pub workdir: Option<String>,
    pub user: Option<String>,
    pub entrypoint_override: Option<Vec<String>>,
    pub tty: bool,
    pub interactive: bool,
    pub rm: bool,
    pub name: Option<String>,
    pub max_traps: usize,
    pub debug_state_path: Option<String>,
    pub fs: Option<FsBackendKind>,
    /// PID namespace mode (`docker run --pid`). Defaults to `Private`.
    pub pid: PidMode,
    /// Raw `--stop-signal` value (e.g. `SIGQUIT`/`9`), or `None` to fall back to
    /// the image's OCI `STOPSIGNAL`. Resolved to a host signum at create time
    /// and persisted in the container's `RunConfig`; the engine itself does not
    /// consume it (stop/restart read it from the registry).
    pub stop_signal: Option<String>,
    /// `--stop-timeout` in seconds (graceful-stop window before SIGKILL), or
    /// `None` for the default. Persisted in the container's `RunConfig`.
    pub stop_timeout: Option<u64>,
}

/// Parse the request's `--platform` into the canonical [`Platform`], falling
/// back to the host default (arm64) when absent or unrecognised.
pub fn request_platform(req: &CliRunRequest) -> Platform {
    req.platform
        .as_deref()
        .and_then(Platform::from_oci_str)
        .unwrap_or_default()
}

pub fn resolve_run_spec(req: CliRunRequest, image: ResolvedImage) -> Result<RunSpec, String> {
    let platform = request_platform(&req);

    // 1. Resolve argv (entrypoint + cmd overrides)
    let effective_entrypoint = match req.entrypoint_override {
        Some(overrides) => overrides,
        None => image.config.entrypoint.clone().unwrap_or_default(),
    };

    let effective_cmd = if !req.args.is_empty() {
        req.args.clone()
    } else {
        image.config.cmd.clone().unwrap_or_default()
    };

    let mut argv = Vec::new();
    argv.extend(effective_entrypoint);
    argv.extend(effective_cmd);

    if argv.is_empty() {
        return Err("no command specified".to_string());
    }

    let executable = argv[0].clone();

    // 2. Resolve env variables
    let mut env_map = HashMap::new();

    // Add image env
    for entry in &image.config.env {
        if let Some((k, v)) = entry.split_once('=') {
            env_map.insert(k.to_string(), v.to_string());
        }
    }

    // Add baseline defaults ONLY if not already set by image config
    let baseline_defaults = [
        (
            "PATH",
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        ),
        ("HOME", "/root"),
        ("TERM", "xterm-256color"),
        ("LANG", "C.UTF-8"),
        ("LC_ALL", "C.UTF-8"),
        ("DEBIAN_FRONTEND", "noninteractive"),
        ("PAGER", "cat"),
    ];
    for (k, v) in baseline_defaults {
        env_map
            .entry(k.to_string())
            .or_insert_with(|| v.to_string());
    }

    // Add env overrides (last-wins). A bare `KEY` (no `=`) imports the value
    // from the HOST environment, matching docker's `-e KEY` / env-file semantics;
    // an unset host var contributes nothing (docker drops it too).
    for entry in &req.env_overrides {
        match entry.split_once('=') {
            Some((k, v)) => {
                env_map.insert(k.to_string(), v.to_string());
            }
            None => {
                if let Ok(v) = std::env::var(entry) {
                    env_map.insert(entry.to_string(), v);
                }
            }
        }
    }

    let mut envp: Vec<String> = env_map
        .into_iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect();
    envp.sort();

    // 3. Resolve working directory
    let cwd = match req.workdir {
        Some(w) => Some(Utf8PathBuf::from(w)),
        None => image.config.working_dir.clone(),
    }
    .or_else(|| Some(Utf8PathBuf::from("/")));

    // 4. Resolve user (`--user` overrides image USER). Numeric `uid[:gid]` only;
    // a user/group NAME needs in-image /etc/passwd resolution (not yet
    // supported), so warn and run as root rather than silently mis-mapping.
    let (uid, gid) = match req.user.clone().or_else(|| image.config.user.clone()) {
        None => (0, 0),
        Some(s) if s.is_empty() => (0, 0),
        Some(s) => match parse_numeric_user(&s) {
            Some((u, g)) => (u, g),
            None => {
                eprintln!(
                    "carrick: --user {s:?}: name resolution is not yet supported; running as root (use a numeric uid[:gid])"
                );
                (0, 0)
            }
        },
    };

    // 5. Select fs backend (fall back to case sensitivity probe)
    let fs_backend = req.fs.unwrap_or_else(|| {
        let probe = carrick_runtime::apfs::preferred_scratch_root()
            .unwrap_or_else(|_| std::env::temp_dir().join("carrick-scratch"));
        if std::fs::create_dir_all(&probe).is_err() {
            FsBackendKind::Memory
        } else if carrick_runtime::apfs::probe_case_sensitive(&probe) {
            FsBackendKind::Host
        } else {
            FsBackendKind::Memory
        }
    });

    let debug_state_path = req.debug_state_path.map(Utf8PathBuf::from);

    Ok(RunSpec {
        executable,
        argv,
        envp,
        cwd,
        rootfs_layers: image.layers,
        fs_backend,
        mounts: req.mounts,
        tty: req.tty,
        raw: true,
        interactive: req.interactive,
        max_traps: req.max_traps,
        debug_state_path,
        platform,
        pid: req.pid,
        uid,
        gid,
    })
}

/// Parse a `docker run --user` value as numeric `uid[:gid]`. `gid` defaults to 0
/// when only a uid is given (docker's behavior for a numeric user with no passwd
/// lookup). Returns `None` for a non-numeric user/group name — carrick has no
/// in-image `/etc/passwd` resolution yet, so the caller warns and runs as root.
fn parse_numeric_user(spec: &str) -> Option<(u32, u32)> {
    let (u, g) = match spec.split_once(':') {
        Some((u, g)) => (u, Some(g)),
        None => (spec, None),
    };
    let uid: u32 = u.parse().ok()?;
    let gid: u32 = match g {
        Some(g) => g.parse().ok()?,
        None => 0,
    };
    Some((uid, gid))
}

pub struct Engine {
    store: ImageStore,
}

impl Engine {
    pub fn new(store: ImageStore) -> Self {
        Self { store }
    }

    /// Resolve a run request to a `RunSpec`: parse the image ref, pull/resolve
    /// the image for the target platform, and merge into a fully-specified spec.
    /// This is the ONLY async part of a run — it does NOT execute, so no fork
    /// happens here and it is safe to drive inside a tokio runtime. The caller
    /// drops the runtime (joining its blocking pool in the parent) BEFORE
    /// calling `carrick_runtime::Runtime::execute`, so tokio is never alive
    /// across a fork. See docs/superpowers/specs/2026-06-06-tokio-fork-isolation.
    pub async fn resolve(&self, req: CliRunRequest) -> Result<RunSpec, anyhow::Error> {
        let image_ref = carrick_spec::ImageReference::parse(&req.image_ref)
            .map_err(|e| anyhow::anyhow!("invalid image reference: {}", e))?;

        // Select the OCI manifest entry for the requested platform. amd64
        // images are cached separately from the host-native arm64 so the two
        // never collide in the store, and pulling honours the platform hint.
        let platform = request_platform(&req);
        let target = carrick_image::PlatformTarget {
            os: "linux".to_string(),
            arch: platform.oci_arch().to_string(),
            variant: None,
        };
        let resolved = self
            .store
            .resolve_with_platform(&image_ref, &target)
            .await
            .map_err(|e| anyhow::anyhow!("failed to resolve image: {}", e))?;

        resolve_run_spec(req, resolved).map_err(anyhow::Error::msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_image(
        entrypoint: Option<Vec<String>>,
        cmd: Option<Vec<String>>,
        env: Vec<String>,
        working_dir: Option<Utf8PathBuf>,
    ) -> ResolvedImage {
        ResolvedImage {
            layers: vec![Utf8PathBuf::from("/layer1")],
            config: ImageConfig {
                entrypoint,
                cmd,
                env,
                working_dir,
                user: Some("root".to_string()),
                exposed_ports: None,
                labels: None,
                stop_signal: None,
            },
        }
    }

    fn base_req(user: Option<&str>) -> CliRunRequest {
        CliRunRequest {
            image_ref: "alpine".to_string(),
            platform: None,
            args: vec!["/bin/ls".to_string()],
            env_overrides: vec![],
            mounts: vec![],
            workdir: None,
            user: user.map(|s| s.to_string()),
            entrypoint_override: None,
            tty: false,
            interactive: false,
            rm: false,
            name: None,
            max_traps: 100,
            debug_state_path: None,
            fs: Some(FsBackendKind::Memory),
            pid: PidMode::default(),
            stop_signal: None,
            stop_timeout: None,
        }
    }

    #[test]
    fn user_numeric_uid_and_gid() {
        let image = make_test_image(None, Some(vec!["/bin/ls".into()]), vec![], None);
        let spec = resolve_run_spec(base_req(Some("1000:2000")), image).unwrap();
        assert_eq!((spec.uid, spec.gid), (1000, 2000));
    }

    #[test]
    fn user_numeric_uid_defaults_gid_zero() {
        // docker: `--user 1000` with no group → gid 0.
        let image = make_test_image(None, Some(vec!["/bin/ls".into()]), vec![], None);
        let spec = resolve_run_spec(base_req(Some("1000")), image).unwrap();
        assert_eq!((spec.uid, spec.gid), (1000, 0));
    }

    #[test]
    fn user_absent_defaults_root() {
        // No --user; the test image's USER is the name "root" (unresolved) → root.
        let image = make_test_image(None, Some(vec!["/bin/ls".into()]), vec![], None);
        let spec = resolve_run_spec(base_req(None), image).unwrap();
        assert_eq!((spec.uid, spec.gid), (0, 0));
    }

    #[test]
    fn bare_env_key_imports_host_value() {
        // SAFETY: test setup; the unique key avoids racing other tests' env.
        unsafe { std::env::set_var("CARRICK_TEST_IMPORT_XYZ", "from-host") };
        let image = make_test_image(None, Some(vec!["/bin/ls".into()]), vec![], None);
        let mut req = base_req(None);
        req.env_overrides = vec!["CARRICK_TEST_IMPORT_XYZ".to_string()];
        let spec = resolve_run_spec(req, image).unwrap();
        unsafe { std::env::remove_var("CARRICK_TEST_IMPORT_XYZ") };
        assert!(
            spec.envp
                .iter()
                .any(|e| e == "CARRICK_TEST_IMPORT_XYZ=from-host"),
            "bare `-e KEY` should import the host value; envp={:?}",
            spec.envp
        );
    }

    #[test]
    fn cleared_entrypoint_runs_cmd_only() {
        // `--entrypoint ""` (lowered to Some(vec![]) by the CLI) clears the image
        // entrypoint, leaving only the command.
        let image = make_test_image(
            Some(vec!["/bin/sh".into()]),
            Some(vec!["echo".into(), "hi".into()]),
            vec![],
            None,
        );
        let mut req = base_req(None);
        req.entrypoint_override = Some(vec![]);
        req.args = vec![];
        let spec = resolve_run_spec(req, image).unwrap();
        assert_eq!(spec.argv, vec!["echo", "hi"]);
    }

    #[test]
    fn test_merge_argv_no_override() {
        let image = make_test_image(
            Some(vec!["/bin/sh".to_string()]),
            Some(vec!["-c".to_string(), "echo hi".to_string()]),
            vec![],
            None,
        );
        let req = CliRunRequest {
            image_ref: "alpine".to_string(),
            platform: None,
            args: vec![],
            env_overrides: vec![],
            mounts: vec![],
            workdir: None,
            user: None,
            entrypoint_override: None,
            tty: false,
            interactive: false,
            rm: false,
            name: None,
            max_traps: 100,
            debug_state_path: None,
            fs: Some(FsBackendKind::Memory),
            pid: PidMode::default(),
            stop_signal: None,
            stop_timeout: None,
        };
        let spec = resolve_run_spec(req, image).unwrap();
        assert_eq!(spec.executable, "/bin/sh");
        assert_eq!(spec.argv, vec!["/bin/sh", "-c", "echo hi"]);
    }

    #[test]
    fn test_merge_argv_cmd_override() {
        let image = make_test_image(
            Some(vec!["/bin/sh".to_string()]),
            Some(vec!["-c".to_string(), "echo hi".to_string()]),
            vec![],
            None,
        );
        let req = CliRunRequest {
            image_ref: "alpine".to_string(),
            platform: None,
            args: vec!["/bin/ls".to_string()],
            env_overrides: vec![],
            mounts: vec![],
            workdir: None,
            user: None,
            entrypoint_override: None,
            tty: false,
            interactive: false,
            rm: false,
            name: None,
            max_traps: 100,
            debug_state_path: None,
            fs: Some(FsBackendKind::Memory),
            pid: PidMode::default(),
            stop_signal: None,
            stop_timeout: None,
        };
        let spec = resolve_run_spec(req, image).unwrap();
        assert_eq!(spec.argv, vec!["/bin/sh", "/bin/ls"]);
    }

    #[test]
    fn test_merge_argv_entrypoint_override() {
        let image = make_test_image(
            Some(vec!["/bin/sh".to_string()]),
            Some(vec!["-c".to_string(), "echo hi".to_string()]),
            vec![],
            None,
        );
        let req = CliRunRequest {
            image_ref: "alpine".to_string(),
            platform: None,
            args: vec![],
            env_overrides: vec![],
            mounts: vec![],
            workdir: None,
            user: None,
            entrypoint_override: Some(vec!["/bin/bash".to_string()]),
            tty: false,
            interactive: false,
            rm: false,
            name: None,
            max_traps: 100,
            debug_state_path: None,
            fs: Some(FsBackendKind::Memory),
            pid: PidMode::default(),
            stop_signal: None,
            stop_timeout: None,
        };
        let spec = resolve_run_spec(req, image).unwrap();
        assert_eq!(spec.argv, vec!["/bin/bash", "-c", "echo hi"]);
    }

    #[test]
    fn test_merge_env_variables() {
        let image = make_test_image(
            None,
            None,
            vec!["PATH=/image/bin".to_string(), "CUSTOM=1".to_string()],
            None,
        );
        let req = CliRunRequest {
            image_ref: "alpine".to_string(),
            platform: None,
            args: vec!["/bin/ls".to_string()],
            env_overrides: vec!["CUSTOM=2".to_string(), "USER_VAR=yes".to_string()],
            mounts: vec![],
            workdir: None,
            user: None,
            entrypoint_override: None,
            tty: false,
            interactive: false,
            rm: false,
            name: None,
            max_traps: 100,
            debug_state_path: None,
            fs: Some(FsBackendKind::Memory),
            pid: PidMode::default(),
            stop_signal: None,
            stop_timeout: None,
        };
        let spec = resolve_run_spec(req, image).unwrap();

        let env_map: HashMap<String, String> = spec
            .envp
            .iter()
            .map(|e| {
                e.split_once('=')
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .unwrap()
            })
            .collect();

        assert_eq!(env_map.get("PATH").unwrap(), "/image/bin"); // Image env wins over baseline defaults
        assert_eq!(env_map.get("CUSTOM").unwrap(), "2"); // Override wins over image env
        assert_eq!(env_map.get("USER_VAR").unwrap(), "yes");
        assert_eq!(env_map.get("HOME").unwrap(), "/root"); // Baseline default is set
    }

    #[test]
    fn test_merge_workdir() {
        let image = make_test_image(None, None, vec![], Some(Utf8PathBuf::from("/image/app")));
        let req = CliRunRequest {
            image_ref: "alpine".to_string(),
            platform: None,
            args: vec!["/bin/ls".to_string()],
            env_overrides: vec![],
            mounts: vec![],
            workdir: Some("/user/app".to_string()),
            user: None,
            entrypoint_override: None,
            tty: false,
            interactive: false,
            rm: false,
            name: None,
            max_traps: 100,
            debug_state_path: None,
            fs: Some(FsBackendKind::Memory),
            pid: PidMode::default(),
            stop_signal: None,
            stop_timeout: None,
        };
        let spec = resolve_run_spec(req, image).unwrap();
        assert_eq!(spec.cwd.unwrap().as_str(), "/user/app");
    }
}
