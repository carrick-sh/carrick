//! `ContainerBuilder`: the Docker-shaped happy path, lowered into
//! `carrick_engine::RunRequest` so the engine's single merge path
//! (`resolve_run_spec`) decides every image-vs-request precedence rule.

use std::io::Write;

use camino::Utf8PathBuf;
use carrick_engine::{Engine, RunRequest};
use carrick_image::{ImageStore, PullPolicy};
use carrick_runtime::prepare::{RuntimeExtensions, StdioSink};
use carrick_runtime::runtime::DEFAULT_MAX_TRAPS;
use carrick_spec::{Mount, Platform, StdioMode};

use crate::result::{CaptureBuffer, CapturedStreams};
use crate::{ContainerResult, EmbedError, PreparedContainer};

/// Where one guest stdio stream goes.
pub enum StdioConfig {
    /// Buffer the bytes into [`ContainerResult`].
    Captured,
    /// Write through to the host process's own fd 1/2.
    Inherit,
    /// Hand every write to this writer as the guest produces it.
    Piped(Box<dyn Write + Send>),
}

impl StdioConfig {
    fn is_captured(&self) -> bool {
        matches!(self, Self::Captured)
    }

    fn is_inherit(&self) -> bool {
        matches!(self, Self::Inherit)
    }
}

/// The request-level stdio mode for a pair of per-stream configs. Only a
/// homogeneous pair maps onto the runtime's `Captured`/`Inherit` sinks; any
/// mixed pair is `Piped` with embed-owned writers (see [`StdioPlan::lower`]).
pub(crate) fn stdio_mode(stdout: &StdioConfig, stderr: &StdioConfig) -> StdioMode {
    if stdout.is_captured() && stderr.is_captured() {
        StdioMode::Captured
    } else if stdout.is_inherit() && stderr.is_inherit() {
        StdioMode::Inherit
    } else {
        StdioMode::Piped
    }
}

/// The runtime sink for a run plus the embed-side buffers that back any
/// `Captured` stream inside a `Piped` sink.
pub(crate) struct StdioPlan {
    pub(crate) sink: StdioSink,
    pub(crate) captured: CapturedStreams,
}

impl StdioPlan {
    pub(crate) fn lower(stdout: StdioConfig, stderr: StdioConfig) -> Self {
        match stdio_mode(&stdout, &stderr) {
            StdioMode::Captured => Self {
                sink: StdioSink::Captured,
                captured: CapturedStreams::default(),
            },
            StdioMode::Inherit => Self {
                sink: StdioSink::Inherit,
                captured: CapturedStreams::default(),
            },
            StdioMode::Piped => {
                let mut captured = CapturedStreams::default();
                let stdout =
                    piped_writer(stdout, || Box::new(std::io::stdout()), &mut captured.stdout);
                let stderr =
                    piped_writer(stderr, || Box::new(std::io::stderr()), &mut captured.stderr);
                Self {
                    sink: StdioSink::Piped { stdout, stderr },
                    captured,
                }
            }
        }
    }
}

fn piped_writer(
    config: StdioConfig,
    inherit: impl FnOnce() -> Box<dyn Write + Send>,
    capture_slot: &mut Option<CaptureBuffer>,
) -> Box<dyn Write + Send> {
    match config {
        StdioConfig::Captured => {
            let buffer = CaptureBuffer::default();
            *capture_slot = Some(buffer.clone());
            Box::new(buffer)
        }
        StdioConfig::Inherit => inherit(),
        StdioConfig::Piped(writer) => writer,
    }
}

/// Docker-shaped description of one containerized run.
///
/// Every setter is a by-value builder step; [`Self::to_run_request`] lowers the
/// whole thing into [`RunRequest`] so `carrick_engine::resolve_run_spec` — the
/// CLI's merge path — applies image-vs-request precedence. The builder itself
/// only rejects what the engine could never honour (a named user, a relative
/// mount path, a malformed env key).
pub struct ContainerBuilder {
    image: String,
    platform: Option<Platform>,
    pull: PullPolicy,
    store: Option<ImageStore>,
    command: Vec<String>,
    entrypoint: Option<Vec<String>>,
    env: Vec<(String, String)>,
    workdir: Option<String>,
    user: Option<String>,
    hostname: Option<String>,
    mounts: Vec<Mount>,
    stdout: StdioConfig,
    stderr: StdioConfig,
    max_traps: usize,
}

impl ContainerBuilder {
    /// Start from an image reference (`ubuntu:24.04`, `ghcr.io/org/app@sha256:…`).
    pub fn from_image(image: impl Into<String>) -> Self {
        Self {
            image: image.into(),
            platform: None,
            pull: PullPolicy::Missing,
            store: None,
            command: Vec::new(),
            entrypoint: None,
            env: Vec::new(),
            workdir: None,
            user: None,
            hostname: None,
            mounts: Vec::new(),
            stdout: StdioConfig::Captured,
            stderr: StdioConfig::Captured,
            max_traps: DEFAULT_MAX_TRAPS,
        }
    }

    /// Replace the image `Cmd` (the image `Entrypoint`, if any, still prefixes it).
    pub fn command<I, S>(mut self, argv: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.command = argv.into_iter().map(Into::into).collect();
        self
    }

    /// Replace the image `Entrypoint`; an empty iterator clears it (`--entrypoint ""`).
    pub fn entrypoint<I, S>(mut self, argv: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.entrypoint = Some(argv.into_iter().map(Into::into).collect());
        self
    }

    /// Set one environment variable (last call for a key wins, over the image `Env`).
    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.push((key.into(), value.into()));
        self
    }

    /// Working directory; a relative path resolves against the image `WorkingDir`.
    pub fn workdir(mut self, path: impl Into<String>) -> Self {
        self.workdir = Some(path.into());
        self
    }

    /// Numeric `uid[:gid]` (names are rejected: no in-image `/etc/passwd` lookup exists).
    pub fn user(mut self, user: impl Into<String>) -> Self {
        self.user = Some(user.into());
        self
    }

    /// Container hostname / UTS identity.
    pub fn hostname(mut self, hostname: impl Into<String>) -> Self {
        self.hostname = Some(hostname.into());
        self
    }

    /// Bind-mount an absolute host path at an absolute guest path, read-write.
    pub fn mount(self, host: impl Into<String>, guest: impl Into<String>) -> Self {
        self.push_mount(host, guest, false)
    }

    /// Bind-mount an absolute host path at an absolute guest path, read-only.
    pub fn mount_readonly(self, host: impl Into<String>, guest: impl Into<String>) -> Self {
        self.push_mount(host, guest, true)
    }

    fn push_mount(
        mut self,
        host: impl Into<String>,
        guest: impl Into<String>,
        readonly: bool,
    ) -> Self {
        self.mounts.push(Mount {
            source: Utf8PathBuf::from(host.into()),
            target: Utf8PathBuf::from(guest.into()),
            readonly,
        });
        self
    }

    /// Target ISA (default: the host-native platform).
    pub fn platform(mut self, platform: Platform) -> Self {
        self.platform = Some(platform);
        self
    }

    /// Docker `--pull` policy (default: `Missing`).
    pub fn pull_policy(mut self, policy: PullPolicy) -> Self {
        self.pull = policy;
        self
    }

    /// Image store root (default: `ImageStore::default_for_user`, i.e. `$CARRICK_HOME`).
    pub fn image_store(mut self, store: ImageStore) -> Self {
        self.store = Some(store);
        self
    }

    /// Guest stdout destination (default: `Captured`).
    pub fn stdout(mut self, config: StdioConfig) -> Self {
        self.stdout = config;
        self
    }

    /// Guest stderr destination (default: `Captured`).
    pub fn stderr(mut self, config: StdioConfig) -> Self {
        self.stderr = config;
        self
    }

    /// Stop the run after this many syscall traps (default: unlimited).
    pub fn max_traps(mut self, max_traps: usize) -> Self {
        self.max_traps = max_traps;
        self
    }

    /// Lower into the engine's request. Pure: no I/O, no ambient reads.
    pub fn to_run_request(&self) -> Result<RunRequest, EmbedError> {
        if self.image.trim().is_empty() {
            return Err(EmbedError::Config("image reference is empty".to_string()));
        }
        let mut env_overrides = Vec::with_capacity(self.env.len());
        for (key, value) in &self.env {
            if key.is_empty() || key.contains('=') {
                return Err(EmbedError::Config(format!(
                    "environment key {key:?} must be non-empty and contain no '='"
                )));
            }
            env_overrides.push(format!("{key}={value}"));
        }
        if let Some(user) = &self.user
            && !is_numeric_user(user)
        {
            return Err(EmbedError::Config(format!(
                "user {user:?} must be numeric `uid[:gid]`: carrick-embed does not resolve \
                 names against the image's /etc/passwd"
            )));
        }
        for mount in &self.mounts {
            if !mount.source.is_absolute() || !mount.target.is_absolute() {
                return Err(EmbedError::Config(format!(
                    "mount {} -> {} must use absolute host and guest paths",
                    mount.source, mount.target
                )));
            }
        }
        Ok(RunRequest {
            image_ref: self.image.clone(),
            platform: self
                .platform
                .map(|platform| format!("linux/{}", platform.oci_arch())),
            args: self.command.clone(),
            entrypoint_override: self.entrypoint.clone(),
            env_overrides,
            // Bare `KEY` host-env import is a CLI convenience; a library caller
            // passes explicit values, so the engine is told there is nothing to import.
            host_env: None,
            mounts: self.mounts.clone(),
            workdir: self.workdir.clone(),
            user: self.user.clone(),
            hostname: self.hostname.clone(),
            max_traps: self.max_traps,
            pull: self.pull,
            stdio: stdio_mode(&self.stdout, &self.stderr),
            // Networking is the engine default (`NetworkMode::Host`); no bridge
            // namespace is requested, so no id is needed. Never derived from a pid.
            bridge_namespace_id: None,
            ..RunRequest::default()
        })
    }

    /// Resolve the image (async) and freeze the run. No guest work happens here.
    pub async fn prepare(self) -> Result<PreparedContainer, EmbedError> {
        let request = self.to_run_request()?;
        let store = self
            .store
            .clone()
            .unwrap_or_else(ImageStore::default_for_user);
        let carrick_engine::Resolved { spec, warnings } = Engine::new(store)
            .resolve(request)
            .await
            .map_err(EmbedError::Image)?;
        let plan = StdioPlan::lower(self.stdout, self.stderr);
        let mut extensions = RuntimeExtensions::default();
        if let StdioSink::Piped { .. } = plan.sink {
            extensions = extensions.stdio(plan.sink);
        }
        Ok(PreparedContainer::new(
            spec,
            warnings,
            extensions,
            plan.captured,
        ))
    }

    /// Resolve on the ambient tokio runtime, then execute on its blocking pool.
    ///
    /// Requires the runtime seam (Task 21/22) to have retired the
    /// `Handle::try_current().is_err()` debug assertion that guarded the old
    /// `Runtime::execute` (`execute.rs:197-201`): a `spawn_blocking` thread
    /// carries a runtime handle by construction.
    pub async fn run(self) -> Result<ContainerResult, EmbedError> {
        let prepared = self.prepare().await?;
        tokio::task::spawn_blocking(move || prepared.execute())
            .await
            .map_err(|join| EmbedError::ExecutePanicked(join.to_string()))?
    }

    /// Resolve on a private current-thread runtime (dropped before execution),
    /// then execute on the calling thread. Refuses to run inside a tokio
    /// runtime (`block_on` would panic there); use [`Self::run`] instead.
    pub fn run_blocking(self) -> Result<ContainerResult, EmbedError> {
        if tokio::runtime::Handle::try_current().is_ok() {
            return Err(EmbedError::Config(
                "run_blocking() was called from inside a tokio runtime; use `.run().await` there"
                    .to_string(),
            ));
        }
        let prepared = {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|error| {
                    EmbedError::Config(format!(
                        "failed to build the image-resolution tokio runtime: {error}"
                    ))
                })?;
            runtime.block_on(self.prepare())?
        };
        prepared.execute()
    }
}

/// `uid[:gid]`, both decimal — the only form `resolve_run_spec` honours
/// (its private `parse_numeric_user`, `crates/carrick-engine/src/lib.rs:494-505`).
fn is_numeric_user(spec: &str) -> bool {
    let (uid, gid) = match spec.split_once(':') {
        Some((uid, gid)) => (uid, Some(gid)),
        None => (spec, None),
    };
    let gid_ok = match gid {
        Some(gid) => gid.parse::<u32>().is_ok(),
        None => true,
    };
    uid.parse::<u32>().is_ok() && gid_ok
}

#[cfg(test)]
mod tests {
    use super::*;
    use camino::Utf8PathBuf;
    use carrick_engine::{request_platform, resolve_run_spec};
    use carrick_image::ResolvedImage;
    use carrick_spec::ImageConfig;

    fn strings(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    fn image(entrypoint: Option<&[&str]>, cmd: Option<&[&str]>, env: &[&str]) -> ResolvedImage {
        ResolvedImage {
            layers: vec![Utf8PathBuf::from("/layer1")],
            config: ImageConfig {
                entrypoint: entrypoint.map(strings),
                cmd: cmd.map(strings),
                env: strings(env),
                ..ImageConfig::default()
            },
        }
    }

    #[test]
    fn env_precedence_matches_a_hand_built_request() {
        let builder = ContainerBuilder::from_image("alpine")
            .command(["/bin/ls"])
            .env("A", "builder")
            .env("A", "later");
        let from_builder = resolve_run_spec(
            builder.to_run_request().unwrap(),
            image(None, None, &["A=image", "B=image"]),
        )
        .unwrap()
        .spec;

        let hand = RunRequest {
            image_ref: "alpine".to_string(),
            args: strings(&["/bin/ls"]),
            env_overrides: strings(&["A=builder", "A=later"]),
            stdio: StdioMode::Captured,
            max_traps: DEFAULT_MAX_TRAPS,
            ..RunRequest::default()
        };
        let from_hand = resolve_run_spec(hand, image(None, None, &["A=image", "B=image"]))
            .unwrap()
            .spec;

        assert_eq!(from_builder, from_hand);
        assert!(from_builder.envp.contains(&"A=later".to_string()));
        assert!(from_builder.envp.contains(&"B=image".to_string()));
        assert!(!from_builder.envp.contains(&"A=image".to_string()));
    }

    #[test]
    fn command_overrides_image_cmd_but_not_image_entrypoint() {
        let spec = resolve_run_spec(
            ContainerBuilder::from_image("alpine")
                .command(["/bin/ls"])
                .to_run_request()
                .unwrap(),
            image(Some(&["/bin/sh"]), Some(&["-c", "true"]), &[]),
        )
        .unwrap()
        .spec;
        assert_eq!(
            spec.argv,
            strings(&["/bin/sh", "/bin/ls"]),
            "docker: cmd override keeps ENTRYPOINT"
        );
    }

    #[test]
    fn entrypoint_overrides_and_an_empty_entrypoint_clears() {
        let img = || image(Some(&["/bin/sh"]), Some(&["-c", "true"]), &[]);
        let overridden = resolve_run_spec(
            ContainerBuilder::from_image("alpine")
                .entrypoint(["/bin/ls"])
                .to_run_request()
                .unwrap(),
            img(),
        )
        .unwrap()
        .spec;
        assert_eq!(overridden.argv, strings(&["/bin/ls", "-c", "true"]));

        let cleared = resolve_run_spec(
            ContainerBuilder::from_image("alpine")
                .entrypoint(Vec::<String>::new())
                .command(["/bin/true"])
                .to_run_request()
                .unwrap(),
            img(),
        )
        .unwrap()
        .spec;
        assert_eq!(cleared.argv, strings(&["/bin/true"]));
    }

    #[test]
    fn mounts_lower_in_order_with_readonly_preserved() {
        let request = ContainerBuilder::from_image("alpine")
            .command(["/bin/true"])
            .mount("/host/data", "/data")
            .mount_readonly("/host/ro", "/ro")
            .to_run_request()
            .unwrap();
        assert_eq!(
            request.mounts,
            vec![
                Mount {
                    source: "/host/data".into(),
                    target: "/data".into(),
                    readonly: false
                },
                Mount {
                    source: "/host/ro".into(),
                    target: "/ro".into(),
                    readonly: true
                },
            ]
        );
        let spec = resolve_run_spec(request.clone(), image(None, Some(&["/bin/sh"]), &[]))
            .unwrap()
            .spec;
        assert_eq!(spec.mounts, request.mounts);
    }

    #[test]
    fn relative_mount_paths_are_a_config_error() {
        let error = ContainerBuilder::from_image("alpine")
            .mount("data", "/data")
            .to_run_request()
            .unwrap_err();
        assert!(matches!(error, EmbedError::Config(_)), "{error}");
        let error = ContainerBuilder::from_image("alpine")
            .mount("/host", "data")
            .to_run_request()
            .unwrap_err();
        assert!(matches!(error, EmbedError::Config(_)), "{error}");
    }

    #[test]
    fn platform_round_trips_through_the_oci_string() {
        let request = ContainerBuilder::from_image("alpine")
            .platform(Platform::Aarch64)
            .to_run_request()
            .unwrap();
        assert_eq!(request.platform.as_deref(), Some("linux/arm64"));
        assert_eq!(request_platform(&request), Platform::Aarch64);
        let amd = ContainerBuilder::from_image("alpine")
            .platform(Platform::Amd64)
            .to_run_request()
            .unwrap();
        assert_eq!(request_platform(&amd), Platform::Amd64);
    }

    #[test]
    fn workdir_user_hostname_and_max_traps_lower_verbatim() {
        let request = ContainerBuilder::from_image("alpine")
            .workdir("/srv")
            .user("1000:1000")
            .hostname("embedded")
            .max_traps(42)
            .pull_policy(PullPolicy::Never)
            .to_run_request()
            .unwrap();
        assert_eq!(request.workdir.as_deref(), Some("/srv"));
        assert_eq!(request.user.as_deref(), Some("1000:1000"));
        assert_eq!(request.hostname.as_deref(), Some("embedded"));
        assert_eq!(request.max_traps, 42);
        assert_eq!(request.pull, PullPolicy::Never);
        let spec = resolve_run_spec(request, image(None, Some(&["/bin/sh"]), &[]))
            .unwrap()
            .spec;
        // `NsUid`/`NsGid` expose `.raw()` (carrick-abi/src/lib.rs:2867-2880, 2987-3000).
        assert_eq!(spec.uid.raw(), 1000);
        assert_eq!(spec.gid.raw(), 1000);
        assert_eq!(spec.hostname.as_deref(), Some("embedded"));
        assert_eq!(spec.max_traps, 42);
    }

    #[test]
    fn a_named_user_is_a_config_error_not_a_silent_root() {
        let error = ContainerBuilder::from_image("alpine")
            .user("nobody")
            .to_run_request()
            .unwrap_err();
        match error {
            EmbedError::Config(message) => assert!(message.contains("numeric"), "{message}"),
            other => panic!("expected Config, got {other:?}"),
        }
    }

    #[test]
    fn env_keys_must_be_non_empty_and_free_of_equals() {
        for (key, value) in [("", "x"), ("A=B", "x")] {
            let error = ContainerBuilder::from_image("alpine")
                .env(key, value)
                .to_run_request()
                .unwrap_err();
            assert!(matches!(error, EmbedError::Config(_)), "{error}");
        }
    }

    #[test]
    fn bare_host_env_import_and_bridge_ids_are_never_requested() {
        let request = ContainerBuilder::from_image("alpine")
            .to_run_request()
            .unwrap();
        assert_eq!(request.host_env, None);
        assert_eq!(request.bridge_namespace_id, None);
    }

    #[test]
    fn stdio_defaults_to_captured_and_mixed_configs_lower_to_piped() {
        let default = ContainerBuilder::from_image("alpine")
            .to_run_request()
            .unwrap();
        assert_eq!(default.stdio, StdioMode::Captured);

        let inherit = ContainerBuilder::from_image("alpine")
            .stdout(StdioConfig::Inherit)
            .stderr(StdioConfig::Inherit)
            .to_run_request()
            .unwrap();
        assert_eq!(inherit.stdio, StdioMode::Inherit);

        let mixed = ContainerBuilder::from_image("alpine")
            .stdout(StdioConfig::Captured)
            .stderr(StdioConfig::Inherit)
            .to_run_request()
            .unwrap();
        assert_eq!(mixed.stdio, StdioMode::Piped);

        let plan = StdioPlan::lower(StdioConfig::Captured, StdioConfig::Inherit);
        assert!(matches!(plan.sink, StdioSink::Piped { .. }));
        assert!(
            plan.captured.stdout.is_some(),
            "captured stream gets an embed-side buffer"
        );
        assert!(
            plan.captured.stderr.is_none(),
            "inherited stream has no buffer"
        );

        let both = StdioPlan::lower(StdioConfig::Captured, StdioConfig::Captured);
        assert!(matches!(both.sink, StdioSink::Captured));
        assert!(both.captured.stdout.is_none() && both.captured.stderr.is_none());
    }

    #[test]
    fn piped_writer_receives_bytes_written_through_the_plan() {
        let sink_buffer = CaptureBuffer::default();
        let plan = StdioPlan::lower(
            StdioConfig::Piped(Box::new(sink_buffer.clone())),
            StdioConfig::Captured,
        );
        let StdioSink::Piped { mut stdout, .. } = plan.sink else {
            panic!("mixed config must lower to Piped");
        };
        stdout.write_all(b"hello").unwrap();
        assert_eq!(sink_buffer.take(), b"hello");
    }

    #[tokio::test]
    async fn run_blocking_inside_a_tokio_runtime_is_a_config_error() {
        let error = ContainerBuilder::from_image("alpine")
            .command(["/bin/true"])
            .run_blocking()
            .unwrap_err();
        match error {
            EmbedError::Config(message) => assert!(message.contains("run().await"), "{message}"),
            other => panic!("expected Config, got {other:?}"),
        }
    }

    /// gzip a single-file tar: the layer-blob shape a docker-archive carries.
    fn gzip_layer(path: &str, contents: &[u8]) -> Vec<u8> {
        use flate2::Compression;
        use flate2::write::GzEncoder;
        let mut tar_bytes = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_bytes);
            let mut header = tar::Header::new_gnu();
            header.set_size(contents.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, path, contents).unwrap();
            builder.finish().unwrap();
        }
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&tar_bytes).unwrap();
        encoder.finish().unwrap()
    }

    /// Ingest a one-layer docker-archive into `store` under `tag` so resolution
    /// with `PullPolicy::Never` needs no registry.
    fn seed_local_image(store: &ImageStore, tag: &str, config_json: &str) {
        let layer = gzip_layer("etc/embed-fixture", b"fixture");
        let manifest = serde_json::json!([{
            "Config": "config.json",
            "RepoTags": [tag],
            "Layers": ["layer.tar.gz"],
        }]);
        let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
        let mut tar_bytes = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_bytes);
            for (name, data) in [
                ("manifest.json", manifest_bytes.as_slice()),
                ("config.json", config_json.as_bytes()),
                ("layer.tar.gz", layer.as_slice()),
            ] {
                let mut header = tar::Header::new_gnu();
                header.set_size(data.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                builder.append_data(&mut header, name, data).unwrap();
            }
            builder.finish().unwrap();
        }
        let archive = store.root().join("embed-fixture.tar");
        std::fs::write(&archive, &tar_bytes).unwrap();
        store.load_docker_archive(&archive).unwrap();
    }

    #[tokio::test]
    async fn prepare_resolves_a_local_image_without_pulling() {
        let tmp = tempfile::tempdir().unwrap();
        let store = ImageStore::new(tmp.path());
        seed_local_image(
            &store,
            "embedtest:latest",
            r#"{"architecture":"arm64","os":"linux","config":{"Cmd":["/bin/sh"],"Env":["FOO=image"],"WorkingDir":"/srv"}}"#,
        );

        let prepared = ContainerBuilder::from_image("embedtest:latest")
            .image_store(store)
            .pull_policy(PullPolicy::Never)
            .command(["/bin/true"])
            .env("BAR", "builder")
            .prepare()
            .await
            .expect("resolves from the seeded store");
        let spec = prepared.run_spec();
        assert_eq!(spec.argv, strings(&["/bin/true"]));
        assert!(spec.envp.contains(&"FOO=image".to_string()));
        assert!(spec.envp.contains(&"BAR=builder".to_string()));
        assert_eq!(spec.cwd.as_deref().map(|p| p.as_str()), Some("/srv"));
        assert_eq!(spec.rootfs_layers.len(), 1);
        assert_eq!(spec.stdio, StdioMode::Captured);
    }

    #[tokio::test]
    async fn an_absent_image_with_pull_never_is_an_image_error() {
        let tmp = tempfile::tempdir().unwrap();
        // `PreparedContainer` has no `Debug` (it owns a `RuntimeExtensions`), so
        // `unwrap_err()` cannot be used on this Result; destructure instead.
        let Err(error) = ContainerBuilder::from_image("never-pulled:latest")
            .image_store(ImageStore::new(tmp.path()))
            .pull_policy(PullPolicy::Never)
            .command(["/bin/true"])
            .prepare()
            .await
        else {
            panic!("an absent image under PullPolicy::Never must not resolve");
        };
        assert!(matches!(error, EmbedError::Image(_)), "{error}");
    }
}
