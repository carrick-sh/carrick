//! The bridge from the API server to the existing CLI lifecycle and on-disk
//! registry. Carrier birth is delegated to the lifecycle module's one typed
//! `CarrierLauncher`; the multi-threaded API server never forks or self-spawns
//! an intermediate CLI helper.

use carrick_runtime::container;

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
    pub hostname: Option<&'a str>,
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
    /// Docker `HostConfig.SecurityOpt`, already validated by the handler;
    /// forwarded verbatim so `carrick create` persists them in `RunConfig`
    /// and start/restart/exec relaunch under the requested policy.
    pub security_opts: &'a [String],
    pub labels: &'a std::collections::HashMap<String, String>,
    pub api_auto_remove: bool,
    pub api_network_mode: Option<&'a str>,
    pub network_container: Option<&'a str>,
    pub network_attachments: &'a [carrick_runtime::container::NetworkAttachment],
}

pub(crate) fn create_container(
    image: &str,
    cmd: &[String],
    opts: &CreateContainerOpts<'_>,
) -> anyhow::Result<String> {
    let (network, network_bridge, network_container) = match opts.network.unwrap_or("host") {
        "host" => (carrick_spec::NetworkMode::Host, None, None),
        "none" => (carrick_spec::NetworkMode::None, None, None),
        value if value.starts_with("container:") => (
            carrick_spec::NetworkMode::Host,
            None,
            Some(value.trim_start_matches("container:").to_owned()),
        ),
        "bridge" => (carrick_spec::NetworkMode::Bridge, None, None),
        bridge => (
            carrick_spec::NetworkMode::Bridge,
            Some(bridge.to_owned()),
            None,
        ),
    };
    let mut mounts = opts
        .binds
        .iter()
        .map(|spec| crate::runtime_util::parse_volume_mount(spec))
        .collect::<anyhow::Result<Vec<_>>>()?;
    mounts.extend(
        opts.mount_specs
            .iter()
            .map(|spec| crate::runtime_util::parse_mount_flag(spec))
            .collect::<anyhow::Result<Vec<_>>>()?,
    );
    mounts.extend(crate::runtime_util::resolve_volumes_from_specs(
        opts.volumes_from,
    )?);
    let request = carrick_engine::CliRunRequest {
        image_ref: image.to_owned(),
        platform: None,
        args: cmd.to_vec(),
        env_overrides: opts.env.to_vec(),
        mounts,
        workdir: opts.workdir.map(str::to_owned),
        user: opts.user.map(str::to_owned),
        hostname: opts.hostname.map(str::to_owned),
        entrypoint_override: opts.entrypoint.map(<[String]>::to_vec),
        tty: opts.tty,
        interactive: opts.interactive,
        rm: opts.auto_remove,
        name: opts.name.map(str::to_owned),
        max_traps: carrick_runtime::runtime::DEFAULT_MAX_TRAPS,
        debug_state_path: None,
        fs: Some(carrick_spec::FsBackendKind::Host),
        pull: carrick_image::PullPolicy::Missing,
        exec_backend: carrick_spec::ExecBackendRequest::HvPatch,
        pid: carrick_spec::PidMode::Private,
        network,
        network_bridge,
        network_container,
        network_namespace_id: None,
        network_attachments: Vec::new(),
        network_ipv4: None,
        network_aliases: opts.network_aliases.to_vec(),
        extra_hosts: opts.extra_hosts.to_vec(),
        dns_servers: opts.dns_servers.to_vec(),
        dns_search: opts.dns_search.to_vec(),
        dns_options: opts.dns_options.to_vec(),
        volumes_from: opts.volumes_from.to_vec(),
        published_ports: crate::runtime_util::parse_publish_specs(network, opts.publish_specs)?,
        stop_signal: None,
        stop_timeout: None,
        security_opts: opts.security_opts.to_vec(),
        cap_add: Vec::new(),
    };
    let name = opts.name.map(str::to_owned);
    let metadata = crate::lifecycle::InitialContainerMetadata {
        hostname: opts.hostname.map(str::to_owned),
        labels: opts.labels.clone(),
        api_auto_remove: opts.api_auto_remove,
        api_network_mode: opts.api_network_mode.map(str::to_owned),
        network_container: opts.network_container.map(str::to_owned),
        network_attachments: opts.network_attachments.to_vec(),
    };
    crate::lifecycle::create_one_direct_with_metadata(
        request,
        carrick_image::ImageStore::default_for_user(),
        name,
        metadata,
    )
}

/// Block until the container exits, returning its exit code. Polls the on-disk
/// registry's reconciled status (no daemon push exists). Bounded by `timeout`.
pub(crate) fn wait_container(id: &str, timeout: std::time::Duration) -> anyhow::Result<i32> {
    let real = container::resolve(id).map_err(|e| anyhow::anyhow!(e))?;
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let _lifecycle_lock = container::lock_lifecycle(&real)?;
        let mut state = match container::ContainerState::load(&real) {
            Ok(state) => state,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return container::terminal_receipt(&real)?
                    .map(|receipt| receipt.exit_code)
                    .ok_or_else(|| {
                        anyhow::anyhow!("container {real} disappeared without a terminal receipt")
                    });
            }
            Err(error) => return Err(error.into()),
        };
        if container::reconcile_terminal_state(&mut state) == container::ContainerStatus::Exited {
            return Ok(state
                .exit_code
                .unwrap_or(container::UNKNOWN_CARRIER_EXIT_CODE));
        }
        drop(_lifecycle_lock);
        if std::time::Instant::now() >= deadline {
            anyhow::bail!("wait timed out for {id}");
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

/// Remove a container through the in-process lifecycle API.
pub(crate) fn remove_container(id: &str, force: bool) -> anyhow::Result<()> {
    crate::lifecycle::remove_one_direct(id, force).map(|_| ())
}

/// Start a container through the one typed CarrierLauncher boundary.
pub(crate) fn start_container(id: &str) -> anyhow::Result<()> {
    let store = carrick_image::ImageStore::default_for_user();
    crate::lifecycle::start_one_direct(&store, id).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_wait_reports_unknown_when_carrier_dies_without_receipt() {
        let id = format!("api-wait-dead-carrier-{}", std::process::id());
        let _ = container::ContainerState::remove(&id);
        let mut state: container::ContainerState = serde_json::from_str(
            r#"{"id":"placeholder","name":null,"image":"img","command":[],
                "status":"running","supervisor_pid":999999999,"init_pid":999999999,
                "created_secs":0,"exit_code":null,"auto_remove":false}"#,
        )
        .expect("state fixture");
        state.id = id.clone();
        state.create().expect("create state");

        assert_eq!(
            wait_container(&id, std::time::Duration::from_secs(1)).expect("wait result"),
            container::UNKNOWN_CARRIER_EXIT_CODE
        );

        let _ = container::ContainerState::remove(&id);
    }
}
