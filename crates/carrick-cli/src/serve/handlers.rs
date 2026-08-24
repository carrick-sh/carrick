//! Endpoint handlers: translate an HTTP request into a registry/spawn action
//! and a JSON response body. Each returns the body bytes; the router wraps them
//! in a response with the right status.

use crate::serve::model::{
    ContainerSummary, CreateBody, CreateHostConfig, CreateMount, CreateNetworkingConfig,
    CreatePortBinding, CreateResponse, EndpointSettings, ExecCreateBody, ExecCreateResponse,
    ExecInspectResponse, ExecStartBody, HostConfigSummary, ImageInspectResponse, ImageSummary,
    InfoResponse, NetworkSettingsSummary, TopResponse, VersionResponse, WaitResponse,
};
use hyper::body::{Bytes, Frame};
use hyper::{Response, StatusCode};
use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::Mutex;
use std::sync::OnceLock;
use tokio::sync::mpsc;

pub(crate) fn version_json() -> String {
    serde_json::to_string(&VersionResponse::default()).unwrap_or_else(|_| "{}".to_string())
}

pub(crate) fn info_json() -> String {
    let info = InfoResponse {
        id: "carrick".to_string(),
        name: "carrick".to_string(),
        server_version: format!("carrick-{}", env!("CARGO_PKG_VERSION")),
        operating_system: "carrick (HVF)".to_string(),
        os_type: "linux".to_string(),
        architecture: "arm64".to_string(),
        containers: carrick_runtime::container::list().len() as i64,
        images: carrick_image::ImageStore::default_for_user()
            .list_images()
            .len() as i64,
    };
    serde_json::to_string(&info).unwrap_or_else(|_| "{}".to_string())
}

/// Returns (status, json). Reads the create body, persists a Created entry, and
/// returns the new id. `name` is the optional `?name=` query value.
pub(crate) fn create_container(body: &[u8], name: Option<&str>) -> (u16, String) {
    let req: CreateBody = match serde_json::from_slice(body) {
        Ok(b) => b,
        Err(e) => return (400, error_json(&format!("invalid body: {e}"))),
    };
    let Some(image) = req.image else {
        return (400, error_json("no image specified"));
    };
    let cmd = req.cmd.unwrap_or_default();
    let env = req.env.unwrap_or_default();
    let labels = req.labels.unwrap_or_default();
    let host_config = req.host_config.as_ref();
    let binds = req
        .host_config
        .as_ref()
        .and_then(|hc| hc.binds.as_ref())
        .cloned()
        .unwrap_or_default();
    let mount_specs = match create_mount_specs(
        req.volumes.as_ref(),
        host_config.and_then(|hc| hc.mounts.as_deref()),
    ) {
        Ok(m) => m,
        Err(e) => return (400, error_json(&e)),
    };
    let publish_specs = match publish_specs_from_port_bindings(
        host_config.and_then(|hc| hc.port_bindings.as_ref()),
    ) {
        Ok(p) => p,
        Err(e) => return (400, error_json(&e)),
    };
    let api_auto_remove = host_config.and_then(|hc| hc.auto_remove).unwrap_or(false);
    let extra_hosts = host_config
        .and_then(|hc| hc.extra_hosts.as_ref())
        .cloned()
        .unwrap_or_default();
    let dns_servers = host_config
        .and_then(|hc| hc.dns.as_ref())
        .cloned()
        .unwrap_or_default();
    let dns_search = host_config
        .and_then(|hc| hc.dns_search.as_ref())
        .cloned()
        .unwrap_or_default();
    let dns_options = host_config
        .and_then(|hc| hc.dns_options.as_ref())
        .cloned()
        .unwrap_or_default();
    let volumes_from = host_config
        .and_then(|hc| hc.volumes_from.as_ref())
        .cloned()
        .unwrap_or_default();
    let security_opts = host_config
        .and_then(|hc| hc.security_opt.as_ref())
        .cloned()
        .unwrap_or_default();
    // Validate NOW, mirroring the CLI's posture: a client that explicitly
    // requests `seccomp=unconfined` must get it (before the launch-time policy
    // existed, ignoring this field was harmless — now ignoring it would
    // silently invert the requested sandbox), and an option carrick cannot
    // honor is refused with a clear error, never silently dropped.
    if let Err(e) = carrick_engine::resolve_seccomp_policy(
        carrick_spec::SeccompPolicy::ContainerDefault,
        &security_opts,
    ) {
        return (400, error_json(&e));
    }
    let network = match create_network_selection(
        host_config,
        req.networking_config.as_ref(),
        !publish_specs.is_empty(),
    ) {
        Ok(n) => n,
        Err(e) => return (400, error_json(&e)),
    };
    let network_aliases = network.flat_aliases();
    let opts = crate::serve::spawn::CreateContainerOpts {
        name,
        env: &env,
        workdir: req.working_dir.as_deref(),
        tty: req.tty.unwrap_or(false),
        interactive: req.open_stdin.unwrap_or(false),
        user: req.user.as_deref(),
        hostname: req.hostname.as_deref(),
        entrypoint: req.entrypoint.as_deref(),
        auto_remove: false,
        binds: &binds,
        mount_specs: &mount_specs,
        publish_specs: &publish_specs,
        network: network.cli_mode.as_deref(),
        network_aliases: &network_aliases,
        extra_hosts: &extra_hosts,
        dns_servers: &dns_servers,
        dns_search: &dns_search,
        dns_options: &dns_options,
        volumes_from: &volumes_from,
        security_opts: &security_opts,
        labels: &labels,
        api_auto_remove,
        api_network_mode: network.api_network_mode.as_deref(),
        network_container: network.network_container.as_deref(),
        network_attachments: &network.attachments,
    };
    match crate::serve::spawn::create_container(&image, &cmd, &opts) {
        // `id` is the 64-hex container id `carrick create` generated; the Docker
        // `Id` is always that id, not the (optional) name.
        Ok(id) => {
            if !network.attachments.is_empty() {
                let attach_result = carrick_runtime::container::ContainerState::load(&id)
                    .map_err(anyhow::Error::from)
                    .and_then(|state| {
                        crate::serve::resources::attach_container_to_networks(&state)
                    });
                if let Err(e) = attach_result {
                    return (500, error_json(&e.to_string()));
                }
            }
            let resp = CreateResponse {
                id,
                warnings: vec![],
            };
            (
                201,
                serde_json::to_string(&resp).unwrap_or_else(|_| "{}".to_string()),
            )
        }
        Err(e) => (500, error_json(&e.to_string())),
    }
}

struct CreateNetworkSelection {
    cli_mode: Option<String>,
    api_network_mode: Option<String>,
    attachments: Vec<carrick_runtime::container::NetworkAttachment>,
    network_container: Option<String>,
}

impl CreateNetworkSelection {
    fn flat_aliases(&self) -> Vec<String> {
        let mut aliases = Vec::new();
        for attachment in &self.attachments {
            for alias in &attachment.aliases {
                if !aliases.contains(alias) {
                    aliases.push(alias.clone());
                }
            }
        }
        aliases
    }
}

fn create_mount_specs(
    volumes: Option<&HashMap<String, serde_json::Value>>,
    mounts: Option<&[CreateMount]>,
) -> Result<Vec<String>, String> {
    let mut specs = Vec::new();
    if let Some(volumes) = volumes {
        let mut targets: Vec<_> = volumes.keys().collect();
        targets.sort();
        for target in targets {
            let (_name, host_source) =
                crate::serve::resources::create_anonymous_volume_mountpoint()
                    .map_err(|e| e.to_string())?;
            specs.push(format!("type=bind,source={host_source},target={target}"));
        }
    }
    if let Some(mounts) = mounts {
        for mount in mounts {
            let source = mount
                .source
                .as_deref()
                .ok_or_else(|| "mount missing Source".to_string())?;
            let target = mount
                .target
                .as_deref()
                .ok_or_else(|| "mount missing Target".to_string())?;
            let typ = mount.typ.as_deref().unwrap_or("bind");
            let host_source = match typ {
                "bind" => source.to_string(),
                "volume" => crate::serve::resources::resolve_or_create_volume_mountpoint(source)
                    .map_err(|e| e.to_string())?,
                other => {
                    return Err(format!(
                        "unsupported mount type {other:?}; expected bind or volume"
                    ));
                }
            };
            let mut spec = format!("type=bind,source={host_source},target={target}");
            if mount.read_only.unwrap_or(false) {
                spec.push_str(",readonly");
            }
            specs.push(spec);
        }
    }
    Ok(specs)
}

fn publish_specs_from_port_bindings(
    bindings: Option<&HashMap<String, Option<Vec<CreatePortBinding>>>>,
) -> Result<Vec<String>, String> {
    let Some(bindings) = bindings else {
        return Ok(Vec::new());
    };
    let mut specs = Vec::new();
    let mut entries: Vec<_> = bindings.iter().collect();
    entries.sort_by_key(|(container, _)| *container);
    for (container, host_bindings) in entries {
        let (container_port, proto) = parse_container_port_key(container)?;
        let host_bindings = host_bindings.as_deref().unwrap_or(&[]);
        if host_bindings.is_empty() {
            specs.push(format!("{container_port}/{proto}"));
            continue;
        }
        for binding in host_bindings {
            let host_port = binding
                .host_port
                .as_deref()
                .filter(|port| !port.is_empty())
                .ok_or_else(|| format!("port binding for {container:?} missing HostPort"))?;
            if let Some(host_ip) = binding.host_ip.as_deref().filter(|ip| !ip.is_empty()) {
                specs.push(format!("{host_ip}:{host_port}:{container_port}/{proto}"));
            } else {
                specs.push(format!("{host_port}:{container_port}/{proto}"));
            }
        }
    }
    Ok(specs)
}

fn parse_container_port_key(key: &str) -> Result<(u16, &str), String> {
    let (port, proto) = key
        .split_once('/')
        .ok_or_else(|| format!("invalid PortBindings key {key:?}; expected port/proto"))?;
    match proto {
        "tcp" | "udp" => {}
        other => {
            return Err(format!(
                "invalid PortBindings protocol {other:?}; expected tcp or udp"
            ));
        }
    }
    let port = port
        .parse::<u16>()
        .map_err(|_| format!("invalid PortBindings container port {port:?}"))?;
    Ok((port, proto))
}

fn create_network_selection(
    host_config: Option<&CreateHostConfig>,
    networking: Option<&CreateNetworkingConfig>,
    has_published_ports: bool,
) -> Result<CreateNetworkSelection, String> {
    let endpoint_attachments = create_network_attachments(networking);
    let has_endpoint = !endpoint_attachments.is_empty();
    match host_config.and_then(|hc| hc.network_mode.as_deref()) {
        Some("none") if has_endpoint || has_published_ports => Err(
            "network mode \"none\" cannot be combined with endpoints or published ports"
                .to_string(),
        ),
        Some("none") => Ok(CreateNetworkSelection {
            cli_mode: Some("none".to_string()),
            api_network_mode: Some("none".to_string()),
            attachments: Vec::new(),
            network_container: None,
        }),
        Some("host") if !has_endpoint => Ok(CreateNetworkSelection {
            cli_mode: Some("host".to_string()),
            api_network_mode: Some("host".to_string()),
            attachments: Vec::new(),
            network_container: None,
        }),
        Some("host") | Some("bridge") if has_endpoint => Ok(CreateNetworkSelection {
            cli_mode: Some("bridge".to_string()),
            api_network_mode: Some("bridge".to_string()),
            attachments: endpoint_attachments,
            network_container: None,
        }),
        Some("bridge") => Ok(CreateNetworkSelection {
            cli_mode: Some("bridge".to_string()),
            api_network_mode: Some("bridge".to_string()),
            attachments: Vec::new(),
            network_container: None,
        }),
        Some(mode) if mode.starts_with("container:") => {
            if has_endpoint || has_published_ports {
                return Err(
                    "network mode \"container\" cannot be combined with endpoints or published ports"
                        .to_string(),
                );
            }
            let target = mode
                .strip_prefix("container:")
                .filter(|target| !target.is_empty())
                .ok_or_else(|| "network mode \"container\" requires a target".to_string())?;
            let target_id = carrick_runtime::container::resolve(target)
                .map_err(|_| format!("No such container: {target}"))?;
            let target_state = carrick_runtime::container::ContainerState::load(&target_id)
                .map_err(|e| e.to_string())?;
            Ok(CreateNetworkSelection {
                cli_mode: Some(effective_cli_network_mode(&target_state).to_string()),
                api_network_mode: Some(format!("container:{target_id}")),
                attachments: Vec::new(),
                network_container: Some(target_id),
            })
        }
        Some(mode) if !mode.is_empty() => {
            let attachments = if has_endpoint {
                primary_network_first(endpoint_attachments, mode)
            } else {
                vec![carrick_runtime::container::NetworkAttachment {
                    name: mode.to_string(),
                    aliases: Vec::new(),
                    links: Vec::new(),
                    mac_address: None,
                    gw_priority: 0,
                    ipv4_address: None,
                    ipv6_address: None,
                    link_local_ips: Vec::new(),
                    driver_opts: std::collections::HashMap::new(),
                }]
            };
            Ok(CreateNetworkSelection {
                cli_mode: Some("bridge".to_string()),
                api_network_mode: Some(mode.to_string()),
                attachments,
                network_container: None,
            })
        }
        _ if has_endpoint => Ok(CreateNetworkSelection {
            cli_mode: Some("bridge".to_string()),
            api_network_mode: endpoint_attachments
                .first()
                .map(|attachment| attachment.name.clone()),
            attachments: endpoint_attachments,
            network_container: None,
        }),
        _ if has_published_ports => Ok(CreateNetworkSelection {
            cli_mode: Some("bridge".to_string()),
            api_network_mode: Some("bridge".to_string()),
            attachments: Vec::new(),
            network_container: None,
        }),
        _ => Ok(CreateNetworkSelection {
            cli_mode: None,
            api_network_mode: None,
            attachments: Vec::new(),
            network_container: None,
        }),
    }
}

fn effective_cli_network_mode(state: &carrick_runtime::container::ContainerState) -> &'static str {
    match state.config.network {
        carrick_spec::NetworkMode::Bridge => "bridge",
        carrick_spec::NetworkMode::Host => "host",
        carrick_spec::NetworkMode::None => "none",
    }
}

fn create_network_attachments(
    networking: Option<&CreateNetworkingConfig>,
) -> Vec<carrick_runtime::container::NetworkAttachment> {
    let Some(endpoints) = networking.and_then(|n| n.endpoints_config.as_ref()) else {
        return Vec::new();
    };
    let mut entries: Vec<_> = endpoints.iter().collect();
    entries.sort_by_key(|(name, _)| *name);
    entries
        .into_iter()
        .map(
            |(name, endpoint)| carrick_runtime::container::NetworkAttachment {
                name: name.clone(),
                aliases: endpoint.aliases.clone().unwrap_or_default(),
                links: endpoint.links.clone().unwrap_or_default(),
                mac_address: endpoint.mac_address.clone(),
                gw_priority: endpoint.gw_priority.unwrap_or(0),
                ipv4_address: endpoint
                    .ipam_config
                    .as_ref()
                    .and_then(|ipam| ipam.ipv4_address.clone()),
                ipv6_address: endpoint
                    .ipam_config
                    .as_ref()
                    .and_then(|ipam| ipam.ipv6_address.clone()),
                link_local_ips: endpoint
                    .ipam_config
                    .as_ref()
                    .and_then(|ipam| ipam.link_local_ips.clone())
                    .unwrap_or_default(),
                driver_opts: endpoint.driver_opts.clone().unwrap_or_default(),
            },
        )
        .collect()
}

fn primary_network_first(
    mut attachments: Vec<carrick_runtime::container::NetworkAttachment>,
    primary: &str,
) -> Vec<carrick_runtime::container::NetworkAttachment> {
    let primary_name = crate::serve::resources::resolve_network_name(primary)
        .unwrap_or_else(|| primary.to_string());
    if let Some(index) = attachments
        .iter()
        .position(|attachment| attachment.name == primary_name)
    {
        attachments.swap(0, index);
    }
    attachments
}

/// Docker returns 204 No Content on a successful start.
pub(crate) fn start_container(id: &str) -> (u16, String) {
    match crate::serve::spawn::start_container(id) {
        Ok(()) => (204, String::new()),
        Err(e) => (500, error_json(&e.to_string())),
    }
}

pub(crate) fn wait_container(id: &str) -> (u16, String) {
    // Bound the wait so a stuck guest cannot hang the connection forever.
    match crate::serve::spawn::wait_container(id, std::time::Duration::from_secs(300)) {
        Ok(code) => {
            let resp = WaitResponse {
                status_code: code as i64,
            };
            (
                200,
                serde_json::to_string(&resp).unwrap_or_else(|_| "{}".to_string()),
            )
        }
        Err(e) => (500, error_json(&e.to_string())),
    }
}

pub(crate) fn wait_container_stream(id: String) -> Response<crate::serve::router::ResponseBody> {
    use http_body_util::BodyExt;
    use http_body_util::StreamBody;

    let fallback = || {
        Response::new(
            http_body_util::Full::new(Bytes::new())
                .map_err(|never| match never {})
                .boxed(),
        )
    };

    let real_id = match carrick_runtime::container::resolve(&id) {
        Ok(real_id) => real_id,
        Err(e) => {
            return Response::builder()
                .status(StatusCode::NOT_FOUND)
                .header("Content-Type", "application/json")
                .body(
                    http_body_util::Full::new(Bytes::from(error_json(&e)))
                        .map_err(|never| match never {})
                        .boxed(),
                )
                .unwrap_or_else(|_| fallback());
        }
    };

    let state_for_cleanup = carrick_runtime::container::ContainerState::load(&real_id).ok();
    let expected_terminal_control = state_for_cleanup.as_ref().and_then(|state| {
        state
            .control
            .clone()
            .or_else(|| state.terminal_control.clone())
    });
    let (tx, rx) = mpsc::channel::<Result<Frame<Bytes>, std::io::Error>>(1);
    tokio::task::spawn_blocking(move || {
        let (status, body) = wait_container(&real_id);
        if status == 200
            && state_for_cleanup
                .as_ref()
                .is_some_and(|state| state.api_auto_remove)
            && let Some(expected) = expected_terminal_control.as_ref()
        {
            std::thread::sleep(std::time::Duration::from_millis(300));
            let _ = cleanup_api_auto_remove(&real_id, expected);
        }
        let _ = tx.blocking_send(Ok(Frame::data(Bytes::from(body))));
    });

    let stream = crate::serve::build::ReceiverStream { rx };
    let body = StreamBody::new(stream).boxed();
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/json")
        .body(body)
        .unwrap_or_else(|_| fallback())
}

fn cleanup_api_auto_remove(
    id: &str,
    expected: &carrick_runtime::container::CarrierControlState,
) -> anyhow::Result<bool> {
    let _lifecycle_lock = carrick_runtime::container::lock_lifecycle(id)?;
    let current = carrick_runtime::container::ContainerState::load(id)?;
    if current.status != carrick_runtime::container::ContainerStatus::Exited
        || current.terminal_control.as_ref() != Some(expected)
        || !current.api_auto_remove
    {
        return Ok(false);
    }
    crate::serve::resources::detach_container_from_all_networks(&current);
    carrick_runtime::container::ContainerState::remove(id)?;
    carrick_runtime::container::clear_terminal_receipt(id)?;
    Ok(true)
}

/// Docker returns 204 No Content on a successful remove.
pub(crate) fn remove_container(id: &str, force: bool, remove_volumes: bool) -> (u16, String) {
    let state = carrick_runtime::container::resolve(id)
        .ok()
        .and_then(|real| carrick_runtime::container::ContainerState::load(&real).ok());
    match crate::serve::spawn::remove_container(id, force) {
        Ok(()) => {
            if let Some(state) = state.as_ref() {
                crate::serve::resources::detach_container_from_all_networks(state);
                if remove_volumes
                    && let Err(e) =
                        crate::serve::resources::remove_anonymous_volumes_for_container(state)
                {
                    return (500, error_json(&e.to_string()));
                }
            }
            (204, String::new())
        }
        Err(e) if e.to_string().contains("is running") => (409, error_json(&e.to_string())),
        Err(e) => (500, error_json(&e.to_string())),
    }
}

pub(crate) fn error_json(msg: &str) -> String {
    format!(
        "{{\"message\":{}}}",
        serde_json::to_string(msg).unwrap_or_else(|_| "\"\"".to_string())
    )
}

pub(crate) fn list_containers(all: bool, query: &str) -> (u16, String) {
    let filters = crate::serve::resources::docker_filters(query);
    let mut containers = carrick_runtime::container::list();
    // Stable, newest-first by creation time.
    containers.sort_by_key(|c| std::cmp::Reverse(c.created_secs));

    let rows: Vec<ContainerSummary> = containers
        .iter()
        .filter_map(|c| {
            let status = carrick_runtime::container::reconciled_status(c);
            let state_str = match status {
                carrick_runtime::container::ContainerStatus::Created => "created",
                carrick_runtime::container::ContainerStatus::Running => "running",
                carrick_runtime::container::ContainerStatus::Exited => "exited",
            };
            if !container_matches_filters(c, state_str, &filters)
                || (!all && state_str != "running")
            {
                return None;
            }
            let status_str = match status {
                carrick_runtime::container::ContainerStatus::Created => "Created".to_string(),
                carrick_runtime::container::ContainerStatus::Running => {
                    format!(
                        "Up {}",
                        crate::runtime_util::human_age(c.created_secs).trim_end_matches(" ago")
                    )
                }
                carrick_runtime::container::ContainerStatus::Exited => format!(
                    "Exited ({}) {}",
                    c.exit_code.unwrap_or(0),
                    crate::runtime_util::human_age(c.created_secs)
                ),
            };
            let name_str = c.name.clone().unwrap_or_else(|| c.id[..12].to_string());
            Some(ContainerSummary {
                id: c.id.clone(),
                names: vec![format!("/{}", name_str)],
                image: c.image.clone(),
                image_id: c.image.clone(),
                command: c.command.join(" "),
                created: c.created_secs as i64,
                ports: container_summary_ports(c),
                labels: c.labels.clone(),
                state: state_str.to_string(),
                status: status_str,
                host_config: HostConfigSummary {
                    network_mode: container_network_mode(c),
                },
                network_settings: NetworkSettingsSummary {
                    networks: container_networks(c),
                },
            })
        })
        .collect();

    (
        200,
        serde_json::to_string(&rows).unwrap_or_else(|_| "[]".to_string()),
    )
}

fn container_matches_filters(
    c: &carrick_runtime::container::ContainerState,
    status: &str,
    filters: &HashMap<String, Vec<String>>,
) -> bool {
    filters.iter().all(|(key, values)| match key.as_str() {
        "id" => crate::serve::resources::any_filter_value(values, |value| c.id.starts_with(value)),
        "label" => crate::serve::resources::label_filters_match(&c.labels, values),
        "name" => crate::serve::resources::any_filter_value(values, |value| {
            container_name_matches(c, value)
        }),
        "network" => crate::serve::resources::any_filter_value(values, |value| {
            container_network_matches(c, value)
        }),
        "status" => crate::serve::resources::any_filter_value(values, |value| status == value),
        _ => true,
    })
}

fn container_name_matches(c: &carrick_runtime::container::ContainerState, value: &str) -> bool {
    if c.id.starts_with(value) {
        return true;
    }
    let name = c.name.as_deref().unwrap_or_default();
    name.contains(value) || format!("/{name}").contains(value)
}

fn container_network_matches(c: &carrick_runtime::container::ContainerState, value: &str) -> bool {
    if c.config.network_container.is_some() {
        return false;
    }
    if has_no_effective_network_endpoint(c) {
        return false;
    }
    let resolved = crate::serve::resources::resolve_network_name(value);
    if !c.config.network_attachments.is_empty() {
        return c.config.network_attachments.iter().any(|attachment| {
            attachment.name == value || resolved.as_deref() == Some(attachment.name.as_str())
        });
    }
    match c.config.network {
        carrick_spec::NetworkMode::Bridge => value == "bridge",
        carrick_spec::NetworkMode::Host => value == "host",
        carrick_spec::NetworkMode::None => value == "none",
    }
}

fn container_network_mode(c: &carrick_runtime::container::ContainerState) -> String {
    if let Some(target) = c.config.network_container.as_deref() {
        return format!("container:{target}");
    }
    if let Some(mode) = c.config.api_network_mode.as_deref() {
        return mode.to_string();
    }
    c.config
        .network_attachments
        .first()
        .map(|attachment| attachment.name.clone())
        .unwrap_or_else(|| match c.config.network {
            carrick_spec::NetworkMode::Bridge => "bridge".to_string(),
            carrick_spec::NetworkMode::Host => "host".to_string(),
            carrick_spec::NetworkMode::None => "none".to_string(),
        })
}

fn container_networks(
    c: &carrick_runtime::container::ContainerState,
) -> std::collections::HashMap<String, EndpointSettings> {
    if c.config.network_container.is_some() {
        return std::collections::HashMap::new();
    }
    if has_no_effective_network_endpoint(c) {
        return std::collections::HashMap::new();
    }
    if !c.config.network_attachments.is_empty() {
        return c
            .config
            .network_attachments
            .iter()
            .map(|attachment| {
                (
                    attachment.name.clone(),
                    endpoint_settings(c, &attachment.name, EndpointView::from(attachment)),
                )
            })
            .collect();
    }
    if c.config.network == carrick_spec::NetworkMode::Bridge {
        return std::iter::once((
            "bridge".to_string(),
            endpoint_settings(
                c,
                "bridge",
                EndpointView::with_aliases(c.config.network_aliases.clone()),
            ),
        ))
        .collect();
    }
    if c.config.network == carrick_spec::NetworkMode::None {
        return std::iter::once((
            "none".to_string(),
            endpoint_settings(c, "none", EndpointView::default()),
        ))
        .collect();
    }
    if c.config.network == carrick_spec::NetworkMode::Host {
        return std::iter::once((
            "host".to_string(),
            endpoint_settings(c, "host", EndpointView::default()),
        ))
        .collect();
    }
    std::collections::HashMap::new()
}

fn has_no_effective_network_endpoint(c: &carrick_runtime::container::ContainerState) -> bool {
    c.config.network == carrick_spec::NetworkMode::None
        && c.config.network_attachments.is_empty()
        && c.config
            .api_network_mode
            .as_deref()
            .is_some_and(|mode| mode != "none")
}

#[derive(Default)]
struct EndpointView {
    aliases: Option<Vec<String>>,
    links: Option<Vec<String>>,
    mac_address: Option<String>,
    gw_priority: i64,
    ipv4_address: Option<String>,
    ipv6_address: Option<String>,
    link_local_ips: Vec<String>,
    driver_opts: std::collections::HashMap<String, String>,
}

impl EndpointView {
    fn with_aliases(aliases: Vec<String>) -> Self {
        Self {
            aliases: Some(aliases),
            ..Self::default()
        }
    }
}

impl From<&carrick_runtime::container::NetworkAttachment> for EndpointView {
    fn from(attachment: &carrick_runtime::container::NetworkAttachment) -> Self {
        Self {
            aliases: Some(attachment.aliases.clone()),
            links: Some(attachment.links.clone()),
            mac_address: attachment.mac_address.clone(),
            gw_priority: attachment.gw_priority,
            ipv4_address: attachment.ipv4_address.clone(),
            ipv6_address: attachment.ipv6_address.clone(),
            link_local_ips: attachment.link_local_ips.clone(),
            driver_opts: attachment.driver_opts.clone(),
        }
    }
}

fn endpoint_settings(
    c: &carrick_runtime::container::ContainerState,
    network_name: &str,
    endpoint: EndpointView,
) -> EndpointSettings {
    let dns_names = endpoint_dns_names(c, network_name, endpoint.aliases.as_deref());
    let aliases = endpoint.aliases.clone().unwrap_or_default();
    let ip_address = crate::serve::resources::endpoint_ipv4_address(
        c,
        endpoint.ipv4_address.as_deref(),
        &aliases,
    );
    let has_ipv4 = !ip_address.is_empty();
    let ipam_config = endpoint_ipam_config(
        endpoint.ipv4_address.as_deref(),
        endpoint.ipv6_address.as_deref(),
        &endpoint.link_local_ips,
    );
    EndpointSettings {
        ipam_config,
        links: endpoint.links,
        aliases: endpoint.aliases,
        driver_opts: (!endpoint.driver_opts.is_empty()).then_some(endpoint.driver_opts),
        gw_priority: endpoint.gw_priority,
        network_id: crate::serve::resources::network_id(network_name).unwrap_or_default(),
        endpoint_id: crate::serve::resources::endpoint_id(&c.id, network_name),
        gateway: if has_ipv4 {
            "172.31.0.1".to_string()
        } else {
            String::new()
        },
        ip_address,
        mac_address: endpoint.mac_address.unwrap_or_default(),
        ip_prefix_len: if has_ipv4 { 16 } else { 0 },
        ipv6_gateway: String::new(),
        global_ipv6_address: String::new(),
        global_ipv6_prefix_len: 0,
        dns_names,
    }
}

fn endpoint_ipam_config(
    ipv4_address: Option<&str>,
    ipv6_address: Option<&str>,
    link_local_ips: &[String],
) -> Option<serde_json::Value> {
    if ipv4_address.is_none() && ipv6_address.is_none() && link_local_ips.is_empty() {
        return None;
    }
    let mut ipam = serde_json::Map::new();
    if let Some(ipv4) = ipv4_address {
        ipam.insert("IPv4Address".to_string(), serde_json::json!(ipv4));
    }
    if let Some(ipv6) = ipv6_address {
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

fn endpoint_dns_names(
    c: &carrick_runtime::container::ContainerState,
    network_name: &str,
    aliases: Option<&[String]>,
) -> Option<Vec<String>> {
    if matches!(network_name, "bridge" | "host" | "none") {
        return None;
    }
    let mut names = Vec::new();
    if let Some(name) = c.name.as_deref().filter(|name| !name.is_empty()) {
        names.push(name.to_string());
    }
    if let Some(aliases) = aliases {
        for alias in aliases {
            if !alias.is_empty() && !names.contains(alias) {
                names.push(alias.clone());
            }
        }
    }
    let short_id = c.id[..12].to_string();
    if !names.contains(&short_id) {
        names.push(short_id);
    }
    Some(names)
}

fn container_summary_ports(
    c: &carrick_runtime::container::ContainerState,
) -> Vec<serde_json::Value> {
    if matches!(
        c.config.network,
        carrick_spec::NetworkMode::Host | carrick_spec::NetworkMode::None
    ) {
        return Vec::new();
    }
    c.config
        .published_ports
        .iter()
        .map(|mapping| {
            let mut value = serde_json::json!({
                "PrivatePort": mapping.container_port,
                "Type": port_protocol_str(mapping.protocol),
            });
            if let Some(obj) = value.as_object_mut() {
                if let Some(host_port) = mapping.host_port {
                    obj.insert("PublicPort".to_string(), serde_json::json!(host_port));
                }
                if let Some(host_ip) = mapping.host_ip {
                    obj.insert("IP".to_string(), serde_json::json!(host_ip.to_string()));
                }
            }
            value
        })
        .collect()
}

fn port_protocol_str(protocol: carrick_spec::PortProtocol) -> &'static str {
    match protocol {
        carrick_spec::PortProtocol::Tcp => "tcp",
        carrick_spec::PortProtocol::Udp => "udp",
    }
}

pub(crate) fn inspect_container(id: &str) -> (u16, String) {
    let real = match carrick_runtime::container::resolve(id) {
        Ok(r) => r,
        Err(e) => return (404, error_json(&e)),
    };
    let state = match carrick_runtime::container::ContainerState::load(&real) {
        Ok(s) => s,
        Err(e) => return (500, error_json(&e.to_string())),
    };
    let status = carrick_runtime::container::reconciled_status(&state);
    let json_val = crate::lifecycle::container_to_json(&state, status);
    (
        200,
        serde_json::to_string(&json_val).unwrap_or_else(|_| "{}".to_string()),
    )
}

pub(crate) fn events_stream(query: &str) -> Response<crate::serve::router::ResponseBody> {
    use http_body_util::BodyExt;
    use http_body_util::StreamBody;

    let filters = crate::serve::resources::docker_filters(query);
    let (tx, rx) = mpsc::channel::<Result<Frame<Bytes>, std::io::Error>>(64);
    tokio::spawn(async move {
        run_events_task(filters, tx).await;
    });

    let stream = crate::serve::build::ReceiverStream { rx };
    let body = StreamBody::new(stream).boxed();
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/json")
        .body(body)
        .unwrap_or_else(|_| {
            Response::new(
                http_body_util::Full::new(Bytes::new())
                    .map_err(|never| match never {})
                    .boxed(),
            )
        })
}

#[derive(Clone)]
struct ContainerEventSnapshot {
    id: String,
    name: String,
    image: String,
    labels: HashMap<String, String>,
    status: carrick_runtime::container::ContainerStatus,
}

impl ContainerEventSnapshot {
    fn from_state(state: &carrick_runtime::container::ContainerState) -> Self {
        Self {
            id: state.id.clone(),
            name: state
                .name
                .clone()
                .unwrap_or_else(|| state.id[..12].to_string()),
            image: state.image.clone(),
            labels: state.labels.clone(),
            status: carrick_runtime::container::reconciled_status(state),
        }
    }
}

async fn run_events_task(
    filters: HashMap<String, Vec<String>>,
    tx: mpsc::Sender<Result<Frame<Bytes>, std::io::Error>>,
) {
    let mut known: HashMap<String, ContainerEventSnapshot> = current_event_snapshots()
        .into_iter()
        .map(|s| (s.id.clone(), s))
        .collect();

    loop {
        let current: HashMap<String, ContainerEventSnapshot> = current_event_snapshots()
            .into_iter()
            .map(|s| (s.id.clone(), s))
            .collect();

        for snapshot in current.values() {
            match known.get(&snapshot.id) {
                None => {
                    if !send_container_event(&tx, snapshot, "create", &filters).await {
                        return;
                    }
                }
                Some(previous) if previous.status != snapshot.status => {
                    if let Some(action) = event_action_for_status(snapshot.status)
                        && !send_container_event(&tx, snapshot, action, &filters).await
                    {
                        return;
                    }
                }
                _ => {}
            }
        }

        let current_ids: HashSet<_> = current.keys().cloned().collect();
        for snapshot in known.values() {
            if !current_ids.contains(&snapshot.id)
                && !send_container_event(&tx, snapshot, "destroy", &filters).await
            {
                return;
            }
        }

        known = current;
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}

fn current_event_snapshots() -> Vec<ContainerEventSnapshot> {
    carrick_runtime::container::list()
        .iter()
        .map(ContainerEventSnapshot::from_state)
        .collect()
}

fn event_action_for_status(
    status: carrick_runtime::container::ContainerStatus,
) -> Option<&'static str> {
    match status {
        carrick_runtime::container::ContainerStatus::Created => Some("create"),
        carrick_runtime::container::ContainerStatus::Running => Some("start"),
        carrick_runtime::container::ContainerStatus::Exited => Some("die"),
    }
}

async fn send_container_event(
    tx: &mpsc::Sender<Result<Frame<Bytes>, std::io::Error>>,
    snapshot: &ContainerEventSnapshot,
    action: &str,
    filters: &HashMap<String, Vec<String>>,
) -> bool {
    if !container_event_matches_filters(snapshot, action, filters) {
        return true;
    }
    let now = now_unix_secs();
    let mut attributes = snapshot.labels.clone();
    attributes.insert("name".to_string(), snapshot.name.clone());
    attributes.insert("image".to_string(), snapshot.image.clone());
    let event = serde_json::json!({
        "Type": "container",
        "Action": action,
        "Actor": {
            "ID": snapshot.id,
            "Attributes": attributes,
        },
        "scope": "local",
        "time": now,
        "timeNano": now.saturating_mul(1_000_000_000),
    });
    let mut line = match serde_json::to_vec(&event) {
        Ok(bytes) => bytes,
        Err(_) => return true,
    };
    line.push(b'\n');
    tx.send(Ok(Frame::data(Bytes::from(line)))).await.is_ok()
}

fn container_event_matches_filters(
    snapshot: &ContainerEventSnapshot,
    action: &str,
    filters: &HashMap<String, Vec<String>>,
) -> bool {
    filters.iter().all(|(key, values)| match key.as_str() {
        "container" => crate::serve::resources::any_filter_value(values, |value| {
            snapshot.id.starts_with(value)
                || snapshot.name == value
                || format!("/{}", snapshot.name) == value
        }),
        "event" => crate::serve::resources::any_filter_value(values, |value| action == value),
        "label" => crate::serve::resources::label_filters_match(&snapshot.labels, values),
        "type" => crate::serve::resources::any_filter_value(values, |value| value == "container"),
        _ => true,
    })
}

fn now_unix_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or_default()
}

pub(crate) fn stop_container(id: &str, time: Option<u64>) -> (u16, String) {
    match crate::lifecycle::stop_one(id, time) {
        Ok(_) => (204, String::new()),
        Err(e) => (500, error_json(&e.to_string())),
    }
}

pub(crate) fn kill_container(id: &str, signal: Option<&str>) -> (u16, String) {
    let sig_str = signal.unwrap_or("SIGKILL");
    let signum = match crate::lifecycle::parse_signal(sig_str) {
        Some(n) => n,
        None => return (400, error_json(&format!("invalid signal: {sig_str}"))),
    };
    match crate::lifecycle::kill_one(id, signum) {
        Ok(_) => (204, String::new()),
        Err(e) => (500, error_json(&e.to_string())),
    }
}

pub(crate) fn restart_container(id: &str, time: Option<u64>) -> (u16, String) {
    if let Err(e) = crate::lifecycle::stop_one(id, time) {
        return (500, error_json(&e.to_string()));
    }
    match crate::serve::spawn::start_container(id) {
        Ok(()) => (204, String::new()),
        Err(e) => (500, error_json(&e.to_string())),
    }
}

pub(crate) fn resize_container_tty(id: &str) -> (u16, String) {
    let real = match carrick_runtime::container::resolve(id) {
        Ok(r) => r,
        Err(e) => return (404, error_json(&e)),
    };
    match carrick_runtime::container::ContainerState::load(&real) {
        Ok(_) => (200, String::new()),
        Err(e) => (500, error_json(&e.to_string())),
    }
}

pub(crate) fn logs_container(
    id: String,
    follow: bool,
    tail: Option<usize>,
) -> Response<crate::serve::router::ResponseBody> {
    use http_body_util::BodyExt;
    use http_body_util::StreamBody;
    use hyper::body::{Bytes, Frame};
    use tokio::sync::mpsc;

    let fallback = || {
        Response::new(
            http_body_util::Full::new(Bytes::new())
                .map_err(|never| match never {})
                .boxed(),
        )
    };

    let real_id = match carrick_runtime::container::resolve(&id) {
        Ok(r) => r,
        Err(e) => {
            return Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(
                    http_body_util::Full::new(Bytes::from(error_json(&e)))
                        .map_err(|never| match never {})
                        .boxed(),
                )
                .unwrap_or_else(|_| fallback());
        }
    };

    let state = match carrick_runtime::container::ContainerState::load(&real_id) {
        Ok(s) => s,
        Err(e) => {
            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(
                    http_body_util::Full::new(Bytes::from(error_json(&e.to_string())))
                        .map_err(|never| match never {})
                        .boxed(),
                )
                .unwrap_or_else(|_| fallback());
        }
    };

    let tty = state.config.tty;
    let path = match carrick_runtime::container::log_path(&real_id) {
        Ok(p) => p,
        Err(e) => {
            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(
                    http_body_util::Full::new(Bytes::from(error_json(&e.to_string())))
                        .map_err(|never| match never {})
                        .boxed(),
                )
                .unwrap_or_else(|_| fallback());
        }
    };

    let (tx, rx) = mpsc::channel::<Result<Frame<Bytes>, std::io::Error>>(64);

    tokio::spawn(async move {
        run_logs_task(real_id, path, tty, follow, tail, tx).await;
    });

    let stream = crate::serve::build::ReceiverStream { rx };
    let body = StreamBody::new(stream).boxed();
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/octet-stream")
        .body(body)
        .unwrap_or_else(|_| fallback())
}

pub(crate) async fn attach_container_route(
    id: String,
    query: String,
    mut req: hyper::Request<hyper::body::Incoming>,
) -> Response<crate::serve::router::ResponseBody> {
    use http_body_util::BodyExt;
    use hyper::body::Bytes;

    let fallback = || {
        Response::new(
            http_body_util::Full::new(Bytes::new())
                .map_err(|never| match never {})
                .boxed(),
        )
    };

    let real_id = match carrick_runtime::container::resolve(&id) {
        Ok(r) => r,
        Err(e) => {
            return Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(
                    http_body_util::Full::new(Bytes::from(error_json(&e)))
                        .map_err(|never| match never {})
                        .boxed(),
                )
                .unwrap_or_else(|_| fallback());
        }
    };
    let state = match carrick_runtime::container::ContainerState::load(&real_id) {
        Ok(s) => s,
        Err(e) => {
            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(
                    http_body_util::Full::new(Bytes::from(error_json(&e.to_string())))
                        .map_err(|never| match never {})
                        .boxed(),
                )
                .unwrap_or_else(|_| fallback());
        }
    };
    let path = match carrick_runtime::container::log_path(&real_id) {
        Ok(p) => p,
        Err(e) => {
            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(
                    http_body_util::Full::new(Bytes::from(error_json(&e.to_string())))
                        .map_err(|never| match never {})
                        .boxed(),
                )
                .unwrap_or_else(|_| fallback());
        }
    };

    let options = AttachOptions {
        tty: state.config.tty,
        logs: query_bool(&query, "logs"),
        stream: query_bool(&query, "stream"),
        stdout: query_bool(&query, "stdout"),
        stderr: query_bool(&query, "stderr"),
    };
    let upgraded = hyper::upgrade::on(&mut req);
    tokio::spawn(async move {
        match upgraded.await {
            Ok(upgraded) => {
                let io = hyper_util::rt::TokioIo::new(upgraded);
                if let Err(e) = run_attach_task(real_id, path, options, io).await
                    && !is_broken_pipe(&e)
                {
                    tracing::error!("container attach error: {e}");
                }
            }
            Err(e) => tracing::error!("container attach upgrade error: {e}"),
        }
    });

    Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header("Connection", "Upgrade")
        .header("Upgrade", "tcp")
        .header(
            "Content-Type",
            if state.config.tty {
                "application/vnd.docker.raw-stream"
            } else {
                "application/vnd.docker.multiplexed-stream"
            },
        )
        .body(
            http_body_util::Full::new(Bytes::new())
                .map_err(|never| match never {})
                .boxed(),
        )
        .unwrap_or_else(|_| fallback())
}

pub(crate) async fn download_archive_route(
    id: String,
    query: String,
) -> Response<crate::serve::router::ResponseBody> {
    use http_body_util::BodyExt;

    let path = match decode_archive_query_path(&query) {
        Ok(path) => path,
        Err(error) => return archive_error_response(StatusCode::BAD_REQUEST, &error),
    };
    let result = tokio::task::spawn_blocking(move || download_archive(&id, path)).await;
    match result {
        Ok(Ok(download)) => Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/x-tar")
            .header("X-Docker-Container-Path-Stat", download.stat_header)
            .body(
                http_body_util::Full::new(Bytes::from(download.bytes))
                    .map_err(|never| match never {})
                    .boxed(),
            )
            .unwrap_or_else(|_| archive_fallback()),
        Ok(Err(error)) => archive_error_response(error.status, &error.message),
        Err(error) => archive_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("archive download worker failed: {error}"),
        ),
    }
}

pub(crate) async fn head_archive_route(
    id: String,
    query: String,
) -> Response<crate::serve::router::ResponseBody> {
    use http_body_util::BodyExt;

    let path = match decode_archive_query_path(&query) {
        Ok(path) => path,
        Err(error) => return archive_error_response(StatusCode::BAD_REQUEST, &error),
    };
    let result = tokio::task::spawn_blocking(move || archive_metadata(&id, path)).await;
    match result {
        Ok(Ok(stat_header)) => Response::builder()
            .status(StatusCode::OK)
            .header("X-Docker-Container-Path-Stat", stat_header)
            .body(
                http_body_util::Full::new(Bytes::new())
                    .map_err(|never| match never {})
                    .boxed(),
            )
            .unwrap_or_else(|_| archive_fallback()),
        Ok(Err(error)) => archive_error_response(error.status, &error.message),
        Err(error) => archive_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("archive metadata worker failed: {error}"),
        ),
    }
}

pub(crate) async fn upload_archive_route(
    id: String,
    query: String,
    body_bytes: Bytes,
) -> Response<crate::serve::router::ResponseBody> {
    use http_body_util::BodyExt;

    let path = match decode_archive_query_path(&query) {
        Ok(path) => path,
        Err(error) => return archive_error_response(StatusCode::BAD_REQUEST, &error),
    };
    if body_bytes.len() > crate::serve::router::MAX_HTTP_ARCHIVE_BYTES {
        return archive_error_response(StatusCode::PAYLOAD_TOO_LARGE, "archive body is too large");
    }
    let result = tokio::task::spawn_blocking(move || upload_archive(&id, path, &body_bytes)).await;
    match result {
        Ok(Ok(())) => Response::builder()
            .status(StatusCode::OK)
            .body(
                http_body_util::Full::new(Bytes::new())
                    .map_err(|never| match never {})
                    .boxed(),
            )
            .unwrap_or_else(|_| archive_fallback()),
        Ok(Err(error)) => archive_error_response(error.status, &error.message),
        Err(error) => archive_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("archive upload worker failed: {error}"),
        ),
    }
}

struct ArchiveHttpError {
    status: StatusCode,
    message: String,
}

struct DownloadedArchive {
    bytes: Vec<u8>,
    stat_header: String,
}

/// Best-effort cancellation for a carrier archive capability. The carrier's
/// idle deadline remains the authority when the transport itself is gone, but
/// every local error path must release eagerly so eight failed HTTP clients
/// cannot pin the bounded table until expiry.
struct ArchiveCapabilityGuard {
    real_id: String,
    control: carrick_runtime::container::CarrierControlState,
    capability: carrick_runtime::kernel::control::ArchiveCapability,
    armed: bool,
}

impl ArchiveCapabilityGuard {
    fn new(
        real_id: String,
        control: carrick_runtime::container::CarrierControlState,
        capability: carrick_runtime::kernel::control::ArchiveCapability,
    ) -> Self {
        Self {
            real_id,
            control,
            capability,
            armed: true,
        }
    }

    fn capability(&self) -> carrick_runtime::kernel::control::ArchiveCapability {
        self.capability
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for ArchiveCapabilityGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let _ = carrick_runtime::kernel::control::send(
            &self.real_id,
            &self.control,
            carrick_runtime::kernel::control::ControlOperation::ArchiveAbort {
                capability: self.capability,
            },
        );
    }
}

fn archive_control_target(
    id: &str,
) -> Result<(String, carrick_runtime::container::CarrierControlState), ArchiveHttpError> {
    let real_id = carrick_runtime::container::resolve(id).map_err(|message| ArchiveHttpError {
        status: StatusCode::NOT_FOUND,
        message,
    })?;
    let _lifecycle_lock =
        carrick_runtime::container::lock_lifecycle(&real_id).map_err(|error| ArchiveHttpError {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: format!("lock container archive lifecycle: {error}"),
        })?;
    let state = carrick_runtime::container::ContainerState::load(&real_id).map_err(|error| {
        ArchiveHttpError {
            status: if error.kind() == std::io::ErrorKind::NotFound {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            },
            message: error.to_string(),
        }
    })?;
    if state.status != carrick_runtime::container::ContainerStatus::Running {
        return Err(ArchiveHttpError {
            status: StatusCode::CONFLICT,
            message: "stopped-container archive is unavailable: persisted state does not authenticate the exact writable upper and immutable lower filesystem authorities".to_owned(),
        });
    }
    let control = state.control.ok_or_else(|| ArchiveHttpError {
        status: StatusCode::CONFLICT,
        message: "container has no live carrier control endpoint".to_owned(),
    })?;
    Ok((real_id, control))
}

fn archive_metadata(id: &str, path: String) -> Result<String, ArchiveHttpError> {
    use carrick_runtime::kernel::control::{ControlOperation, ControlOutcome};

    let (real_id, control) = archive_control_target(id)?;
    let request = carrick_runtime::kernel::control::ArchiveRequest::new(path)
        .map_err(archive_http_control_error)?;
    let outcome = carrick_runtime::kernel::control::send(
        &real_id,
        &control,
        ControlOperation::ArchiveMetadata { request },
    )
    .map_err(archive_http_transport_error)?;
    let ControlOutcome::ArchiveMetadata { metadata } = outcome else {
        return Err(archive_http_outcome_error(outcome));
    };
    docker_archive_stat_header(&metadata).map_err(|message| ArchiveHttpError {
        status: StatusCode::BAD_GATEWAY,
        message,
    })
}

fn download_archive(id: &str, path: String) -> Result<DownloadedArchive, ArchiveHttpError> {
    use carrick_runtime::kernel::control::{ControlOperation, ControlOutcome};

    let (real_id, control) = archive_control_target(id)?;
    let request = carrick_runtime::kernel::control::ArchiveRequest::new(path)
        .map_err(archive_http_control_error)?;
    let outcome = carrick_runtime::kernel::control::send(
        &real_id,
        &control,
        ControlOperation::ArchiveBeginRead { request },
    )
    .map_err(archive_http_transport_error)?;
    let ControlOutcome::ArchiveReadAccepted {
        capability,
        metadata,
    } = outcome
    else {
        return Err(archive_http_outcome_error(outcome));
    };
    let mut guard = ArchiveCapabilityGuard::new(real_id, control, capability);
    let stat_header =
        docker_archive_stat_header(&metadata).map_err(|message| ArchiveHttpError {
            status: StatusCode::BAD_GATEWAY,
            message,
        })?;
    let mut result = Vec::new();
    loop {
        let outcome = carrick_runtime::kernel::control::send(
            &guard.real_id,
            &guard.control,
            ControlOperation::ArchiveReadChunk {
                capability: guard.capability(),
            },
        )
        .map_err(archive_http_transport_error)?;
        match outcome {
            ControlOutcome::ArchiveChunk { chunk } => {
                if chunk.bytes.len() > carrick_runtime::kernel::control::MAX_ARCHIVE_CHUNK_BYTES
                    || result.len().saturating_add(chunk.bytes.len())
                        > crate::serve::router::MAX_HTTP_ARCHIVE_BYTES
                    || (chunk.bytes.is_empty() && !chunk.eof)
                {
                    return Err(ArchiveHttpError {
                        status: StatusCode::BAD_GATEWAY,
                        message: "carrier returned an invalid archive chunk".to_owned(),
                    });
                }
                result.extend_from_slice(&chunk.bytes);
                if chunk.eof {
                    guard.disarm();
                    return Ok(DownloadedArchive {
                        bytes: result,
                        stat_header,
                    });
                }
            }
            other => {
                return Err(archive_http_outcome_error(other));
            }
        }
    }
}

fn docker_archive_stat_header(
    metadata: &carrick_runtime::kernel::control::ArchiveMetadata,
) -> Result<String, String> {
    use base64::Engine as _;

    #[derive(serde::Serialize)]
    #[serde(rename_all = "camelCase")]
    struct DockerPathStat<'a> {
        name: &'a str,
        size: u64,
        mode: u32,
        mtime: String,
        link_target: &'a str,
    }

    let timestamp = chrono::DateTime::from_timestamp(metadata.mtime_secs, metadata.mtime_nanos)
        .ok_or_else(|| "carrier returned an invalid archive timestamp".to_owned())?;
    let stat = DockerPathStat {
        name: &metadata.name,
        size: metadata.size,
        mode: metadata.mode,
        mtime: timestamp.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true),
        link_target: metadata.link_target.as_deref().unwrap_or(""),
    };
    let json = serde_json::to_vec(&stat)
        .map_err(|error| format!("encode archive path metadata: {error}"))?;
    Ok(base64::engine::general_purpose::STANDARD.encode(json))
}

fn upload_archive(id: &str, path: String, bytes: &[u8]) -> Result<(), ArchiveHttpError> {
    use carrick_runtime::kernel::control::{ControlOperation, ControlOutcome};

    let (real_id, control) = archive_control_target(id)?;
    let request = carrick_runtime::kernel::control::ArchiveRequest::new(path)
        .map_err(archive_http_control_error)?;
    let outcome = carrick_runtime::kernel::control::send(
        &real_id,
        &control,
        ControlOperation::ArchiveBeginWrite { request },
    )
    .map_err(archive_http_transport_error)?;
    let ControlOutcome::ArchiveAccepted { capability } = outcome else {
        return Err(archive_http_outcome_error(outcome));
    };
    let mut guard = ArchiveCapabilityGuard::new(real_id, control, capability);

    if bytes.is_empty() {
        let outcome = carrick_runtime::kernel::control::send(
            &guard.real_id,
            &guard.control,
            ControlOperation::ArchiveWriteChunk {
                capability: guard.capability(),
                bytes: Vec::new(),
                eof: true,
            },
        )
        .map_err(archive_http_transport_error)?;
        return match outcome {
            ControlOutcome::ArchiveComplete => {
                guard.disarm();
                Ok(())
            }
            other => Err(archive_http_outcome_error(other)),
        };
    }

    for (index, chunk) in bytes
        .chunks(carrick_runtime::kernel::control::MAX_ARCHIVE_CHUNK_BYTES)
        .enumerate()
    {
        let eof =
            (index + 1) * carrick_runtime::kernel::control::MAX_ARCHIVE_CHUNK_BYTES >= bytes.len();
        let outcome = carrick_runtime::kernel::control::send(
            &guard.real_id,
            &guard.control,
            ControlOperation::ArchiveWriteChunk {
                capability: guard.capability(),
                bytes: chunk.to_vec(),
                eof,
            },
        )
        .map_err(archive_http_transport_error)?;
        let accepted = match &outcome {
            ControlOutcome::ArchiveWriteReady => !eof,
            ControlOutcome::ArchiveComplete => eof,
            _ => false,
        };
        if !accepted {
            return Err(archive_http_outcome_error(outcome));
        }
    }
    guard.disarm();
    Ok(())
}

fn archive_http_transport_error(error: impl ToString) -> ArchiveHttpError {
    ArchiveHttpError {
        status: StatusCode::BAD_GATEWAY,
        message: error.to_string(),
    }
}

fn archive_http_control_error(
    error: carrick_runtime::kernel::control::ArchiveControlError,
) -> ArchiveHttpError {
    use carrick_runtime::kernel::control::ArchiveControlError;
    let status = match error {
        ArchiveControlError::InvalidPath | ArchiveControlError::InvalidArchive => {
            StatusCode::BAD_REQUEST
        }
        ArchiveControlError::NotFound => StatusCode::NOT_FOUND,
        ArchiveControlError::NotDirectory => StatusCode::NOT_ACCEPTABLE,
        ArchiveControlError::TooLarge => StatusCode::PAYLOAD_TOO_LARGE,
        ArchiveControlError::Capacity => StatusCode::TOO_MANY_REQUESTS,
        ArchiveControlError::UnknownCapability
        | ArchiveControlError::Filesystem(_)
        | ArchiveControlError::Unavailable => StatusCode::INTERNAL_SERVER_ERROR,
    };
    ArchiveHttpError {
        status,
        message: error.to_string(),
    }
}

fn archive_http_outcome_error(
    outcome: carrick_runtime::kernel::control::ControlOutcome,
) -> ArchiveHttpError {
    if let carrick_runtime::kernel::control::ControlOutcome::ArchiveError { error } = outcome {
        archive_http_control_error(error)
    } else {
        ArchiveHttpError {
            status: StatusCode::BAD_GATEWAY,
            message: format!("carrier returned an invalid archive outcome: {outcome:?}"),
        }
    }
}

fn archive_error_response(
    status: StatusCode,
    message: &str,
) -> Response<crate::serve::router::ResponseBody> {
    use http_body_util::BodyExt as _;
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(
            http_body_util::Full::new(Bytes::from(error_json(message)))
                .map_err(|never| match never {})
                .boxed(),
        )
        .unwrap_or_else(|_| archive_fallback())
}

fn archive_fallback() -> Response<crate::serve::router::ResponseBody> {
    use http_body_util::BodyExt as _;
    Response::new(
        http_body_util::Full::new(Bytes::new())
            .map_err(|never| match never {})
            .boxed(),
    )
}

fn decode_archive_query_path(query: &str) -> Result<String, String> {
    let raw = crate::serve::router::query_param(query, "path")
        .ok_or_else(|| "archive path query parameter is required".to_owned())?;
    let bytes = raw.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'+' {
            decoded.push(b' ');
            index += 1;
            continue;
        }
        if bytes[index] != b'%' {
            decoded.push(bytes[index]);
            index += 1;
            continue;
        }
        if index + 2 >= bytes.len() {
            return Err("archive path has an incomplete percent escape".to_owned());
        }
        let high = hex_value(bytes[index + 1])
            .ok_or_else(|| "archive path has an invalid percent escape".to_owned())?;
        let low = hex_value(bytes[index + 2])
            .ok_or_else(|| "archive path has an invalid percent escape".to_owned())?;
        decoded.push((high << 4) | low);
        index += 3;
    }
    let path =
        String::from_utf8(decoded).map_err(|_| "archive path is not valid UTF-8".to_owned())?;
    carrick_runtime::kernel::control::ArchiveRequest::new(path.clone())
        .map_err(|error| error.to_string())?;
    Ok(path)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn query_bool(query: &str, key: &str) -> bool {
    crate::serve::router::query_param(query, key)
        .is_some_and(|value| value == "true" || value == "1")
}

fn is_broken_pipe(e: &anyhow::Error) -> bool {
    e.downcast_ref::<std::io::Error>()
        .is_some_and(|io| io.kind() == std::io::ErrorKind::BrokenPipe)
}

struct AttachOptions {
    tty: bool,
    logs: bool,
    stream: bool,
    stdout: bool,
    stderr: bool,
}

async fn run_attach_task(
    id: String,
    path: std::path::PathBuf,
    options: AttachOptions,
    mut io: hyper_util::rt::TokioIo<hyper::upgrade::Upgraded>,
) -> anyhow::Result<()> {
    let mut offset = 0;
    if options.logs {
        let data = tokio::fs::read(&path).await.unwrap_or_default();
        offset = data.len() as u64;
        write_attach_bytes(&mut io, &data, &options).await?;
    } else if let Ok(metadata) = tokio::fs::metadata(&path).await {
        offset = metadata.len();
    }

    if !options.stream {
        return Ok(());
    }

    loop {
        if let Ok((new_data, new_offset)) = read_appended_async(&path, offset).await {
            if !new_data.is_empty() {
                write_attach_bytes(&mut io, &new_data, &options).await?;
            }
            offset = new_offset;
        }

        match carrick_runtime::container::ContainerState::load(&id) {
            Ok(state) => {
                if carrick_runtime::container::reconciled_status(&state)
                    == carrick_runtime::container::ContainerStatus::Exited
                {
                    if let Ok((new_data, _)) = read_appended_async(&path, offset).await
                        && !new_data.is_empty()
                    {
                        write_attach_bytes(&mut io, &new_data, &options).await?;
                    }
                    return Ok(());
                }
            }
            Err(_) => return Ok(()),
        }

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}

async fn write_attach_bytes(
    io: &mut hyper_util::rt::TokioIo<hyper::upgrade::Upgraded>,
    data: &[u8],
    options: &AttachOptions,
) -> anyhow::Result<()> {
    use tokio::io::AsyncWriteExt;

    if data.is_empty() || (!options.stdout && !options.stderr) {
        return Ok(());
    }
    let stream_type = if options.stdout { 1 } else { 2 };
    let framed = frame_stream_data(data, stream_type, options.tty);
    io.write_all(&framed).await?;
    io.flush().await?;
    Ok(())
}

/// Build a Docker raw-stream frame: 8-byte header (stream type + big-endian
/// length) followed by the payload. `stream_type` is 1 for stdout, 2 for stderr.
/// When `tty` is true the header is omitted (Docker raw-stream TTY mode).
fn frame_stream_data(data: &[u8], stream_type: u8, tty: bool) -> Bytes {
    if tty {
        Bytes::copy_from_slice(data)
    } else {
        let mut frame = Vec::with_capacity(8 + data.len());
        frame.push(stream_type);
        frame.push(0);
        frame.push(0);
        frame.push(0);
        let len = data.len() as u32;
        frame.extend_from_slice(&len.to_be_bytes());
        frame.extend_from_slice(data);
        Bytes::from(frame)
    }
}

async fn read_appended_async(
    path: &std::path::Path,
    offset: u64,
) -> std::io::Result<(Vec<u8>, u64)> {
    use tokio::io::{AsyncReadExt, AsyncSeekExt};
    let mut f = match tokio::fs::File::open(path).await {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((Vec::new(), offset)),
        Err(e) => return Err(e),
    };
    let metadata = f.metadata().await?;
    let len = metadata.len();
    if len <= offset {
        return Ok((Vec::new(), offset));
    }
    f.seek(std::io::SeekFrom::Start(offset)).await?;
    let mut buf = Vec::with_capacity((len - offset) as usize);
    f.read_to_end(&mut buf).await?;
    Ok((buf, len))
}

async fn run_logs_task(
    id: String,
    path: std::path::PathBuf,
    tty: bool,
    follow: bool,
    tail: Option<usize>,
    tx: mpsc::Sender<Result<Frame<Bytes>, std::io::Error>>,
) {
    use hyper::body::Frame;

    // 1. Read existing log file data.
    let data = tokio::fs::read(&path).await.unwrap_or_default();
    let tail_data = crate::lifecycle::select_tail(&data, tail);
    if !tail_data.is_empty() {
        let framed = frame_stream_data(tail_data, 1, tty);
        if tx.send(Ok(Frame::data(framed))).await.is_err() {
            return; // Client hung up
        }
    }

    if !follow {
        return;
    }

    // 2. Stream new bytes.
    let mut offset = data.len() as u64;
    loop {
        // Read new bytes
        if let Ok((new_data, new_offset)) = read_appended_async(&path, offset).await {
            if !new_data.is_empty() {
                let framed = frame_stream_data(&new_data, 1, tty);
                if tx.send(Ok(Frame::data(framed))).await.is_err() {
                    return; // Client hung up
                }
            }
            offset = new_offset;
        }

        // Check if init is still alive
        let alive = match carrick_runtime::container::ContainerState::load(&id) {
            Ok(s) => s.init_alive(),
            Err(_) => false,
        };

        if !alive {
            // Final drain
            if let Ok((new_data, _)) = read_appended_async(&path, offset).await
                && !new_data.is_empty()
            {
                let framed = frame_stream_data(&new_data, 1, tty);
                let _ = tx.send(Ok(Frame::data(framed))).await;
            }
            return;
        }

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}

/// `GET /images/json`: list all locally-stored images.
pub(crate) fn list_images() -> (u16, String) {
    let store = carrick_image::ImageStore::default_for_user();
    let images = store.list_images();
    let summaries: Vec<ImageSummary> = images
        .into_iter()
        .map(|info| ImageSummary {
            id: format!("sha256:{}", info.id),
            parent_id: String::new(),
            repo_tags: vec![format!("{}:{}", info.repository, info.tag)],
            repo_digests: vec![],
            created: info.created_secs as i64,
            size: info.size as i64,
            shared_size: -1,
            virtual_size: info.size as i64,
            labels: std::collections::HashMap::new(),
            containers: -1,
        })
        .collect();

    (
        200,
        serde_json::to_string(&summaries).unwrap_or_else(|_| "[]".to_string()),
    )
}

/// `DELETE /images/{name}`: remove an image by name, tag, or id.
pub(crate) fn remove_image(spec: &str) -> (u16, String) {
    let store = carrick_image::ImageStore::default_for_user();
    match store.remove_image_by_spec(spec) {
        Ok(Some(name)) => {
            let resp = serde_json::json!([
                { "Untagged": name }
            ]);
            (
                200,
                serde_json::to_string(&resp).unwrap_or_else(|_| "[]".to_string()),
            )
        }
        Ok(None) => (404, error_json(&format!("No such image: {spec}"))),
        Err(e) => (500, error_json(&e.to_string())),
    }
}

/// `POST /images/create`: pull an image, streaming NDJSON progress. Shells out
/// to `carrick pull` (never forks a guest in-process).
pub(crate) fn pull_image(query: &str) -> Response<crate::serve::router::ResponseBody> {
    use http_body_util::BodyExt;
    use http_body_util::StreamBody;

    let fallback = || {
        Response::new(
            http_body_util::Full::new(Bytes::new())
                .map_err(|never| match never {})
                .boxed(),
        )
    };

    let from_image = match crate::serve::router::query_param(query, "fromImage") {
        Some(v) => crate::serve::build::url_decode(&v),
        None => {
            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(
                    http_body_util::Full::new(Bytes::from(error_json(
                        "fromImage parameter is required",
                    )))
                    .map_err(|never| match never {})
                    .boxed(),
                )
                .unwrap_or_else(|_| fallback());
        }
    };

    let tag = crate::serve::router::query_param(query, "tag")
        .map(|v| crate::serve::build::url_decode(&v))
        .unwrap_or_else(|| "latest".to_string());

    let image_ref = if from_image.contains(':') {
        from_image
    } else {
        format!("{from_image}:{tag}")
    };

    let (tx, rx) = mpsc::channel::<Result<Frame<Bytes>, std::io::Error>>(64);

    tokio::spawn(async move {
        run_pull_task(image_ref, tx).await;
    });

    let stream = crate::serve::build::ReceiverStream { rx };
    let body = StreamBody::new(stream).boxed();
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/json")
        .body(body)
        .unwrap_or_else(|_| fallback())
}

async fn run_pull_task(image_ref: String, tx: mpsc::Sender<Result<Frame<Bytes>, std::io::Error>>) {
    async fn send(
        tx: &mpsc::Sender<Result<Frame<Bytes>, std::io::Error>>,
        value: serde_json::Value,
    ) {
        let mut line = value.to_string();
        line.push('\n');
        let _ = tx.send(Ok(Frame::data(Bytes::from(line)))).await;
    }

    let image = match carrick_image::ImageReference::parse(&image_ref) {
        Ok(image) => image,
        Err(error) => {
            send(&tx, serde_json::json!({ "error": error.to_string() })).await;
            return;
        }
    };
    let store = carrick_image::ImageStore::default_for_user();
    let target = carrick_image::PlatformTarget::default_target();
    send(
        &tx,
        serde_json::json!({ "status": format!("Pulling {}", image.canonical()) }),
    )
    .await;
    match carrick_image::pull_image_with_platform(&image, &store, &target).await {
        Ok(_) => {
            send(
                &tx,
                serde_json::json!({
                    "status": format!("Downloaded newer image for {}", image.canonical())
                }),
            )
            .await;
        }
        Err(error) => {
            send(&tx, serde_json::json!({ "error": error.to_string() })).await;
        }
    }
}
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub(crate) struct ExecConfig {
    pub container_id: String,
    pub cmd: Vec<String>,
    pub env: Vec<String>,
    pub tty: bool,
    pub interactive: bool,
    pub user: Option<String>,
    pub workdir: Option<String>,
}

#[derive(Clone, Debug)]
pub(crate) struct ExecInstanceState {
    pub container_id: String,
    pub running: bool,
    pub exit_code: i64,
    pub pid: i64,
    pub guest_result: Option<carrick_runtime::kernel::control::ExecResult>,
    pub transport_failed: bool,
}

const MAX_EXEC_API_INSTANCES: usize = 1_024;
const PENDING_EXEC_API_TTL: std::time::Duration = std::time::Duration::from_secs(15 * 60);
const COMPLETED_EXEC_API_TTL: std::time::Duration = std::time::Duration::from_secs(5 * 60);

#[derive(Debug)]
struct ExecApiEntry {
    config: Option<ExecConfig>,
    state: ExecInstanceState,
    created_at: std::time::Instant,
    completed_at: Option<std::time::Instant>,
}

#[derive(Debug)]
struct ExecApiRegistry {
    entries: HashMap<String, ExecApiEntry>,
    capacity: usize,
    pending_ttl: std::time::Duration,
    completed_ttl: std::time::Duration,
}

impl ExecApiRegistry {
    fn with_limits(
        capacity: usize,
        pending_ttl: std::time::Duration,
        completed_ttl: std::time::Duration,
    ) -> Self {
        Self {
            entries: HashMap::new(),
            capacity: capacity.max(1),
            pending_ttl,
            completed_ttl,
        }
    }

    fn production() -> Self {
        Self::with_limits(
            MAX_EXEC_API_INSTANCES,
            PENDING_EXEC_API_TTL,
            COMPLETED_EXEC_API_TTL,
        )
    }

    fn prune(&mut self, now: std::time::Instant) {
        let pending_ttl = self.pending_ttl;
        let completed_ttl = self.completed_ttl;
        self.entries.retain(|_, entry| {
            entry.state.running
                || entry.completed_at.map_or_else(
                    || now.saturating_duration_since(entry.created_at) < pending_ttl,
                    |completed_at| now.saturating_duration_since(completed_at) < completed_ttl,
                )
        });
    }

    fn insert(
        &mut self,
        id: String,
        config: ExecConfig,
        now: std::time::Instant,
    ) -> Result<(), ()> {
        self.prune(now);
        if self.entries.contains_key(&id) {
            return Err(());
        }
        if self.entries.len() >= self.capacity {
            let oldest_idle = self
                .entries
                .iter()
                .filter(|(_, entry)| !entry.state.running)
                .min_by_key(|(_, entry)| entry.completed_at.unwrap_or(entry.created_at))
                .map(|(id, _)| id.clone());
            if let Some(oldest_idle) = oldest_idle {
                self.entries.remove(&oldest_idle);
            }
        }
        if self.entries.len() >= self.capacity {
            return Err(());
        }
        let container_id = config.container_id.clone();
        self.entries.insert(
            id,
            ExecApiEntry {
                config: Some(config),
                state: ExecInstanceState {
                    container_id,
                    running: false,
                    exit_code: 0,
                    pid: 0,
                    guest_result: None,
                    transport_failed: false,
                },
                created_at: now,
                completed_at: None,
            },
        );
        Ok(())
    }

    fn config(&mut self, id: &str, now: std::time::Instant) -> Option<ExecConfig> {
        self.prune(now);
        self.entries.get(id)?.config.clone()
    }

    fn begin(&mut self, id: &str, now: std::time::Instant) -> Option<ExecConfig> {
        self.prune(now);
        let entry = self.entries.get_mut(id)?;
        let config = entry.config.take()?;
        entry.state.running = true;
        Some(config)
    }

    fn complete_guest(
        &mut self,
        id: &str,
        result: carrick_runtime::kernel::control::ExecResult,
        transport_failed: bool,
        now: std::time::Instant,
    ) -> bool {
        let Some(entry) = self.entries.get_mut(id) else {
            return false;
        };
        entry.state.running = false;
        entry.state.exit_code = i64::from(result.exit_code);
        entry.state.guest_result = Some(result);
        entry.state.transport_failed = transport_failed;
        entry.completed_at = Some(now);
        true
    }

    fn fail_before_guest(&mut self, id: &str, now: std::time::Instant) -> bool {
        let Some(entry) = self.entries.get_mut(id) else {
            return false;
        };
        entry.state.running = false;
        entry.state.exit_code = 1;
        entry.state.guest_result = None;
        entry.state.transport_failed = false;
        entry.completed_at = Some(now);
        true
    }

    fn mark_transport_failed(&mut self, id: &str) -> bool {
        let Some(entry) = self.entries.get_mut(id) else {
            return false;
        };
        if entry.state.guest_result.is_none() {
            return false;
        }
        entry.state.transport_failed = true;
        true
    }

    fn state(&mut self, id: &str, now: std::time::Instant) -> Option<ExecInstanceState> {
        self.prune(now);
        self.entries.get(id).map(|entry| entry.state.clone())
    }

    #[cfg(test)]
    fn contains(&self, id: &str) -> bool {
        self.entries.contains_key(id)
    }
}

static EXEC_API_REGISTRY: OnceLock<Mutex<ExecApiRegistry>> = OnceLock::new();

fn get_exec_registry() -> &'static Mutex<ExecApiRegistry> {
    EXEC_API_REGISTRY.get_or_init(|| Mutex::new(ExecApiRegistry::production()))
}

/// `POST /containers/{id}/exec`: register an exec instance and return its id.
/// The actual execution is deferred until `POST /exec/{id}/start`.
pub(crate) fn create_exec(body: &[u8], container_id: &str) -> (u16, String) {
    let req: ExecCreateBody = match serde_json::from_slice(body) {
        Ok(b) => b,
        Err(e) => return (400, error_json(&format!("invalid body: {e}"))),
    };
    let Some(cmd) = req.cmd else {
        return (400, error_json("no cmd specified"));
    };

    let entropy = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let exec_id = carrick_runtime::container::make_id(std::process::id() as u64, entropy);

    let config = ExecConfig {
        container_id: container_id.to_string(),
        cmd,
        env: req.env.unwrap_or_default(),
        tty: req.tty.unwrap_or(false),
        interactive: req.attach_stdin.unwrap_or(false),
        user: req.user,
        workdir: req.working_dir,
    };

    if get_exec_registry()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(exec_id.clone(), config, std::time::Instant::now())
        .is_err()
    {
        return (503, error_json("exec instance registry is at capacity"));
    }

    let resp = ExecCreateResponse { id: exec_id };
    (
        201,
        serde_json::to_string(&resp).unwrap_or_else(|_| "{}".to_string()),
    )
}

/// `POST /exec/{id}/start`: start a previously-created exec instance. Returns
/// `101 Switching Protocols` for attached mode (bollard requires the upgrade
/// handshake) or `204 No Content` for detached mode.
pub(crate) async fn start_exec_route(
    exec_id: String,
    mut req: hyper::Request<hyper::body::Incoming>,
) -> Response<crate::serve::router::ResponseBody> {
    use http_body_util::BodyExt;
    use hyper::body::Bytes;

    let fallback = || {
        Response::new(
            http_body_util::Full::new(Bytes::new())
                .map_err(|never| match never {})
                .boxed(),
        )
    };

    let config = {
        let mut registry = get_exec_registry()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        match registry.config(&exec_id, std::time::Instant::now()) {
            Some(c) => c,
            None => {
                return Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(
                        http_body_util::Full::new(Bytes::from(error_json("No such exec instance")))
                            .map_err(|never| match never {})
                            .boxed(),
                    )
                    .unwrap_or_else(|_| fallback());
            }
        }
    };

    let first_frame = match req.body_mut().frame().await {
        Some(Ok(f)) => f,
        _ => {
            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(
                    http_body_util::Full::new(Bytes::from(error_json("Empty request body")))
                        .map_err(|never| match never {})
                        .boxed(),
                )
                .unwrap_or_else(|_| fallback());
        }
    };

    let Some(data) = first_frame.data_ref() else {
        return Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(
                http_body_util::Full::new(Bytes::from(error_json("Invalid frame data")))
                    .map_err(|never| match never {})
                    .boxed(),
            )
            .unwrap_or_else(|_| fallback());
    };

    let start_body: ExecStartBody = match serde_json::from_slice(data) {
        Ok(b) => b,
        Err(e) => {
            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(
                    http_body_util::Full::new(Bytes::from(error_json(&format!(
                        "invalid JSON body: {e}"
                    ))))
                    .map_err(|never| match never {})
                    .boxed(),
                )
                .unwrap_or_else(|_| fallback());
        }
    };

    let detach = start_body.detach.unwrap_or(false);

    if config.tty || config.interactive {
        return Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(
                http_body_util::Full::new(Bytes::from(error_json(
                    "interactive/TTY exec is unavailable until carrier-control stdin and TTY framing is implemented",
                )))
                .map_err(|never| match never {})
                .boxed(),
            )
            .unwrap_or_else(|_| fallback());
    }

    let config = {
        let mut registry = get_exec_registry()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        match registry.begin(&exec_id, std::time::Instant::now()) {
            Some(config) => config,
            None => {
                return Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(
                        http_body_util::Full::new(Bytes::from(error_json("No such exec instance")))
                            .map_err(|never| match never {})
                            .boxed(),
                    )
                    .unwrap_or_else(|_| fallback());
            }
        }
    };

    if detach {
        let exec_id_clone = exec_id.clone();
        tokio::spawn(async move {
            match run_exec_detached(config).await {
                Ok(result) => {
                    get_exec_registry()
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .complete_guest(&exec_id_clone, result, false, std::time::Instant::now());
                }
                Err(error) => {
                    tracing::error!(%error, "detached exec failed before guest completion");
                    get_exec_registry()
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .fail_before_guest(&exec_id_clone, std::time::Instant::now());
                }
            }
        });
        return Response::builder()
            .status(StatusCode::NO_CONTENT)
            .body(
                http_body_util::Full::new(Bytes::new())
                    .map_err(|never| match never {})
                    .boxed(),
            )
            .unwrap_or_else(|_| fallback());
    }

    let upgraded = hyper::upgrade::on(&mut req);

    let exec_id_for_state = exec_id.clone();
    tokio::spawn(async move {
        match upgraded.await {
            Ok(upgraded) => {
                let io = hyper_util::rt::TokioIo::new(upgraded);
                match run_exec_attached(config, io, &exec_id_for_state).await {
                    Ok(Some(error)) => {
                        tracing::error!(%error, "guest exec completed but attached transport failed");
                    }
                    Ok(None) => {}
                    Err(error) => {
                        tracing::error!(%error, "attached exec failed before guest completion");
                        get_exec_registry()
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .fail_before_guest(&exec_id_for_state, std::time::Instant::now());
                    }
                }
            }
            Err(e) => {
                tracing::error!("upgrade error: {e}");
                get_exec_registry()
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .fail_before_guest(&exec_id_for_state, std::time::Instant::now());
            }
        }
    });

    Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header("Connection", "Upgrade")
        .header("Upgrade", "tcp")
        .body(
            http_body_util::Full::new(Bytes::new())
                .map_err(|never| match never {})
                .boxed(),
        )
        .unwrap_or_else(|_| fallback())
}

async fn run_exec_detached(
    config: ExecConfig,
) -> anyhow::Result<carrick_runtime::kernel::control::ExecResult> {
    execute_noninteractive_config(config).await
}

async fn run_exec_attached(
    config: ExecConfig,
    mut io: hyper_util::rt::TokioIo<hyper::upgrade::Upgraded>,
    exec_id: &str,
) -> anyhow::Result<Option<anyhow::Error>> {
    let result = execute_noninteractive_config(config).await?;
    get_exec_registry()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .complete_guest(exec_id, result.clone(), false, std::time::Instant::now());
    let transport_error = deliver_exec_result(&mut io, &result).await;
    if transport_error.is_some() {
        get_exec_registry()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .mark_transport_failed(exec_id);
    }
    Ok(transport_error)
}

async fn deliver_exec_result<W>(
    writer: &mut W,
    result: &carrick_runtime::kernel::control::ExecResult,
) -> Option<anyhow::Error>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt as _;

    async {
        write_docker_exec_frame(writer, 1, &result.stdout).await?;
        write_docker_exec_frame(writer, 2, &result.stderr).await?;
        writer.shutdown().await?;
        anyhow::Ok(())
    }
    .await
    .err()
}

async fn execute_noninteractive_config(
    config: ExecConfig,
) -> anyhow::Result<carrick_runtime::kernel::control::ExecResult> {
    if config.tty || config.interactive {
        anyhow::bail!(
            "interactive/TTY Docker exec is unavailable until carrier-control stdin and TTY framing is implemented"
        );
    }
    tokio::task::spawn_blocking(move || {
        let state = carrick_runtime::container::ContainerState::load(&config.container_id)?;
        if state.status != carrick_runtime::container::ContainerStatus::Running {
            anyhow::bail!("container is not running");
        }
        let request = crate::lifecycle::build_control_exec_request(
            &state,
            config.cmd,
            config.user,
            config.workdir,
            config.env,
        )?;
        crate::lifecycle::run_control_exec_capture(&config.container_id, &state, request)
    })
    .await
    .map_err(|error| anyhow::anyhow!("logical exec worker failed: {error}"))?
}

async fn write_docker_exec_frame<W>(writer: &mut W, stream: u8, bytes: &[u8]) -> anyhow::Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt as _;

    if bytes.is_empty() {
        return Ok(());
    }
    let length = u32::try_from(bytes.len()).map_err(|_| anyhow::anyhow!("exec frame too large"))?;
    let mut header = [0_u8; 8];
    header[0] = stream;
    header[4..].copy_from_slice(&length.to_be_bytes());
    writer.write_all(&header).await?;
    writer.write_all(bytes).await?;
    Ok(())
}

#[cfg(test)]
mod exec_control_tests {
    use super::{ExecApiRegistry, ExecConfig, deliver_exec_result, write_docker_exec_frame};

    fn config() -> ExecConfig {
        ExecConfig {
            container_id: "container".to_owned(),
            cmd: vec!["/bin/true".to_owned()],
            env: Vec::new(),
            tty: false,
            interactive: false,
            user: None,
            workdir: None,
        }
    }

    #[test]
    fn noninteractive_api_output_uses_docker_multiplex_framing() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        runtime.block_on(async {
            let (mut writer, mut reader) = tokio::io::duplex(64);
            write_docker_exec_frame(&mut writer, 1, b"abc")
                .await
                .expect("stdout frame");
            writer.shutdown().await.expect("shutdown");
            let mut bytes = Vec::new();
            reader.read_to_end(&mut bytes).await.expect("read frame");
            assert_eq!(bytes, [1, 0, 0, 0, 0, 0, 0, 3, b'a', b'b', b'c']);
        });
    }

    #[test]
    fn transport_failure_preserves_the_exact_guest_result() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        runtime.block_on(async {
            let result = carrick_runtime::kernel::control::ExecResult {
                exit_code: 42,
                terminating_signal: None,
                stdout: b"output".to_vec(),
                stderr: Vec::new(),
                output_truncated: false,
            };
            let (mut writer, reader) = tokio::io::duplex(1);
            drop(reader);
            let mut registry = ExecApiRegistry::with_limits(
                1,
                std::time::Duration::from_secs(10),
                std::time::Duration::from_secs(10),
            );
            let now = std::time::Instant::now();
            registry
                .insert("exec".to_owned(), config(), now)
                .expect("instance");
            assert!(registry.begin("exec", now).is_some());
            assert!(registry.complete_guest("exec", result.clone(), false, now));
            let transport_error = deliver_exec_result(&mut writer, &result).await;
            assert!(transport_error.is_some());
            assert!(registry.mark_transport_failed("exec"));
            let state = registry.state("exec", now).expect("persisted result");
            assert_eq!(state.guest_result, Some(result));
            assert_eq!(state.exit_code, 42);
            assert!(state.transport_failed);
        });
    }

    #[test]
    fn exec_api_registry_is_hard_capped_and_expires_abandoned_entries() {
        let now = std::time::Instant::now();
        let mut registry = ExecApiRegistry::with_limits(
            2,
            std::time::Duration::from_secs(10),
            std::time::Duration::from_secs(5),
        );
        registry
            .insert("running".to_owned(), config(), now)
            .expect("first");
        assert!(registry.begin("running", now).is_some());
        registry
            .insert("abandoned".to_owned(), config(), now)
            .expect("second");
        registry
            .insert(
                "replacement".to_owned(),
                config(),
                now + std::time::Duration::from_secs(1),
            )
            .expect("evict oldest idle entry");
        assert!(!registry.contains("abandoned"));
        assert!(registry.begin("replacement", now).is_some());
        assert!(
            registry
                .insert("overflow".to_owned(), config(), now)
                .is_err(),
            "running entries must not be evicted to admit unbounded instances",
        );

        let result = carrick_runtime::kernel::control::ExecResult {
            exit_code: 7,
            terminating_signal: None,
            stdout: Vec::new(),
            stderr: Vec::new(),
            output_truncated: false,
        };
        assert!(registry.complete_guest("running", result.clone(), false, now));
        let state = registry.state("running", now).expect("completed state");
        assert_eq!(state.guest_result, Some(result));
        assert_eq!(state.exit_code, 7);
        assert!(!state.transport_failed);
        assert!(registry.mark_transport_failed("running"));
        let state = registry.state("running", now).expect("transport state");
        assert_eq!(state.exit_code, 7);
        assert_eq!(
            state.guest_result.as_ref().map(|result| result.exit_code),
            Some(7)
        );
        assert!(state.transport_failed);
        registry.prune(now + std::time::Duration::from_secs(6));
        assert!(!registry.contains("running"));
        assert!(registry.contains("replacement"));
    }
}

#[cfg(test)]
mod archive_control_tests {
    use base64::Engine as _;

    use super::{archive_control_target, decode_archive_query_path, docker_archive_stat_header};

    #[test]
    fn archive_query_path_is_percent_decoded_and_rejects_malformed_or_traversing_input() {
        assert_eq!(
            decode_archive_query_path("path=%2Fvar%2Flib%2Fapp").as_deref(),
            Ok("/var/lib/app")
        );
        assert_eq!(
            decode_archive_query_path("path=%2Fvar%2Flib%2Fmy+app").as_deref(),
            Ok("/var/lib/my app")
        );
        assert!(decode_archive_query_path("path=/var/../etc").is_err());
        assert!(decode_archive_query_path("path=%2Ftmp%2Gbad").is_err());
        assert!(decode_archive_query_path("missing=value").is_err());
    }

    #[test]
    fn stopped_archive_fails_closed_after_the_exact_lifecycle_lock() {
        let id = carrick_runtime::container::make_id(
            u64::from(std::process::id()),
            0x0061_7263_6869_7665,
        );
        let state = carrick_runtime::container::ContainerState {
            id: id.clone(),
            name: None,
            image: "archive-stopped-test".to_owned(),
            command: Vec::new(),
            status: carrick_runtime::container::ContainerStatus::Exited,
            supervisor_pid: 0,
            init_pid: 0,
            created_secs: 0,
            exit_code: Some(0),
            auto_remove: false,
            api_auto_remove: false,
            labels: std::collections::HashMap::new(),
            control: None,
            terminal_control: None,
            launch_ticket: None,
            config: carrick_runtime::container::RunConfig::default(),
        };
        std::fs::create_dir_all(carrick_runtime::container::container_dir(&id))
            .expect("create test container directory");
        state.persist().expect("persist stopped state");
        let held = carrick_runtime::container::lock_lifecycle(&id).expect("hold lifecycle lock");
        let thread_id = id.clone();
        let (finished_tx, finished_rx) = std::sync::mpsc::sync_channel(1);
        let join = std::thread::spawn(move || {
            let result = archive_control_target(&thread_id);
            finished_tx.send(result).expect("report archive result");
        });
        assert!(
            finished_rx
                .recv_timeout(std::time::Duration::from_millis(50))
                .is_err(),
            "stopped-state classification must serialize with start/remove"
        );
        drop(held);
        let error = finished_rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .expect("archive classification resumed")
            .expect_err("stopped archive must fail closed");
        assert_eq!(error.status, hyper::StatusCode::CONFLICT);
        assert!(error.message.contains("does not authenticate"));
        join.join().expect("archive thread");
        carrick_runtime::container::ContainerState::remove(&id).expect("remove test state");
    }

    #[test]
    fn docker_archive_stat_header_carries_exact_carrier_metadata() {
        let encoded =
            docker_archive_stat_header(&carrick_runtime::kernel::control::ArchiveMetadata {
                name: "payload".to_owned(),
                size: 7,
                mode: 0o100640,
                mtime_secs: 56,
                mtime_nanos: 123,
                link_target: None,
            })
            .expect("stat header");
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .expect("base64");
        let json: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        assert_eq!(json["name"], "payload");
        assert_eq!(json["size"], 7);
        assert_eq!(json["mode"], 0o100640);
        assert_eq!(json["mtime"], "1970-01-01T00:00:56.000000123Z");
        assert_eq!(json["linkTarget"], "");
    }
}

/// `GET /exec/{id}/json`: return the exec instance's running state and exit code.
pub(crate) fn inspect_exec(exec_id: &str) -> (u16, String) {
    if let Some(state) = get_exec_registry()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .state(exec_id, std::time::Instant::now())
    {
        let resp = ExecInspectResponse {
            id: exec_id.to_string(),
            running: state.running,
            exit_code: state.exit_code,
            container_id: state.container_id.clone(),
            pid: state.pid,
        };
        return (
            200,
            serde_json::to_string(&resp).unwrap_or_else(|_| "{}".to_string()),
        );
    }
    (404, error_json("No such exec instance"))
}

/// `GET /images/{name}/json`: inspect an image by name, tag, or id.
pub(crate) fn inspect_image(spec: &str) -> (u16, String) {
    let store = carrick_image::ImageStore::default_for_user();
    // Try as an ImageReference first, then as an id prefix.
    let info = if let Ok(image_ref) = carrick_image::ImageReference::parse(spec) {
        store.list_images().into_iter().find(|i| {
            let tag = format!("{}:{}", i.repository, i.tag);
            let canonical = image_ref.canonical();
            tag == spec || canonical.ends_with(&tag) || format!("sha256:{}", i.id) == spec
        })
    } else {
        store
            .list_images()
            .into_iter()
            .find(|i| i.id.starts_with(spec))
    };
    match info {
        Some(i) => {
            let resp = ImageInspectResponse {
                id: format!("sha256:{}", i.id),
                repo_tags: vec![format!("{}:{}", i.repository, i.tag)],
                created: chrono::DateTime::from_timestamp(i.created_secs as i64, 0)
                    .map(|dt| dt.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true))
                    .unwrap_or_default(),
                size: i.size as i64,
                virtual_size: i.size as i64,
                os: "linux".to_string(),
                architecture: "arm64".to_string(),
            };
            (
                200,
                serde_json::to_string(&resp).unwrap_or_else(|_| "{}".to_string()),
            )
        }
        None => (404, error_json(&format!("No such image: {spec}"))),
    }
}

/// `POST /images/{name}/tag`: create a new tag for an existing image.
pub(crate) fn tag_image(source_name: &str, repo: &str, tag: &str) -> (u16, String) {
    let store = carrick_image::ImageStore::default_for_user();
    let src = match carrick_image::ImageReference::parse(source_name) {
        Ok(r) => r,
        Err(e) => {
            return (
                404,
                error_json(&format!("No such image: {source_name}: {e}")),
            );
        }
    };
    let dst_ref = if tag.is_empty() {
        format!("{repo}:latest")
    } else {
        format!("{repo}:{tag}")
    };
    let dst = match carrick_image::ImageReference::parse(&dst_ref) {
        Ok(r) => r,
        Err(e) => return (400, error_json(&format!("invalid target reference: {e}"))),
    };
    match store.tag_image(&src, &dst) {
        Ok(()) => (201, String::new()),
        Err(e) => (500, error_json(&e.to_string())),
    }
}

/// `POST /containers/{id}/rename?name=new_name`: rename a container.
pub(crate) fn rename_container(id: &str, new_name: &str) -> (u16, String) {
    let real = match carrick_runtime::container::resolve(id) {
        Ok(r) => r,
        Err(e) => return (404, error_json(&e)),
    };
    let _lifecycle_lock = match carrick_runtime::container::lock_lifecycle(&real) {
        Ok(lock) => lock,
        Err(e) => return (500, error_json(&e.to_string())),
    };
    let _name_lock = match carrick_runtime::container::lock_name_registry() {
        Ok(lock) => lock,
        Err(e) => return (500, error_json(&e.to_string())),
    };
    if let Ok(owner) = carrick_runtime::container::resolve(new_name)
        && owner != real
    {
        return (409, error_json("container name is already in use"));
    }
    let mut state = match carrick_runtime::container::ContainerState::load(&real) {
        Ok(s) => s,
        Err(e) => return (500, error_json(&e.to_string())),
    };
    state.name = Some(new_name.to_string());
    match state.persist() {
        Ok(()) => (204, String::new()),
        Err(e) => (500, error_json(&e.to_string())),
    }
}

/// `GET /containers/{id}/top`: list processes running inside the container.
/// Runs `ps -eo pid,user,comm` in the container via `carrick exec`.
pub(crate) fn top_container(id: &str) -> (u16, String) {
    let real = match carrick_runtime::container::resolve(id) {
        Ok(r) => r,
        Err(e) => return (404, error_json(&e)),
    };
    let state = match carrick_runtime::container::ContainerState::load(&real) {
        Ok(s) => s,
        Err(e) => return (500, error_json(&e.to_string())),
    };
    if !state.init_alive() {
        return (409, error_json(&format!("Container {id} is not running")));
    }
    let snapshot = match carrick_runtime::kernel::debug::fetch(
        &real,
        Some(vec![carrick_runtime::kernel::debug::KernelDebugTable::Task]),
    ) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            return (
                503,
                error_json(&format!(
                    "container process snapshot is unavailable from carrier control: {error}"
                )),
            );
        }
    };
    let processes = snapshot
        .tasks
        .unwrap_or_default()
        .into_iter()
        .map(|task| {
            vec![
                task.key.id.to_string(),
                "-".to_owned(),
                task.diagnostic_name.unwrap_or(task.lifecycle),
            ]
        })
        .collect();
    let response = TopResponse {
        titles: vec!["PID".to_owned(), "USER".to_owned(), "COMMAND".to_owned()],
        processes,
    };
    (
        200,
        serde_json::to_string(&response).unwrap_or_else(|_| "{}".to_owned()),
    )
}

#[cfg(test)]
mod lifecycle_transaction_tests {
    use super::*;

    fn created_state(id: &str, name: &str) -> carrick_runtime::container::ContainerState {
        let mut state: carrick_runtime::container::ContainerState = serde_json::from_str(
            r#"{"id":"placeholder","name":null,"image":"img","command":[],
                "status":"created","supervisor_pid":0,"init_pid":0,"created_secs":0,
                "exit_code":null,"auto_remove":false}"#,
        )
        .expect("state fixture");
        state.id = id.to_owned();
        state.name = Some(name.to_owned());
        state
    }

    #[test]
    fn rename_rechecks_name_claim_and_release_atomically() {
        let suffix = std::process::id();
        let first_id = format!("rename-first-{suffix}");
        let second_id = format!("rename-second-{suffix}");
        let first_name = format!("rename-owned-{suffix}");
        let second_name = format!("rename-other-{suffix}");
        let _ = carrick_runtime::container::ContainerState::remove(&first_id);
        let _ = carrick_runtime::container::ContainerState::remove(&second_id);
        created_state(&first_id, &first_name)
            .create()
            .expect("first state");
        created_state(&second_id, &second_name)
            .create()
            .expect("second state");

        assert_eq!(rename_container(&second_id, &first_name).0, 409);
        assert_eq!(
            carrick_runtime::container::ContainerState::load(&second_id)
                .expect("preserved second")
                .name
                .as_deref(),
            Some(second_name.as_str())
        );

        carrick_runtime::container::ContainerState::remove(&first_id).expect("release first name");
        assert_eq!(rename_container(&second_id, &first_name).0, 204);
        assert_eq!(
            carrick_runtime::container::ContainerState::load(&second_id)
                .expect("renamed second")
                .name
                .as_deref(),
            Some(first_name.as_str())
        );
        let _ = carrick_runtime::container::ContainerState::remove(&second_id);
    }

    #[test]
    fn api_auto_remove_requires_the_exact_terminal_incarnation() {
        let id = format!("api-auto-remove-exact-{}", std::process::id());
        let _ = carrick_runtime::container::ContainerState::remove(&id);
        let expected = carrick_runtime::container::CarrierControlState {
            schema: carrick_runtime::kernel::control::CARRIER_CONTROL_STATE_SCHEMA.to_owned(),
            owner_nonce: carrick_runtime::kernel::control::ControlNonce::fresh().expect("nonce"),
            init: carrick_runtime::kernel::control::ControlTaskKey { pid: 1, serial: 8 },
        };
        let stale = carrick_runtime::container::CarrierControlState {
            schema: carrick_runtime::kernel::control::CARRIER_CONTROL_STATE_SCHEMA.to_owned(),
            owner_nonce: carrick_runtime::kernel::control::ControlNonce::fresh().expect("nonce"),
            init: carrick_runtime::kernel::control::ControlTaskKey { pid: 1, serial: 7 },
        };
        let mut state = created_state(&id, "api-auto-remove");
        state.status = carrick_runtime::container::ContainerStatus::Exited;
        state.exit_code = Some(23);
        state.api_auto_remove = true;
        state.terminal_control = Some(expected.clone());
        state.create().expect("terminal state");

        assert!(!cleanup_api_auto_remove(&id, &stale).expect("stale cleanup rejected"));
        assert!(carrick_runtime::container::ContainerState::load(&id).is_ok());
        assert!(cleanup_api_auto_remove(&id, &expected).expect("exact cleanup"));
        assert_eq!(
            carrick_runtime::container::ContainerState::load(&id)
                .expect_err("exact cleanup removed state")
                .kind(),
            std::io::ErrorKind::NotFound
        );
    }
}
