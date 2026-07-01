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
    };
    match crate::serve::spawn::create_container(&image, &cmd, &opts) {
        // `id` is the 64-hex container id `carrick create` generated; the Docker
        // `Id` is always that id, not the (optional) name.
        Ok(id) => {
            if let Err(e) = persist_api_container_metadata(
                &id,
                &network.attachments,
                network.network_container.as_deref(),
                &labels,
                api_auto_remove,
            ) {
                return (500, error_json(&e.to_string()));
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
            attachments: Vec::new(),
            network_container: None,
        }),
        Some("host") if !has_endpoint => Ok(CreateNetworkSelection {
            cli_mode: Some("host".to_string()),
            attachments: Vec::new(),
            network_container: None,
        }),
        Some("host") | Some("bridge") if has_endpoint => Ok(CreateNetworkSelection {
            cli_mode: Some("bridge".to_string()),
            attachments: endpoint_attachments,
            network_container: None,
        }),
        Some("bridge") => Ok(CreateNetworkSelection {
            cli_mode: Some("bridge".to_string()),
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
                attachments,
                network_container: None,
            })
        }
        _ if has_endpoint => Ok(CreateNetworkSelection {
            cli_mode: Some("bridge".to_string()),
            attachments: endpoint_attachments,
            network_container: None,
        }),
        _ if has_published_ports => Ok(CreateNetworkSelection {
            cli_mode: Some("bridge".to_string()),
            attachments: Vec::new(),
            network_container: None,
        }),
        _ => Ok(CreateNetworkSelection {
            cli_mode: None,
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

fn persist_api_container_metadata(
    id: &str,
    attachments: &[carrick_runtime::container::NetworkAttachment],
    network_container: Option<&str>,
    labels: &HashMap<String, String>,
    api_auto_remove: bool,
) -> anyhow::Result<()> {
    if attachments.is_empty()
        && network_container.is_none()
        && labels.is_empty()
        && !api_auto_remove
    {
        return Ok(());
    }
    let mut state = carrick_runtime::container::ContainerState::load(id)?;
    if !attachments.is_empty() {
        state.config.network_attachments = attachments.to_vec();
    }
    if let Some(target) = network_container {
        state.config.network_container = Some(target.to_string());
    }
    if !labels.is_empty() {
        state.labels = labels.clone();
    }
    state.api_auto_remove = api_auto_remove;
    state.persist()?;
    if !attachments.is_empty() {
        crate::serve::resources::attach_container_to_networks(&state)?;
    }
    Ok(())
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
    let (tx, rx) = mpsc::channel::<Result<Frame<Bytes>, std::io::Error>>(1);
    tokio::task::spawn_blocking(move || {
        let (_status, body) = wait_container(&real_id);
        if state_for_cleanup
            .as_ref()
            .is_some_and(|state| state.api_auto_remove)
            && let Some(state) = state_for_cleanup.as_ref()
        {
            std::thread::sleep(std::time::Duration::from_millis(300));
            crate::serve::resources::detach_container_from_all_networks(state);
            let _ = carrick_runtime::container::ContainerState::remove(&real_id);
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
    let Some(raw_path) = crate::serve::router::query_param(&query, "path") else {
        return Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .header("Content-Type", "application/json")
            .body(
                http_body_util::Full::new(Bytes::from(error_json("archive path is required")))
                    .map_err(|never| match never {})
                    .boxed(),
            )
            .unwrap_or_else(|_| fallback());
    };
    let guest_path = crate::serve::build::url_decode(&raw_path);
    let Some((parent, entry)) = archive_path_args(&guest_path) else {
        return Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .header("Content-Type", "application/json")
            .body(
                http_body_util::Full::new(Bytes::from(error_json("invalid archive path")))
                    .map_err(|never| match never {})
                    .boxed(),
            )
            .unwrap_or_else(|_| fallback());
    };

    let entry_for_tar = entry.clone();
    let output = tokio::task::spawn_blocking(move || {
        wait_until_running_for_archive(&real_id, std::time::Duration::from_secs(10))?;
        let exe = std::env::current_exe()?;
        let out = std::process::Command::new(exe)
            .arg("exec")
            .arg(&real_id)
            .arg("/usr/bin/tar")
            .arg("-C")
            .arg(parent)
            .arg("-cf")
            .arg("-")
            .arg(&entry_for_tar)
            .output()?;
        anyhow::Ok(out)
    })
    .await;
    let output = match output {
        Ok(Ok(output)) => output,
        Ok(Err(e)) => {
            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .header("Content-Type", "application/json")
                .body(
                    http_body_util::Full::new(Bytes::from(error_json(&e.to_string())))
                        .map_err(|never| match never {})
                        .boxed(),
                )
                .unwrap_or_else(|_| fallback());
        }
        Err(e) => {
            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .header("Content-Type", "application/json")
                .body(
                    http_body_util::Full::new(Bytes::from(error_json(&e.to_string())))
                        .map_err(|never| match never {})
                        .boxed(),
                )
                .unwrap_or_else(|_| fallback());
        }
    };
    if !output.status.success() {
        return Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header("Content-Type", "application/json")
            .body(
                http_body_util::Full::new(Bytes::from(error_json(&String::from_utf8_lossy(
                    &output.stderr,
                ))))
                .map_err(|never| match never {})
                .boxed(),
            )
            .unwrap_or_else(|_| fallback());
    }
    let stat_header = archive_stat_header(&entry, &output.stdout);

    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/x-tar")
        .header("X-Docker-Container-Path-Stat", stat_header)
        .body(
            http_body_util::Full::new(Bytes::from(output.stdout))
                .map_err(|never| match never {})
                .boxed(),
        )
        .unwrap_or_else(|_| fallback())
}

pub(crate) async fn upload_archive_route(
    id: String,
    query: String,
    body_bytes: Bytes,
) -> Response<crate::serve::router::ResponseBody> {
    use http_body_util::BodyExt;

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
    let Some(raw_path) = crate::serve::router::query_param(&query, "path") else {
        return Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .header("Content-Type", "application/json")
            .body(
                http_body_util::Full::new(Bytes::from(error_json("archive path is required")))
                    .map_err(|never| match never {})
                    .boxed(),
            )
            .unwrap_or_else(|_| fallback());
    };
    let guest_path = crate::serve::build::url_decode(&raw_path);
    if guest_path.is_empty() {
        return Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .header("Content-Type", "application/json")
            .body(
                http_body_util::Full::new(Bytes::from(error_json("invalid archive path")))
                    .map_err(|never| match never {})
                    .boxed(),
            )
            .unwrap_or_else(|_| fallback());
    }

    let result = tokio::task::spawn_blocking(move || {
        use std::io::Write;
        use std::process::Stdio;

        wait_until_running_for_archive(&real_id, std::time::Duration::from_secs(10))?;
        let exe = std::env::current_exe()?;
        let mut child = std::process::Command::new(exe)
            .arg("exec")
            .arg(&real_id)
            .arg("-i")
            .arg("/usr/bin/tar")
            .arg("-C")
            .arg(&guest_path)
            .arg("-xf")
            .arg("-")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        if let Some(stdin) = child.stdin.as_mut() {
            stdin.write_all(&body_bytes)?;
        }
        let out = child.wait_with_output()?;
        anyhow::Ok(out)
    })
    .await;
    let output = match result {
        Ok(Ok(output)) => output,
        Ok(Err(e)) => {
            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .header("Content-Type", "application/json")
                .body(
                    http_body_util::Full::new(Bytes::from(error_json(&e.to_string())))
                        .map_err(|never| match never {})
                        .boxed(),
                )
                .unwrap_or_else(|_| fallback());
        }
        Err(e) => {
            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .header("Content-Type", "application/json")
                .body(
                    http_body_util::Full::new(Bytes::from(error_json(&e.to_string())))
                        .map_err(|never| match never {})
                        .boxed(),
                )
                .unwrap_or_else(|_| fallback());
        }
    };
    if !output.status.success() {
        return Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .header("Content-Type", "application/json")
            .body(
                http_body_util::Full::new(Bytes::from(error_json(&String::from_utf8_lossy(
                    &output.stderr,
                ))))
                .map_err(|never| match never {})
                .boxed(),
            )
            .unwrap_or_else(|_| fallback());
    }

    Response::builder()
        .status(StatusCode::OK)
        .body(
            http_body_util::Full::new(Bytes::new())
                .map_err(|never| match never {})
                .boxed(),
        )
        .unwrap_or_else(|_| fallback())
}

fn wait_until_running_for_archive(id: &str, timeout: std::time::Duration) -> anyhow::Result<()> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        match carrick_runtime::container::ContainerState::load(id) {
            Ok(state) => {
                if carrick_runtime::container::reconciled_status(&state)
                    == carrick_runtime::container::ContainerStatus::Running
                {
                    return Ok(());
                }
            }
            Err(e) => anyhow::bail!(e),
        }
        if std::time::Instant::now() >= deadline {
            anyhow::bail!(
                "container {} is not running",
                carrick_runtime::container::short_id(id)
            );
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

fn archive_stat_header(entry: &str, tar_bytes: &[u8]) -> String {
    use base64::Engine as _;

    let name = tar_header_name(tar_bytes).unwrap_or_else(|| entry.to_string());
    let size = tar_header_octal(tar_bytes, 124, 12).unwrap_or(0);
    let mode = tar_header_octal(tar_bytes, 100, 8).unwrap_or(0o644);
    let stat = serde_json::json!({
        "name": name,
        "size": size,
        "mode": mode,
        "mtime": "1970-01-01T00:00:00Z",
        "linkTarget": "",
    });
    base64::engine::general_purpose::STANDARD.encode(stat.to_string())
}

fn tar_header_name(tar_bytes: &[u8]) -> Option<String> {
    let header = tar_bytes.get(..100)?;
    let end = header.iter().position(|b| *b == 0).unwrap_or(header.len());
    if end == 0 {
        return None;
    }
    Some(String::from_utf8_lossy(&header[..end]).into_owned())
}

fn tar_header_octal(tar_bytes: &[u8], offset: usize, len: usize) -> Option<u64> {
    let field = tar_bytes.get(offset..offset.checked_add(len)?)?;
    let text = String::from_utf8_lossy(field);
    let trimmed = text.trim_matches(char::from(0)).trim();
    if trimmed.is_empty() {
        return None;
    }
    u64::from_str_radix(trimmed, 8).ok()
}

fn archive_path_args(path: &str) -> Option<(String, String)> {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        return None;
    }
    if trimmed == "/" {
        return Some(("/".to_string(), ".".to_string()));
    }
    match trimmed.rsplit_once('/') {
        Some(("", entry)) if !entry.is_empty() => Some(("/".to_string(), entry.to_string())),
        Some((parent, entry)) if !parent.is_empty() && !entry.is_empty() => {
            Some((parent.to_string(), entry.to_string()))
        }
        None => Some((".".to_string(), trimmed.to_string())),
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
    use hyper::body::Frame;
    use tokio::io::{AsyncBufReadExt, BufReader};

    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            let msg = format!("failed to resolve carrick binary: {e}");
            let _ = tx
                .send(Ok(Frame::data(Bytes::from(
                    serde_json::json!({ "error": msg }).to_string() + "\n",
                ))))
                .await;
            return;
        }
    };

    let mut cmd = tokio::process::Command::new(exe);
    cmd.arg("pull").arg(&image_ref);
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());
    cmd.stdin(std::process::Stdio::null());

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            let msg = format!("failed to spawn carrick pull: {e}");
            let _ = tx
                .send(Ok(Frame::data(Bytes::from(
                    serde_json::json!({ "error": msg }).to_string() + "\n",
                ))))
                .await;
            return;
        }
    };

    let stdout = child.stdout.take();
    let stderr = child.stderr.take();

    let tx_clone = tx.clone();
    let stdout_handle = tokio::spawn(async move {
        if let Some(out) = stdout {
            let mut lines = BufReader::new(out).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let frame = serde_json::json!({ "status": format!("{line}\n") }).to_string() + "\n";
                if tx_clone
                    .send(Ok(Frame::data(Bytes::from(frame))))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        }
    });

    let tx_clone2 = tx.clone();
    let stderr_handle = tokio::spawn(async move {
        if let Some(err) = stderr {
            let mut lines = BufReader::new(err).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let frame = serde_json::json!({ "status": format!("{line}\n") }).to_string() + "\n";
                if tx_clone2
                    .send(Ok(Frame::data(Bytes::from(frame))))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        }
    });

    let _ = tokio::join!(stdout_handle, stderr_handle);
    match child.wait().await {
        Ok(status) if !status.success() => {
            let msg = format!("pull failed (carrick pull exited with {status})");
            let frame = serde_json::json!({ "error": msg }).to_string() + "\n";
            let _ = tx.send(Ok(Frame::data(Bytes::from(frame)))).await;
        }
        _ => {}
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ExecConfig {
    pub container_id: String,
    pub cmd: Vec<String>,
    pub env: Vec<String>,
    pub tty: bool,
    pub interactive: bool,
    pub user: Option<String>,
    pub workdir: Option<String>,
}

static EXEC_REGISTRY: OnceLock<Mutex<HashMap<String, ExecConfig>>> = OnceLock::new();

fn get_exec_registry() -> &'static Mutex<HashMap<String, ExecConfig>> {
    EXEC_REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

#[derive(Clone, Debug)]
pub(crate) struct ExecInstanceState {
    pub container_id: String,
    pub running: bool,
    pub exit_code: i64,
    pub pid: i64,
}

static EXEC_INSTANCE_STATE: OnceLock<Mutex<HashMap<String, ExecInstanceState>>> = OnceLock::new();

fn get_exec_state() -> &'static Mutex<HashMap<String, ExecInstanceState>> {
    EXEC_INSTANCE_STATE.get_or_init(|| Mutex::new(HashMap::new()))
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

    get_exec_registry()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(exec_id.clone(), config);

    get_exec_state()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(
            exec_id.clone(),
            ExecInstanceState {
                container_id: container_id.to_string(),
                running: false,
                exit_code: 0,
                pid: 0,
            },
        );

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
        match registry.remove(&exec_id) {
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

    if detach {
        let exec_id_clone = exec_id.clone();
        tokio::spawn(async move {
            get_exec_state()
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .entry(exec_id_clone.clone())
                .and_modify(|s| s.running = true);
            let result = run_exec_detached(config).await;
            let code = if result.is_ok() { 0 } else { 1 };
            get_exec_state()
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .entry(exec_id_clone)
                .and_modify(|s| {
                    s.running = false;
                    s.exit_code = code;
                });
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
        get_exec_state()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(exec_id_for_state.clone())
            .and_modify(|s| s.running = true);
        match upgraded.await {
            Ok(upgraded) => {
                let io = hyper_util::rt::TokioIo::new(upgraded);
                let result = run_exec_attached(config, io).await;
                if let Err(e) = &result {
                    tracing::error!("exec attached error: {e}");
                }
                let code = if result.is_ok() { 0 } else { 1 };
                get_exec_state()
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .entry(exec_id_for_state)
                    .and_modify(|s| {
                        s.running = false;
                        s.exit_code = code;
                    });
            }
            Err(e) => {
                tracing::error!("upgrade error: {e}");
                get_exec_state()
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .entry(exec_id_for_state)
                    .and_modify(|s| {
                        s.running = false;
                        s.exit_code = 1;
                    });
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

async fn run_exec_detached(config: ExecConfig) -> anyhow::Result<()> {
    // nosemgrep: rust.lang.security.args.command-injection -- the server spawns
    // itself (current_exe) with operator-controlled API inputs as separate argv
    // entries, never a shell; a CLI that re-execs itself is expected here.
    let exe = std::env::current_exe()?;
    let mut cmd = tokio::process::Command::new(exe);
    cmd.arg("exec");
    if config.tty {
        cmd.arg("-t");
    }
    if config.interactive {
        cmd.arg("-i");
    }
    if let Some(u) = &config.user {
        cmd.arg("-u").arg(u);
    }
    if let Some(w) = &config.workdir {
        cmd.arg("-w").arg(w);
    }
    for e in &config.env {
        cmd.arg("-e").arg(e);
    }
    cmd.arg(&config.container_id);
    for arg in &config.cmd {
        cmd.arg(arg);
    }
    cmd.stdout(std::process::Stdio::null());
    cmd.stderr(std::process::Stdio::null());
    cmd.stdin(std::process::Stdio::null());

    let mut child = cmd.spawn()?;
    child.wait().await?;
    Ok(())
}

async fn run_exec_attached(
    config: ExecConfig,
    io: hyper_util::rt::TokioIo<hyper::upgrade::Upgraded>,
) -> anyhow::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // nosemgrep: rust.lang.security.args.command-injection -- the server spawns
    // itself (current_exe) with operator-controlled API inputs as separate argv
    // entries, never a shell; a CLI that re-execs itself is expected here.
    let exe = std::env::current_exe()?;

    let mut cmd = tokio::process::Command::new(exe);
    cmd.arg("exec");
    if config.tty {
        cmd.arg("-t");
    }
    if config.interactive {
        cmd.arg("-i");
    }
    if let Some(u) = &config.user {
        cmd.arg("-u").arg(u);
    }
    if let Some(w) = &config.workdir {
        cmd.arg("-w").arg(w);
    }
    for e in &config.env {
        cmd.arg("-e").arg(e);
    }
    cmd.arg(&config.container_id);
    for arg in &config.cmd {
        cmd.arg(arg);
    }

    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());
    if config.interactive {
        cmd.stdin(std::process::Stdio::piped());
    } else {
        cmd.stdin(std::process::Stdio::null());
    }

    let (mut client_read, mut client_write) = tokio::io::split(io);
    let (tx_write, mut rx_write) = mpsc::channel::<Bytes>(64);

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            let msg = format!("failed to spawn carrick exec: {e}");
            let framed = frame_stream_data(msg.as_bytes(), 1, config.tty);
            let _ = client_write.write_all(&framed).await;
            return Err(e.into());
        }
    };

    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow::anyhow!("stdout not piped"))?;
    let mut stderr = child
        .stderr
        .take()
        .ok_or_else(|| anyhow::anyhow!("stderr not piped"))?;
    let stdin = child.stdin.take();

    let write_handle = tokio::spawn(async move {
        while let Some(data) = rx_write.recv().await {
            if client_write.write_all(&data).await.is_err() {
                break;
            }
        }
    });

    let stdin_handle = tokio::spawn(async move {
        if let Some(mut sin) = stdin {
            let mut buf = [0u8; 4096];
            loop {
                match client_read.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        if sin.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                        if sin.flush().await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        }
    });

    let tx_stdout = tx_write.clone();
    let tty = config.tty;
    let stdout_handle = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        loop {
            match stdout.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    let framed = frame_stream_data(&buf[..n], 1, tty);
                    if tx_stdout.send(framed).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    let tx_stderr = tx_write.clone();
    let stderr_handle = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        loop {
            match stderr.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    let framed = frame_stream_data(&buf[..n], 2, tty);
                    if tx_stderr.send(framed).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    drop(tx_write);

    let _ = tokio::join!(stdin_handle, stdout_handle, stderr_handle, write_handle);
    let _ = child.wait().await;
    Ok(())
}

/// `GET /exec/{id}/json`: return the exec instance's running state and exit code.
pub(crate) fn inspect_exec(exec_id: &str) -> (u16, String) {
    // Check state registry first (exec has been started or completed).
    if let Some(state) = get_exec_state()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(exec_id)
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
    // Check config registry (exec created but not yet started).
    if let Some(config) = get_exec_registry()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(exec_id)
    {
        let resp = ExecInspectResponse {
            id: exec_id.to_string(),
            running: false,
            exit_code: 0,
            container_id: config.container_id.clone(),
            pid: 0,
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
    // Shell out to `carrick exec` to get the process list.
    // nosemgrep: rust.lang.security.args.command-injection -- the server spawns
    // itself (current_exe) with operator-controlled API inputs as separate argv
    // entries, never a shell; a CLI that re-execs itself is expected here.
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => return (500, error_json(&e.to_string())),
    };
    let output = std::process::Command::new(exe)
        .arg("exec")
        .arg(&real)
        .arg("ps")
        .arg("-eo")
        .arg("pid,user,comm")
        .output();
    match output {
        Ok(out) if out.status.success() => {
            let text = String::from_utf8_lossy(&out.stdout);
            let mut lines = text.lines();
            let titles: Vec<String> = lines
                .next()
                .unwrap_or_default()
                .split_whitespace()
                .map(String::from)
                .collect();
            let processes: Vec<Vec<String>> = lines
                .filter(|l| !l.trim().is_empty())
                .map(|l| l.split_whitespace().map(String::from).collect())
                .collect();
            let resp = TopResponse { titles, processes };
            (
                200,
                serde_json::to_string(&resp).unwrap_or_else(|_| "{}".to_string()),
            )
        }
        Ok(_) => {
            // ps failed — return an empty list rather than an error
            let resp = TopResponse {
                titles: vec!["PID".to_string(), "USER".to_string(), "COMMAND".to_string()],
                processes: vec![],
            };
            (
                200,
                serde_json::to_string(&resp).unwrap_or_else(|_| "{}".to_string()),
            )
        }
        Err(e) => (500, error_json(&e.to_string())),
    }
}
