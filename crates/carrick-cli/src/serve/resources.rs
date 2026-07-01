//! Persisted Docker API resource objects that are not containers.
//!
//! Compose clients create networks and volumes before they create containers.
//! Carrick's runtime already owns bridge socket translation and host bind
//! mounts; this store gives the API layer Docker-shaped network/volume resources
//! so those clients can negotiate the expected Engine API lifecycle.

use crate::serve::model::{
    NetworkConnectBody, NetworkCreateBody, NetworkCreateResponse, NetworkDisconnectBody,
    NetworkResource, VolumeCreateBody, VolumeListResponse, VolumeResource,
};
use carrick_runtime::container;
use serde::Serialize;
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

const NETWORKS: &str = "networks";
const VOLUMES: &str = "volumes";
const STATE_FILE: &str = "state.json";
static RESOURCE_WRITE_SEQ: AtomicU64 = AtomicU64::new(0);
const PREDEFINED_NETWORK_NAMES: &[(&str, &str)] =
    &[("bridge", "bridge"), ("host", "host"), ("none", "null")];

pub(crate) fn create_network(body: &[u8]) -> (u16, String) {
    let req: NetworkCreateBody = match serde_json::from_slice(body) {
        Ok(b) => b,
        Err(e) => {
            return (
                400,
                crate::serve::handlers::error_json(&format!("invalid body: {e}")),
            );
        }
    };
    if !is_safe_resource_name(&req.name) {
        return (
            400,
            crate::serve::handlers::error_json("invalid network name"),
        );
    }
    if is_predefined_network_name(&req.name) {
        return (
            409,
            crate::serve::handlers::error_json("network already exists"),
        );
    }
    let _check_duplicate = req.check_duplicate.unwrap_or(false);
    if load_named::<NetworkResource>(NETWORKS, &req.name).is_ok() {
        return (
            409,
            crate::serve::handlers::error_json("network already exists"),
        );
    }

    let created = now_rfc3339();
    let network = NetworkResource {
        id: stable_id(NETWORKS, &req.name, &created),
        name: req.name,
        created,
        scope: req.scope.unwrap_or_else(|| "local".to_string()),
        driver: req.driver.unwrap_or_else(|| "bridge".to_string()),
        enable_ipv4: req.enable_ipv4.unwrap_or(true),
        enable_ipv6: req.enable_ipv6.unwrap_or(false),
        ipam: req
            .ipam
            .filter(|ipam| !ipam.is_null())
            .unwrap_or_else(default_ipam),
        internal: req.internal.unwrap_or(false),
        attachable: req.attachable.unwrap_or(false),
        ingress: req.ingress.unwrap_or(false),
        config_from: req.config_from,
        config_only: req.config_only.unwrap_or(false),
        containers: HashMap::new(),
        options: req.options.unwrap_or_default(),
        labels: req.labels.unwrap_or_default(),
    };
    match persist_named(NETWORKS, &network.name, &network) {
        Ok(()) => {
            let resp = NetworkCreateResponse {
                id: network.id,
                warning: String::new(),
            };
            (
                201,
                serde_json::to_string(&resp).unwrap_or_else(|_| "{}".to_string()),
            )
        }
        Err(e) => (500, crate::serve::handlers::error_json(&e.to_string())),
    }
}

pub(crate) fn list_networks(query: &str) -> (u16, String) {
    let filters = docker_filters(query);
    let mut networks = predefined_networks();
    networks.extend(
        list_named::<NetworkResource>(NETWORKS)
            .into_iter()
            .filter(|network| !is_predefined_network_name(&network.name)),
    );
    networks.retain(|network| network_matches_filters(network, &filters));
    networks = networks.into_iter().map(network_for_api).collect();
    networks.sort_by(|a, b| a.name.cmp(&b.name));
    (
        200,
        serde_json::to_string(&networks).unwrap_or_else(|_| "[]".to_string()),
    )
}

pub(crate) fn inspect_network(name_or_id: &str) -> (u16, String) {
    if let Some(network) = predefined_network(name_or_id) {
        return (
            200,
            serde_json::to_string(&network_for_api(network)).unwrap_or_else(|_| "{}".to_string()),
        );
    }
    match resolve_named::<NetworkResource, _>(NETWORKS, name_or_id, |network| {
        network_name_or_id_matches(network, name_or_id)
    }) {
        Ok(network) => (
            200,
            serde_json::to_string(&network_for_api(network)).unwrap_or_else(|_| "{}".to_string()),
        ),
        Err(e) => (404, crate::serve::handlers::error_json(&e)),
    }
}

pub(crate) fn resolve_network_name(name_or_id: &str) -> Option<String> {
    if let Some(network) = predefined_network(name_or_id) {
        return Some(network.name);
    }
    resolve_name(NETWORKS, name_or_id, |network: &NetworkResource| {
        network_name_or_id_matches(network, name_or_id)
    })
    .ok()
}

pub(crate) fn remove_network(name_or_id: &str) -> (u16, String) {
    if predefined_network(name_or_id).is_some() {
        return (
            403,
            crate::serve::handlers::error_json("predefined network cannot be removed"),
        );
    }
    match resolve_named::<NetworkResource, _>(NETWORKS, name_or_id, |network| {
        network_name_or_id_matches(network, name_or_id)
    }) {
        Ok(network) if network_has_active_endpoints(&network) => (
            409,
            crate::serve::handlers::error_json("network has active endpoints"),
        ),
        Ok(network) => match remove_named(NETWORKS, &network.name) {
            Ok(()) => (204, String::new()),
            Err(e) => (500, crate::serve::handlers::error_json(&e.to_string())),
        },
        Err(e) => (404, crate::serve::handlers::error_json(&e)),
    }
}

pub(crate) fn prune_networks(query: &str) -> (u16, String) {
    let filters = docker_filters(query);
    let mut networks = list_named::<NetworkResource>(NETWORKS);
    networks.sort_by(|a, b| a.name.cmp(&b.name));
    let mut deleted = Vec::new();
    for network in networks {
        if !network_has_active_endpoints(&network)
            && network_matches_filters(&network, &filters)
            && prune_labels_match(&network.labels, &filters)
            && remove_named(NETWORKS, &network.name).is_ok()
        {
            deleted.push(network.name);
        }
    }
    (
        200,
        serde_json::to_string(&serde_json::json!({
            "NetworksDeleted": deleted,
        }))
        .unwrap_or_else(|_| "{}".to_string()),
    )
}

pub(crate) fn connect_network(name_or_id: &str, body: &[u8]) -> (u16, String) {
    let req: NetworkConnectBody = match serde_json::from_slice(body) {
        Ok(b) => b,
        Err(e) => {
            return (
                400,
                crate::serve::handlers::error_json(&format!("invalid body: {e}")),
            );
        }
    };
    let Some(container_ref) = req.container.as_deref() else {
        return (
            400,
            crate::serve::handlers::error_json("network connect missing Container"),
        );
    };
    let network_name = match resolve_connectable_network_name(name_or_id) {
        Ok(name) => name,
        Err(e) => return (404, crate::serve::handlers::error_json(&e)),
    };
    let id = match container::resolve(container_ref) {
        Ok(id) => id,
        Err(e) => return (404, crate::serve::handlers::error_json(&e)),
    };
    let mut state = match container::ContainerState::load(&id) {
        Ok(state) => state,
        Err(e) => return (500, crate::serve::handlers::error_json(&e.to_string())),
    };
    let update = req
        .endpoint_config
        .map(|endpoint| {
            let ipam = endpoint.ipam_config;
            NetworkAttachmentUpdate {
                aliases: endpoint.aliases.unwrap_or_default(),
                links: endpoint.links.unwrap_or_default(),
                mac_address: endpoint.mac_address,
                gw_priority: endpoint.gw_priority.unwrap_or(0),
                ipv4_address: ipam.as_ref().and_then(|ipam| ipam.ipv4_address.clone()),
                ipv6_address: ipam.as_ref().and_then(|ipam| ipam.ipv6_address.clone()),
                link_local_ips: ipam
                    .map(|ipam| ipam.link_local_ips.unwrap_or_default())
                    .unwrap_or_default(),
                driver_opts: endpoint.driver_opts.unwrap_or_default(),
            }
        })
        .unwrap_or_default();
    upsert_attachment(&mut state, &network_name, update);
    state.config.network = carrick_spec::NetworkMode::Bridge;
    state.config.network_aliases = flat_aliases(&state.config.network_attachments);
    if let Err(e) = state.persist() {
        return (500, crate::serve::handlers::error_json(&e.to_string()));
    }
    match attach_container_to_networks(&state) {
        Ok(()) => (200, String::new()),
        Err(e) => (500, crate::serve::handlers::error_json(&e.to_string())),
    }
}

pub(crate) fn disconnect_network(name_or_id: &str, body: &[u8]) -> (u16, String) {
    let req: NetworkDisconnectBody = match serde_json::from_slice(body) {
        Ok(b) => b,
        Err(e) => {
            return (
                400,
                crate::serve::handlers::error_json(&format!("invalid body: {e}")),
            );
        }
    };
    let _force = req.force.unwrap_or(false);
    let Some(container_ref) = req.container.as_deref() else {
        return (
            400,
            crate::serve::handlers::error_json("network disconnect missing Container"),
        );
    };
    let network_name = match resolve_connectable_network_name(name_or_id) {
        Ok(name) => name,
        Err(e) => return (404, crate::serve::handlers::error_json(&e)),
    };
    let id = match container::resolve(container_ref) {
        Ok(id) => id,
        Err(e) => return (404, crate::serve::handlers::error_json(&e)),
    };
    let mut state = match container::ContainerState::load(&id) {
        Ok(state) => state,
        Err(e) => return (500, crate::serve::handlers::error_json(&e.to_string())),
    };
    if !container_has_network_endpoint(&state, &network_name) {
        return (
            403,
            crate::serve::handlers::error_json(&format!(
                "container {} is not connected to the network {}",
                container::short_id(&state.id),
                network_name
            )),
        );
    }
    state
        .config
        .network_attachments
        .retain(|attachment| attachment.name != network_name);
    state.config.network_aliases = flat_aliases(&state.config.network_attachments);
    if state.config.network_attachments.is_empty() {
        state.config.network = carrick_spec::NetworkMode::Host;
    }
    if let Err(e) = state.persist() {
        return (500, crate::serve::handlers::error_json(&e.to_string()));
    }
    match detach_container_from_network(&network_name, &state.id) {
        Ok(()) => (200, String::new()),
        Err(e) => (500, crate::serve::handlers::error_json(&e.to_string())),
    }
}

pub(crate) fn attach_container_to_networks(
    state: &container::ContainerState,
) -> anyhow::Result<()> {
    for attachment in &state.config.network_attachments {
        attach_container_to_network(state, attachment)?;
    }
    Ok(())
}

pub(crate) fn detach_container_from_all_networks(state: &container::ContainerState) {
    for attachment in &state.config.network_attachments {
        let _ = detach_container_from_network(&attachment.name, &state.id);
    }
}

pub(crate) fn create_volume(body: &[u8]) -> (u16, String) {
    let req: VolumeCreateBody = match serde_json::from_slice(body) {
        Ok(b) => b,
        Err(e) => {
            return (
                400,
                crate::serve::handlers::error_json(&format!("invalid body: {e}")),
            );
        }
    };
    let name = req.name.unwrap_or_else(generated_volume_name);
    if !is_safe_resource_name(&name) {
        return (
            400,
            crate::serve::handlers::error_json("invalid volume name"),
        );
    }
    if let Ok(existing) = load_named::<VolumeResource>(VOLUMES, &name) {
        return (
            201,
            serde_json::to_string(&existing).unwrap_or_else(|_| "{}".to_string()),
        );
    }

    let data_dir = resource_data_dir(VOLUMES, &name);
    if let Err(e) = std::fs::create_dir_all(&data_dir) {
        return (500, crate::serve::handlers::error_json(&e.to_string()));
    }
    let created_at = now_rfc3339();
    let volume = VolumeResource {
        name,
        driver: req.driver.unwrap_or_else(|| "local".to_string()),
        mountpoint: data_dir.to_string_lossy().into_owned(),
        created_at,
        labels: req.labels.unwrap_or_default(),
        scope: "local".to_string(),
        options: req.driver_opts.unwrap_or_default(),
    };
    match persist_named(VOLUMES, &volume.name, &volume) {
        Ok(()) => (
            201,
            serde_json::to_string(&volume).unwrap_or_else(|_| "{}".to_string()),
        ),
        Err(e) => (500, crate::serve::handlers::error_json(&e.to_string())),
    }
}

pub(crate) fn list_volumes(query: &str) -> (u16, String) {
    let filters = docker_filters(query);
    let mut volumes = list_named::<VolumeResource>(VOLUMES);
    volumes.retain(|volume| volume_matches_filters(volume, &filters));
    volumes.sort_by(|a, b| a.name.cmp(&b.name));
    let resp = VolumeListResponse {
        volumes,
        warnings: vec![],
    };
    (
        200,
        serde_json::to_string(&resp).unwrap_or_else(|_| "{}".to_string()),
    )
}

pub(crate) fn inspect_volume(name: &str) -> (u16, String) {
    match load_named::<VolumeResource>(VOLUMES, name) {
        Ok(volume) => (
            200,
            serde_json::to_string(&volume).unwrap_or_else(|_| "{}".to_string()),
        ),
        Err(e) => (404, crate::serve::handlers::error_json(&e.to_string())),
    }
}

pub(crate) fn resolve_or_create_volume_mountpoint(name: &str) -> anyhow::Result<String> {
    if !is_safe_resource_name(name) {
        anyhow::bail!("invalid volume name");
    }
    if let Ok(volume) = load_named::<VolumeResource>(VOLUMES, name) {
        return Ok(volume.mountpoint);
    }
    let data_dir = resource_data_dir(VOLUMES, name);
    std::fs::create_dir_all(&data_dir)?;
    let volume = VolumeResource {
        name: name.to_string(),
        driver: "local".to_string(),
        mountpoint: data_dir.to_string_lossy().into_owned(),
        created_at: now_rfc3339(),
        labels: HashMap::new(),
        scope: "local".to_string(),
        options: HashMap::new(),
    };
    persist_named(VOLUMES, name, &volume)?;
    Ok(volume.mountpoint)
}

pub(crate) fn create_anonymous_volume_mountpoint() -> anyhow::Result<(String, String)> {
    let name = generated_volume_name();
    let data_dir = resource_data_dir(VOLUMES, &name);
    std::fs::create_dir_all(&data_dir)?;
    let volume = VolumeResource {
        name: name.clone(),
        driver: "local".to_string(),
        mountpoint: data_dir.to_string_lossy().into_owned(),
        created_at: now_rfc3339(),
        labels: HashMap::new(),
        scope: "local".to_string(),
        options: HashMap::new(),
    };
    persist_named(VOLUMES, &name, &volume)?;
    Ok((name, volume.mountpoint))
}

pub(crate) fn remove_anonymous_volumes_for_container(
    state: &container::ContainerState,
) -> anyhow::Result<()> {
    for mount in &state.config.mounts {
        let volume = list_named::<VolumeResource>(VOLUMES)
            .into_iter()
            .find(|volume| {
                is_anonymous_volume(volume) && volume.mountpoint == mount.source.as_str()
            });
        if let Some(volume) = volume
            && !volume_in_use(&volume)
        {
            remove_named(VOLUMES, &volume.name)?;
        }
    }
    Ok(())
}

fn is_anonymous_volume(volume: &VolumeResource) -> bool {
    looks_like_generated_volume_name(&volume.name)
}

fn looks_like_generated_volume_name(name: &str) -> bool {
    name.len() == 64 && name.bytes().all(|b| b.is_ascii_hexdigit())
}

pub(crate) fn remove_volume(name: &str, force: bool) -> (u16, String) {
    if !is_safe_resource_name(name) {
        return (
            404,
            crate::serve::handlers::error_json("invalid resource name"),
        );
    }
    match load_named::<VolumeResource>(VOLUMES, name) {
        Ok(volume) if volume_in_use(&volume) => {
            (409, crate::serve::handlers::error_json("volume is in use"))
        }
        Ok(volume) => match remove_named(VOLUMES, &volume.name) {
            Ok(()) => (204, String::new()),
            Err(e) => (500, crate::serve::handlers::error_json(&e.to_string())),
        },
        Err(_) if force => (204, String::new()),
        Err(e) => (404, crate::serve::handlers::error_json(&e.to_string())),
    }
}

pub(crate) fn prune_volumes(query: &str) -> (u16, String) {
    let filters = docker_filters(query);
    let prune_all = filters
        .get("all")
        .is_some_and(|values| any_filter_value(values, |value| value == "true" || value == "1"));
    let mut volumes = list_named::<VolumeResource>(VOLUMES);
    volumes.sort_by(|a, b| a.name.cmp(&b.name));
    let mut deleted = Vec::new();
    for volume in volumes {
        if volume_matches_filters(&volume, &filters)
            && prune_labels_match(&volume.labels, &filters)
            && (prune_all || is_anonymous_volume(&volume))
            && !volume_in_use(&volume)
            && remove_named(VOLUMES, &volume.name).is_ok()
        {
            deleted.push(volume.name);
        }
    }
    (
        200,
        serde_json::to_string(&serde_json::json!({
            "VolumesDeleted": deleted,
            "SpaceReclaimed": 0,
        }))
        .unwrap_or_else(|_| "{}".to_string()),
    )
}

#[derive(Default)]
struct NetworkAttachmentUpdate {
    aliases: Vec<String>,
    links: Vec<String>,
    mac_address: Option<String>,
    gw_priority: i64,
    ipv4_address: Option<String>,
    ipv6_address: Option<String>,
    link_local_ips: Vec<String>,
    driver_opts: std::collections::HashMap<String, String>,
}

fn upsert_attachment(
    state: &mut container::ContainerState,
    network_name: &str,
    update: NetworkAttachmentUpdate,
) {
    if let Some(existing) = state
        .config
        .network_attachments
        .iter_mut()
        .find(|attachment| attachment.name == network_name)
    {
        existing.aliases = update.aliases;
        existing.links = update.links;
        existing.mac_address = update.mac_address;
        existing.gw_priority = update.gw_priority;
        existing.ipv4_address = update.ipv4_address;
        existing.ipv6_address = update.ipv6_address;
        existing.link_local_ips = update.link_local_ips;
        existing.driver_opts = update.driver_opts;
        return;
    }
    state
        .config
        .network_attachments
        .push(container::NetworkAttachment {
            name: network_name.to_string(),
            aliases: update.aliases,
            links: update.links,
            mac_address: update.mac_address,
            gw_priority: update.gw_priority,
            ipv4_address: update.ipv4_address,
            ipv6_address: update.ipv6_address,
            link_local_ips: update.link_local_ips,
            driver_opts: update.driver_opts,
        });
}

pub(crate) fn docker_filters(query: &str) -> HashMap<String, Vec<String>> {
    let Some(raw) = crate::serve::router::query_param(query, "filters") else {
        return HashMap::new();
    };
    let decoded = percent_decode_query_value(&raw);
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&decoded) else {
        return HashMap::new();
    };
    let Some(object) = value.as_object() else {
        return HashMap::new();
    };

    object
        .iter()
        .filter_map(|(key, value)| {
            let mut values = match value {
                serde_json::Value::Array(items) => items
                    .iter()
                    .filter_map(|item| item.as_str().map(ToOwned::to_owned))
                    .collect::<Vec<_>>(),
                serde_json::Value::Object(items) => items
                    .iter()
                    .filter_map(|(selector, enabled)| {
                        if enabled.as_bool().unwrap_or(true) {
                            Some(selector.clone())
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<_>>(),
                serde_json::Value::String(selector) => vec![selector.clone()],
                _ => Vec::new(),
            };
            values.sort();
            if values.is_empty() {
                None
            } else {
                Some((key.clone(), values))
            }
        })
        .collect()
}

fn percent_decode_query_value(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hi = hex_value(bytes[i + 1]);
                let lo = hex_value(bytes[i + 2]);
                if let (Some(hi), Some(lo)) = (hi, lo) {
                    out.push((hi << 4) | lo);
                    i += 3;
                } else {
                    out.push(bytes[i]);
                    i += 1;
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).unwrap_or_default()
}

fn hex_value(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn network_matches_filters(
    network: &NetworkResource,
    filters: &HashMap<String, Vec<String>>,
) -> bool {
    filters.iter().all(|(key, values)| match key.as_str() {
        "driver" => any_filter_value(values, |value| network.driver == value),
        "id" => any_filter_value(values, |value| network.id.starts_with(value)),
        "label" => label_filters_match(&network.labels, values),
        "name" => any_filter_value(values, |value| network.name.contains(value)),
        "scope" => any_filter_value(values, |value| network.scope == value),
        "type" => any_filter_value(values, |value| value == network_resource_type(network)),
        _ => true,
    })
}

fn predefined_networks() -> Vec<NetworkResource> {
    PREDEFINED_NETWORK_NAMES
        .iter()
        .map(|(name, driver)| predefined_network_resource(name, driver))
        .collect()
}

fn predefined_network(name_or_id: &str) -> Option<NetworkResource> {
    predefined_networks()
        .into_iter()
        .find(|network| network_name_or_id_matches(network, name_or_id))
}

pub(crate) fn network_id(name_or_id: &str) -> Option<String> {
    if let Some(network) = predefined_network(name_or_id) {
        return Some(network.id);
    }
    resolve_named::<NetworkResource, _>(NETWORKS, name_or_id, |network| {
        network_name_or_id_matches(network, name_or_id)
    })
    .ok()
    .map(|network| network.id)
}

fn predefined_network_resource(name: &str, driver: &str) -> NetworkResource {
    NetworkResource {
        name: name.to_string(),
        id: stable_id(NETWORKS, name, "predefined"),
        created: "1970-01-01T00:00:00Z".to_string(),
        scope: "local".to_string(),
        driver: driver.to_string(),
        enable_ipv4: true,
        enable_ipv6: false,
        ipam: default_ipam(),
        internal: false,
        attachable: false,
        ingress: false,
        config_from: None,
        config_only: false,
        containers: predefined_network_containers(name),
        options: HashMap::new(),
        labels: HashMap::new(),
    }
}

fn predefined_network_containers(network_name: &str) -> HashMap<String, serde_json::Value> {
    match network_name {
        "bridge" => predefined_bridge_containers(),
        "host" => predefined_mode_containers("host", carrick_spec::NetworkMode::Host),
        "none" => predefined_mode_containers("none", carrick_spec::NetworkMode::None),
        _ => HashMap::new(),
    }
}

fn predefined_bridge_containers() -> HashMap<String, serde_json::Value> {
    container::list()
        .into_iter()
        .filter(container_endpoint_visible)
        .filter_map(|state| {
            let aliases = state
                .config
                .network_attachments
                .iter()
                .find(|attachment| attachment.name == "bridge")
                .map(|attachment| attachment.aliases.clone())
                .or_else(|| {
                    (state.config.network == carrick_spec::NetworkMode::Bridge
                        && state.config.network_attachments.is_empty())
                    .then(|| state.config.network_aliases.clone())
                })?;
            Some((
                state.id.clone(),
                container_endpoint(&state, "bridge", aliases),
            ))
        })
        .collect()
}

fn predefined_mode_containers(
    network_name: &str,
    mode: carrick_spec::NetworkMode,
) -> HashMap<String, serde_json::Value> {
    container::list()
        .into_iter()
        .filter(container_endpoint_visible)
        .filter(|state| state.config.network == mode && state.config.network_attachments.is_empty())
        .map(|state| {
            (
                state.id.clone(),
                container_endpoint(&state, network_name, Vec::new()),
            )
        })
        .collect()
}

fn network_for_api(mut network: NetworkResource) -> NetworkResource {
    network
        .containers
        .retain(|container_id, _| container_id_has_active_endpoint(container_id));
    network
}

fn network_has_active_endpoints(network: &NetworkResource) -> bool {
    network
        .containers
        .keys()
        .any(|container_id| container_id_has_active_endpoint(container_id))
}

fn container_id_has_active_endpoint(container_id: &str) -> bool {
    container::ContainerState::load(container_id)
        .is_ok_and(|state| container_endpoint_visible(&state))
}

fn container_endpoint_visible(state: &container::ContainerState) -> bool {
    if state.config.network_container.is_some() {
        return false;
    }
    container::reconciled_status(state) == container::ContainerStatus::Running
}

fn resolve_connectable_network_name(name_or_id: &str) -> Result<String, String> {
    if let Some(network) = predefined_network(name_or_id) {
        if network.name == "bridge" {
            return Ok(network.name);
        }
        return Err("predefined network is not connectable".to_string());
    }
    resolve_name(NETWORKS, name_or_id, |network: &NetworkResource| {
        network_name_or_id_matches(network, name_or_id)
    })
}

fn is_predefined_network_name(name: &str) -> bool {
    PREDEFINED_NETWORK_NAMES
        .iter()
        .any(|(predefined, _driver)| *predefined == name)
}

fn network_resource_type(network: &NetworkResource) -> &str {
    if is_predefined_network_name(&network.name) {
        "builtin"
    } else {
        "custom"
    }
}

fn network_name_or_id_matches(network: &NetworkResource, name_or_id: &str) -> bool {
    network.name == name_or_id || network.id == name_or_id || network.id.starts_with(name_or_id)
}

fn volume_matches_filters(volume: &VolumeResource, filters: &HashMap<String, Vec<String>>) -> bool {
    filters.iter().all(|(key, values)| match key.as_str() {
        "dangling" => {
            let in_use = volume_in_use(volume);
            any_filter_value(values, |value| match value {
                "false" | "0" => in_use,
                "true" | "1" => !in_use,
                _ => true,
            })
        }
        "driver" => any_filter_value(values, |value| volume.driver == value),
        "label" => label_filters_match(&volume.labels, values),
        "name" => any_filter_value(values, |value| volume.name.contains(value)),
        "all" => true,
        _ => true,
    })
}

fn prune_labels_match(
    labels: &HashMap<String, String>,
    filters: &HashMap<String, Vec<String>>,
) -> bool {
    filters.get("label!").is_none_or(|values| {
        values
            .iter()
            .all(|selector| !label_filter_matches(labels, selector))
    })
}

pub(crate) fn any_filter_value(values: &[String], matches: impl Fn(&str) -> bool) -> bool {
    values.is_empty() || values.iter().any(|value| matches(value))
}

pub(crate) fn label_filters_match(labels: &HashMap<String, String>, values: &[String]) -> bool {
    any_filter_value(values, |selector| label_filter_matches(labels, selector))
}

fn label_filter_matches(labels: &HashMap<String, String>, selector: &str) -> bool {
    if let Some((key, value)) = selector
        .split_once('=')
        .or_else(|| selector.split_once(':'))
    {
        labels.get(key).is_some_and(|actual| actual == value)
    } else {
        labels.contains_key(selector)
    }
}

fn flat_aliases(attachments: &[container::NetworkAttachment]) -> Vec<String> {
    let mut aliases = Vec::new();
    for attachment in attachments {
        for alias in &attachment.aliases {
            if !aliases.contains(alias) {
                aliases.push(alias.clone());
            }
        }
    }
    aliases
}

fn container_has_network_endpoint(state: &container::ContainerState, network_name: &str) -> bool {
    if state.config.network_container.is_some() {
        return false;
    }
    state
        .config
        .network_attachments
        .iter()
        .any(|attachment| attachment.name == network_name)
        || (network_name == "bridge"
            && state.config.network == carrick_spec::NetworkMode::Bridge
            && state.config.network_attachments.is_empty())
}

fn attach_container_to_network(
    state: &container::ContainerState,
    attachment: &container::NetworkAttachment,
) -> anyhow::Result<()> {
    if is_predefined_network_name(&attachment.name) {
        return Ok(());
    }
    let mut network = load_named::<NetworkResource>(NETWORKS, &attachment.name)?;
    network.containers.insert(
        state.id.clone(),
        container_endpoint(state, &attachment.name, attachment.aliases.clone()),
    );
    persist_named(NETWORKS, &network.name, &network)
}

fn detach_container_from_network(network_name: &str, container_id: &str) -> anyhow::Result<()> {
    if is_predefined_network_name(network_name) {
        return Ok(());
    }
    let mut network = load_named::<NetworkResource>(NETWORKS, network_name)?;
    network.containers.remove(container_id);
    persist_named(NETWORKS, &network.name, &network)
}

fn container_endpoint(
    state: &container::ContainerState,
    network_name: &str,
    aliases: Vec<String>,
) -> serde_json::Value {
    let attachment = state
        .config
        .network_attachments
        .iter()
        .find(|attachment| attachment.name == network_name);
    let ipv4_address = endpoint_ipv4_address(
        state,
        attachment.and_then(|a| a.ipv4_address.as_deref()),
        &aliases,
    );
    serde_json::json!({
        "Name": state.name.as_deref().unwrap_or(&state.id[..12]),
        "EndpointID": endpoint_id(&state.id, network_name),
        "MacAddress": attachment.and_then(|a| a.mac_address.as_deref()).unwrap_or(""),
        "IPv4Address": ipv4_address,
        "IPv6Address": attachment.and_then(|a| a.ipv6_address.as_deref()).unwrap_or(""),
        "LinkLocalIPs": attachment
            .map(|a| a.link_local_ips.clone())
            .unwrap_or_default(),
        "DriverOpts": attachment
            .map(|a| a.driver_opts.clone())
            .unwrap_or_default(),
        "Aliases": aliases,
    })
}

pub(crate) fn endpoint_ipv4_address(
    state: &container::ContainerState,
    explicit_ipv4: Option<&str>,
    aliases: &[String],
) -> String {
    if let Some(ipv4) = explicit_ipv4.filter(|addr| !addr.is_empty()) {
        return ipv4.to_string();
    }
    if state.config.network != carrick_spec::NetworkMode::Bridge
        || state.config.network_container.is_some()
    {
        return String::new();
    }
    carrick_spec::NetworkNamespaceSpec::bridge_default(
        state.name.clone(),
        aliases.to_vec(),
        Vec::new(),
    )
    .ipv4
    .to_string()
}

pub(crate) fn endpoint_id(container_id: &str, network_name: &str) -> String {
    stable_id("endpoint", container_id, network_name)
}

fn volume_in_use(volume: &VolumeResource) -> bool {
    container::list().into_iter().any(|state| {
        state
            .config
            .mounts
            .iter()
            .any(|mount| mount.source.as_str() == volume.mountpoint)
    })
}

fn default_ipam() -> serde_json::Value {
    serde_json::json!({
        "Driver": "default",
        "Config": [],
        "Options": {}
    })
}

fn generated_volume_name() -> String {
    let created = now_rfc3339();
    stable_id(VOLUMES, "anonymous", &created)
}

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Nanos, true)
}

fn stable_id(kind: &str, name: &str, created: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(kind.as_bytes());
    hasher.update([0]);
    hasher.update(name.as_bytes());
    hasher.update([0]);
    hasher.update(created.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn is_safe_resource_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name != "."
        && name != ".."
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.')
}

fn api_root() -> PathBuf {
    let containers = container::registry_root();
    containers
        .parent()
        .map(|p| p.join("docker-api"))
        .unwrap_or_else(|| containers.join("_docker-api"))
}

fn resource_root(kind: &str) -> PathBuf {
    api_root().join(kind)
}

fn resource_dir(kind: &str, name: &str) -> PathBuf {
    resource_root(kind).join(name)
}

fn resource_data_dir(kind: &str, name: &str) -> PathBuf {
    resource_dir(kind, name).join("_data")
}

fn state_path(kind: &str, name: &str) -> anyhow::Result<PathBuf> {
    if !is_safe_resource_name(name) {
        anyhow::bail!("invalid resource name");
    }
    Ok(resource_dir(kind, name).join(STATE_FILE))
}

fn persist_named<T: Serialize>(kind: &str, name: &str, value: &T) -> anyhow::Result<()> {
    let dir = resource_dir(kind, name);
    std::fs::create_dir_all(&dir)?;
    let path = state_path(kind, name)?;
    let json = serde_json::to_vec_pretty(value)?;
    let seq = RESOURCE_WRITE_SEQ.fetch_add(1, Ordering::Relaxed);
    let tmp = dir.join(format!("{STATE_FILE}.tmp.{}.{}", std::process::id(), seq));
    std::fs::write(&tmp, json)?;
    match std::fs::rename(&tmp, &path) {
        Ok(()) => {}
        Err(err) => {
            let _ = std::fs::remove_file(&tmp);
            return Err(err.into());
        }
    }
    Ok(())
}

fn load_named<T: DeserializeOwned>(kind: &str, name: &str) -> anyhow::Result<T> {
    let path = state_path(kind, name)?;
    let bytes = std::fs::read(path)?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn list_named<T: DeserializeOwned>(kind: &str) -> Vec<T> {
    let root = resource_root(kind);
    let Ok(entries) = std::fs::read_dir(root) else {
        return Vec::new();
    };
    entries
        .filter_map(Result::ok)
        .filter_map(|entry| read_resource_state(entry.path()).ok())
        .collect()
}

fn read_resource_state<T: DeserializeOwned>(dir: PathBuf) -> anyhow::Result<T> {
    let bytes = std::fs::read(dir.join(STATE_FILE))?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn resolve_named<T, F>(kind: &str, name_or_id: &str, matches: F) -> Result<T, String>
where
    T: DeserializeOwned,
    F: Fn(&T) -> bool,
{
    if is_safe_resource_name(name_or_id)
        && let Ok(value) = load_named(kind, name_or_id)
    {
        return Ok(value);
    }
    list_named(kind)
        .into_iter()
        .find(matches)
        .ok_or_else(|| "resource not found".to_string())
}

fn resolve_name<T, F>(kind: &str, name_or_id: &str, matches: F) -> Result<String, String>
where
    T: DeserializeOwned + ResourceName,
    F: Fn(&T) -> bool,
{
    resolve_named(kind, name_or_id, matches).map(|value: T| value.resource_name().to_string())
}

fn remove_named(kind: &str, name: &str) -> anyhow::Result<()> {
    if !is_safe_resource_name(name) {
        anyhow::bail!("invalid resource name");
    }
    let dir = resource_dir(kind, name);
    if !dir.exists() {
        anyhow::bail!("resource not found");
    }
    std::fs::remove_dir_all(dir)?;
    Ok(())
}

trait ResourceName {
    fn resource_name(&self) -> &str;
}

impl ResourceName for NetworkResource {
    fn resource_name(&self) -> &str {
        &self.name
    }
}

#[cfg(test)]
mod tests {
    use super::docker_filters;

    #[test]
    fn docker_filters_accepts_compose_object_form() {
        let query = concat!(
            "filters=%7B",
            "%22label%22%3A%7B",
            "%22com.docker.compose.project%3Ddemo%22%3Atrue%2C",
            "%22com.docker.compose.config-hash%22%3Atrue",
            "%7D%2C",
            "%22name%22%3A%7B%22demo_default%22%3Atrue%7D",
            "%7D"
        );

        let filters = docker_filters(query);
        let labels = filters.get("label").unwrap();
        assert!(labels.contains(&"com.docker.compose.project=demo".to_string()));
        assert!(labels.contains(&"com.docker.compose.config-hash".to_string()));
        assert_eq!(filters.get("name"), Some(&vec!["demo_default".to_string()]));
    }
}
