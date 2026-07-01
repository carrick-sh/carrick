//! Wire schema for the Docker Engine API responses carrick serves. Field names
//! match Docker's JSON exactly (PascalCase) so strongly-typed clients (bollard,
//! docker-java) deserialize without error.

use serde::Deserialize;
use serde::Serialize;
use std::collections::HashMap;

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct VersionResponse {
    pub version: String,
    pub api_version: String,
    pub min_api_version: String,
    pub os: String,
    pub arch: String,
    pub kernel_version: String,
}

impl Default for VersionResponse {
    fn default() -> Self {
        Self {
            version: format!("carrick-{}", env!("CARGO_PKG_VERSION")),
            api_version: "1.43".to_string(),
            min_api_version: "1.24".to_string(),
            os: "linux".to_string(),
            arch: "arm64".to_string(),
            kernel_version: "carrick".to_string(),
        }
    }
}

/// The subset of Docker's container-create body M0 consumes.
#[derive(Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct CreateBody {
    pub image: Option<String>,
    pub cmd: Option<Vec<String>>,
    pub env: Option<Vec<String>>,
    pub working_dir: Option<String>,
    pub tty: Option<bool>,
    pub open_stdin: Option<bool>,
    pub user: Option<String>,
    pub entrypoint: Option<Vec<String>>,
    pub labels: Option<HashMap<String, String>>,
    pub volumes: Option<HashMap<String, serde_json::Value>>,
    pub host_config: Option<CreateHostConfig>,
    pub networking_config: Option<CreateNetworkingConfig>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct CreateHostConfig {
    pub auto_remove: Option<bool>,
    pub binds: Option<Vec<String>>,
    pub network_mode: Option<String>,
    pub mounts: Option<Vec<CreateMount>>,
    pub port_bindings: Option<HashMap<String, Option<Vec<CreatePortBinding>>>>,
    pub extra_hosts: Option<Vec<String>>,
    #[serde(rename = "Dns")]
    pub dns: Option<Vec<String>>,
    pub dns_search: Option<Vec<String>>,
    pub dns_options: Option<Vec<String>>,
    pub volumes_from: Option<Vec<String>>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct CreateNetworkingConfig {
    pub endpoints_config: Option<HashMap<String, CreateEndpointSettings>>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct CreateEndpointSettings {
    #[serde(rename = "IPAMConfig")]
    pub ipam_config: Option<CreateEndpointIpamConfig>,
    pub aliases: Option<Vec<String>>,
    pub links: Option<Vec<String>>,
    pub mac_address: Option<String>,
    pub gw_priority: Option<i64>,
    pub driver_opts: Option<HashMap<String, String>>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct CreateEndpointIpamConfig {
    #[serde(rename = "IPv4Address")]
    pub ipv4_address: Option<String>,
    #[serde(rename = "IPv6Address")]
    pub ipv6_address: Option<String>,
    #[serde(rename = "LinkLocalIPs")]
    pub link_local_ips: Option<Vec<String>>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct CreateMount {
    #[serde(rename = "Type")]
    pub typ: Option<String>,
    pub source: Option<String>,
    pub target: Option<String>,
    pub read_only: Option<bool>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct CreatePortBinding {
    #[serde(rename = "HostIp")]
    pub host_ip: Option<String>,
    pub host_port: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct CreateResponse {
    pub id: String,
    pub warnings: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct WaitResponse {
    pub status_code: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct InfoResponse {
    pub id: String,
    pub name: String,
    pub server_version: String,
    pub operating_system: String,
    pub os_type: String,
    pub architecture: String,
    pub containers: i64,
    pub images: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct ContainerSummary {
    #[serde(rename = "Id")]
    pub id: String,
    pub names: Vec<String>,
    pub image: String,
    #[serde(rename = "ImageID")]
    pub image_id: String,
    pub command: String,
    pub created: i64,
    pub ports: Vec<serde_json::Value>,
    pub labels: std::collections::HashMap<String, String>,
    pub state: String,
    pub status: String,
    pub host_config: HostConfigSummary,
    pub network_settings: NetworkSettingsSummary,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct HostConfigSummary {
    pub network_mode: String,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct NetworkSettingsSummary {
    pub networks: std::collections::HashMap<String, EndpointSettings>,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct EndpointSettings {
    #[serde(rename = "IPAMConfig")]
    pub ipam_config: Option<serde_json::Value>,
    pub links: Option<Vec<String>>,
    #[serde(rename = "Aliases")]
    pub aliases: Option<Vec<String>>,
    pub driver_opts: Option<std::collections::HashMap<String, String>>,
    pub gw_priority: i64,
    #[serde(rename = "NetworkID")]
    pub network_id: String,
    #[serde(rename = "EndpointID")]
    pub endpoint_id: String,
    pub gateway: String,
    #[serde(rename = "IPAddress")]
    pub ip_address: String,
    pub mac_address: String,
    #[serde(rename = "IPPrefixLen")]
    pub ip_prefix_len: i64,
    #[serde(rename = "IPv6Gateway")]
    pub ipv6_gateway: String,
    #[serde(rename = "GlobalIPv6Address")]
    pub global_ipv6_address: String,
    #[serde(rename = "GlobalIPv6PrefixLen")]
    pub global_ipv6_prefix_len: i64,
    #[serde(rename = "DNSNames")]
    pub dns_names: Option<Vec<String>>,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct ImageSummary {
    #[serde(rename = "Id")]
    pub id: String,
    pub parent_id: String,
    pub repo_tags: Vec<String>,
    pub repo_digests: Vec<String>,
    pub created: i64,
    pub size: i64,
    pub shared_size: i64,
    pub virtual_size: i64,
    pub labels: std::collections::HashMap<String, String>,
    pub containers: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct ImageInspectResponse {
    #[serde(rename = "Id")]
    pub id: String,
    pub repo_tags: Vec<String>,
    pub created: String,
    pub size: i64,
    pub virtual_size: i64,
    pub os: String,
    pub architecture: String,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct ExecInspectResponse {
    #[serde(rename = "ID")]
    pub id: String,
    pub running: bool,
    pub exit_code: i64,
    #[serde(rename = "ContainerID")]
    pub container_id: String,
    pub pid: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct TopResponse {
    pub titles: Vec<String>,
    pub processes: Vec<Vec<String>>,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
#[allow(dead_code)]
pub(crate) struct ExecCreateBody {
    pub attach_stdin: Option<bool>,
    pub attach_stdout: Option<bool>,
    pub attach_stderr: Option<bool>,
    pub tty: Option<bool>,
    pub cmd: Option<Vec<String>>,
    pub env: Option<Vec<String>>,
    pub working_dir: Option<String>,
    pub user: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct ExecCreateResponse {
    pub id: String,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
#[allow(dead_code)]
pub(crate) struct ExecStartBody {
    pub detach: Option<bool>,
    pub tty: Option<bool>,
}

#[derive(Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct NetworkCreateBody {
    pub name: String,
    pub check_duplicate: Option<bool>,
    pub driver: Option<String>,
    pub scope: Option<String>,
    pub internal: Option<bool>,
    pub attachable: Option<bool>,
    pub ingress: Option<bool>,
    pub config_from: Option<serde_json::Value>,
    pub config_only: Option<bool>,
    #[serde(rename = "IPAM")]
    pub ipam: Option<serde_json::Value>,
    #[serde(rename = "EnableIPv4")]
    pub enable_ipv4: Option<bool>,
    #[serde(rename = "EnableIPv6")]
    pub enable_ipv6: Option<bool>,
    pub options: Option<HashMap<String, String>>,
    pub labels: Option<HashMap<String, String>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct NetworkConnectBody {
    pub container: Option<String>,
    pub endpoint_config: Option<CreateEndpointSettings>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct NetworkDisconnectBody {
    pub container: Option<String>,
    pub force: Option<bool>,
}

#[derive(Serialize)]
pub(crate) struct NetworkCreateResponse {
    #[serde(rename = "Id")]
    pub id: String,
    #[serde(rename = "Warning")]
    pub warning: String,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct NetworkResource {
    pub name: String,
    #[serde(rename = "Id")]
    pub id: String,
    pub created: String,
    pub scope: String,
    pub driver: String,
    #[serde(rename = "EnableIPv4")]
    pub enable_ipv4: bool,
    #[serde(rename = "EnableIPv6")]
    pub enable_ipv6: bool,
    #[serde(rename = "IPAM")]
    pub ipam: serde_json::Value,
    pub internal: bool,
    pub attachable: bool,
    pub ingress: bool,
    pub config_from: Option<serde_json::Value>,
    #[serde(default)]
    pub config_only: bool,
    pub containers: HashMap<String, serde_json::Value>,
    pub options: HashMap<String, String>,
    pub labels: HashMap<String, String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct VolumeCreateBody {
    pub name: Option<String>,
    pub driver: Option<String>,
    pub driver_opts: Option<HashMap<String, String>>,
    pub labels: Option<HashMap<String, String>>,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct VolumeResource {
    pub name: String,
    pub driver: String,
    pub mountpoint: String,
    pub created_at: String,
    pub labels: HashMap<String, String>,
    pub scope: String,
    pub options: HashMap<String, String>,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct VolumeListResponse {
    pub volumes: Vec<VolumeResource>,
    pub warnings: Vec<String>,
}
