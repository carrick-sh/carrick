//! Wire schema for the Docker Engine API responses carrick serves. Field names
//! match Docker's JSON exactly (PascalCase) so strongly-typed clients (bollard,
//! docker-java) deserialize without error.

use serde::Deserialize;
use serde::Serialize;

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
    pub host_config: Option<CreateHostConfig>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct CreateHostConfig {
    pub binds: Option<Vec<String>>,
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
    #[serde(rename = "IPAddress")]
    pub ip_address: String,
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
