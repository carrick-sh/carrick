//! Wire schema for the Docker Engine API responses carrick serves. Field names
//! match Docker's JSON exactly (PascalCase) so strongly-typed clients (bollard,
//! docker-java) deserialize without error.

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
