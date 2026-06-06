//! Endpoint handlers: translate an HTTP request into a registry/spawn action
//! and a JSON response body. Each returns the body bytes; the router wraps them
//! in a response with the right status.

use crate::serve::model::{InfoResponse, VersionResponse};

pub(crate) fn version_json() -> String {
    serde_json::to_string(&VersionResponse::default())
        .unwrap_or_else(|_| "{}".to_string())
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
        images: 0,
    };
    serde_json::to_string(&info).unwrap_or_else(|_| "{}".to_string())
}
