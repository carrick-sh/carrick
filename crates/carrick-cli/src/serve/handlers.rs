//! Endpoint handlers: translate an HTTP request into a registry/spawn action
//! and a JSON response body. Each returns the body bytes; the router wraps them
//! in a response with the right status.

use crate::serve::model::{CreateBody, CreateResponse, InfoResponse, VersionResponse, WaitResponse};

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
    match crate::serve::spawn::create_container(
        name,
        &image,
        &cmd,
        &env,
        req.working_dir.as_deref(),
    ) {
        // `id` is the 64-hex container id `carrick create` generated; the Docker
        // `Id` is always that id, not the (optional) name.
        Ok(id) => {
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
            let resp = WaitResponse { status_code: code as i64 };
            (200, serde_json::to_string(&resp).unwrap_or_else(|_| "{}".to_string()))
        }
        Err(e) => (500, error_json(&e.to_string())),
    }
}

pub(crate) fn error_json(msg: &str) -> String {
    format!(
        "{{\"message\":{}}}",
        serde_json::to_string(msg).unwrap_or_else(|_| "\"\"".to_string())
    )
}
