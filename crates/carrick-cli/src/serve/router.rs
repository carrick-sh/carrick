//! HTTP routing for the Docker Engine API server: maps (method, path) to a
//! handler and renders the result as an HTTP response. The Docker API prefixes
//! every path with an optional `/v1.NN` version segment, which we strip.

use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::{Method, Request, Response, StatusCode};

/// Strip a leading `/v1.43`-style version segment, returning the bare path.
fn strip_version(path: &str) -> &str {
    if let Some(rest) = path.strip_prefix("/v") {
        if let Some(slash) = rest.find('/') {
            // Only strip if the segment looks like a version (digits/dots).
            let (ver, tail) = rest.split_at(slash);
            if !ver.is_empty() && ver.chars().all(|c| c.is_ascii_digit() || c == '.') {
                return tail;
            }
        }
    }
    path
}

/// Parse `/containers/<id>/<action>` into `(id, action)`.
fn container_action(path: &str) -> Option<(&str, &str)> {
    let rest = path.strip_prefix("/containers/")?;
    let (id, action) = rest.split_once('/')?;
    if id.is_empty() || action.is_empty() { return None; }
    Some((id, action))
}

/// Pull a single `key=value` out of a raw query string (`a=1&b=2`).
fn query_param(query: &str, key: &str) -> Option<String> {
    query.split('&').find_map(|kv| {
        let (k, v) = kv.split_once('=')?;
        if k == key { Some(v.to_string()) } else { None }
    })
}

fn text(status: StatusCode, body: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .body(Full::new(Bytes::from(body.to_owned())))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::new())))
}

fn json(status: StatusCode, body: String) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(Full::new(Bytes::from(body)))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::new())))
}

/// The single service entry point. Infallible at the HTTP layer: every handler
/// error becomes a response, never a panic (the no-panic gate).
pub(crate) async fn route(
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    let method = req.method().clone();
    let path = strip_version(req.uri().path()).to_string();
    let query = req.uri().query().unwrap_or("").to_string();
    let body_bytes = match BodyExt::collect(req.into_body()).await {
        Ok(b) => b.to_bytes(),
        Err(_) => Bytes::new(),
    };

    let resp = match (&method, path.as_str()) {
        (&Method::GET, "/_ping") => text(StatusCode::OK, "OK"),
        (&Method::GET, "/version") => {
            json(StatusCode::OK, crate::serve::handlers::version_json())
        }
        (&Method::GET, "/info") => {
            json(StatusCode::OK, crate::serve::handlers::info_json())
        }
        (&Method::POST, "/containers/create") => {
            let name = query_param(&query, "name");
            let (status, body) =
                crate::serve::handlers::create_container(&body_bytes, name.as_deref());
            json(
                StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                body,
            )
        }
        (&Method::POST, p) if container_action(p).map(|(_, a)| a) == Some("start") => {
            let id = container_action(p).map(|(id, _)| id).unwrap_or_default();
            let (status, body) = crate::serve::handlers::start_container(id);
            json(StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR), body)
        }
        _ => text(StatusCode::NOT_FOUND, "page not found"),
    };
    Ok(resp)
}
