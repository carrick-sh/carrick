//! HTTP routing for the Docker Engine API server: maps (method, path) to a
//! handler and renders the result as an HTTP response. The Docker API prefixes
//! every path with an optional `/v1.NN` version segment, which we strip.

use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::{Method, Request, Response, StatusCode};

/// The server's unified response body. Buffered endpoints wrap their
/// `Full<Bytes>` via [`boxed`]; `/build` streams via `http_body_util::StreamBody`.
/// Boxing both behind one type lets `route` return a single body type while
/// still streaming where needed.
pub(crate) type ResponseBody = BoxBody<Bytes, std::io::Error>;

/// Wrap a buffered `Full<Bytes>` response as the boxed `ResponseBody`. `Full`'s
/// error is `Infallible`, so the `map_err` arm is unreachable; this only adapts
/// the error type to `io::Error` so it unifies with the streaming body.
fn boxed(resp: Response<Full<Bytes>>) -> Response<ResponseBody> {
    resp.map(|body| body.map_err(|never| match never {}).boxed())
}

/// Strip a leading `/v1.43`-style version segment, returning the bare path.
fn strip_version(path: &str) -> &str {
    if let Some(rest) = path.strip_prefix("/v")
        && let Some(slash) = rest.find('/')
    {
        // Only strip if the segment looks like a version (digits/dots).
        let (ver, tail) = rest.split_at(slash);
        if !ver.is_empty() && ver.chars().all(|c| c.is_ascii_digit() || c == '.') {
            return tail;
        }
    }
    path
}

/// Parse `/containers/<id>/<action>` into `(id, action)`.
fn container_action(path: &str) -> Option<(&str, &str)> {
    let rest = path.strip_prefix("/containers/")?;
    let (id, action) = rest.split_once('/')?;
    if id.is_empty() || action.is_empty() {
        return None;
    }
    Some((id, action))
}

/// Pull a single `key=value` out of a raw query string (`a=1&b=2`).
pub(crate) fn query_param(query: &str, key: &str) -> Option<String> {
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
/// error becomes a response, never a panic (the no-panic gate). The response
/// body is the boxed [`ResponseBody`]: buffered endpoints box their
/// `Full<Bytes>`, while `/build` streams.
pub(crate) async fn route(
    req: Request<Incoming>,
) -> Result<Response<ResponseBody>, std::convert::Infallible> {
    let method = req.method().clone();
    let path = strip_version(req.uri().path()).to_string();
    let query = req.uri().query().unwrap_or("").to_string();

    // `/build`'s request body is a (potentially large) gzipped tar streamed
    // back as NDJSON; it is the only streaming endpoint. Handle it before the
    // buffered dispatch so its response body stays unboxed-but-streaming.
    if method == Method::POST && path == "/build" {
        let body_bytes = match BodyExt::collect(req.into_body()).await {
            Ok(b) => b.to_bytes(),
            Err(_) => Bytes::new(),
        };
        return Ok(crate::serve::build::build_response(&query, body_bytes));
    }

    if method == Method::GET && container_action(&path).map(|(_, a)| a) == Some("logs") {
        let id = container_action(&path)
            .map(|(id, _)| id)
            .unwrap_or_default()
            .to_string();
        let follow = query_param(&query, "follow").is_some_and(|v| v == "true" || v == "1");
        let tail = query_param(&query, "tail").and_then(|v| v.parse::<usize>().ok());
        return Ok(crate::serve::handlers::logs_container(id, follow, tail));
    }

    if method == Method::POST && path == "/images/create" {
        return Ok(crate::serve::handlers::pull_image(&query));
    }

    if method == Method::POST && path.starts_with("/exec/") && path.ends_with("/start") {
        let exec_id = path
            .strip_prefix("/exec/")
            .and_then(|s| s.strip_suffix("/start"))
            .unwrap_or_default()
            .to_string();
        return Ok(crate::serve::handlers::start_exec_route(exec_id, req).await);
    }

    let body_bytes = match BodyExt::collect(req.into_body()).await {
        Ok(b) => b.to_bytes(),
        Err(_) => Bytes::new(),
    };

    let resp = match (&method, path.as_str()) {
        (&Method::GET, "/_ping") | (&Method::HEAD, "/_ping") => text(StatusCode::OK, "OK"),
        (&Method::GET, "/version") => json(StatusCode::OK, crate::serve::handlers::version_json()),
        (&Method::GET, "/info") => json(StatusCode::OK, crate::serve::handlers::info_json()),
        (&Method::GET, "/containers/json") => {
            let all = query_param(&query, "all").is_some_and(|v| v == "true" || v == "1");
            let (status, body) = crate::serve::handlers::list_containers(all);
            json(
                StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                body,
            )
        }
        (&Method::GET, p) if container_action(p).map(|(_, a)| a) == Some("json") => {
            let id = container_action(p).map(|(id, _)| id).unwrap_or_default();
            let (status, body) = crate::serve::handlers::inspect_container(id);
            json(
                StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                body,
            )
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
            json(
                StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                body,
            )
        }
        (&Method::POST, p) if container_action(p).map(|(_, a)| a) == Some("stop") => {
            let id = container_action(p).map(|(id, _)| id).unwrap_or_default();
            let t = query_param(&query, "t").and_then(|v| v.parse::<u64>().ok());
            let (status, body) = crate::serve::handlers::stop_container(id, t);
            json(
                StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                body,
            )
        }
        (&Method::POST, p) if container_action(p).map(|(_, a)| a) == Some("kill") => {
            let id = container_action(p).map(|(id, _)| id).unwrap_or_default();
            let signal = query_param(&query, "signal");
            let (status, body) = crate::serve::handlers::kill_container(id, signal.as_deref());
            json(
                StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                body,
            )
        }
        (&Method::POST, p) if container_action(p).map(|(_, a)| a) == Some("restart") => {
            let id = container_action(p).map(|(id, _)| id).unwrap_or_default();
            let t = query_param(&query, "t").and_then(|v| v.parse::<u64>().ok());
            let (status, body) = crate::serve::handlers::restart_container(id, t);
            json(
                StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                body,
            )
        }
        (&Method::POST, p) if container_action(p).map(|(_, a)| a) == Some("wait") => {
            let id_owned = container_action(p)
                .map(|(id, _)| id.to_string())
                .unwrap_or_default();
            let (status, body) = tokio::task::spawn_blocking(move || {
                crate::serve::handlers::wait_container(&id_owned)
            })
            .await
            .unwrap_or((
                500,
                crate::serve::handlers::error_json("wait task panicked"),
            ));
            json(
                StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                body,
            )
        }
        (&Method::DELETE, p)
            if p.strip_prefix("/containers/")
                .is_some_and(|s| !s.is_empty() && !s.contains('/')) =>
        {
            let id = p.strip_prefix("/containers/").unwrap_or_default();
            let (status, body) = crate::serve::handlers::remove_container(id);
            json(
                StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                body,
            )
        }
        (&Method::GET, "/images/json") => {
            let (status, body) = crate::serve::handlers::list_images();
            json(
                StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                body,
            )
        }
        (&Method::GET, p)
            if p.starts_with("/images/") && p.ends_with("/json") && p != "/images/json" =>
        {
            let name = p
                .strip_prefix("/images/")
                .and_then(|s| s.strip_suffix("/json"))
                .unwrap_or_default();
            let (status, body) = crate::serve::handlers::inspect_image(name);
            json(
                StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                body,
            )
        }
        (&Method::POST, p) if p.starts_with("/images/") && p.ends_with("/tag") => {
            let name = p
                .strip_prefix("/images/")
                .and_then(|s| s.strip_suffix("/tag"))
                .unwrap_or_default();
            let repo = query_param(&query, "repo").unwrap_or_default();
            let tag = query_param(&query, "tag").unwrap_or_default();
            let (status, body) = crate::serve::handlers::tag_image(name, &repo, &tag);
            json(
                StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                body,
            )
        }
        (&Method::DELETE, p) if p.strip_prefix("/images/").is_some_and(|s| !s.is_empty()) => {
            let name = p.strip_prefix("/images/").unwrap_or_default();
            let (status, body) = crate::serve::handlers::remove_image(name);
            json(
                StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                body,
            )
        }
        (&Method::GET, p) if p.starts_with("/exec/") && p.ends_with("/json") => {
            let exec_id = p
                .strip_prefix("/exec/")
                .and_then(|s| s.strip_suffix("/json"))
                .unwrap_or_default();
            let (status, body) = crate::serve::handlers::inspect_exec(exec_id);
            json(
                StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                body,
            )
        }
        (&Method::POST, p) if container_action(p).map(|(_, a)| a) == Some("exec") => {
            let id = container_action(p).map(|(id, _)| id).unwrap_or_default();
            let (status, body) = crate::serve::handlers::create_exec(&body_bytes, id);
            json(
                StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                body,
            )
        }
        (&Method::POST, p) if container_action(p).map(|(_, a)| a) == Some("rename") => {
            let id = container_action(p).map(|(id, _)| id).unwrap_or_default();
            let new_name = query_param(&query, "name").unwrap_or_default();
            let (status, body) = crate::serve::handlers::rename_container(id, &new_name);
            json(
                StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                body,
            )
        }
        (&Method::GET, p) if container_action(p).map(|(_, a)| a) == Some("top") => {
            let id = container_action(p).map(|(id, _)| id).unwrap_or_default();
            let (status, body) = crate::serve::handlers::top_container(id);
            json(
                StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                body,
            )
        }
        _ => text(StatusCode::NOT_FOUND, "page not found"),
    };
    Ok(boxed(resp))
}
