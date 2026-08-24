//! HTTP routing for the Docker Engine API server: maps (method, path) to a
//! handler and renders the result as an HTTP response. The Docker API prefixes
//! every path with an optional `/v1.NN` version segment, which we strip.

use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::{Body, Bytes, Incoming};
use hyper::{Method, Request, Response, StatusCode};
use std::sync::{Arc, LazyLock};

pub(crate) const MAX_HTTP_ARCHIVE_BYTES: usize = 16 * 1024 * 1024;
const MAX_CONCURRENT_ARCHIVE_BODY_BYTES: usize = 32 * 1024 * 1024;
static ARCHIVE_BODY_BUDGET: LazyLock<Arc<tokio::sync::Semaphore>> = LazyLock::new(|| {
    Arc::new(tokio::sync::Semaphore::new(
        MAX_CONCURRENT_ARCHIVE_BODY_BYTES,
    ))
});

#[derive(Debug, Eq, PartialEq)]
enum LimitedBodyError {
    TooLarge,
    Transport(String),
}

async fn collect_limited_body<B>(mut body: B, limit: usize) -> Result<Bytes, LimitedBodyError>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: std::fmt::Display,
{
    let mut bytes = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|error| LimitedBodyError::Transport(error.to_string()))?;
        let Ok(data) = frame.into_data() else {
            continue;
        };
        let next = bytes
            .len()
            .checked_add(data.len())
            .ok_or(LimitedBodyError::TooLarge)?;
        if next > limit {
            return Err(LimitedBodyError::TooLarge);
        }
        bytes.extend_from_slice(&data);
    }
    Ok(Bytes::from(bytes))
}

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

async fn lifecycle_handler(
    operation: impl FnOnce() -> (u16, String) + Send + 'static,
) -> (u16, String) {
    match tokio::task::spawn_blocking(operation).await {
        Ok(response) => response,
        Err(error) => (
            500,
            serde_json::json!({ "message": format!("lifecycle worker failed: {error}") })
                .to_string(),
        ),
    }
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

    if method == Method::POST && container_action(&path).map(|(_, a)| a) == Some("attach") {
        let id = container_action(&path)
            .map(|(id, _)| id)
            .unwrap_or_default()
            .to_string();
        return Ok(crate::serve::handlers::attach_container_route(id, query, req).await);
    }

    if method == Method::POST && container_action(&path).map(|(_, a)| a) == Some("wait") {
        let id = container_action(&path)
            .map(|(id, _)| id)
            .unwrap_or_default()
            .to_string();
        return Ok(crate::serve::handlers::wait_container_stream(id));
    }

    if method == Method::GET && container_action(&path).map(|(_, a)| a) == Some("archive") {
        let id = container_action(&path)
            .map(|(id, _)| id)
            .unwrap_or_default()
            .to_string();
        return Ok(crate::serve::handlers::download_archive_route(id, query).await);
    }

    if method == Method::HEAD && container_action(&path).map(|(_, a)| a) == Some("archive") {
        let id = container_action(&path)
            .map(|(id, _)| id)
            .unwrap_or_default()
            .to_string();
        return Ok(crate::serve::handlers::head_archive_route(id, query).await);
    }

    if method == Method::PUT && container_action(&path).map(|(_, a)| a) == Some("archive") {
        let id = container_action(&path)
            .map(|(id, _)| id)
            .unwrap_or_default()
            .to_string();
        if req
            .headers()
            .get(hyper::header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<usize>().ok())
            .is_some_and(|length| length > MAX_HTTP_ARCHIVE_BYTES)
        {
            return Ok(boxed(json(
                StatusCode::PAYLOAD_TOO_LARGE,
                serde_json::json!({ "message": "archive body is too large" }).to_string(),
            )));
        }
        let budget = match Arc::clone(&ARCHIVE_BODY_BUDGET)
            .acquire_many_owned(MAX_HTTP_ARCHIVE_BYTES as u32)
            .await
        {
            Ok(budget) => budget,
            Err(error) => {
                return Ok(boxed(json(
                    StatusCode::SERVICE_UNAVAILABLE,
                    serde_json::json!({ "message": format!("archive body budget is unavailable: {error}") }).to_string(),
                )));
            }
        };
        let body_bytes = match collect_limited_body(req.into_body(), MAX_HTTP_ARCHIVE_BYTES).await {
            Ok(bytes) => bytes,
            Err(LimitedBodyError::TooLarge) => {
                return Ok(boxed(json(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    serde_json::json!({ "message": "archive body is too large" }).to_string(),
                )));
            }
            Err(LimitedBodyError::Transport(error)) => {
                return Ok(boxed(json(
                    StatusCode::BAD_REQUEST,
                    serde_json::json!({ "message": format!("archive request body failed: {error}") }).to_string(),
                )));
            }
        };
        let response = crate::serve::handlers::upload_archive_route(id, query, body_bytes).await;
        drop(budget);
        return Ok(response);
    }

    if method == Method::GET && path == "/events" {
        return Ok(crate::serve::handlers::events_stream(&query));
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
            let (status, body) = crate::serve::handlers::list_containers(all, &query);
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
            let (status, body) = lifecycle_handler(move || {
                crate::serve::handlers::create_container(&body_bytes, name.as_deref())
            })
            .await;
            json(
                StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                body,
            )
        }
        (&Method::POST, "/networks/create") => {
            let (status, body) = crate::serve::resources::create_network(&body_bytes);
            json(
                StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                body,
            )
        }
        (&Method::POST, "/networks/prune") => {
            let (status, body) = crate::serve::resources::prune_networks(&query);
            json(
                StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                body,
            )
        }
        (&Method::GET, "/networks") => {
            let (status, body) = crate::serve::resources::list_networks(&query);
            json(
                StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                body,
            )
        }
        (&Method::GET, p) if p.strip_prefix("/networks/").is_some_and(|s| !s.is_empty()) => {
            let id = p.strip_prefix("/networks/").unwrap_or_default();
            let (status, body) = crate::serve::resources::inspect_network(id);
            json(
                StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                body,
            )
        }
        (&Method::DELETE, p) if p.strip_prefix("/networks/").is_some_and(|s| !s.is_empty()) => {
            let id = p.strip_prefix("/networks/").unwrap_or_default();
            let (status, body) = crate::serve::resources::remove_network(id);
            json(
                StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                body,
            )
        }
        (&Method::POST, p) if p.starts_with("/networks/") && p.ends_with("/connect") => {
            let id = p
                .strip_prefix("/networks/")
                .and_then(|s| s.strip_suffix("/connect"))
                .unwrap_or_default()
                .trim_end_matches('/');
            let (status, body) = crate::serve::resources::connect_network(id, &body_bytes);
            json(
                StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                body,
            )
        }
        (&Method::POST, p) if p.starts_with("/networks/") && p.ends_with("/disconnect") => {
            let id = p
                .strip_prefix("/networks/")
                .and_then(|s| s.strip_suffix("/disconnect"))
                .unwrap_or_default()
                .trim_end_matches('/');
            let (status, body) = crate::serve::resources::disconnect_network(id, &body_bytes);
            json(
                StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                body,
            )
        }
        (&Method::POST, "/volumes/create") => {
            let (status, body) = crate::serve::resources::create_volume(&body_bytes);
            json(
                StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                body,
            )
        }
        (&Method::POST, "/volumes/prune") => {
            let (status, body) = crate::serve::resources::prune_volumes(&query);
            json(
                StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                body,
            )
        }
        (&Method::GET, "/volumes") => {
            let (status, body) = crate::serve::resources::list_volumes(&query);
            json(
                StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                body,
            )
        }
        (&Method::GET, p) if p.strip_prefix("/volumes/").is_some_and(|s| !s.is_empty()) => {
            let name = p.strip_prefix("/volumes/").unwrap_or_default();
            let (status, body) = crate::serve::resources::inspect_volume(name);
            json(
                StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                body,
            )
        }
        (&Method::DELETE, p) if p.strip_prefix("/volumes/").is_some_and(|s| !s.is_empty()) => {
            let name = p.strip_prefix("/volumes/").unwrap_or_default();
            let force = query_param(&query, "force").is_some_and(|v| v == "true" || v == "1");
            let (status, body) = crate::serve::resources::remove_volume(name, force);
            json(
                StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                body,
            )
        }
        (&Method::POST, p) if container_action(p).map(|(_, a)| a) == Some("start") => {
            let id = container_action(p)
                .map(|(id, _)| id)
                .unwrap_or_default()
                .to_owned();
            let (status, body) =
                lifecycle_handler(move || crate::serve::handlers::start_container(&id)).await;
            json(
                StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                body,
            )
        }
        (&Method::POST, p) if container_action(p).map(|(_, a)| a) == Some("stop") => {
            let id = container_action(p)
                .map(|(id, _)| id)
                .unwrap_or_default()
                .to_owned();
            let t = query_param(&query, "t").and_then(|v| v.parse::<u64>().ok());
            let (status, body) =
                lifecycle_handler(move || crate::serve::handlers::stop_container(&id, t)).await;
            json(
                StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                body,
            )
        }
        (&Method::POST, p) if container_action(p).map(|(_, a)| a) == Some("kill") => {
            let id = container_action(p)
                .map(|(id, _)| id)
                .unwrap_or_default()
                .to_owned();
            let signal = query_param(&query, "signal");
            let (status, body) = lifecycle_handler(move || {
                crate::serve::handlers::kill_container(&id, signal.as_deref())
            })
            .await;
            json(
                StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                body,
            )
        }
        (&Method::POST, p) if container_action(p).map(|(_, a)| a) == Some("restart") => {
            let id = container_action(p)
                .map(|(id, _)| id)
                .unwrap_or_default()
                .to_owned();
            let t = query_param(&query, "t").and_then(|v| v.parse::<u64>().ok());
            let (status, body) =
                lifecycle_handler(move || crate::serve::handlers::restart_container(&id, t)).await;
            json(
                StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                body,
            )
        }
        (&Method::POST, p) if container_action(p).map(|(_, a)| a) == Some("resize") => {
            let id = container_action(p).map(|(id, _)| id).unwrap_or_default();
            let (status, body) = crate::serve::handlers::resize_container_tty(id);
            json(
                StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                body,
            )
        }
        (&Method::DELETE, p)
            if p.strip_prefix("/containers/")
                .is_some_and(|s| !s.is_empty() && !s.contains('/')) =>
        {
            let id = p
                .strip_prefix("/containers/")
                .unwrap_or_default()
                .to_owned();
            let force = query_param(&query, "force").is_some_and(|v| v == "true" || v == "1");
            let remove_volumes = query_param(&query, "v").is_some_and(|v| v == "true" || v == "1");
            let (status, body) = lifecycle_handler(move || {
                crate::serve::handlers::remove_container(&id, force, remove_volumes)
            })
            .await;
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
            let id = container_action(p)
                .map(|(id, _)| id)
                .unwrap_or_default()
                .to_owned();
            let new_name = query_param(&query, "name").unwrap_or_default();
            let (status, body) =
                lifecycle_handler(move || crate::serve::handlers::rename_container(&id, &new_name))
                    .await;
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

#[cfg(test)]
mod archive_body_tests {
    use super::*;
    use hyper::body::Frame;
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll};

    struct TestBody {
        frames: VecDeque<Result<Frame<Bytes>, std::io::Error>>,
        polls: Arc<AtomicUsize>,
    }

    impl Body for TestBody {
        type Data = Bytes;
        type Error = std::io::Error;

        fn poll_frame(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            self.polls.fetch_add(1, Ordering::Relaxed);
            Poll::Ready(self.frames.pop_front())
        }
    }

    fn body(
        frames: impl IntoIterator<Item = Result<Frame<Bytes>, std::io::Error>>,
    ) -> (TestBody, Arc<AtomicUsize>) {
        let polls = Arc::new(AtomicUsize::new(0));
        (
            TestBody {
                frames: frames.into_iter().collect(),
                polls: Arc::clone(&polls),
            },
            polls,
        )
    }

    #[tokio::test]
    async fn archive_body_collector_stops_at_the_first_oversized_chunk() {
        let (body, polls) = body([
            Ok(Frame::data(Bytes::from_static(b"abc"))),
            Ok(Frame::data(Bytes::from_static(b"def"))),
            Ok(Frame::data(Bytes::from_static(b"must-not-be-polled"))),
        ]);

        assert_eq!(
            collect_limited_body(body, 5).await,
            Err(LimitedBodyError::TooLarge)
        );
        assert_eq!(polls.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn archive_body_collector_preserves_transport_errors() {
        let (body, _) = body([
            Ok(Frame::data(Bytes::from_static(b"abc"))),
            Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                "fixture transport loss",
            )),
        ]);

        assert_eq!(
            collect_limited_body(body, 16).await,
            Err(LimitedBodyError::Transport(
                "fixture transport loss".to_owned()
            ))
        );
    }

    #[tokio::test]
    async fn archive_body_collector_preserves_bounded_chunks() {
        let (body, _) = body([
            Ok(Frame::data(Bytes::from_static(b"abc"))),
            Ok(Frame::data(Bytes::from_static(b"def"))),
        ]);

        assert_eq!(
            collect_limited_body(body, 6).await,
            Ok(Bytes::from_static(b"abcdef"))
        );
    }
}
