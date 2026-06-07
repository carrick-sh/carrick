//! Endpoint handlers: translate an HTTP request into a registry/spawn action
//! and a JSON response body. Each returns the body bytes; the router wraps them
//! in a response with the right status.

use crate::serve::model::{
    ContainerSummary, CreateBody, CreateResponse, ExecCreateBody, ExecCreateResponse,
    ExecInspectResponse, ExecStartBody, HostConfigSummary, ImageInspectResponse, ImageSummary,
    InfoResponse, NetworkSettingsSummary, TopResponse, VersionResponse, WaitResponse,
};
use hyper::body::{Bytes, Frame};
use hyper::{Response, StatusCode};
use std::collections::HashMap;
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
    let binds = req
        .host_config
        .as_ref()
        .and_then(|hc| hc.binds.as_ref())
        .cloned()
        .unwrap_or_default();
    let opts = crate::serve::spawn::CreateContainerOpts {
        name,
        env: &env,
        workdir: req.working_dir.as_deref(),
        tty: req.tty.unwrap_or(false),
        interactive: req.open_stdin.unwrap_or(false),
        user: req.user.as_deref(),
        entrypoint: req.entrypoint.as_deref(),
        binds: &binds,
    };
    match crate::serve::spawn::create_container(&image, &cmd, &opts) {
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

/// Docker returns 204 No Content on a successful remove.
pub(crate) fn remove_container(id: &str) -> (u16, String) {
    match crate::serve::spawn::remove_container(id) {
        Ok(()) => (204, String::new()),
        Err(e) => (500, error_json(&e.to_string())),
    }
}

pub(crate) fn error_json(msg: &str) -> String {
    format!(
        "{{\"message\":{}}}",
        serde_json::to_string(msg).unwrap_or_else(|_| "\"\"".to_string())
    )
}

pub(crate) fn list_containers(all: bool) -> (u16, String) {
    let mut containers = carrick_runtime::container::list();
    // Stable, newest-first by creation time.
    containers.sort_by_key(|c| std::cmp::Reverse(c.created_secs));

    let rows: Vec<ContainerSummary> = containers
        .iter()
        .map(|c| {
            let status = carrick_runtime::container::reconciled_status(c);
            let state_str = match status {
                carrick_runtime::container::ContainerStatus::Created => "created",
                carrick_runtime::container::ContainerStatus::Running => "running",
                carrick_runtime::container::ContainerStatus::Exited => "exited",
            };
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
            ContainerSummary {
                id: c.id.clone(),
                names: vec![format!("/{}", name_str)],
                image: c.image.clone(),
                image_id: c.image.clone(),
                command: c.command.join(" "),
                created: c.created_secs as i64,
                ports: vec![],
                labels: std::collections::HashMap::new(),
                state: state_str.to_string(),
                status: status_str,
                host_config: HostConfigSummary {
                    network_mode: "host".to_string(),
                },
                network_settings: NetworkSettingsSummary {
                    networks: std::collections::HashMap::new(),
                },
            }
        })
        .filter(|c| all || c.state == "running")
        .collect();

    (
        200,
        serde_json::to_string(&rows).unwrap_or_else(|_| "[]".to_string()),
    )
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
