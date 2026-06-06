# carrick serve M0 — Engine-API socket handshake + basic lifecycle — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `carrick serve --docker-api`, an optional unix-socket server that answers the minimal Docker Engine API (`/_ping`, `/version`, `/info`, container create/start/wait/delete) by reusing carrick's daemonless on-disk registry and detached-fork lifecycle — proven by a bollard client that creates, starts, waits on, and removes an `ubuntu:24.04 echo hi` container over the socket.

**Architecture:** Server-as-translator. The server runs its own multi-thread tokio runtime (a *separate* command from the single-threaded `run` path, so it never forks in-process — honoring the no-tokio-main invariant). It spawns containers by shelling out to the existing `carrick` binary (`run -d --name <id>`), which does its own single-threaded fork; it answers queries by reading the on-disk registry via `carrick_runtime::container::*` directly. It owns no container lifetime — killing the server leaves detached containers running.

**Tech Stack:** Rust, `hyper` 1.x + `hyper-util` (HTTP/1 server), `tokio` `UnixListener` (`net` + `rt-multi-thread` features), `http-body-util`, `serde`/`serde_json` for API bodies. Tests use `bollard` (Docker API client) + `tempfile`, both already dev-deps.

**Scope note:** This is milestone **M0** of the `carrick serve` goal (`docs/superpowers/specs/2026-06-05-carrick-serve-engine-api-design.md`). M1–M5 (labels, split-stream logs, syscall-NAT, compose, docker-CLI parity, Ryuk, matrix) each get their own plan once their predecessor lands. M0 deliberately uses **host-identity ports** (no NAT yet) and does **not** implement labels, logs, exec, or events.

---

## File Structure

**New files (all under `crates/carrick-cli/src/serve/`):**
- `mod.rs` — the `serve` entry point: build the multi-thread runtime, bind the socket, accept loop. One responsibility: process/runtime/socket lifecycle.
- `router.rs` — `(method, path)` → handler dispatch; the `hyper` `service_fn`. One responsibility: HTTP routing + error→HTTP mapping.
- `handlers.rs` — the endpoint handler functions. One responsibility: translate an HTTP request into a registry/spawn action and a JSON response.
- `spawn.rs` — container spawn (shell out to `carrick run -d`) + registry reads (`wait`, `remove`). One responsibility: the bridge to the existing lifecycle/registry.
- `model.rs` — `serde` structs for request/response bodies. One responsibility: the wire schema.

**Modified files:**
- `Cargo.toml` (workspace) — add `hyper`, `hyper-util`, `http-body-util` to `[workspace.dependencies]`; widen `tokio` features.
- `crates/carrick-cli/Cargo.toml` — depend on the above.
- `crates/carrick-cli/src/args.rs` — add the `Serve` subcommand variant.
- `crates/carrick-cli/src/commands.rs` — add the `Commands::Serve { .. }` match arm.
- `crates/carrick-cli/src/main.rs` — `mod serve;`.

**Test file:**
- `crates/carrick-cli/tests/serve.rs` — bollard integration tests.

---

## Task 0: Verify the CLI lifecycle foundation the server reuses

This is a verification spike, not code. The server stands on `carrick run -d` + the registry; confirm they work end-to-end before building on them.

- [ ] **Step 1: Build the signed binary**

Run: `just build`
Expected: a codesigned `target/release/carrick` (a bare `cargo build` fails every run with `HV_DENIED`).

- [ ] **Step 2: Exercise the detached lifecycle by hand**

Run:
```bash
ID=$(./target/release/carrick run -d --name m0probe ubuntu:24.04 /bin/echo hi)
echo "id=$ID"
./target/release/carrick ps -a
sleep 2
./target/release/carrick logs "$ID" || true
./target/release/carrick rm -f "$ID"
```
Expected: `run -d` prints a container id and frees the shell; `ps -a` shows the container; after it exits, `logs` replays `hi`; `rm -f` removes it. If `run -d` requires an explicit `--fs host`, record that — the spawn helper in Task 6 must pass it. (Default is `--fs host` for the container path per `args.rs:83-85`, so no flag is expected to be needed.)

- [ ] **Step 3: Note the registry location**

Run: `ls "$(./target/release/carrick run --help >/dev/null 2>&1; echo)"; ls -d "$TMPDIR"/carrick/containers 2>/dev/null || ls -d /tmp/carrick/containers 2>/dev/null || true`
Expected: confirm the per-user `containers/` registry dir exists (its root is `carrick_runtime::container::registry_root()`). No code change; this just confirms reads will find entries.

No commit (verification only).

---

## Task 1: Add the hyper/tokio dependencies

**Files:**
- Modify: `Cargo.toml` (workspace `[workspace.dependencies]`)
- Modify: `crates/carrick-cli/Cargo.toml`

- [ ] **Step 1: Add the server stack to workspace deps**

In `Cargo.toml` under `[workspace.dependencies]`, add (versions match `Cargo.lock`, which already resolves them via bollard):
```toml
hyper = { version = "1", features = ["server", "http1"] }
hyper-util = { version = "0.1", features = ["tokio", "server"] }
http-body-util = "0.1"
```
And widen the existing `tokio` line to include the server features:
```toml
tokio = { version = "1.48.0", features = ["fs", "io-util", "macros", "rt", "rt-multi-thread", "net"] }
```

- [ ] **Step 2: Depend on them in the CLI crate**

In `crates/carrick-cli/Cargo.toml` under `[dependencies]`, add:
```toml
hyper.workspace = true
hyper-util.workspace = true
http-body-util.workspace = true
```

- [ ] **Step 3: Verify the workspace still builds**

Run: `cargo build -p carrick-cli`
Expected: PASS (compiles; no new code uses the deps yet, so this only proves the manifest resolves).

- [ ] **Step 4: Commit**

```bash
git add Cargo.toml crates/carrick-cli/Cargo.toml Cargo.lock
git commit -m "build(serve): add hyper/tokio server deps for carrick serve"
```

---

## Task 2: Wire the `serve` subcommand (stub)

**Files:**
- Modify: `crates/carrick-cli/src/args.rs` (the `Commands` enum, after the `Start` variant ~line 300)
- Modify: `crates/carrick-cli/src/main.rs` (add `mod serve;`)
- Create: `crates/carrick-cli/src/serve/mod.rs`
- Modify: `crates/carrick-cli/src/commands.rs` (add the match arm)
- Test: `crates/carrick-cli/tests/serve.rs`

- [ ] **Step 1: Write the failing test**

Create `crates/carrick-cli/tests/serve.rs`:
```rust
use assert_cmd::Command;

#[test]
fn serve_help_lists_docker_api_flag() {
    Command::cargo_bin("carrick")
        .unwrap()
        .args(["serve", "--help"])
        .assert()
        .success()
        .stdout(predicates::str::contains("--docker-api"));
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test -p carrick-cli --test serve serve_help_lists_docker_api_flag`
Expected: FAIL — `serve` is not a recognized subcommand.

- [ ] **Step 3: Add the `Serve` variant**

In `crates/carrick-cli/src/args.rs`, add to the `Commands` enum:
```rust
    /// Run an optional Docker Engine API server over a unix socket
    /// (`DOCKER_HOST=unix://<host>`). Daemonless: a translator over the on-disk
    /// container registry, not a resident owner of containers.
    Serve {
        /// Answer the Docker Engine HTTP API (required; reserved for future
        /// protocols).
        #[arg(long = "docker-api")]
        docker_api: bool,
        /// Unix socket path to listen on.
        #[arg(long = "host", value_name = "PATH", default_value = "/tmp/carrick.sock")]
        host: String,
    },
```

- [ ] **Step 4: Create the stub module**

Create `crates/carrick-cli/src/serve/mod.rs`:
```rust
//! `carrick serve --docker-api`: an optional Docker Engine API server over a
//! unix socket. Server-as-translator — see
//! docs/superpowers/specs/2026-06-05-carrick-serve-engine-api-design.md.

/// Entry point for `carrick serve`. Runs its own multi-thread tokio runtime so
/// the (single-threaded, fork-based) `run` path is untouched.
pub(crate) fn serve(docker_api: bool, host: String) -> anyhow::Result<()> {
    if !docker_api {
        anyhow::bail!("carrick serve currently supports only --docker-api");
    }
    anyhow::bail!("carrick serve --docker-api: not yet implemented (host {host})")
}
```

- [ ] **Step 5: Declare the module and dispatch**

In `crates/carrick-cli/src/main.rs`, add alongside the other `mod` lines:
```rust
mod serve;
```
In `crates/carrick-cli/src/commands.rs`, add a match arm next to the other `Commands::*` arms:
```rust
        Commands::Serve { docker_api, host } => crate::serve::serve(docker_api, host),
```

- [ ] **Step 6: Run the test to verify it passes**

Run: `cargo test -p carrick-cli --test serve serve_help_lists_docker_api_flag`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add crates/carrick-cli/src/args.rs crates/carrick-cli/src/main.rs \
        crates/carrick-cli/src/serve/mod.rs crates/carrick-cli/src/commands.rs \
        crates/carrick-cli/tests/serve.rs
git commit -m "feat(serve): add carrick serve --docker-api subcommand stub"
```

---

## Task 3: The keystone — unix-socket hyper server answering `GET /_ping`

This proves the whole stack: socket bind, hyper HTTP/1, the multi-thread runtime, and that the server path needs no codesigning (no HVF). Everything else hangs off this.

**Files:**
- Modify: `crates/carrick-cli/src/serve/mod.rs`
- Create: `crates/carrick-cli/src/serve/router.rs`
- Test: `crates/carrick-cli/tests/serve.rs`

- [ ] **Step 1: Write the failing test**

Add to `crates/carrick-cli/tests/serve.rs`:
```rust
use std::time::Duration;

/// Spawn `carrick serve` on a temp socket, return (child, socket_path, tempdir).
fn spawn_server() -> (std::process::Child, String, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("carrick.sock");
    let sock_str = sock.to_str().unwrap().to_string();
    let bin = assert_cmd::cargo::cargo_bin("carrick");
    let child = std::process::Command::new(bin)
        .args(["serve", "--docker-api", "--host", &sock_str])
        .spawn()
        .unwrap();
    // Wait for the socket to appear (server bound).
    for _ in 0..100 {
        if sock.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    (child, sock_str, dir)
}

#[tokio::test]
async fn ping_returns_ok() {
    let (mut child, sock, _dir) = spawn_server();
    let docker = bollard::Docker::connect_with_unix(
        &sock,
        5,
        bollard::API_DEFAULT_VERSION,
    )
    .unwrap();
    let pong = docker.ping().await.unwrap();
    assert_eq!(pong, "OK");
    let _ = child.kill();
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test -p carrick-cli --test serve ping_returns_ok`
Expected: FAIL — the server bails "not yet implemented", the socket never appears, `ping()` errors.

- [ ] **Step 3: Implement the router skeleton**

Create `crates/carrick-cli/src/serve/router.rs`:
```rust
//! HTTP routing for the Docker Engine API server: maps (method, path) to a
//! handler and renders the result as an HTTP response. The Docker API prefixes
//! every path with an optional `/v1.NN` version segment, which we strip.

use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::{Method, Request, Response, StatusCode};

/// Strip a leading `/v1.43`-style version segment, returning the bare path.
fn strip_version(path: &str) -> &str {
    if let Some(rest) = path.strip_prefix("/v") {
        if let Some(slash) = rest.find('/') {
            // Only strip if the segment looks like a version (digits/dots).
            let (ver, tail) = rest.split_at(slash);
            if ver.chars().all(|c| c.is_ascii_digit() || c == '.') {
                return tail;
            }
        }
    }
    path
}

fn text(status: StatusCode, body: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .body(Full::new(Bytes::from(body.to_owned())))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::new())))
}

/// The single service entry point. Infallible at the HTTP layer: every handler
/// error becomes a response, never a panic (the no-panic gate).
pub(crate) async fn route(
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    let method = req.method().clone();
    let path = strip_version(req.uri().path()).to_string();

    let resp = match (&method, path.as_str()) {
        (&Method::GET, "/_ping") => text(StatusCode::OK, "OK"),
        _ => text(StatusCode::NOT_FOUND, "page not found"),
    };
    Ok(resp)
}
```

- [ ] **Step 4: Implement the accept loop in `mod.rs`**

Replace the body of `serve` in `crates/carrick-cli/src/serve/mod.rs`:
```rust
//! `carrick serve --docker-api`: an optional Docker Engine API server over a
//! unix socket. Server-as-translator — see
//! docs/superpowers/specs/2026-06-05-carrick-serve-engine-api-design.md.

mod router;

use std::path::Path;

use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::UnixListener;

/// Entry point for `carrick serve`. Runs its own multi-thread tokio runtime so
/// the (single-threaded, fork-based) `run` path is untouched.
pub(crate) fn serve(docker_api: bool, host: String) -> anyhow::Result<()> {
    if !docker_api {
        anyhow::bail!("carrick serve currently supports only --docker-api");
    }
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(serve_loop(&host))
}

async fn serve_loop(host: &str) -> anyhow::Result<()> {
    let sock = Path::new(host);
    // A stale socket file blocks bind(); remove it (best-effort) first.
    if sock.exists() {
        let _ = std::fs::remove_file(sock);
    }
    let listener = UnixListener::bind(sock)?;
    tracing::info!("carrick serve listening on unix://{host}");
    loop {
        let (stream, _addr) = listener.accept().await?;
        let io = TokioIo::new(stream);
        tokio::spawn(async move {
            if let Err(e) = http1::Builder::new()
                .serve_connection(io, service_fn(router::route))
                .await
            {
                tracing::debug!("serve connection ended: {e}");
            }
        });
    }
}
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `cargo test -p carrick-cli --test serve ping_returns_ok`
Expected: PASS (`ping()` returns `"OK"`). Note: this test does **not** require codesigning — the server forks no guest.

- [ ] **Step 6: Verify the no-panic gate**

Run: `cargo clippy -p carrick-cli --all-targets`
Expected: no new `unwrap`/`expect`/`panic` errors in `src/serve/`. (The `.unwrap_or_else` fallback in `text` avoids an unwrap on `Response::builder`.)

- [ ] **Step 7: Commit**

```bash
git add crates/carrick-cli/src/serve/mod.rs crates/carrick-cli/src/serve/router.rs \
        crates/carrick-cli/tests/serve.rs
git commit -m "feat(serve): unix-socket hyper server answering GET /_ping"
```

---

## Task 4: `GET /version` and `GET /info`

bollard negotiates and many clients gate on `/version`'s `ApiVersion`. Return a minimal but well-formed JSON both endpoints' typed clients accept.

**Files:**
- Create: `crates/carrick-cli/src/serve/model.rs`
- Create: `crates/carrick-cli/src/serve/handlers.rs`
- Modify: `crates/carrick-cli/src/serve/router.rs`, `crates/carrick-cli/src/serve/mod.rs`
- Test: `crates/carrick-cli/tests/serve.rs`

- [ ] **Step 1: Write the failing test**

Add to `crates/carrick-cli/tests/serve.rs`:
```rust
#[tokio::test]
async fn version_reports_carrick() {
    let (mut child, sock, _dir) = spawn_server();
    let docker = bollard::Docker::connect_with_unix(
        &sock, 5, bollard::API_DEFAULT_VERSION,
    ).unwrap();
    let v = docker.version().await.unwrap();
    assert_eq!(v.os.as_deref(), Some("linux"));
    assert!(v.api_version.is_some());
    let _ = child.kill();
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test -p carrick-cli --test serve version_reports_carrick`
Expected: FAIL — `/version` returns 404, `version()` errors.

- [ ] **Step 3: Add the model structs**

Create `crates/carrick-cli/src/serve/model.rs`:
```rust
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
```

- [ ] **Step 4: Add the handlers**

Create `crates/carrick-cli/src/serve/handlers.rs`:
```rust
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
```

- [ ] **Step 5: Route to them and declare the modules**

In `crates/carrick-cli/src/serve/mod.rs`, add under the existing `mod router;`:
```rust
mod handlers;
mod model;
```
In `crates/carrick-cli/src/serve/router.rs`, add a JSON helper and the routes. Add this helper next to `text`:
```rust
fn json(status: StatusCode, body: String) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(Full::new(Bytes::from(body)))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::new())))
}
```
And add arms to the `match`:
```rust
        (&Method::GET, "/version") => {
            json(StatusCode::OK, crate::serve::handlers::version_json())
        }
        (&Method::GET, "/info") => {
            json(StatusCode::OK, crate::serve::handlers::info_json())
        }
```

- [ ] **Step 6: Run the test to verify it passes**

Run: `cargo test -p carrick-cli --test serve version_reports_carrick`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add crates/carrick-cli/src/serve/
git commit -m "feat(serve): GET /version and /info"
```

---

## Task 5: `POST /containers/create`

Persist the create intent and return a stable 64-hex `Id` the client uses for start/wait/delete. M0 keeps a Created registry entry by shelling out to `carrick create`.

**Files:**
- Modify: `crates/carrick-cli/src/serve/model.rs`, `handlers.rs`, `router.rs`
- Create: `crates/carrick-cli/src/serve/spawn.rs`
- Test: `crates/carrick-cli/tests/serve.rs`

- [ ] **Step 1: Write the failing test**

Add to `crates/carrick-cli/tests/serve.rs`:
```rust
use bollard::container::CreateContainerOptions;
use bollard::secret::ContainerCreateBody;

#[tokio::test]
async fn create_returns_id() {
    let (mut child, sock, _dir) = spawn_server();
    let docker = bollard::Docker::connect_with_unix(
        &sock, 5, bollard::API_DEFAULT_VERSION,
    ).unwrap();
    let body = ContainerCreateBody {
        image: Some("ubuntu:24.04".to_string()),
        cmd: Some(vec!["/bin/echo".to_string(), "hi".to_string()]),
        ..Default::default()
    };
    let created = docker
        .create_container(
            Some(CreateContainerOptions { name: "m0create".to_string(), ..Default::default() }),
            body,
        )
        .await
        .unwrap();
    assert_eq!(created.id.len(), 64);
    let _ = docker.remove_container("m0create", None).await;
    let _ = child.kill();
}
```
(If the installed `bollard` exposes these types under different paths, adjust the `use` lines; the create call shape is stable.)

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test -p carrick-cli --test serve create_returns_id`
Expected: FAIL — `/containers/create` returns 404.

- [ ] **Step 3: Add the create request/response model**

In `crates/carrick-cli/src/serve/model.rs`, add:
```rust
use serde::Deserialize;

/// The subset of Docker's container-create body M0 consumes.
#[derive(Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct CreateBody {
    pub image: Option<String>,
    pub cmd: Option<Vec<String>>,
    pub env: Option<Vec<String>>,
    pub working_dir: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct CreateResponse {
    pub id: String,
    pub warnings: Vec<String>,
}
```

- [ ] **Step 4: Add the spawn/registry bridge**

Create `crates/carrick-cli/src/serve/spawn.rs`:
```rust
//! The bridge from the API server to the existing CLI lifecycle and on-disk
//! registry. Containers are spawned by shelling out to the `carrick` binary
//! (`run -d`), which performs its own single-threaded fork — so the server's
//! multi-thread tokio runtime never forks a guest in-process.

use std::process::Command;

use carrick_runtime::container;

/// Generate a docker-style 64-hex container id (seeded from pid + nanos).
pub(crate) fn new_id() -> String {
    let pid = std::process::id() as u64;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    container::make_id(pid, nanos)
}

/// Persist a `Created` entry by invoking `carrick create --name <id> <image> <cmd...>`.
/// Returns the server-facing id (== the carrick `--name`, resolvable later).
pub(crate) fn create_container(
    id: &str,
    image: &str,
    cmd: &[String],
    env: &[String],
    workdir: Option<&str>,
) -> anyhow::Result<()> {
    let exe = std::env::current_exe()?;
    let mut c = Command::new(exe);
    c.arg("create").arg("--name").arg(id);
    for e in env {
        c.arg("-e").arg(e);
    }
    if let Some(w) = workdir {
        c.arg("-w").arg(w);
    }
    c.arg(image);
    for a in cmd {
        c.arg(a);
    }
    let out = c.output()?;
    if !out.status.success() {
        anyhow::bail!(
            "carrick create failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(())
}
```

- [ ] **Step 5: Handler + route**

In `crates/carrick-cli/src/serve/handlers.rs`, add:
```rust
use crate::serve::model::{CreateBody, CreateResponse};

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
    let id = crate::serve::spawn::new_id();
    let label = name.unwrap_or(&id).to_string();
    let cmd = req.cmd.unwrap_or_default();
    let env = req.env.unwrap_or_default();
    match crate::serve::spawn::create_container(&label, &image, &cmd, &env, req.working_dir.as_deref()) {
        Ok(()) => {
            let resp = CreateResponse { id: label, warnings: vec![] };
            (201, serde_json::to_string(&resp).unwrap_or_else(|_| "{}".to_string()))
        }
        Err(e) => (500, error_json(&e.to_string())),
    }
}

pub(crate) fn error_json(msg: &str) -> String {
    format!("{{\"message\":{}}}", serde_json::to_string(msg).unwrap_or_else(|_| "\"\"".to_string()))
}
```
In `crates/carrick-cli/src/serve/router.rs`, the router must read the body for POSTs. Change the signature to read the full body before matching. Replace the route function body with:
```rust
    let method = req.method().clone();
    let path = strip_version(req.uri().path()).to_string();
    let query = req.uri().query().unwrap_or("").to_string();
    let body_bytes = match http_body_util::BodyExt::collect(req.into_body()).await {
        Ok(b) => b.to_bytes(),
        Err(_) => Bytes::new(),
    };

    let resp = match (&method, path.as_str()) {
        (&Method::GET, "/_ping") => text(StatusCode::OK, "OK"),
        (&Method::GET, "/version") => json(StatusCode::OK, crate::serve::handlers::version_json()),
        (&Method::GET, "/info") => json(StatusCode::OK, crate::serve::handlers::info_json()),
        (&Method::POST, "/containers/create") => {
            let name = query_param(&query, "name");
            let (status, body) = crate::serve::handlers::create_container(&body_bytes, name.as_deref());
            json(StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR), body)
        }
        _ => text(StatusCode::NOT_FOUND, "page not found"),
    };
    Ok(resp)
```
Add a tiny query parser near `strip_version`:
```rust
fn query_param(query: &str, key: &str) -> Option<String> {
    query.split('&').find_map(|kv| {
        let (k, v) = kv.split_once('=')?;
        if k == key { Some(v.to_string()) } else { None }
    })
}
```
And declare `spawn` in `mod.rs`: add `mod spawn;`.

- [ ] **Step 6: Run the test to verify it passes**

Run: `cargo test -p carrick-cli --test serve create_returns_id`
Expected: PASS (requires `just build` first if the test path uses the release binary; for create, `carrick create` pulls the image — ensure network/`ubuntu:24.04` is reachable, or pre-pull).

- [ ] **Step 7: Commit**

```bash
git add crates/carrick-cli/src/serve/
git commit -m "feat(serve): POST /containers/create over the on-disk registry"
```

---

## Task 6: `POST /containers/{id}/start`

**Files:**
- Modify: `crates/carrick-cli/src/serve/spawn.rs`, `handlers.rs`, `router.rs`
- Test: `crates/carrick-cli/tests/serve.rs`

- [ ] **Step 1: Write the failing test**

Add to `crates/carrick-cli/tests/serve.rs`:
```rust
#[tokio::test]
async fn create_then_start_runs() {
    let (mut child, sock, _dir) = spawn_server();
    let docker = bollard::Docker::connect_with_unix(
        &sock, 5, bollard::API_DEFAULT_VERSION,
    ).unwrap();
    let body = bollard::secret::ContainerCreateBody {
        image: Some("ubuntu:24.04".to_string()),
        cmd: Some(vec!["/bin/echo".to_string(), "hi".to_string()]),
        ..Default::default()
    };
    docker.create_container(
        Some(bollard::container::CreateContainerOptions { name: "m0start".to_string(), ..Default::default() }),
        body,
    ).await.unwrap();
    docker.start_container("m0start", None::<bollard::container::StartContainerOptions<String>>)
        .await
        .unwrap();
    let _ = docker.remove_container("m0start", Some(bollard::container::RemoveContainerOptions { force: true, ..Default::default() })).await;
    let _ = child.kill();
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test -p carrick-cli --test serve create_then_start_runs`
Expected: FAIL — `/containers/{id}/start` returns 404.

- [ ] **Step 3: Add the start bridge**

In `crates/carrick-cli/src/serve/spawn.rs`, add:
```rust
/// Start a previously-created container by relaunching it: `carrick start <id>`.
/// Resolves the server id (the `--name`) to carrick's internal id implicitly.
pub(crate) fn start_container(id: &str) -> anyhow::Result<()> {
    let real = container::resolve(id).map_err(|e| anyhow::anyhow!(e))?;
    let exe = std::env::current_exe()?;
    let out = Command::new(exe).arg("start").arg(&real).output()?;
    if !out.status.success() {
        anyhow::bail!("carrick start failed: {}", String::from_utf8_lossy(&out.stderr));
    }
    Ok(())
}
```

- [ ] **Step 4: Handler + route**

In `crates/carrick-cli/src/serve/handlers.rs`, add:
```rust
/// Returns (status, json-or-empty). Docker returns 204 No Content on success.
pub(crate) fn start_container(id: &str) -> (u16, String) {
    match crate::serve::spawn::start_container(id) {
        Ok(()) => (204, String::new()),
        Err(e) => (500, error_json(&e.to_string())),
    }
}
```
In `crates/carrick-cli/src/serve/router.rs`, the path now has an id segment. Add path-prefix matching after the static arms (before the `_` fallback):
```rust
        (&Method::POST, p) if container_action(p).map(|(_, a)| a) == Some("start") => {
            let id = container_action(p).map(|(id, _)| id).unwrap_or_default();
            let (status, body) = crate::serve::handlers::start_container(id);
            json(StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR), body)
        }
```
Add the helper that parses `/containers/<id>/<action>`:
```rust
/// Parse `/containers/<id>/<action>` into `(id, action)`.
fn container_action(path: &str) -> Option<(&str, &str)> {
    let rest = path.strip_prefix("/containers/")?;
    let (id, action) = rest.split_once('/')?;
    if id.is_empty() || action.is_empty() { return None; }
    Some((id, action))
}
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `just build && cargo test -p carrick-cli --test serve create_then_start_runs`
Expected: PASS (this one runs a real guest, so the binary must be codesigned — `just build`).

- [ ] **Step 6: Commit**

```bash
git add crates/carrick-cli/src/serve/
git commit -m "feat(serve): POST /containers/{id}/start via the detached lifecycle"
```

---

## Task 7: `POST /containers/{id}/wait`

**Files:**
- Modify: `crates/carrick-cli/src/serve/spawn.rs`, `model.rs`, `handlers.rs`, `router.rs`
- Test: `crates/carrick-cli/tests/serve.rs`

- [ ] **Step 1: Write the failing test**

Add to `crates/carrick-cli/tests/serve.rs`:
```rust
use futures_util::stream::StreamExt;

#[tokio::test]
async fn wait_returns_exit_code() {
    let (mut child, sock, _dir) = spawn_server();
    let docker = bollard::Docker::connect_with_unix(
        &sock, 30, bollard::API_DEFAULT_VERSION,
    ).unwrap();
    let body = bollard::secret::ContainerCreateBody {
        image: Some("ubuntu:24.04".to_string()),
        cmd: Some(vec!["/bin/echo".to_string(), "hi".to_string()]),
        ..Default::default()
    };
    docker.create_container(
        Some(bollard::container::CreateContainerOptions { name: "m0wait".to_string(), ..Default::default() }),
        body,
    ).await.unwrap();
    docker.start_container("m0wait", None::<bollard::container::StartContainerOptions<String>>).await.unwrap();
    let mut waits = docker.wait_container("m0wait", None::<bollard::container::WaitContainerOptions<String>>);
    let result = waits.next().await.unwrap().unwrap();
    assert_eq!(result.status_code, 0);
    let _ = docker.remove_container("m0wait", Some(bollard::container::RemoveContainerOptions { force: true, ..Default::default() })).await;
    let _ = child.kill();
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test -p carrick-cli --test serve wait_returns_exit_code`
Expected: FAIL — `/wait` returns 404.

- [ ] **Step 3: Add the wait bridge (poll the registry)**

In `crates/carrick-cli/src/serve/spawn.rs`, add:
```rust
/// Block until the container exits, returning its exit code. Polls the on-disk
/// registry's reconciled status (no daemon push exists). Bounded by `timeout`.
pub(crate) fn wait_container(id: &str, timeout: std::time::Duration) -> anyhow::Result<i32> {
    let real = container::resolve(id).map_err(|e| anyhow::anyhow!(e))?;
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let state = container::ContainerState::load(&real)?;
        if matches!(
            container::reconciled_status(&state),
            container::ContainerStatus::Exited
        ) {
            return Ok(state.exit_code.unwrap_or(0));
        }
        if std::time::Instant::now() >= deadline {
            anyhow::bail!("wait timed out for {id}");
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}
```

- [ ] **Step 4: Model + handler + route**

In `crates/carrick-cli/src/serve/model.rs`, add:
```rust
#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct WaitResponse {
    pub status_code: i64,
}
```
In `crates/carrick-cli/src/serve/handlers.rs`, add:
```rust
use crate::serve::model::WaitResponse;

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
```
In `crates/carrick-cli/src/serve/router.rs`, add an arm next to the `start` arm:
```rust
        (&Method::POST, p) if container_action(p).map(|(_, a)| a) == Some("wait") => {
            let id = container_action(p).map(|(id, _)| id).unwrap_or_default();
            // Run the blocking registry poll off the async reactor.
            let id_owned = id.to_string();
            let (status, body) = tokio::task::spawn_blocking(move || {
                crate::serve::handlers::wait_container(&id_owned)
            })
            .await
            .unwrap_or((500, crate::serve::handlers::error_json("wait task panicked")));
            json(StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR), body)
        }
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `just build && cargo test -p carrick-cli --test serve wait_returns_exit_code`
Expected: PASS (`status_code == 0`).

- [ ] **Step 6: Commit**

```bash
git add crates/carrick-cli/src/serve/
git commit -m "feat(serve): POST /containers/{id}/wait (registry poll)"
```

---

## Task 8: `DELETE /containers/{id}`

**Files:**
- Modify: `crates/carrick-cli/src/serve/spawn.rs`, `handlers.rs`, `router.rs`
- Test: `crates/carrick-cli/tests/serve.rs`

- [ ] **Step 1: Write the failing test**

Add to `crates/carrick-cli/tests/serve.rs`:
```rust
#[tokio::test]
async fn delete_removes_container() {
    let (mut child, sock, _dir) = spawn_server();
    let docker = bollard::Docker::connect_with_unix(
        &sock, 30, bollard::API_DEFAULT_VERSION,
    ).unwrap();
    let body = bollard::secret::ContainerCreateBody {
        image: Some("ubuntu:24.04".to_string()),
        cmd: Some(vec!["/bin/echo".to_string(), "hi".to_string()]),
        ..Default::default()
    };
    docker.create_container(
        Some(bollard::container::CreateContainerOptions { name: "m0del".to_string(), ..Default::default() }),
        body,
    ).await.unwrap();
    docker.remove_container("m0del", Some(bollard::container::RemoveContainerOptions { force: true, ..Default::default() }))
        .await
        .unwrap();
    let _ = child.kill();
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test -p carrick-cli --test serve delete_removes_container`
Expected: FAIL — DELETE returns 404.

- [ ] **Step 3: Add the remove bridge**

In `crates/carrick-cli/src/serve/spawn.rs`, add:
```rust
/// Remove a container: `carrick rm -f <id>` (force-kills if running, then drops
/// the registry entry). Reused rather than reimplemented so kill/grace/cleanup
/// stay identical to the CLI.
pub(crate) fn remove_container(id: &str) -> anyhow::Result<()> {
    let real = container::resolve(id).map_err(|e| anyhow::anyhow!(e))?;
    let exe = std::env::current_exe()?;
    let out = Command::new(exe).arg("rm").arg("-f").arg(&real).output()?;
    if !out.status.success() {
        anyhow::bail!("carrick rm failed: {}", String::from_utf8_lossy(&out.stderr));
    }
    Ok(())
}
```
(Task 0 confirms `carrick rm -f` exists; if the verb differs, adjust here only.)

- [ ] **Step 4: Handler + route**

In `crates/carrick-cli/src/serve/handlers.rs`, add:
```rust
pub(crate) fn remove_container(id: &str) -> (u16, String) {
    match crate::serve::spawn::remove_container(id) {
        Ok(()) => (204, String::new()),
        Err(e) => (500, error_json(&e.to_string())),
    }
}
```
In `crates/carrick-cli/src/serve/router.rs`, add an arm (DELETE has no `/action` suffix — match the bare `/containers/<id>`):
```rust
        (&Method::DELETE, p) if p.strip_prefix("/containers/").is_some_and(|s| !s.is_empty() && !s.contains('/')) => {
            let id = p.strip_prefix("/containers/").unwrap_or_default();
            let (status, body) = crate::serve::handlers::remove_container(id);
            json(StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR), body)
        }
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `just build && cargo test -p carrick-cli --test serve delete_removes_container`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/carrick-cli/src/serve/
git commit -m "feat(serve): DELETE /containers/{id}"
```

---

## Task 9: End-to-end milestone test + docs

The M0 exit criterion: the full create→start→wait→remove loop over the socket, plus the daemonless-survival invariant.

**Files:**
- Test: `crates/carrick-cli/tests/serve.rs`
- Modify: `docs/superpowers/specs/2026-06-05-carrick-serve-engine-api-design.md` (tick M0)

- [ ] **Step 1: Write the end-to-end test**

Add to `crates/carrick-cli/tests/serve.rs`:
```rust
#[tokio::test]
async fn m0_full_lifecycle_echo_hi() {
    let (mut child, sock, _dir) = spawn_server();
    let docker = bollard::Docker::connect_with_unix(
        &sock, 60, bollard::API_DEFAULT_VERSION,
    ).unwrap();
    assert_eq!(docker.ping().await.unwrap(), "OK");

    let body = bollard::secret::ContainerCreateBody {
        image: Some("ubuntu:24.04".to_string()),
        cmd: Some(vec!["/bin/echo".to_string(), "hi".to_string()]),
        ..Default::default()
    };
    let created = docker.create_container(
        Some(bollard::container::CreateContainerOptions { name: "m0e2e".to_string(), ..Default::default() }),
        body,
    ).await.unwrap();
    assert_eq!(created.id.len(), 64);

    docker.start_container("m0e2e", None::<bollard::container::StartContainerOptions<String>>).await.unwrap();

    let mut waits = docker.wait_container("m0e2e", None::<bollard::container::WaitContainerOptions<String>>);
    let result = waits.next().await.unwrap().unwrap();
    assert_eq!(result.status_code, 0);

    docker.remove_container("m0e2e", Some(bollard::container::RemoveContainerOptions { force: true, ..Default::default() })).await.unwrap();
    let _ = child.kill();
}
```

- [ ] **Step 2: Run the full serve test suite**

Run: `just build && cargo test -p carrick-cli --test serve`
Expected: all tests PASS (ping, version, create, start, wait, delete, full lifecycle).

- [ ] **Step 3: Manually confirm the daemonless-survival invariant**

Run:
```bash
./target/release/carrick serve --docker-api --host /tmp/m0.sock &
SERVER=$!
docker -H unix:///tmp/m0.sock run -d --name m0survive ubuntu:24.04 sleep 30 2>/dev/null \
  || echo "(use bollard if docker CLI negotiation rejects v1.43)"
kill $SERVER
./target/release/carrick ps -a   # m0survive should still be Running/Exited, not gone
./target/release/carrick rm -f m0survive
```
Expected: killing `carrick serve` does NOT kill the container — it remains in `ps -a`. This proves the server owns no container lifetime (acceptance rule 4 in the spec).

- [ ] **Step 4: Tick M0 in the spec**

In `docs/superpowers/specs/2026-06-05-carrick-serve-engine-api-design.md`, under "### M0 — Socket handshake", append a line:
```markdown
**Landed 2026-06-05:** `carrick serve --docker-api` answers `/_ping`/`/version`/`/info` and the create/start/wait/delete loop over a unix socket; proven by `crates/carrick-cli/tests/serve.rs::m0_full_lifecycle_echo_hi` and the daemonless-survival check.
```

- [ ] **Step 5: Commit**

```bash
git add crates/carrick-cli/tests/serve.rs docs/superpowers/specs/2026-06-05-carrick-serve-engine-api-design.md
git commit -m "test(serve): M0 end-to-end create/start/wait/remove over the socket"
```

---

## Self-Review

**1. Spec coverage (M0 section of the design doc):**
- "answers `GET /_ping` + `/version` + `/info`" → Tasks 3, 4. ✓
- "POST `/containers/create` + `/{id}/start` + `/{id}/wait` + `DELETE /containers/{id}`" → Tasks 5, 6, 7, 8. ✓
- "demonstrated by a bollard client that creates, starts, waits on, and removes an `ubuntu:24.04 echo hi` container" → Task 9. ✓
- "the no-tokio-main fork isolation is proven (forks via the lifecycle path, not a tokio worker)" → architecture: every container action shells out to the `carrick` binary (`spawn.rs`), so the server process never forks a guest. The daemonless-survival check (Task 9 Step 3) exercises this. ✓
- Out of M0 scope (labels, split-stream logs, exec, events, NAT, Ryuk) → not attempted; called out in the plan's scope note. ✓

**2. Placeholder scan:** No "TBD"/"handle errors appropriately"/"similar to Task N". Every code step shows the actual code. The two bollard-type-path caveats (Tasks 5, 8) are explicit "adjust the `use`/verb here only" notes, not missing logic.

**3. Type consistency:** `create_container`/`start_container`/`wait_container`/`remove_container` names are identical across `spawn.rs` (the bridge) and `handlers.rs` (the wrappers); `error_json` defined once (Task 5) and reused; `container_action` defined once (Task 6) and reused (Task 7); `json`/`text` helpers defined in Task 3/4 and reused throughout; `CreateResponse.id`/`WaitResponse.status_code` field names match the handler construction sites. The router's `route` signature is established in Task 3 and only its `match` body grows.

**4. Known execution risks (flagged, not placeholders):** (a) bollard's exact module paths for `ContainerCreateBody`/`CreateContainerOptions` vary by version — the plan says adjust the `use` lines only. (b) `carrick create`/`start`/`rm -f` verb spellings are confirmed in Task 0 before the bridge code relies on them. (c) Image pull needs network or a pre-pulled `ubuntu:24.04`. None of these change the task structure.
