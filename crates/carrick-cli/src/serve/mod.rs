//! `carrick serve --docker-api`: an optional Docker Engine API server over a
//! unix socket. Server-as-translator — see
//! docs/superpowers/specs/2026-06-05-carrick-serve-engine-api-design.md.

mod handlers;
mod model;
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
    let sock = Path::new(host); // nosemgrep: rust.actix.path-traversal.tainted-path.tainted-path -- `host` is the operator-supplied --host CLI flag, not HTTP user input
    // A stale socket file blocks bind(); remove it (best-effort) first.
    if sock.exists() {
        let _ = std::fs::remove_file(sock);
    }
    let listener = UnixListener::bind(sock)?;
    tracing::info!("carrick serve listening on unix://{host}");
    loop {
        let (stream, _addr) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("carrick serve accept error (continuing): {e}");
                continue;
            }
        };
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
