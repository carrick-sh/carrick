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
