//! Public-Carrier fixture for the scoped signed namespace work binding.
use crate::EmbedError;
use std::path::Path;

/// Execute two live Linux actors. The surrounding registered trace binding
/// supplies exact host-call and owned path-visit observations, not API counters.
pub fn host_namespace_fixture(
    image: &str,
    probes: &Path,
    scale: u64,
    population: u64,
    parents: &str,
) -> Result<String, EmbedError> {
    if ![1, 8, 32, 128].contains(&scale)
        || ![0, 128].contains(&population)
        || !["same", "unrelated"].contains(&parents)
        || !image.split_once("@sha256:").is_some_and(|(_, digest)| {
            digest.len() == 64
                && digest
                    .bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        })
    {
        return Err(EmbedError::Config(
            "unregistered namespace fixture parameters".into(),
        ));
    }
    if !probes.join("perf_namespace_scale").is_file() {
        return Err(EmbedError::Config(
            "namespace fixture executable missing".into(),
        ));
    }
    let probes = probes
        .canonicalize()
        .map_err(|error| EmbedError::Config(error.to_string()))?;
    let carrier = crate::Carrier::new()?;
    let result = carrier
        .container(image)
        .pull_policy(crate::PullPolicy::Never)
        .mount_readonly(probes.to_string_lossy(), "/p")
        .command([
            "/bin/sh".into(),
            "-c".into(),
            format!("/p/perf_namespace_scale {scale} {population} {parents}"),
        ])
        .run_blocking();
    let shutdown = carrick_engine::block_on_oci(carrier.shutdown());
    let result = result?;
    shutdown?;
    let stdout = result.ensure_success()?.stdout_utf8();
    let expected = format!(
        "namespace_scale={scale}\nnamespace_population={population}\nnamespace_actors=2\nnamespace_complete=1\n"
    );
    if stdout != expected {
        return Err(EmbedError::Config(format!(
            "incomplete namespace fixture transcript: {stdout:?}"
        )));
    }
    Ok(stdout)
}
