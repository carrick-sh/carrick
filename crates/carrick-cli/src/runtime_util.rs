//! Shared CLI runtime utilities.

/// When `--raw` is set, emit the guest's buffered stdout/stderr to the
/// carrick host process's fd 1 / fd 2 instead of wrapping them in JSON.
/// This makes carrick feel like a normal command runner: `carrick run
/// alpine /bin/busybox echo hi --raw` prints just `hi`.
pub(crate) fn emit_raw(result: &carrick_runtime::runtime::RunResult) {
    use std::io::Write;
    let _ = std::io::stdout().write_all(&result.stdout);
    let _ = std::io::stderr().write_all(&result.stderr);
    let _ = std::io::stdout().flush();
    let _ = std::io::stderr().flush();
}

pub(crate) fn parse_volume_mount(s: &str) -> anyhow::Result<carrick_spec::Mount> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() < 2 || parts.len() > 3 {
        anyhow::bail!(
            "invalid volume format '{}', expected host_path:guest_path[:ro|rw]",
            s
        );
    }
    let source = camino::Utf8PathBuf::from(parts[0]);
    let target = camino::Utf8PathBuf::from(parts[1]);
    let readonly = if parts.len() == 3 {
        match parts[2] {
            "ro" => true,
            "rw" => false,
            other => anyhow::bail!("invalid volume mode '{}', expected ro or rw", other),
        }
    } else {
        false
    };
    Ok(carrick_spec::Mount {
        source,
        target,
        readonly,
    })
}

pub(crate) fn parse_mount_flag(s: &str) -> anyhow::Result<carrick_spec::Mount> {
    let mut source = None;
    let mut target = None;
    let mut readonly = false;
    for part in s.split(',') {
        if let Some((k, v)) = part.split_once('=') {
            match k {
                "source" | "src" => source = Some(camino::Utf8PathBuf::from(v)),
                "target" | "dst" | "destination" => target = Some(camino::Utf8PathBuf::from(v)),
                "readonly" | "ro" => {
                    readonly = v.parse::<bool>().unwrap_or(true);
                }
                _ => {}
            }
        } else if part == "readonly" {
            readonly = true;
        }
    }
    let source = source.ok_or_else(|| anyhow::anyhow!("mount option missing source: {}", s))?;
    let target = target.ok_or_else(|| anyhow::anyhow!("mount option missing target: {}", s))?;
    Ok(carrick_spec::Mount {
        source,
        target,
        readonly,
    })
}

pub(crate) fn parse_env_file(path: &std::path::Path) -> anyhow::Result<Vec<String>> {
    let content = std::fs::read_to_string(path)?;
    let mut envs = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        envs.push(trimmed.to_string());
    }
    Ok(envs)
}

/// Run a single OCI-related future on a short-lived current-thread tokio
/// runtime. The runtime is dropped before returning, so by the time the
/// guest issues `clone(2)` and we fork the host process there is no
/// async runtime alive in the parent to corrupt the child.
pub(crate) fn block_on_oci<F: std::future::Future>(fut: F) -> F::Output {
    // INVARIANT: fatal at startup - if the host cannot even build a
    // current-thread tokio runtime there is nothing to recover to; aborting
    // here (before any guest forks) is the correct, safe failure mode.
    #[allow(clippy::expect_used)]
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to build current-thread tokio runtime")
        .block_on(fut)
}

pub(crate) fn register_dtrace_probes() {
    match carrick_runtime::probes::register_dtrace_probes() {
        Ok(()) => {
            if std::env::var_os("CARRICK_DTRACE_DEBUG").is_some() {
                tracing::warn!(
                    "carrick: dtrace probes registered (pid={})",
                    std::process::id()
                );
            }
        }
        Err(err) => {
            // Always surface registration failures: silent failure here is
            // what makes the dtrace path feel broken.
            tracing::warn!("carrick: failed to register DTrace probes: {err}");
        }
    }
}
