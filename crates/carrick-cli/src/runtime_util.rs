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
            "invalid volume format '{}', expected host_path:guest_path[:options]",
            s
        );
    }
    let source = camino::Utf8PathBuf::from(parts[0]);
    let target = camino::Utf8PathBuf::from(parts[1]);
    // The 3rd field is a comma-separated option list (docker: `:ro,z`). `ro`/`rw`
    // set the mode; SELinux relabel (`z`/`Z`) and macOS cache-consistency hints
    // (`cached`/`delegated`/`consistent`) are accepted-and-warned for copy-paste
    // portability but not enforced — carrick has no SELinux, and the host FS is
    // already coherent. An unknown option is a hard error.
    let mut readonly = false;
    if let Some(opts) = parts.get(2) {
        for opt in opts.split(',') {
            match opt {
                "ro" => readonly = true,
                "rw" => readonly = false,
                "z" | "Z" | "cached" | "delegated" | "consistent" => {
                    eprintln!("carrick: volume option {opt:?} is not enforced (treated as rw)");
                }
                "" => {}
                other => anyhow::bail!(
                    "invalid volume option {other:?} in '{}', expected ro/rw/z/Z/cached/delegated/consistent",
                    s
                ),
            }
        }
    }
    Ok(carrick_spec::Mount {
        source,
        target,
        readonly,
    })
}

/// Validate `-p/--publish` specs under carrick's host-only networking. A port
/// REMAP (hostPort != containerPort) can never work — the guest binds the host
/// port directly — so per the hybrid unsupported-flag policy it is a hard error;
/// an identity map (hostPort == containerPort) is accepted as a documented
/// no-op. Accepts docker's `[ip:]hostPort:containerPort[/proto]`; a bare
/// `containerPort` (docker assigns a random host port) is a remap and rejected.
pub(crate) fn validate_publish(specs: &[String]) -> anyhow::Result<()> {
    for spec in specs {
        let body = spec.split('/').next().unwrap_or(spec.as_str());
        let parts: Vec<&str> = body.split(':').collect();
        let (host, container) = match parts.as_slice() {
            [c] => (None, *c),
            [h, c] => (Some(*h), *c),
            [_ip, h, c] => (Some(*h), *c),
            _ => anyhow::bail!("invalid -p {spec:?}: expected [ip:]hostPort:containerPort[/proto]"),
        };
        let cport: u16 = container.parse().map_err(|_| {
            anyhow::anyhow!("invalid -p {spec:?}: bad container port {container:?}")
        })?;
        match host {
            None => anyhow::bail!(
                "-p {spec:?}: publishing to a random host port is unsupported under carrick's host networking (the guest binds the host directly); use -p {cport}:{cport} or drop -p"
            ),
            Some(h) => {
                let hport: u16 = h
                    .parse()
                    .map_err(|_| anyhow::anyhow!("invalid -p {spec:?}: bad host port {h:?}"))?;
                if hport != cport {
                    anyhow::bail!(
                        "-p {spec:?}: port remapping {hport}->{cport} is unsupported under carrick's host networking; the container binds {cport} on the host directly. Use -p {cport}:{cport} or drop -p"
                    );
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{parse_volume_mount, validate_publish};

    #[test]
    fn publish_identity_map_accepted() {
        assert!(validate_publish(&["80:80".into()]).is_ok());
        assert!(validate_publish(&["127.0.0.1:80:80".into()]).is_ok());
        assert!(validate_publish(&["80:80/tcp".into()]).is_ok());
        assert!(validate_publish(&[]).is_ok());
    }

    #[test]
    fn publish_remap_rejected() {
        assert!(validate_publish(&["8080:80".into()]).is_err());
        assert!(validate_publish(&["127.0.0.1:8080:80".into()]).is_err());
        assert!(validate_publish(&["80".into()]).is_err()); // random host port
    }

    #[test]
    fn publish_malformed_rejected() {
        assert!(validate_publish(&["a:b:c:d".into()]).is_err());
        assert!(validate_publish(&["80:notaport".into()]).is_err());
    }

    #[test]
    fn volume_z_option_accepted_as_rw() {
        let m = parse_volume_mount("/h:/g:z").unwrap();
        assert!(!m.readonly);
    }

    #[test]
    fn volume_ro_with_z_is_readonly() {
        let m = parse_volume_mount("/h:/g:ro,z").unwrap();
        assert!(m.readonly);
    }

    #[test]
    fn volume_unknown_option_rejected() {
        assert!(parse_volume_mount("/h:/g:bogus").is_err());
    }
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
    // `path` is the file the operator explicitly named via `--env-file`; reading
    // it is the intended behavior, not a traversal of attacker-controlled input.
    let content = std::fs::read_to_string(path)?; // nosemgrep
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

/// Truncate `s` to `max` chars (with an ellipsis) for table columns.
pub(crate) fn truncate_str(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let cut: String = s.chars().take(max.saturating_sub(1)).collect();
        format!("{cut}…")
    }
}

/// Format a byte count docker-style with decimal (1000) units, e.g. `78.1MB`.
pub(crate) fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "kB", "MB", "GB", "TB"];
    if bytes < 1000 {
        return format!("{bytes}B");
    }
    let mut size = bytes as f64;
    let mut unit = 0;
    while size >= 1000.0 && unit < UNITS.len() - 1 {
        size /= 1000.0;
        unit += 1;
    }
    format!("{size:.1}{}", UNITS[unit])
}

/// Format an epoch-seconds time as a docker-style relative age, e.g. `2 hours
/// ago`. `created_secs == 0` (unknown) renders as `N/A`.
pub(crate) fn human_age(created_secs: u64) -> String {
    if created_secs == 0 {
        return "N/A".to_string();
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(created_secs);
    let age = now.saturating_sub(created_secs);
    let (n, unit) = if age < 60 {
        return "Less than a minute ago".to_string();
    } else if age < 3600 {
        (age / 60, "minute")
    } else if age < 86_400 {
        (age / 3600, "hour")
    } else if age < 86_400 * 7 {
        (age / 86_400, "day")
    } else if age < 86_400 * 30 {
        (age / (86_400 * 7), "week")
    } else if age < 86_400 * 365 {
        (age / (86_400 * 30), "month")
    } else {
        (age / (86_400 * 365), "year")
    };
    format!("{n} {unit}{} ago", if n == 1 { "" } else { "s" })
}
