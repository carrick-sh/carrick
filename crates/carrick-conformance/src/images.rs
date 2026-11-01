//! Image-freshness guard. carrick's `run` reuses a cached image by *tag* without
//! re-resolving the registry digest (crates/carrick-cli `commands.rs` flags this
//! as a missing `--pull`), so a rebuilt+repushed tag leaves carrick running the
//! OLD image while docker (whose local store `docker build` updated) runs the new
//! one — silently breaking the harness's "identical image to both engines"
//! invariant. The full 1228 run hit exactly this: carrick saw 8 stale Go
//! `.test` binaries, docker saw 193, yielding ~181 phantom "failures".
//!
//! This guard restores parity by re-pulling carrick's copy of any image whose
//! registry digest has moved since we last pulled it — SERIALLY, before the
//! parallel carrick phase (so concurrent first-pulls can't race the image dir).
//! Only images served from a reachable `host:port`/domain registry are checked;
//! digest-pinned refs are immutable and skipped. The registry digest is read with
//! the OCI manifest API; the last-pulled digest per image is recorded in a
//! gitignored sidecar under `target/conformance/`.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// `(registry_host, repository, tag)` for an image served from a real registry,
/// or `None` when the ref has no registry host (the n=0/bare-tag case) or is
/// digest-pinned (`@sha256:…`, immutable — nothing to re-resolve).
pub fn parse_registry_ref(image: &str) -> Option<(String, String, String)> {
    // Digest-pinned refs are immutable.
    if image.contains("@") {
        return None;
    }
    let (host, rest) = image.split_once('/')?;
    // A real registry host has a `:` (port) or `.` (domain); otherwise the first
    // segment is a namespace on the default registry (which we don't probe).
    if !(host.contains(':') || host.contains('.')) {
        return None;
    }
    // The tag is the segment after the LAST ':' that follows the last '/'.
    let (repo, tag) = match rest.rsplit_once(':') {
        // Guard against a port-like ':' that is actually part of the path (none
        // here, but be precise): a tag never contains '/'.
        Some((r, t)) if !t.contains('/') => (r.to_string(), t.to_string()),
        _ => (rest.to_string(), "latest".to_string()),
    };
    Some((host.to_string(), repo, tag))
}

/// Whether the registry's current digest differs from the one we last pulled into
/// carrick — i.e. the cache is stale and must be refreshed. A registry digest of
/// `None` (unreachable) means "can't tell" → do NOT refresh (offline-safe: keep
/// whatever carrick has). An absent sidecar entry with a *known* registry digest
/// means we've never recorded a pull → refresh to be sure parity holds.
pub fn is_stale(registry_digest: Option<&str>, last_pulled: Option<&str>) -> bool {
    match registry_digest {
        None => false,                         // unreachable -> keep cache
        Some(reg) => last_pulled != Some(reg), // moved, or never recorded
    }
}

/// Per-image-store sidecar: the local macOS lane uses the macOS Carrick store;
/// the KVM lane's store lives in the lima guest and direct remote-host lanes
/// have their own stores. A refresh of one store says nothing about another.
fn sidecar_path(lane: &crate::lane::Lane) -> PathBuf {
    match lane {
        crate::lane::Lane::Hvf => PathBuf::from("target/conformance/image-digests.json"),
        crate::lane::Lane::Kvm(_) => PathBuf::from("target/conformance/image-digests.kvm.json"),
        crate::lane::Lane::KvmLocal(_) => {
            PathBuf::from("target/conformance/image-digests.kvm-local.json")
        }
        crate::lane::Lane::BhyveLocal(_) => {
            PathBuf::from("target/conformance/image-digests.bhyve-local.json")
        }
        crate::lane::Lane::NvmmLocal(_) => {
            PathBuf::from("target/conformance/image-digests.nvmm-local.json")
        }
    }
}

fn load_sidecar(path: &Path) -> BTreeMap<String, String> {
    std::fs::read(path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

fn save_sidecar(map: &BTreeMap<String, String>, path: &Path) {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(s) = serde_json::to_string_pretty(map) {
        let _ = std::fs::write(path, s);
    }
}

const REGISTRY_CONNECT_TIMEOUT_SECS: &str = "3";
const REGISTRY_MAX_TIME_SECS: &str = "10";

/// Query the registry for the tag's current manifest digest (the
/// `Docker-Content-Digest` header). Shells `curl` (already a hard dep of the dev
/// environment; the harness shells docker/carrick too) with bounded connect and
/// total wall-clock timeouts so a silent listener cannot stall the run. `None`
/// on any failure — treated as "unreachable, keep cache".
fn registry_digest(host: &str, repo: &str, tag: &str) -> Option<String> {
    let url = format!("http://{host}/v2/{repo}/manifests/{tag}");
    let out = Command::new("curl")
        .args([
            "-sS",
            "-I",
            "--connect-timeout",
            REGISTRY_CONNECT_TIMEOUT_SECS,
            "--max-time",
            REGISTRY_MAX_TIME_SECS,
            "-H",
            "Accept: application/vnd.oci.image.index.v1+json",
            "-H",
            "Accept: application/vnd.docker.distribution.manifest.list.v2+json",
            "-H",
            "Accept: application/vnd.docker.distribution.manifest.v2+json",
            "-H",
            "Accept: application/vnd.oci.image.manifest.v1+json",
            &url,
        ])
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let headers = String::from_utf8_lossy(&out.stdout);
    headers.lines().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        if k.trim().eq_ignore_ascii_case("docker-content-digest") {
            Some(v.trim().to_string())
        } else {
            None
        }
    })
}

/// Re-pull, into carrick's store, any selected image whose registry digest has
/// moved since we last pulled it. Returns the number of images refreshed. Run
/// SERIALLY before the parallel carrick phase. Best-effort: a failed refresh
/// warns and continues (the suite will then run against whatever carrick has).
pub fn refresh_stale_images(
    images: &[String],
    carrick_bin: &str,
    lane: &crate::lane::Lane,
) -> usize {
    let sidecar_file = sidecar_path(lane);
    refresh_stale_images_in(
        images,
        carrick_bin,
        lane,
        &sidecar_file,
        &mut std::io::stderr(),
    )
}

fn refresh_stale_images_in(
    images: &[String],
    carrick_bin: &str,
    lane: &crate::lane::Lane,
    sidecar_file: &Path,
    err: &mut impl Write,
) -> usize {
    let mut sidecar = load_sidecar(sidecar_file);
    let mut unique: Vec<&String> = images.iter().collect();
    unique.sort();
    unique.dedup();
    let mut refreshed = 0;
    let mut unreachable_registries = BTreeSet::new();
    for image in unique {
        let Some((host, repo, tag)) = parse_registry_ref(image) else {
            continue;
        };
        // The digest probe always runs on the MAC against the local registry
        // (same registry both lanes); only the rmi/pull must run where the
        // lane's image store lives.
        let reg = registry_digest(&host, &repo, &tag);
        if reg.is_none() {
            unreachable_registries.insert(host.clone());
        }
        if !is_stale(reg.as_deref(), sidecar.get(image).map(String::as_str)) {
            continue;
        }
        let _ = writeln!(
            err,
            "image-guard: {image} registry digest moved -> re-pulling carrick's copy"
        );
        // rmi (ignore "no such image") then pull — `carrick pull` short-circuits
        // on a present cache, so the rmi is what forces a fresh fetch.
        let ok = match lane {
            crate::lane::Lane::Hvf
            | crate::lane::Lane::KvmLocal(_)
            | crate::lane::Lane::BhyveLocal(_)
            | crate::lane::Lane::NvmmLocal(_) => {
                let _ = Command::new(carrick_bin)
                    .args(["rmi", image])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
                let mut pull = Command::new(carrick_bin);
                pull.args(["pull", image]);
                pull.env("CARRICK_INSECURE_REGISTRIES", &host);
                matches!(
                    pull.stdout(Stdio::null()).stderr(Stdio::null()).status(),
                    Ok(s) if s.success()
                )
            }
            crate::lane::Lane::Kvm(cfg) => {
                // KVM lane: `carrick_bin` is the IN-GUEST binary and the image
                // cache lives in the lima guest — run rmi/pull THERE, with the
                // registry host rewritten to the guest-visible gateway (the
                // same rewrite the run argv gets). No `sg kvm` needed: pull is
                // pure userspace (registry fetch + blob store), no /dev/kvm.
                let guest_image =
                    crate::lane::rewrite_registry_host(image, "localhost", &cfg.gateway);
                let guest_host =
                    crate::lane::rewrite_registry_host(&host, "localhost", &cfg.gateway);
                let _ = Command::new("limactl")
                    .args(["shell", &cfg.vm, "--", carrick_bin, "rmi", &guest_image])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
                ::std::matches!(
                    Command::new("limactl")
                        .args([
                            "shell",
                            &cfg.vm,
                            "--",
                            "env",
                            &format!("CARRICK_INSECURE_REGISTRIES={guest_host}"),
                            carrick_bin,
                            "pull",
                            &guest_image,
                        ])
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .status(),
                    Ok(s) if s.success()
                )
            }
        };
        if ok {
            if let Some(d) = reg {
                sidecar.insert(image.clone(), d);
            }
            refreshed += 1;
        } else {
            let _ = writeln!(
                err,
                "image-guard: WARNING failed to re-pull {image}; continuing"
            );
        }
    }
    if !unreachable_registries.is_empty() {
        let hosts: Vec<&str> = unreachable_registries.iter().map(String::as_str).collect();
        let _ = writeln!(
            err,
            "image-guard: registry unreachable ({}); image digests came from cache",
            hosts.join(", ")
        );
    }
    save_sidecar(&sidecar, sidecar_file);
    refreshed
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn parses_registry_tagged_ref() {
        assert_eq!(
            parse_registry_ref("localhost:5005/carrick-go-conformance:1.24"),
            Some((
                "localhost:5005".into(),
                "carrick-go-conformance".into(),
                "1.24".into()
            ))
        );
    }

    #[test]
    fn parses_nested_repo_and_defaults_tag() {
        assert_eq!(
            parse_registry_ref("localhost:5050/ns/ltp:arm64"),
            Some(("localhost:5050".into(), "ns/ltp".into(), "arm64".into()))
        );
        assert_eq!(
            parse_registry_ref("registry.example.com/team/img"),
            Some((
                "registry.example.com".into(),
                "team/img".into(),
                "latest".into()
            ))
        );
    }

    #[test]
    fn skips_bare_and_digest_pinned() {
        // bare daemon tag (no registry host) — not probeable.
        assert_eq!(parse_registry_ref("cpython-test:3.12"), None);
        assert_eq!(parse_registry_ref("ubuntu:24.04"), None);
        // digest-pinned — immutable.
        assert_eq!(parse_registry_ref("localhost:5005/img@sha256:abc123"), None);
    }

    #[test]
    fn staleness_logic() {
        // moved -> stale
        assert!(is_stale(Some("sha256:NEW"), Some("sha256:OLD")));
        // never recorded but registry known -> refresh to be sure
        assert!(is_stale(Some("sha256:NEW"), None));
        // unchanged -> fresh
        assert!(!is_stale(Some("sha256:X"), Some("sha256:X")));
        // registry unreachable -> keep cache (offline-safe), never refresh
        assert!(!is_stale(None, Some("sha256:OLD")));
        assert!(!is_stale(None, None));
    }

    #[test]
    fn silent_registry_listener_times_out_and_returns_none() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
        let accepted = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

        let accepted_flag = std::sync::Arc::clone(&accepted);
        let stop_flag = std::sync::Arc::clone(&stop);
        let server = std::thread::spawn(move || {
            if let Ok((_stream, _peer)) = listener.accept()
                && !stop_flag.load(std::sync::atomic::Ordering::Acquire)
            {
                accepted_flag.store(true, std::sync::atomic::Ordering::Release);
                // Hold the accepted socket open and silent past curl's 10s
                // --max-time bound, capped at 25s so an unbounded curl fails
                // the assertion below instead of hanging the test runner.
                let _ = done_rx.recv_timeout(std::time::Duration::from_secs(25));
            }
        });

        let start = std::time::Instant::now();
        let digest = registry_digest(&addr.to_string(), "carrick-go-conformance", "1.24");
        let elapsed = start.elapsed();

        stop.store(true, std::sync::atomic::Ordering::Release);
        let _ = done_tx.send(());
        if !accepted.load(std::sync::atomic::Ordering::Acquire) {
            let _ = std::net::TcpStream::connect(addr);
        }
        server.join().unwrap();

        assert!(
            accepted.load(std::sync::atomic::Ordering::Acquire),
            "curl must connect to the local silent registry listener"
        );
        assert_eq!(digest, None);
        assert!(
            elapsed < std::time::Duration::from_secs(20),
            "registry_digest took {elapsed:?}, exceeding bounded curl timeout"
        );
    }

    #[test]
    fn registry_digest_reads_manifest_header_when_reachable() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop_flag = std::sync::Arc::clone(&stop);

        let server = std::thread::spawn(move || {
            let Ok((mut stream, _peer)) = listener.accept() else {
                return;
            };
            if stop_flag.load(std::sync::atomic::Ordering::Acquire) {
                return;
            }
            let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(5)));
            let _ = stream.set_write_timeout(Some(std::time::Duration::from_secs(5)));
            let mut req = Vec::new();
            let mut buf = [0_u8; 512];
            for _ in 0..16 {
                match stream.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        req.extend_from_slice(&buf[..n]);
                        if req.windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                }
            }
            let _ = stream.write_all(
                b"HTTP/1.1 200 OK\r\nDocker-Content-Digest: sha256:0123456789abcdef\r\nContent-Length: 0\r\n\r\n",
            );
            let _ = stream.flush();
        });

        let digest = registry_digest(&addr.to_string(), "carrick-go-conformance", "1.24");
        stop.store(true, std::sync::atomic::Ordering::Release);
        let _ = std::net::TcpStream::connect(addr);
        server.join().unwrap();

        assert_eq!(digest.as_deref(), Some("sha256:0123456789abcdef"));
    }

    #[test]
    fn unreachable_registry_reports_cached_digests_once_per_run() {
        fn spawn_empty_reply_listener() -> (
            std::net::SocketAddr,
            std::sync::Arc<std::sync::atomic::AtomicBool>,
            std::thread::JoinHandle<()>,
        ) {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let stop_flag = std::sync::Arc::clone(&stop);
            let handle = std::thread::spawn(move || {
                // Bounded loop: accept and immediately drop each socket so curl
                // fails fast with empty reply while we retain exclusive port custody.
                for _ in 0..8 {
                    let Ok((stream, _peer)) = listener.accept() else {
                        break;
                    };
                    drop(stream);
                    if stop_flag.load(std::sync::atomic::Ordering::Acquire) {
                        break;
                    }
                }
            });
            (addr, stop, handle)
        }

        let (addr_a, stop_a, handle_a) = spawn_empty_reply_listener();
        let (addr_b, stop_b, handle_b) = spawn_empty_reply_listener();

        let dir = tempfile::tempdir().unwrap();
        let sidecar_file = dir.path().join("image-digests.json");
        let img_go = format!("{addr_a}/carrick-go-conformance:1.24");
        let img_node = format!("{addr_a}/carrick-nodejs-conformance:24.16.0");
        let img_py = format!("{addr_b}/cpython-test:3.12.13");
        let initial = BTreeMap::from([
            (img_go.clone(), "sha256:cached-go".to_string()),
            (img_node.clone(), "sha256:cached-node".to_string()),
            (img_py.clone(), "sha256:cached-py".to_string()),
        ]);
        save_sidecar(&initial, &sidecar_file);

        let mut stderr = Vec::new();
        let refreshed = refresh_stale_images_in(
            &[
                img_go.clone(),
                img_node,
                img_go,
                img_py,
                "ubuntu:24.04".to_string(),
            ],
            "/nonexistent/carrick",
            &crate::lane::Lane::Hvf,
            &sidecar_file,
            &mut stderr,
        );

        stop_a.store(true, std::sync::atomic::Ordering::Release);
        let _ = std::net::TcpStream::connect(addr_a);
        handle_a.join().unwrap();

        stop_b.store(true, std::sync::atomic::Ordering::Release);
        let _ = std::net::TcpStream::connect(addr_b);
        handle_b.join().unwrap();

        assert_eq!(refreshed, 0);
        assert_eq!(load_sidecar(&sidecar_file), initial);

        let output = String::from_utf8(stderr).unwrap();
        let lines: Vec<&str> = output.lines().collect();
        let mut expected_hosts = [addr_a.to_string(), addr_b.to_string()];
        expected_hosts.sort();
        assert_eq!(
            lines,
            vec![format!(
                "image-guard: registry unreachable ({}); image digests came from cache",
                expected_hosts.join(", ")
            )]
        );
    }
}
