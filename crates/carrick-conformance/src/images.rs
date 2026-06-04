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

use std::collections::BTreeMap;
use std::path::PathBuf;
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

fn sidecar_path() -> PathBuf {
    PathBuf::from("target/conformance/image-digests.json")
}

fn load_sidecar() -> BTreeMap<String, String> {
    std::fs::read(sidecar_path())
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

fn save_sidecar(map: &BTreeMap<String, String>) {
    if let Some(parent) = sidecar_path().parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(s) = serde_json::to_string_pretty(map) {
        let _ = std::fs::write(sidecar_path(), s);
    }
}

/// Query the registry for the tag's current manifest digest (the
/// `Docker-Content-Digest` header). Shells `curl` (already a hard dep of the dev
/// environment; the harness shells docker/carrick too). `None` on any failure —
/// treated as "unreachable, keep cache".
fn registry_digest(host: &str, repo: &str, tag: &str) -> Option<String> {
    let url = format!("http://{host}/v2/{repo}/manifests/{tag}");
    let out = Command::new("curl")
        .args([
            "-sS",
            "-I",
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
pub fn refresh_stale_images(images: &[String], carrick_bin: &str) -> usize {
    let mut sidecar = load_sidecar();
    let mut unique: Vec<&String> = images.iter().collect();
    unique.sort();
    unique.dedup();
    let mut refreshed = 0;
    for image in unique {
        let Some((host, repo, tag)) = parse_registry_ref(image) else {
            continue;
        };
        let reg = registry_digest(&host, &repo, &tag);
        if !is_stale(reg.as_deref(), sidecar.get(image).map(String::as_str)) {
            continue;
        }
        eprintln!("image-guard: {image} registry digest moved -> re-pulling carrick's copy");
        // rmi (ignore "no such image") then pull — `carrick pull` short-circuits
        // on a present cache, so the rmi is what forces a fresh fetch.
        let _ = Command::new(carrick_bin)
            .args(["rmi", image])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        let mut pull = Command::new(carrick_bin);
        pull.args(["pull", image]);
        if let Some((h, _, _)) = parse_registry_ref(image) {
            pull.env("CARRICK_INSECURE_REGISTRIES", h);
        }
        match pull.stdout(Stdio::null()).stderr(Stdio::null()).status() {
            Ok(s) if s.success() => {
                if let Some(d) = reg {
                    sidecar.insert(image.clone(), d);
                }
                refreshed += 1;
            }
            _ => eprintln!("image-guard: WARNING failed to re-pull {image}; continuing"),
        }
    }
    save_sidecar(&sidecar);
    refreshed
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
