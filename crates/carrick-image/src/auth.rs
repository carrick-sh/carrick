//! Registry credential resolution and `carrick login`/`logout` storage.
//!
//! Auth is resolved per-registry from carrick's own docker-schema `config.json`
//! (at the store root), falling back READ-ONLY to `$DOCKER_CONFIG`/`~/.docker/
//! config.json` so an existing `docker login` works. `login` writes base64
//! `user:pass` into carrick's config (mode 0600); `~/.docker` is never mutated.
//!
//! v1 scope: `Basic` auth from the inline `auth` (or `username`/`password`)
//! fields. `credsStore`/`credHelpers` (cred-helper shell-out) and `Bearer`/token
//! auth are detected-and-warned but not used yet.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use oci_client::secrets::RegistryAuth;
use serde::{Deserialize, Serialize};

use carrick_spec::OciBootstrapError;

/// Docker Hub's credential key (the legacy v1 URL docker itself stores under).
const HUB_KEY: &str = "https://index.docker.io/v1/";

/// Docker's `config.json` (the subset we read/write).
#[derive(Debug, Default, Deserialize, Serialize)]
struct DockerConfig {
    #[serde(default)]
    auths: HashMap<String, AuthEntry>,
    #[serde(
        rename = "credsStore",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    creds_store: Option<String>,
    #[serde(
        rename = "credHelpers",
        default,
        skip_serializing_if = "HashMap::is_empty"
    )]
    cred_helpers: HashMap<String, String>,
}

#[derive(Debug, Default, Clone, Deserialize, Serialize)]
struct AuthEntry {
    // All optional: a credsStore-only config has entries with no inline `auth`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    auth: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    password: Option<String>,
}

/// Normalise a registry host to its credential key. All Docker Hub spellings
/// collapse to the legacy v1 URL (where docker — and `image.registry()`'s
/// `docker.io` — store Hub creds); any other registry becomes a bare host
/// (scheme + trailing slash stripped). Without this collapse a valid Hub login
/// is silently not found and pulls stay anonymous (rate limits).
pub(crate) fn canonical_registry_key(registry: &str) -> String {
    let host = registry
        .trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_end_matches('/');
    match host {
        "docker.io" | "index.docker.io" | "registry-1.docker.io" | "index.docker.io/v1" => {
            HUB_KEY.to_string()
        }
        _ => host.to_string(),
    }
}

fn load_config(path: &Path) -> Option<DockerConfig> {
    let bytes = std::fs::read(path).ok()?;
    match serde_json::from_slice(&bytes) {
        Ok(cfg) => Some(cfg),
        Err(e) => {
            eprintln!("carrick: ignoring malformed {}: {e}", path.display());
            None
        }
    }
}

/// The `RegistryAuth` for `key` in `config`, or `None` if absent/cred-helper-only.
fn auth_for(config: &DockerConfig, key: &str) -> Option<RegistryAuth> {
    let entry = config.auths.get(key)?;
    if let Some(encoded) = &entry.auth {
        match base64::engine::general_purpose::STANDARD.decode(encoded.trim()) {
            Ok(raw) => {
                let s = String::from_utf8_lossy(&raw);
                // Split on the FIRST ':' — passwords may contain ':'.
                if let Some((user, pass)) = s.split_once(':') {
                    return Some(RegistryAuth::Basic(user.to_string(), pass.to_string()));
                }
            }
            Err(e) => eprintln!("carrick: ignoring bad base64 auth for {key}: {e}"),
        }
    }
    if let (Some(u), Some(p)) = (&entry.username, &entry.password) {
        return Some(RegistryAuth::Basic(u.clone(), p.clone()));
    }
    // A cred-helper-only entry: warn once, fall through to Anonymous (v1).
    if entry.auth.is_none()
        && (config.creds_store.is_some() || config.cred_helpers.contains_key(key))
    {
        eprintln!(
            "carrick: {key} uses a credential helper, which is not supported yet; pulling anonymously"
        );
    }
    None
}

/// Resolve the credentials for `registry`: carrick's own config (at `store_root`)
/// first, then `$DOCKER_CONFIG`/`~/.docker/config.json` (read-only), else
/// `Anonymous`.
pub fn resolve_auth(store_root: &Path, registry: &str) -> Result<RegistryAuth, OciBootstrapError> {
    let key = canonical_registry_key(registry);
    if let Some(auth) =
        load_config(&carrick_config_path(store_root)).and_then(|c| auth_for(&c, &key))
    {
        return Ok(auth);
    }
    for path in docker_config_paths() {
        if let Some(auth) = load_config(&path).and_then(|c| auth_for(&c, &key)) {
            return Ok(auth);
        }
    }
    Ok(RegistryAuth::Anonymous)
}

/// Persist a Basic credential for `registry` into carrick's config (mode 0600).
/// Never touches `~/.docker`.
pub fn write_login(
    store_root: &Path,
    registry: &str,
    username: &str,
    password: &str,
) -> Result<(), OciBootstrapError> {
    let path = carrick_config_path(store_root);
    let mut config = load_config(&path).unwrap_or_default();
    let encoded =
        base64::engine::general_purpose::STANDARD.encode(format!("{username}:{password}"));
    config.auths.insert(
        canonical_registry_key(registry),
        AuthEntry {
            auth: Some(encoded),
            username: None,
            password: None,
        },
    );
    write_private(&path, &serde_json::to_vec_pretty(&config)?)?;
    Ok(())
}

/// Remove `registry`'s stored credential. Returns whether one existed.
pub fn remove_login(store_root: &Path, registry: &str) -> Result<bool, OciBootstrapError> {
    let path = carrick_config_path(store_root);
    let Some(mut config) = load_config(&path) else {
        return Ok(false);
    };
    let removed = config
        .auths
        .remove(&canonical_registry_key(registry))
        .is_some();
    if removed {
        write_private(&path, &serde_json::to_vec_pretty(&config)?)?;
    }
    Ok(removed)
}

fn carrick_config_path(store_root: &Path) -> PathBuf {
    store_root.join("config.json")
}

/// Read-only docker config search paths: `$DOCKER_CONFIG/config.json`, then
/// `~/.docker/config.json`.
fn docker_config_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Some(dir) = std::env::var_os("DOCKER_CONFIG") {
        paths.push(PathBuf::from(dir).join("config.json"));
    }
    if let Some(home) = std::env::var_os("HOME") {
        paths.push(PathBuf::from(home).join(".docker").join("config.json"));
    }
    paths
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), OciBootstrapError> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(bytes)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_key_collapses_hub_spellings() {
        for spelling in [
            "docker.io",
            "index.docker.io",
            "registry-1.docker.io",
            "https://index.docker.io/v1/",
        ] {
            assert_eq!(canonical_registry_key(spelling), HUB_KEY, "{spelling}");
        }
        assert_eq!(canonical_registry_key("ghcr.io"), "ghcr.io");
        assert_eq!(
            canonical_registry_key("https://reg.example.com/"),
            "reg.example.com"
        );
    }

    #[test]
    fn auth_for_decodes_inline_base64_splitting_on_first_colon() {
        let mut config = DockerConfig::default();
        // user "alice", password "p:ss:word" (contains colons).
        let encoded = base64::engine::general_purpose::STANDARD.encode("alice:p:ss:word");
        config.auths.insert(
            HUB_KEY.to_string(),
            AuthEntry {
                auth: Some(encoded),
                ..Default::default()
            },
        );
        match auth_for(&config, HUB_KEY) {
            Some(RegistryAuth::Basic(u, p)) => {
                assert_eq!(u, "alice");
                assert_eq!(p, "p:ss:word");
            }
            other => panic!("expected Basic, got {other:?}"),
        }
    }

    #[test]
    fn auth_for_uses_username_password_fields() {
        let mut config = DockerConfig::default();
        config.auths.insert(
            "ghcr.io".to_string(),
            AuthEntry {
                username: Some("bob".into()),
                password: Some("tok".into()),
                ..Default::default()
            },
        );
        assert!(matches!(
            auth_for(&config, "ghcr.io"),
            Some(RegistryAuth::Basic(_, _))
        ));
    }

    #[test]
    fn creds_store_only_entry_is_none_not_a_panic() {
        // A config with credsStore + an entry that has NO inline auth must parse
        // and resolve to None (anonymous), not error.
        let json = r#"{"auths":{"ghcr.io":{}},"credsStore":"osxkeychain"}"#;
        let config: DockerConfig = serde_json::from_str(json).expect("parses");
        assert!(auth_for(&config, "ghcr.io").is_none());
    }

    #[test]
    fn write_then_resolve_round_trips_with_0600() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::TempDir::new().unwrap();
        let root = tmp.path();
        write_login(root, "ghcr.io", "bob", "secret").unwrap();
        // 0600 perms.
        let mode = std::fs::metadata(carrick_config_path(root))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        // resolve_auth reads it back (DOCKER_CONFIG/HOME fallbacks won't match ghcr).
        match resolve_auth(root, "ghcr.io").unwrap() {
            RegistryAuth::Basic(u, p) => {
                assert_eq!(u, "bob");
                assert_eq!(p, "secret");
            }
            other => panic!("expected Basic, got {other:?}"),
        }
        // logout removes it.
        assert!(remove_login(root, "ghcr.io").unwrap());
        assert!(matches!(
            resolve_auth(root, "ghcr.io").unwrap(),
            RegistryAuth::Anonymous
        ));
    }

    #[test]
    fn write_login_preserves_other_registries() {
        let tmp = tempfile::TempDir::new().unwrap();
        let root = tmp.path();
        write_login(root, "ghcr.io", "a", "1").unwrap();
        write_login(root, "quay.io", "b", "2").unwrap();
        // Both survive.
        assert!(matches!(
            resolve_auth(root, "ghcr.io").unwrap(),
            RegistryAuth::Basic(..)
        ));
        assert!(matches!(
            resolve_auth(root, "quay.io").unwrap(),
            RegistryAuth::Basic(..)
        ));
    }
}
