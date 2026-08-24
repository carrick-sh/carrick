//! Synthetic `/etc/resolv.conf` mount.
//!
//! Like `docker run`, carrick injects a working resolv.conf into every guest so
//! DNS resolves out of the box (the `--net host` contract). macOS does not hand
//! a Linux guest a usable one: `/etc/resolv.conf` there is a configd-managed
//! file behind a `/etc -> /private/etc` + `resolv.conf -> /var/run/resolv.conf`
//! symlink chain that `--fs host` does not resolve (the guest just gets ENOENT,
//! and Go/glibc then fall back to `[::1]:53` and fail). The real resolvers live
//! in the SystemConfiguration DNS store.
//!
//! carrick can follow that chain in-process, so it snapshots configd's rendered
//! resolver file and serves a clean copy here. Callers may also inject an
//! explicit launch snapshot through [`HostResolverSnapshot`], keeping resolver
//! discovery outside the carrier without executing a utility. The guest then
//! gets real nameservers; the DNS queries egress through the existing
//! host-socket passthrough (the `dispatch::net` syscall handlers), exactly as
//! `docker run --net host` would.
//!
//! The config is snapshotted once at guest setup (like Docker, which writes the
//! container's resolv.conf at create time); a host DNS change mid-run is not
//! reflected, which matches container semantics.

use super::{EntryKind, Metadata, OpenContext, OpenFlags, Vfs, VfsError, VfsHandle};
use crate::linux_abi::{LINUX_EACCES, LINUX_ENOENT};

pub(crate) const RESOLV_CONF_PATH: &str = "/etc/resolv.conf";

/// Resolver bytes captured at launch, before guest execution begins.
///
/// The type is the provider boundary for an outer launcher that obtains DNS
/// state through SystemConfiguration or another authenticated source. The
/// runtime itself performs no framework FFI and launches no resolver utility.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HostResolverSnapshot {
    contents: String,
    provider_nameservers: Vec<std::net::IpAddr>,
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum HostResolverLaunchError {
    #[error("host network launch has no usable nameserver in the captured resolver snapshot")]
    NoUsableNameserver,
}

impl HostResolverSnapshot {
    pub fn from_resolv_conf(contents: impl Into<String>) -> Self {
        Self {
            contents: contents.into(),
            provider_nameservers: Vec::new(),
        }
    }

    /// Add validated nameservers supplied by an outer launch provider. These
    /// replace the former utility fallback only when the rendered file contains
    /// no `nameserver` directive.
    pub fn with_provider_nameservers(
        mut self,
        nameservers: impl IntoIterator<Item = std::net::IpAddr>,
    ) -> Self {
        self.provider_nameservers.extend(nameservers);
        self
    }

    /// Capture configd's rendered resolver file using only in-process file I/O.
    pub fn capture_launch() -> Self {
        const HOST_RESOLV_CONF_PATHS: [&str; 3] = [
            "/etc/resolv.conf",
            "/var/run/resolv.conf",
            "/private/var/run/resolv.conf",
        ];
        let contents = HOST_RESOLV_CONF_PATHS
            .into_iter()
            .find_map(|path| std::fs::read_to_string(path).ok())
            .unwrap_or_default();
        Self {
            contents,
            provider_nameservers: Vec::new(),
        }
    }

    /// Capture and validate the host resolver only when this launch depends on
    /// it. Network-none needs no resolver, bridge mode owns its gateway DNS,
    /// and an explicit `--dns` is rendered from the network model instead.
    pub fn capture_for_network(
        network: &carrick_spec::NetworkNamespaceSpec,
    ) -> Result<Option<Self>, HostResolverLaunchError> {
        Self::validate_for_network(network, Self::capture_launch())
    }

    pub fn validate_for_network(
        network: &carrick_spec::NetworkNamespaceSpec,
        snapshot: Self,
    ) -> Result<Option<Self>, HostResolverLaunchError> {
        if network.mode != carrick_spec::NetworkMode::Host || !network.dns_servers.is_empty() {
            return Ok(None);
        }
        if snapshot.has_usable_nameserver() {
            Ok(Some(snapshot))
        } else {
            Err(HostResolverLaunchError::NoUsableNameserver)
        }
    }

    pub fn has_usable_nameserver(&self) -> bool {
        !self.provider_nameservers.is_empty()
            || self.contents.lines().any(|line| {
                let line = line.trim();
                let Some(rest) = line.strip_prefix("nameserver") else {
                    return false;
                };
                let Some(address) = rest.split_whitespace().next() else {
                    return false;
                };
                let address = address
                    .split_once('%')
                    .map_or(address, |(address, _)| address);
                address.parse::<std::net::IpAddr>().is_ok()
            })
    }
}

pub struct ResolvConfVfs {
    contents: Vec<u8>,
}

impl ResolvConfVfs {
    pub fn new() -> Self {
        Self::from_host_snapshot(&HostResolverSnapshot::capture_launch())
    }

    pub fn from_host_snapshot(snapshot: &HostResolverSnapshot) -> Self {
        Self {
            contents: synthesize_resolv_conf(snapshot),
        }
    }

    pub fn from_contents(contents: Vec<u8>) -> Self {
        Self { contents }
    }
}

impl Default for ResolvConfVfs {
    fn default() -> Self {
        Self::new()
    }
}

impl Vfs for ResolvConfVfs {
    fn lookup(&self, path: &str) -> Result<Metadata, VfsError> {
        if path == RESOLV_CONF_PATH {
            return Ok(Metadata {
                kind: EntryKind::File,
                mode: 0o644,
                size: self.contents.len() as u64,
                uid: 0,
                gid: 0,
                mtime_secs: 0,
                mtime_nanos: 0,
            });
        }
        Err(LINUX_ENOENT)
    }

    fn read_file(&self, path: &str) -> Result<Vec<u8>, VfsError> {
        if path == RESOLV_CONF_PATH {
            Ok(self.contents.clone())
        } else {
            Err(LINUX_ENOENT)
        }
    }

    fn open(
        &self,
        path: &str,
        flags: OpenFlags,
        _ctx: &OpenContext<'_>,
    ) -> Result<VfsHandle, VfsError> {
        if path != RESOLV_CONF_PATH {
            return Err(LINUX_ENOENT);
        }
        if flags.write {
            return Err(LINUX_EACCES);
        }
        Ok(VfsHandle::Bytes {
            path: path.to_string(),
            contents: self.contents.clone(),
            status_flags: 0,
        })
    }

    /// A guest commonly rewrites /etc/resolv.conf: a mutation detaches this
    /// injection so the path falls through to the writable overlay (the guest's
    /// version wins; a delete makes it gone until recreated).
    fn overridable(&self) -> bool {
        true
    }

    fn name(&self) -> &'static str {
        "resolvconf"
    }
}

/// Build the guest resolv.conf from an explicit launch snapshot, keeping only
/// resolver directives. Always returns a syntactically valid file.
fn synthesize_resolv_conf(snapshot: &HostResolverSnapshot) -> Vec<u8> {
    let mut out = String::from("# Generated by carrick from the macOS host DNS configuration.\n");
    let mut have_ns = false;

    for line in snapshot.contents.lines() {
        let t = line.trim();
        if is_resolver_directive(t) {
            out.push_str(t);
            out.push('\n');
            have_ns |= t.starts_with("nameserver");
        }
    }

    if !have_ns {
        for nameserver in &snapshot.provider_nameservers {
            out.push_str("nameserver ");
            out.push_str(&nameserver.to_string());
            out.push('\n');
            have_ns = true;
        }
    }

    // Last resort: no host resolver at all. Leave a comment rather than a bogus
    // server — DNS genuinely can't work, and a wrong nameserver would only add
    // multi-second timeouts. (Matches the host having no usable DNS.)
    if !have_ns {
        out.push_str("# (no host nameserver found)\n");
    }

    out.into_bytes()
}

fn is_resolver_directive(line: &str) -> bool {
    ["nameserver", "search", "domain", "options", "sortlist"]
        .iter()
        .any(|d| line.starts_with(d) && line[d.len()..].starts_with(char::is_whitespace))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_is_a_regular_file() {
        let v = ResolvConfVfs::new();
        let md = v.lookup(RESOLV_CONF_PATH).unwrap();
        assert_eq!(md.kind, EntryKind::File);
        assert_eq!(md.mode, 0o644);
    }

    #[test]
    fn lookup_other_path_is_enoent() {
        let v = ResolvConfVfs::new();
        assert_eq!(v.lookup("/etc/hosts"), Err(LINUX_ENOENT));
    }

    #[test]
    fn open_read_returns_bytes_open_write_is_eacces() {
        let v = ResolvConfVfs::new();
        let h = v
            .open(
                RESOLV_CONF_PATH,
                OpenFlags {
                    read: true,
                    ..Default::default()
                },
                &OpenContext::default(),
            )
            .unwrap();
        assert!(matches!(h, VfsHandle::Bytes { .. }));
        assert_eq!(
            v.open(
                RESOLV_CONF_PATH,
                OpenFlags {
                    write: true,
                    ..Default::default()
                },
                &OpenContext::default(),
            ),
            Err(LINUX_EACCES)
        );
    }

    #[test]
    fn content_is_valid_resolv_conf() {
        // On any host the synthesized file parses as resolv.conf: every
        // non-comment line is a known directive. (We can't assert a nameserver
        // exists — a CI host may have none — but the format must be clean.)
        let v = ResolvConfVfs::new();
        let text = String::from_utf8(v.contents.clone()).unwrap();
        for line in text.lines() {
            let t = line.trim();
            if t.is_empty() || t.starts_with('#') {
                continue;
            }
            assert!(
                is_resolver_directive(t),
                "unexpected resolv.conf line: {t:?}"
            );
        }
    }

    #[test]
    fn resolv_conf_is_overridable() {
        // It is an injected default the guest commonly rewrites, so it must
        // report overridable (a guest mutation detaches the injection).
        assert!(ResolvConfVfs::new().overridable());
    }

    #[test]
    fn directive_match_is_token_aligned() {
        assert!(is_resolver_directive("nameserver 1.2.3.4"));
        assert!(is_resolver_directive("search example.com"));
        // A word that merely starts with a directive name is not one.
        assert!(!is_resolver_directive("searchengine foo"));
        assert!(!is_resolver_directive("nameservers 1.2.3.4"));
    }

    #[test]
    fn explicit_launch_snapshot_is_filtered_without_a_utility() {
        let snapshot = HostResolverSnapshot::from_resolv_conf(
            "# host generated\nsearch example.test\ninvalid secret\n",
        )
        .with_provider_nameservers(["192.0.2.53".parse().unwrap()]);
        let vfs = ResolvConfVfs::from_host_snapshot(&snapshot);
        let contents = String::from_utf8(vfs.contents).unwrap();
        assert!(contents.contains("nameserver 192.0.2.53\n"));
        assert!(contents.contains("search example.test\n"));
        assert!(!contents.contains("invalid secret"));
    }

    #[test]
    fn rendered_nameserver_precedes_provider_fallback() {
        let snapshot = HostResolverSnapshot::from_resolv_conf("nameserver 192.0.2.1\n")
            .with_provider_nameservers(["192.0.2.2".parse().unwrap()]);
        let contents =
            String::from_utf8(ResolvConfVfs::from_host_snapshot(&snapshot).contents).unwrap();
        assert!(contents.contains("nameserver 192.0.2.1\n"));
        assert!(!contents.contains("192.0.2.2"));
    }

    #[test]
    fn usable_nameserver_validation_rejects_empty_and_malformed_snapshots() {
        assert!(!HostResolverSnapshot::default().has_usable_nameserver());
        assert!(
            !HostResolverSnapshot::from_resolv_conf("nameserver not-an-address\n")
                .has_usable_nameserver()
        );
        assert!(
            HostResolverSnapshot::from_resolv_conf("nameserver fe80::1%en0\n")
                .has_usable_nameserver()
        );
    }

    #[test]
    fn network_modes_that_own_or_disable_dns_do_not_require_a_host_snapshot() {
        let none = carrick_spec::NetworkNamespaceSpec::none();
        assert_eq!(HostResolverSnapshot::capture_for_network(&none), Ok(None));

        let bridge =
            carrick_spec::NetworkNamespaceSpec::bridge_default(None, Vec::new(), Vec::new());
        assert_eq!(HostResolverSnapshot::capture_for_network(&bridge), Ok(None));

        let explicit = carrick_spec::NetworkNamespaceSpec {
            dns_servers: vec!["192.0.2.53".parse().unwrap()],
            ..Default::default()
        };
        assert_eq!(
            HostResolverSnapshot::capture_for_network(&explicit),
            Ok(None)
        );
    }

    #[test]
    fn host_network_without_override_refuses_an_unusable_launch_snapshot() {
        let host = carrick_spec::NetworkNamespaceSpec::default();
        assert_eq!(
            HostResolverSnapshot::validate_for_network(
                &host,
                HostResolverSnapshot::from_resolv_conf("search example.test\n"),
            ),
            Err(HostResolverLaunchError::NoUsableNameserver),
        );
    }
}
