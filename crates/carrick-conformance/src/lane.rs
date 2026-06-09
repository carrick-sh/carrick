//! Conformance LANE: how a suite's `carrick run` is executed. `Hvf` runs the
//! local signed binary (the existing behavior); `Kvm` wraps the SAME carrick
//! argv as `limactl shell <vm> -- env … <carrick-in-guest> run …`, rewriting the
//! `localhost` conformance-registry host to the lima gateway so the guest can
//! pull from the mac registry.

// The `Lane`/`LimaConfig`/`is_kvm` surface is wired into the engine in the next
// commit (`carrick_invocation_argv` + `run_carrick`); allow it to be unused for
// this isolated, test-only first step. Removed once the engine consumes it.
#![allow(dead_code)]

/// How to reach the mac conformance registry from inside the lima guest, plus
/// the in-guest carrick binary path and the VM name.
#[derive(Clone, Debug)]
pub struct LimaConfig {
    /// lima VM name (e.g. "carrick").
    pub vm: String,
    /// Host that the lima guest resolves to the mac (e.g. "host.lima.internal").
    pub gateway: String,
}

/// The selected lane. `Kvm` carries the lima wiring.
#[derive(Clone, Debug)]
pub enum Lane {
    Hvf,
    Kvm(LimaConfig),
}

impl Lane {
    pub fn is_kvm(&self) -> bool {
        matches!(self, Lane::Kvm(_))
    }
}

/// Rewrite the registry HOST component of an OCI image reference from `from`
/// (e.g. "localhost") to `to` (e.g. "host.lima.internal"), preserving the port,
/// path, and tag. A reference's first `/`-separated component is a registry host
/// iff it contains a `.` or `:` or equals "localhost" (the OCI/distribution
/// rule). We only rewrite when that host component's hostname == `from`.
pub fn rewrite_registry_host(image: &str, from: &str, to: &str) -> String {
    let (head, rest) = match image.split_once('/') {
        Some((h, r)) => (h, Some(r)),
        None => (image, None), // bare name, no registry host
    };
    let looks_like_host = head.contains('.') || head.contains(':') || head == "localhost";
    if !looks_like_host {
        return image.to_string();
    }
    let (host, port) = match head.split_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (head, None),
    };
    if host != from {
        return image.to_string();
    }
    let new_head = match port {
        Some(p) => format!("{to}:{p}"),
        None => to.to_string(),
    };
    match rest {
        Some(r) => format!("{new_head}/{r}"),
        None => new_head,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrite_localhost_registry_host_in_image_ref() {
        // The conformance images live at localhost:5005/... on the mac; from the
        // lima guest the mac is reachable as host.lima.internal, so the image-ref
        // host and the insecure-registry env must be rewritten.
        assert_eq!(
            rewrite_registry_host(
                "localhost:5005/carrick-go-conformance:1.24",
                "localhost",
                "host.lima.internal"
            ),
            "host.lima.internal:5005/carrick-go-conformance:1.24"
        );
        // Only the leading host[:port] component is rewritten, and only when it
        // matches `from` exactly — a path/tag containing "localhost" is untouched.
        assert_eq!(
            rewrite_registry_host(
                "docker.io/library/busybox:latest",
                "localhost",
                "host.lima.internal"
            ),
            "docker.io/library/busybox:latest"
        );
        assert_eq!(
            rewrite_registry_host("localhost:5050/x", "localhost", "host.lima.internal"),
            "host.lima.internal:5050/x"
        );
        // A bare image (no registry host) is untouched.
        assert_eq!(
            rewrite_registry_host("busybox", "localhost", "host.lima.internal"),
            "busybox"
        );
    }
}
