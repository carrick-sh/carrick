//! Conformance LANE: how a suite's `carrick run` is executed. `Hvf` runs the
//! local signed binary (the existing behavior); `Kvm` wraps the SAME carrick
//! argv as `limactl shell <vm> -- env … <carrick-in-guest> run …`, rewriting the
//! `localhost` conformance-registry host to the lima gateway so the guest can
//! pull from the mac registry.

use crate::engine::carrick_argv;
use crate::manifest::Suite;

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

/// Build the FULL OS-level argv to execute one suite's `carrick run` on `lane`.
/// `carrick_bin` is the local binary path for Hvf, or the IN-GUEST path for Kvm.
pub fn carrick_invocation_argv(
    suite: &Suite,
    carrick_bin: &str,
    run_id: &str,
    lane: &Lane,
) -> Vec<String> {
    let base = carrick_argv(suite, carrick_bin, run_id); // [carrick_bin, "run", …flags…, image, …cmd]
    match lane {
        Lane::Hvf => base,
        Lane::Kvm(cfg) => {
            // Rewrite the image-ref registry host (the only positional that is an
            // image is `suite.image`; rewrite every token that equals it).
            let rewritten: Vec<String> = base
                .into_iter()
                .map(|tok| {
                    if tok == suite.image {
                        rewrite_registry_host(&tok, "localhost", &cfg.gateway)
                    } else {
                        tok
                    }
                })
                .collect();
            let mut argv = vec![
                "limactl".to_string(),
                "shell".to_string(),
                cfg.vm.clone(),
                "--".to_string(),
            ];
            // Carry the insecure-registries env INTO the guest (limactl shell does
            // not forward the host env), rewritten to the gateway host.
            if let Some(host) = suite.registry_host() {
                let host = rewrite_registry_host(host, "localhost", &cfg.gateway);
                argv.push("env".to_string());
                argv.push(format!("CARRICK_INSECURE_REGISTRIES={host}"));
            }
            argv.extend(rewritten); // [carrick-in-guest, "run", … rewritten image …]
            argv
        }
    }
}

/// Map the `--lane`/`--lima-vm`/`--lima-gateway` CLI strings to a `Lane`.
pub fn lane_from_args(lane: &str, lima_vm: &str, lima_gateway: &str) -> Lane {
    match lane {
        "kvm" => Lane::Kvm(LimaConfig {
            vm: lima_vm.to_string(),
            gateway: lima_gateway.to_string(),
        }),
        _ => Lane::Hvf,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn demo_suite() -> Suite {
        // Minimal suite: image + a one-token cmd; default (empty) flags/env.
        Suite::for_test("localhost:5005/carrick-go-conformance:1.24", &["true"])
    }

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

    #[test]
    fn hvf_invocation_is_the_local_carrick_argv() {
        let s = demo_suite();
        let argv = carrick_invocation_argv(&s, "target/release/carrick", "conf-1-2", &Lane::Hvf);
        // Hvf: run the local binary directly — argv[0] is the carrick bin, then
        // `run --name … <image> <cmd>` (no lima envelope, no host rewrite).
        assert_eq!(argv[0], "target/release/carrick");
        assert_eq!(argv[1], "run");
        assert!(argv.contains(&"localhost:5005/carrick-go-conformance:1.24".to_string()));
        assert!(!argv.contains(&"limactl".to_string()));
    }

    #[test]
    fn kvm_invocation_wraps_in_limactl_with_rewrite_and_registry_env() {
        let s = demo_suite();
        let lane = Lane::Kvm(LimaConfig {
            vm: "carrick".into(),
            gateway: "host.lima.internal".into(),
        });
        let argv = carrick_invocation_argv(&s, "/home/user/ct/release/carrick", "conf-1-2", &lane);
        // Kvm: limactl shell <vm> -- env CARRICK_INSECURE_REGISTRIES=host.lima.internal:5005 <carrick-in-guest> run … <rewritten image> …
        assert_eq!(
            &argv[0..3],
            &["limactl".to_string(), "shell".to_string(), "carrick".to_string()]
        );
        assert_eq!(argv[3], "--");
        assert_eq!(argv[4], "env");
        assert_eq!(argv[5], "CARRICK_INSECURE_REGISTRIES=host.lima.internal:5005");
        assert_eq!(argv[6], "/home/user/ct/release/carrick");
        assert_eq!(argv[7], "run");
        // image-ref host rewritten to the gateway:
        assert!(argv.contains(&"host.lima.internal:5005/carrick-go-conformance:1.24".to_string()));
        assert!(
            !argv
                .iter()
                .any(|t| t == "localhost:5005/carrick-go-conformance:1.24")
        );
    }

    #[test]
    fn lane_from_args_builds_kvm_with_defaults() {
        assert!(matches!(
            lane_from_args("hvf", "carrick", "host.lima.internal"),
            Lane::Hvf
        ));
        match lane_from_args("kvm", "carrick", "host.lima.internal") {
            Lane::Kvm(cfg) => {
                assert_eq!(cfg.vm, "carrick");
                assert_eq!(cfg.gateway, "host.lima.internal");
            }
            _ => panic!("expected Kvm"),
        }
    }

    #[test]
    fn dry_run_hvf_matches_legacy_carrick_argv() {
        // Behavior-preservation: the Hvf dry-run argv equals the pre-lane argv.
        let s = demo_suite();
        let legacy = crate::engine::carrick_argv(&s, "target/release/carrick", "conf-1-2");
        let now = carrick_invocation_argv(&s, "target/release/carrick", "conf-1-2", &Lane::Hvf);
        assert_eq!(legacy, now);
    }
}
