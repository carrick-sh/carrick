//! Conformance LANE: how a suite's `carrick run` is executed. `Hvf` runs the
//! local signed binary (the existing behavior); `Kvm` wraps the SAME carrick
//! argv as `limactl shell <vm> -- env … <carrick-in-guest> run …`, rewriting the
//! `localhost` conformance-registry host to the lima gateway so the guest can
//! pull from the mac registry. `KvmLocal` runs a platform-linux carrick binary
//! directly on a Linux host with `/dev/kvm`. `BhyveLocal` does the same for a
//! platform-freebsd carrick binary on a FreeBSD host with `/dev/vmm`.

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
    /// Multiplier applied to each suite's `timeout_s` for CARRICK runs on this
    /// lane (docker oracles keep the unscaled budget — they are not nested).
    /// Nested KVM roughly doubles toolchain-heavy suites (go-build straddled
    /// its 180 s budget: pass / timeout-then-recover / double-timeout across
    /// three otherwise-green tiers), and a flaky deadline is a flaky GATE.
    pub timeout_scale: f64,
}

/// Direct Linux/KVM lane configuration. The timeout scale is kept separate from
/// Lima: a native x86_64 KVM host should be faster than nested Lima by default,
/// but the operator can still stretch deadlines for loaded hosts.
#[derive(Clone, Debug)]
pub struct LocalKvmConfig {
    pub timeout_scale: f64,
}

/// Direct FreeBSD/bhyve lane configuration. It is separate from KVM because the
/// preflight and timeout cleanup are VMM-specific, even though both lanes run
/// x86_64 Linux containers and therefore share the amd64 OCI platform.
#[derive(Clone, Debug)]
pub struct LocalBhyveConfig {
    pub timeout_scale: f64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DockerPlatform {
    LinuxArm64,
    LinuxAmd64,
}

impl DockerPlatform {
    pub fn as_str(self) -> &'static str {
        match self {
            DockerPlatform::LinuxArm64 => "linux/arm64",
            DockerPlatform::LinuxAmd64 => "linux/amd64",
        }
    }
}

/// The selected lane. `Kvm` carries the lima wiring.
#[derive(Clone, Debug)]
pub enum Lane {
    Hvf,
    Kvm(LimaConfig),
    KvmLocal(LocalKvmConfig),
    BhyveLocal(LocalBhyveConfig),
}

impl Lane {
    pub fn is_lima_kvm(&self) -> bool {
        matches!(self, Lane::Kvm(_))
    }

    pub fn needs_local_registry_env(&self) -> bool {
        matches!(self, Lane::Hvf | Lane::KvmLocal(_) | Lane::BhyveLocal(_))
    }

    pub fn docker_platform(&self) -> DockerPlatform {
        match self {
            Lane::Hvf | Lane::Kvm(_) => DockerPlatform::LinuxArm64,
            Lane::KvmLocal(_) | Lane::BhyveLocal(_) => DockerPlatform::LinuxAmd64,
        }
    }

    /// The carrick-run deadline for a suite on this lane: `timeout_s` as-is on
    /// Hvf (behavior-preserving), scaled by the lane's `timeout_scale` on Kvm.
    /// Docker oracles always use the unscaled `timeout_s`.
    pub fn scaled_timeout(&self, timeout_s: u64) -> u64 {
        match self {
            Lane::Hvf => timeout_s,
            Lane::Kvm(cfg) => (timeout_s as f64 * cfg.timeout_scale).ceil() as u64,
            Lane::KvmLocal(cfg) => (timeout_s as f64 * cfg.timeout_scale).ceil() as u64,
            Lane::BhyveLocal(cfg) => (timeout_s as f64 * cfg.timeout_scale).ceil() as u64,
        }
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
        Lane::KvmLocal(_) | Lane::BhyveLocal(_) => {
            carrick_argv_with_platform(base, &suite.image, DockerPlatform::LinuxAmd64)
        }
        Lane::Kvm(cfg) => {
            // Build the inner command: `env CARRICK_INSECURE_REGISTRIES=<host>
            // <carrick-in-guest> run … <rewritten image> … <cmd>`. The env is
            // carried INTO the guest (limactl shell does not forward host env);
            // the image-ref registry host is rewritten localhost->gateway.
            let mut inner: Vec<String> = Vec::new();
            if let Some(host) = suite.registry_host() {
                let host = rewrite_registry_host(host, "localhost", &cfg.gateway);
                inner.push("env".to_string());
                inner.push(format!("CARRICK_INSECURE_REGISTRIES={host}"));
            }
            inner.extend(base.into_iter().map(|tok| {
                if tok == suite.image {
                    rewrite_registry_host(&tok, "localhost", &cfg.gateway)
                } else {
                    tok
                }
            }));
            // /dev/kvm needs the `kvm` group ACTIVE in the guest; `limactl shell`
            // does not activate it (the guest user is a member but kvm is not the
            // active group), so wrap the inner command in `sg kvm -c '<argv>'` —
            // matching scripts/kvm-smoke-lima.sh. Shell-quote each token so sg's
            // shell reconstructs the EXACT argv: the guest cmd contains shell
            // metacharacters (`&&`, quotes, redirects, the go-build heredoc).
            let argv_str = inner
                .iter()
                .map(|t| shell_quote(t))
                .collect::<Vec<_>>()
                .join(" ");
            // GUEST-SIDE self-cleanup, so a wedged run cannot leak guest
            // processes even if the harness itself dies (a mac-side kill cannot
            // reach into the guest):
            //  - `timeout -k 10 <suite timeout + 10>` group-kills the run 10 s
            //    AFTER the harness's own deadline (the mac-side kill stays the
            //    authoritative TIMEOUT verdict; this is the backstop).
            //  - carrick ESCAPES its process group (it manages guest pgids), so
            //    a group-kill alone strands it: follow with a SCOPED pkill. On
            //    Linux carrick never rewrites argv (proctitle.rs is macOS-only)
            //    and fork children/in-place execve keep the spawn argv, so
            //    `^<carrick-bin> run --name <run-id> ` matches EXACTLY this
            //    run's whole host-process tree. The `^` anchor keeps the pattern
            //    from matching the wrapper shell (whose -c script embeds the
            //    same text); the trailing space keeps run-id prefixes apart
            //    (conf-1-2 vs conf-1-20). `exit $rc` preserves carrick's exit
            //    code for verdict parsing on the non-timeout path.
            let kill_pattern = format!("^{carrick_bin} run --name {run_id} ");
            let script = format!(
                "timeout -k 10 {} {argv_str}; rc=$?; pkill -9 -f {} >/dev/null 2>&1; exit $rc",
                lane.scaled_timeout(suite.timeout_s) + 10,
                shell_quote(&kill_pattern),
            );
            vec![
                "limactl".to_string(),
                "shell".to_string(),
                cfg.vm.clone(),
                "--".to_string(),
                "sg".to_string(),
                "kvm".to_string(),
                "-c".to_string(),
                script,
            ]
        }
    }
}

fn carrick_argv_with_platform(
    mut argv: Vec<String>,
    image: &str,
    platform: DockerPlatform,
) -> Vec<String> {
    if let Some(i) = argv.iter().position(|tok| tok == "--platform")
        && let Some(value) = argv.get_mut(i + 1)
    {
        *value = platform.as_str().to_string();
        return argv;
    }
    let image_idx = argv
        .iter()
        .position(|tok| tok == image)
        .unwrap_or(argv.len());
    argv.splice(
        image_idx..image_idx,
        ["--platform".to_string(), platform.as_str().to_string()],
    );
    argv
}

/// POSIX shell single-quote: a bareword of safe chars is returned as-is; anything
/// else is wrapped in `'…'` with embedded `'` escaped as `'\''`. Used to rebuild
/// the exact in-guest argv inside `sg kvm -c '<argv>'`.
fn shell_quote(s: &str) -> String {
    let safe = !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-/=:,@+".contains(&b));
    if safe {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for c in s.chars() {
        if c == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(c);
        }
    }
    out.push('\'');
    out
}

/// Map the lane CLI strings to a `Lane`. Lima gets its own timeout scale
/// because nested virtualization can be slower; direct local x86_64 lanes use a
/// separate scale that defaults to 1.0.
pub fn lane_from_args(
    lane: &str,
    lima_vm: &str,
    lima_gateway: &str,
    lima_timeout_scale: f64,
    local_timeout_scale: f64,
) -> Lane {
    match lane {
        "kvm" => Lane::Kvm(LimaConfig {
            vm: lima_vm.to_string(),
            gateway: lima_gateway.to_string(),
            timeout_scale: lima_timeout_scale,
        }),
        "kvm-local" | "linux-kvm" => Lane::KvmLocal(LocalKvmConfig {
            timeout_scale: local_timeout_scale,
        }),
        "bhyve-local" | "freebsd-bhyve" => Lane::BhyveLocal(LocalBhyveConfig {
            timeout_scale: local_timeout_scale,
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
            timeout_scale: 1.0,
        });
        let argv =
            carrick_invocation_argv(&s, "/home/user/ct/release/carrick", "conf-1-2", &lane);
        // Kvm: limactl shell <vm> -- sg kvm -c '<shell-quoted: env …=host.lima.internal:5005 <carrick> run … <rewritten image> …>'
        assert_eq!(
            argv[0..7],
            ["limactl", "shell", "carrick", "--", "sg", "kvm", "-c"].map(String::from)
        );
        assert_eq!(argv.len(), 8, "the sg command string is one final arg");
        let inner = &argv[7]; // the single shell-string `sg kvm -c` runs
        assert!(inner.contains("CARRICK_INSECURE_REGISTRIES=host.lima.internal:5005"));
        assert!(inner.contains("/home/user/ct/release/carrick"));
        assert!(inner.contains(" run "));
        // image-ref host rewritten to the gateway, un-rewritten host absent:
        assert!(inner.contains("host.lima.internal:5005/carrick-go-conformance:1.24"));
        assert!(!inner.contains("localhost:5005/carrick-go-conformance:1.24"));
        // Guest-side self-cleanup envelope: the run is bounded by a guest
        // `timeout` 10 s past the suite deadline (for_test timeout_s=1 -> 11),
        // and a SCOPED pkill reaps group escapees (carrick manages guest pgids)
        // even if the harness dies. `exit $rc` preserves carrick's exit code.
        assert!(
            inner.starts_with("timeout -k 10 11 "),
            "guest timeout prefix: {inner}"
        );
        assert!(inner.contains("; rc=$?; pkill -9 -f "));
        // The kill pattern is ^-anchored to the carrick bin (so it can never
        // match the wrapper shell, whose -c script embeds the same text) and
        // ends at the run-id token (prefix safety: conf-1-2 vs conf-1-20).
        assert!(inner.contains("'^/home/user/ct/release/carrick run --name conf-1-2 '"));
        assert!(inner.ends_with("; exit $rc"));
    }

    #[test]
    fn kvm_local_invocation_runs_carrick_directly() {
        let s = demo_suite();
        let lane = Lane::KvmLocal(LocalKvmConfig { timeout_scale: 1.0 });
        let argv = carrick_invocation_argv(&s, "/root/ct/release/carrick", "conf-1-2", &lane);

        assert_eq!(argv[0], "/root/ct/release/carrick");
        assert_eq!(argv[1], "run");
        assert!(
            argv.windows(2)
                .any(|w| w[0] == "--platform" && w[1] == "linux/amd64"),
            "kvm-local carrick side must request the amd64 OCI platform: {argv:?}"
        );
        assert!(argv.contains(&"localhost:5005/carrick-go-conformance:1.24".to_string()));
        assert!(!argv.contains(&"limactl".to_string()));
    }

    #[test]
    fn bhyve_local_invocation_runs_carrick_directly_as_amd64() {
        let s = demo_suite();
        let lane = lane_from_args("bhyve-local", "carrick", "host.lima.internal", 2.0, 1.5);
        let argv = carrick_invocation_argv(&s, "/root/ct/release/carrick", "conf-1-2", &lane);

        assert_eq!(lane.docker_platform(), DockerPlatform::LinuxAmd64);
        assert_eq!(lane.scaled_timeout(s.timeout_s), 2);
        assert_eq!(argv[0], "/root/ct/release/carrick");
        assert_eq!(argv[1], "run");
        assert!(
            argv.windows(2)
                .any(|w| w[0] == "--platform" && w[1] == "linux/amd64"),
            "bhyve-local carrick side must request the amd64 OCI platform: {argv:?}"
        );
        assert!(argv.contains(&"localhost:5005/carrick-go-conformance:1.24".to_string()));
        assert!(!argv.contains(&"limactl".to_string()));
    }

    #[test]
    fn shell_quote_handles_barewords_and_metachars() {
        assert_eq!(shell_quote("simple"), "simple");
        assert_eq!(shell_quote("/usr/local/go/bin"), "/usr/local/go/bin");
        assert_eq!(shell_quote("a b && c"), "'a b && c'");
        assert_eq!(shell_quote("it's"), "'it'\\''s'");
        assert_eq!(shell_quote(""), "''");
    }

    #[test]
    fn lane_from_args_builds_kvm_with_defaults() {
        assert!(matches!(
            lane_from_args("hvf", "carrick", "host.lima.internal", 2.0, 1.0),
            Lane::Hvf
        ));
        match lane_from_args("kvm", "carrick", "host.lima.internal", 2.0, 1.0) {
            Lane::Kvm(cfg) => {
                assert_eq!(cfg.vm, "carrick");
                assert_eq!(cfg.gateway, "host.lima.internal");
                assert_eq!(cfg.timeout_scale, 2.0);
            }
            _ => panic!("expected Kvm"),
        }
        match lane_from_args("kvm-local", "carrick", "host.lima.internal", 3.0, 1.0) {
            Lane::KvmLocal(cfg) => assert_eq!(cfg.timeout_scale, 1.0),
            _ => panic!("expected KvmLocal"),
        }
        match lane_from_args("kvm-local", "carrick", "host.lima.internal", 3.0, 1.5) {
            Lane::KvmLocal(cfg) => assert_eq!(cfg.timeout_scale, 1.5),
            _ => panic!("expected KvmLocal"),
        }
    }

    #[test]
    fn kvm_timeout_scale_stretches_carrick_deadlines_only() {
        // The lane scale applies to the carrick deadline (run_one + the
        // in-band guest `timeout` prefix); Hvf and docker stay unscaled.
        let s = demo_suite(); // timeout_s = 1
        let lane = Lane::Kvm(LimaConfig {
            vm: "carrick".into(),
            gateway: "host.lima.internal".into(),
            timeout_scale: 2.0,
        });
        assert_eq!(lane.scaled_timeout(s.timeout_s), 2);
        assert_eq!(Lane::Hvf.scaled_timeout(s.timeout_s), 1);
        let argv = carrick_invocation_argv(&s, "/x/carrick", "conf-1-2", &lane);
        // guest in-band timeout = scaled deadline + 10 = 12.
        assert!(
            argv[7].starts_with("timeout -k 10 12 "),
            "scaled guest timeout prefix: {}",
            argv[7]
        );
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
