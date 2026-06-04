//! The declarative suite manifest (`scripts/conformance/suites.toml`) and its
//! serde model. `manifest` is the shared vocabulary every other module reads; it
//! depends on nothing else in the crate. See design spec §4.1 / §5.

use serde::Deserialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Ecosystem {
    Cpython,
    Go,
    Node,
    Ltp,
}

impl Ecosystem {
    pub fn as_str(self) -> &'static str {
        match self {
            Ecosystem::Cpython => "cpython",
            Ecosystem::Go => "go",
            Ecosystem::Node => "node",
            Ecosystem::Ltp => "ltp",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum VerdictKind {
    Regrtest,
    Gotest,
    Tap,
    Ltp,
    Shell,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Tier {
    Smoke,
    Full,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Weight {
    Heavy,
    Light,
}

#[derive(Debug, Clone, Deserialize, serde::Serialize)]
pub struct EnvKv {
    pub key: String,
    pub val: String,
}

/// A value that may be shared across both engines or specialized per-engine.
/// Resolution: the engine-specific value wins, else `both`.
#[derive(Debug, Clone, Default, Deserialize, serde::Serialize)]
pub struct EnginePair<T> {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub both: Option<T>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub carrick: Option<T>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub docker: Option<T>,
}

impl<T: Clone> EnginePair<T> {
    pub fn for_carrick(&self) -> Option<T> {
        self.carrick.clone().or_else(|| self.both.clone())
    }
    pub fn for_docker(&self) -> Option<T> {
        self.docker.clone().or_else(|| self.both.clone())
    }
}

#[derive(Debug, Clone, Deserialize, serde::Serialize)]
pub struct Suite {
    pub name: String,
    pub ecosystem: Ecosystem,
    /// Registry ref handed to BOTH engines.
    pub image: String,
    /// Trailing argv handed to BOTH engines (byte-identical).
    pub cmd: Vec<String>,
    pub verdict: VerdictKind,
    pub tier: Tier,
    pub weight: Weight,
    pub timeout_s: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub known_gaps: Vec<String>,
    /// carrick-only envelope flags (e.g. `["--raw","--fs","memory"]`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub carrick_flags: Vec<String>,
    /// docker-only flags (e.g. `["--user","65534"]`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub docker_flags: Vec<String>,
    /// `-v` specs applied to both.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bind_mounts: Vec<String>,
    /// `-e` specs applied to both.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env: Vec<EnvKv>,
    /// `-e` specs, carrick side only.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env_carrick: Vec<EnvKv>,
    /// `-e` specs, docker side only.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env_docker: Vec<EnvKv>,
    /// `-w`, applied to both.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workdir: Option<String>,
    /// Per-engine `--entrypoint` (Node pins `{ both = "/usr/local/bin/nodejs-conformance" }`).
    /// MUST stay LAST: it is the only nested-struct (table) field, so keeping it
    /// after every scalar/array keeps `toml::to_string` valid (a `[[suite]]`
    /// element must list all values before any sub-table).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entrypoint: Option<EnginePair<String>>,
}

impl Suite {
    /// The registry host inferred from the image ref (`localhost:5050/...` ->
    /// `localhost:5050`), for `CARRICK_INSECURE_REGISTRIES`.
    pub fn registry_host(&self) -> Option<&str> {
        let (host, _) = self.image.split_once('/')?;
        // Only a real host:port / domain counts (has a `:` or `.`).
        if host.contains(':') || host.contains('.') {
            Some(host)
        } else {
            None
        }
    }

    /// `--fs` value pinned in `carrick_flags`, if any.
    fn pinned_fs(&self) -> Option<&str> {
        let i = self.carrick_flags.iter().position(|f| f == "--fs")?;
        self.carrick_flags.get(i + 1).map(String::as_str)
    }
}

#[derive(Debug, Clone, Deserialize, serde::Serialize)]
pub struct Manifest {
    #[serde(default)]
    pub suite: Vec<Suite>,
}

impl Manifest {
    pub fn from_toml(text: &str) -> anyhow::Result<Manifest> {
        let m: Manifest = toml::from_str(text)?;
        Ok(m)
    }

    /// Pure validation — returns every problem found (so a unit test can assert
    /// each rejection independently). An empty Vec means the manifest is valid.
    pub fn validate(&self) -> Vec<String> {
        let mut errs = Vec::new();
        if self.suite.is_empty() {
            errs.push("manifest has no [[suite]] entries".to_string());
        }
        let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for s in &self.suite {
            let n = &s.name;
            if !seen.insert(n.as_str()) {
                errs.push(format!("duplicate suite name: {n}"));
            }
            if s.cmd.is_empty() {
                errs.push(format!("{n}: empty cmd"));
            }
            if s.timeout_s == 0 {
                errs.push(format!("{n}: timeout_s must be > 0"));
            }
            if s.known_gaps.iter().any(|g| g.trim().is_empty()) {
                errs.push(format!("{n}: empty known_gap string"));
            }
            // n=0 trap: a bare daemon tag (no registry/namespace separator) can't be
            // pulled by carrick from a local registry -> every test reads n=0.
            if !s.image.contains('/') {
                errs.push(format!(
                    "{n}: image {:?} has no registry/namespace host (the n=0 trap); use e.g. localhost:5050/<repo>:<tag>",
                    s.image
                ));
            }
            // Coherent-rootfs suites must PIN --fs (never inherit the
            // case-sensitive-volume default, which is the slow cap-std host backend).
            // `shell`-verdict discovery suites are exempt (they may want the scratch).
            if s.verdict != VerdictKind::Shell {
                match s.pinned_fs() {
                    Some("memory") | Some("host") => {}
                    Some(other) => errs.push(format!("{n}: --fs {other:?} is not memory|host")),
                    None => errs.push(format!(
                        "{n}: coherent suite must pin `--fs memory` in carrick_flags (the volume default is the slow cap-std host backend; never inherit it)"
                    )),
                }
            }
        }
        errs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = r#"
[[suite]]
name = "cpython-smoke"
ecosystem = "cpython"
image = "localhost:5050/cpython-test:3.12.13"
cmd = ["/usr/local/bin/python3", "-m", "test", "test_subprocess"]
verdict = "regrtest"
tier = "smoke"
weight = "heavy"
timeout_s = 180
carrick_flags = ["--raw", "--fs", "memory"]
"#;

    #[test]
    fn good_manifest_validates() {
        let m = Manifest::from_toml(GOOD).expect("parse");
        assert!(m.validate().is_empty(), "{:?}", m.validate());
        assert_eq!(m.suite[0].registry_host(), Some("localhost:5050"));
    }

    #[test]
    fn rejects_missing_fs_on_coherent_suite() {
        let t = r#"
[[suite]]
name = "x"
ecosystem = "ltp"
image = "localhost:5050/ltp:arm64"
cmd = ["/opt/ltp/testcases/bin/gettid01"]
verdict = "ltp"
tier = "smoke"
weight = "light"
timeout_s = 40
"#;
        let m = Manifest::from_toml(t).expect("parse");
        let e = m.validate();
        assert!(e.iter().any(|s| s.contains("--fs memory")), "{e:?}");
    }

    #[test]
    fn rejects_bare_image_and_dup_and_empty_cmd() {
        let t = r#"
[[suite]]
name = "dup"
ecosystem = "go"
image = "cpython-test:3.12.13"
cmd = []
verdict = "gotest"
tier = "full"
weight = "heavy"
timeout_s = 0
carrick_flags = ["--fs", "memory"]

[[suite]]
name = "dup"
ecosystem = "go"
image = "localhost:5005/x:1"
cmd = ["a"]
verdict = "gotest"
tier = "full"
weight = "heavy"
timeout_s = 10
carrick_flags = ["--fs", "memory"]
"#;
        let m = Manifest::from_toml(t).expect("parse");
        let e = m.validate();
        assert!(
            e.iter().any(|s| s.contains("duplicate suite name")),
            "{e:?}"
        );
        assert!(e.iter().any(|s| s.contains("empty cmd")), "{e:?}");
        assert!(e.iter().any(|s| s.contains("timeout_s")), "{e:?}");
        assert!(e.iter().any(|s| s.contains("n=0 trap")), "{e:?}");
    }
}
