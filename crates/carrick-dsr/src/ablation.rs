//! Ablation-ladder support — measurement builds ONLY.
//!
//! An ablation deletes a subsystem's work outright to put a hard upper bound
//! (a ceiling) on what any correct optimization of that subsystem could ever
//! recover (docs/superpowers/specs/2026-08-07-ablation-ladder-design.md §2).
//! Ablated binaries are **incorrect by construction and must never ship**:
//!
//!  * this module only exists under `--features ablation`, so no
//!    `CARRICK_ABLATE_*` path is reachable in a normal build at all;
//!  * each knob additionally requires its env var set to exactly `1`; and
//!  * the first enabled observation prints a loud stderr banner so no
//!    ablated run can masquerade as a correct one (the measurement harness,
//!    `scripts/perf/ablation_ladder.py`, fails closed on a missing banner).
//!
//! A rung that cannot satisfy all three gates is not run.

use std::sync::OnceLock;

/// The marker the harness greps for; keep in sync with
/// `scripts/perf/ablation_ladder.py` (`BANNER_MARKER`).
pub const BANNER_MARKER: &str = "CARRICK ABLATION ACTIVE";

/// One named ablation knob: env-gated, once-per-process cached, banner on
/// first enabled observation. Forked children inherit both the environment
/// and the cached decision, so an ablated run is ablated end to end.
pub struct Ablation {
    env_var: &'static str,
    enabled: OnceLock<bool>,
}

impl Ablation {
    #[must_use]
    pub const fn new(env_var: &'static str) -> Self {
        Self {
            env_var,
            enabled: OnceLock::new(),
        }
    }

    /// Whether this ablation is active in this process. Exact spelling `1`
    /// opts in; anything else (or unset) is off.
    pub fn enabled(&self) -> bool {
        *self.enabled.get_or_init(|| {
            let on = ablation_opt_in(std::env::var_os(self.env_var).as_deref());
            if on {
                banner(self.env_var);
            }
            on
        })
    }
}

fn ablation_opt_in(value: Option<&std::ffi::OsStr>) -> bool {
    value == Some(std::ffi::OsStr::new("1"))
}

fn banner(env_var: &str) {
    eprintln!(
        "\n\
         ==============================================================\n\
         == {BANNER_MARKER}: {env_var}=1\n\
         == This binary is running an ABLATED, INCORRECT-BY-DESIGN\n\
         == configuration that exists only to measure a performance\n\
         == ceiling. Guest results are NOT trustworthy. Never ship,\n\
         == bless, or gate correctness on this run.\n\
         ==============================================================\n"
    );
}

#[cfg(test)]
mod tests {
    use super::ablation_opt_in;
    use std::ffi::OsStr;

    #[test]
    fn ablation_opt_in_accepts_only_the_exact_spelling() {
        assert!(ablation_opt_in(Some(OsStr::new("1"))));
        assert!(!ablation_opt_in(None));
        assert!(!ablation_opt_in(Some(OsStr::new("0"))));
        assert!(!ablation_opt_in(Some(OsStr::new(""))));
        assert!(!ablation_opt_in(Some(OsStr::new("true"))));
        assert!(!ablation_opt_in(Some(OsStr::new("1 "))));
    }

    #[test]
    fn banner_marker_matches_the_harness_contract() {
        // scripts/perf/ablation_ladder.py greps stderr for this exact text;
        // an ablated arm without it fails the phase.
        assert_eq!(super::BANNER_MARKER, "CARRICK ABLATION ACTIVE");
    }
}
