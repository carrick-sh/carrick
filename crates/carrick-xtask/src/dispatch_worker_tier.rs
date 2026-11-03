//! Worker tier for a dispatch round (#1275): which workers a round may use.
//!
//! Hard systems rounds (kernel, mm, fork, signals, softcpu, scheduler) timed
//! out with no contract on a fast instruction-following worker every time on
//! 2026-10-31, and a strong design-capable model then finished each one. The
//! server decides the tier once, from facts it can show (the owner's brief,
//! the issue's labels, the crates the issue names), and refuses a worker
//! outside it. The coordinator still chooses the worker within the tier; a
//! strong round with no strong worker available ends Blocked, never on a
//! weaker model.

use serde_json::{Value, json};

use crate::ci_scaler::ScalerError;

/// The workers a round may use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WorkerTier {
    /// Any worker the capacity report offers.
    Standard,
    /// Only strong design-capable models ([`strong_model`]).
    Strong,
}

/// A round's tier and the fact it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TierDecision {
    pub(crate) tier: WorkerTier,
    pub(crate) reason: String,
}

/// The owner's explicit choice in an issue body or trigger comment.
const TIER_LINE: &str = "Worker tier: ";
/// Labels that say the work is mechanical, so any worker fits.
const STANDARD_LABELS: &[&str] = &["route:mechanical", "dispatch:argon-high"];
/// Labels that name hard systems work or a strong model.
const STRONG_LABELS: &[&str] = &[
    "shared-kernel",
    "fork",
    "mm",
    "signals",
    "route:design",
    "dispatch:opus",
    "dispatch:sol-high",
];
/// Crates whose changes are kernel, mm, fork, signal, softcpu or scheduler
/// work: AGENTS.md routes them to a strong design-capable worker.
const STRONG_CRATES: &[&str] = &[
    "carrick-kernel",
    "carrick-core",
    "carrick-mem",
    "carrick-mmu-core",
    "carrick-el1",
    "carrick-thread",
    "carrick-softcpu",
    "carrick-softmmu",
    "carrick-signal-core",
    "carrick-personality-linux",
    "carrick-vmm-",
    "carrick-x86",
    "carrick-aarch64",
];

/// Decide a round's tier, most explicit fact first: an owner `Worker tier:`
/// line (trigger before issue body), then an explicit label, then the crates
/// the issue names. Anything else is standard.
pub(crate) fn decide(title: &str, body: &str, trigger: &str, labels: &[String]) -> TierDecision {
    for (source, text) in [("trigger", trigger), ("issue body", body)] {
        if let Some(choice) = text
            .lines()
            .find_map(|line| line.trim().strip_prefix(TIER_LINE))
            .map(|choice| choice.trim().to_ascii_lowercase())
        {
            match choice.as_str() {
                "strong" => {
                    return decision(
                        WorkerTier::Strong,
                        format!("`{TIER_LINE}strong` in the {source}"),
                    );
                }
                "standard" => {
                    return decision(
                        WorkerTier::Standard,
                        format!("`{TIER_LINE}standard` in the {source}"),
                    );
                }
                _ => {}
            }
        }
    }
    if let Some(label) = labels
        .iter()
        .find(|l| STANDARD_LABELS.contains(&l.as_str()))
    {
        return decision(WorkerTier::Standard, format!("label `{label}`"));
    }
    if let Some(label) = labels.iter().find(|l| STRONG_LABELS.contains(&l.as_str())) {
        return decision(WorkerTier::Strong, format!("label `{label}`"));
    }
    let text = format!("{title}\n{body}");
    if let Some(krate) = STRONG_CRATES.iter().find(|c| text.contains(*c)) {
        return decision(WorkerTier::Strong, format!("the issue names `{krate}`"));
    }
    decision(
        WorkerTier::Standard,
        "no strong-tier label, crate or owner line".into(),
    )
}

fn decision(tier: WorkerTier, reason: String) -> TierDecision {
    TierDecision { tier, reason }
}

/// A strong design-capable model: any Codex model (GPT/Sol; dispatch sets
/// no effort, so it runs at the launcher's default), any Claude Opus model,
/// or Claude Sonnet at high effort. Gemini and the smaller open models are
/// the fast instruction-following tier.
///
/// Through Copilot (#1474) only Claude Opus counts: it is the same model
/// agy serves. Copilot's Sonnet ids carry no effort, and its GPT roster
/// mixes small models with Codex ones, so neither is admitted here.
pub(crate) fn strong_model(backend: &str, model: &str) -> bool {
    match backend {
        "codex" => !model.is_empty(),
        "agy" => {
            model.starts_with("claude-opus-")
                || (model.starts_with("claude-sonnet-") && model.ends_with("-high"))
        }
        "copilot" => model.starts_with("claude-opus-"),
        _ => false,
    }
}
/// The strong tier's models, as the coordinator and refusals name them.
const STRONG_MODELS: &str = "any Codex model, any Claude Opus model (on agy or Copilot), or Claude Sonnet at high effort on agy";
/// Owner policy (#231): Copilot bills the owner personally, so it is a
/// strong-tier peer backend, usable on any strong round (Claude Opus only)
/// and never on a standard one.
const COPILOT: &str = "copilot";

impl TierDecision {
    /// Refuse a worker outside the tier.
    pub(crate) fn admits(&self, backend: &str, model: &str) -> Result<(), ScalerError> {
        if self.tier == WorkerTier::Standard && backend == COPILOT {
            return Err(ScalerError::Usage(format!(
                "this round's worker tier is standard ({}); Copilot is billed to the owner and serves strong-tier rounds only. Use a Codex or agy worker.",
                self.reason
            )));
        }
        if self.tier == WorkerTier::Strong && !strong_model(backend, model) {
            return Err(ScalerError::Usage(format!(
                "this round's worker tier is strong ({}); `{backend}` `{model}` is not a strong-tier model. Strong-tier models: {STRONG_MODELS}.",
                self.reason
            )));
        }
        Ok(())
    }
    /// Whether `capacity` (the launcher's report) offers a worker this tier
    /// admits: a usable backend listing at least one admitted model.
    pub(crate) fn available(&self, capacity: &Value) -> bool {
        let Some(backends) = capacity["backends"].as_object() else {
            return false;
        };
        let positive = |v: &Value| v.as_f64().is_some_and(|v| v.is_finite() && v > 0.0);
        backends.iter().any(|(backend, entry)| {
            (self.tier == WorkerTier::Strong || backend != COPILOT)
                && entry["installed"] == true
                && positive(&entry["free_slots"])
                && positive(&entry["quota_free"])
                && entry["models"].as_array().is_some_and(|models| {
                    models
                        .iter()
                        .filter_map(Value::as_str)
                        .any(|m| self.tier == WorkerTier::Standard || strong_model(backend, m))
                })
        })
    }
    /// The state item the coordinator reads.
    pub(crate) fn fact(&self) -> Value {
        json!({
            "tier": match self.tier { WorkerTier::Standard => "standard", WorkerTier::Strong => "strong" },
            "reason": self.reason,
            "admits": match self.tier {
                WorkerTier::Standard => "any Codex or agy worker the capacity report offers; never Copilot, which serves strong-tier rounds only".to_owned(),
                WorkerTier::Strong => format!("{STRONG_MODELS}; invoke_worker refuses other models"),
            },
        })
    }
    /// The outcome's server line.
    pub(crate) fn outcome_line(&self) -> String {
        match self.tier {
            WorkerTier::Standard => format!("Worker tier: standard ({})", self.reason),
            WorkerTier::Strong => format!("Worker tier: strong ({})", self.reason),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn labels(names: &[&str]) -> Vec<String> {
        names.iter().map(|s| (*s).to_owned()).collect()
    }

    /// #1275: kernel-path, labelled and owner-chosen rounds are strong; an
    /// explicit owner line or mechanical label wins over an inference.
    #[test]
    fn the_tier_follows_the_most_explicit_fact() {
        let tier = |title: &str, body: &str, trigger: &str, l: &[&str]| {
            decide(title, body, trigger, &labels(l)).tier
        };
        use WorkerTier::{Standard, Strong};
        assert_eq!(
            tier(
                "softcpu: IDT delivery",
                "In `carrick-softcpu-x86`.",
                "/agent go",
                &[]
            ),
            Strong
        );
        assert_eq!(tier("fix", "", "", &["mm"]), Strong);
        assert_eq!(
            tier("docs: typo", "README only", "/agent go", &[]),
            Standard
        );
        assert_eq!(
            tier("docs", "", "/agent go\nWorker tier: strong", &[]),
            Strong
        );
        // An explicit owner line or mechanical label beats an inference.
        assert_eq!(
            tier("x", "touches carrick-kernel", "Worker tier: standard", &[]),
            Standard
        );
        assert_eq!(
            tier("x", "touches carrick-kernel", "", &["route:mechanical"]),
            Standard
        );
        assert_eq!(
            decide("x", "", "", &labels(&["fork"])).reason,
            "label `fork`"
        );
    }

    /// #1275 acceptance: a strong round refuses Argon and accepts a strong
    /// model; a standard round accepts either.
    #[test]
    fn a_strong_round_refuses_a_fast_worker() {
        let strong = decide("x", "carrick-kernel", "", &[]);
        assert!(strong.admits("agy", "gemini-4-argon-high").is_err());
        assert!(strong.admits("agy", "claude-sonnet-5-5-medium").is_err());
        assert!(strong.admits("agy", "claude-opus-5-5-high").is_ok());
        assert!(strong.admits("codex", "gpt-6.1-sol").is_ok());
        assert!(strong.admits("agy", "claude-opus-5-5-low").is_ok());
        assert!(strong.admits("agy", "gemini-3.8-flash-high").is_err());
        let standard = decide("docs", "", "", &[]);
        assert!(standard.admits("agy", "gemini-4-argon-high").is_ok());
    }

    /// A strong round sees whether any strong worker has capacity, so it can
    /// end Blocked instead of downgrading.
    #[test]
    fn strong_capacity_is_read_from_the_report() {
        let strong = decide("x", "carrick-kernel", "", &[]);
        let report = |models: Value, free: f64| json!({"backends":{"agy":{"installed":true,"free_slots":free,"quota_free":1.0,"score":1.0,"models":models}}});
        assert!(!strong.available(&report(json!(["gemini-4-argon-high"]), 2.0)));
        assert!(strong.available(&report(
            json!(["gemini-4-argon-high", "claude-opus-5-5-high"]),
            2.0
        )));
        assert!(!strong.available(&report(json!(["claude-opus-5-5-high"]), 0.0)));
        assert!(
            decide("docs", "", "", &[]).available(&report(json!(["gemini-4-argon-high"]), 2.0))
        );
    }

    /// #1474: on a strong round Copilot counts only through Claude Opus,
    /// the model agy and the owner already rank strong. Copilot's Sonnet (no
    /// effort is set), GPT (its roster mixes small models with Codex ones)
    /// and other vendors stay out.
    #[test]
    fn a_strong_round_admits_copilot_only_through_claude_opus() {
        let strong = decide("x", "carrick-kernel", "", &[]);
        assert!(strong.admits("copilot", "claude-opus-5.5").is_ok());
        assert!(strong.admits("copilot", "claude-opus-5").is_ok());
        for model in [
            "claude-sonnet-5.5",
            "claude-haiku-5.5",
            "claude-fable-5.1",
            "gpt-6.1-sol",
            "gpt-5-mini",
            "grok-4.7",
            "",
        ] {
            assert!(strong.admits("copilot", model).is_err(), "{model}");
        }
        assert!(
            strong.fact()["admits"]
                .as_str()
                .unwrap()
                .contains("Copilot")
        );
        let report = json!({"backends":{"codex":{"installed":true,"free_slots":0,"quota_free":0.0,
            "score":0.0,"models":["gpt-6.1-sol"]},
            "copilot":{"installed":true,"free_slots":2,"quota_free":1.0,"score":1.0,
            "models":["claude-sonnet-5.5","claude-opus-5.5"]}}});
        assert!(strong.available(&report));
        let mut sonnet_only = report.clone();
        sonnet_only["backends"]["copilot"]["models"] = json!(["claude-sonnet-5.5"]);
        assert!(!strong.available(&sonnet_only));
    }

    /// Owner policy (#231, #1474): Copilot, billed to the owner, is a
    /// strong-tier peer backend. A standard round never uses it, whatever
    /// the model; a strong round may pick Copilot Claude Opus even while
    /// Codex has free slots.
    #[test]
    fn copilot_serves_strong_rounds_only() {
        let standard = decide("docs", "", "", &[]);
        for model in ["claude-opus-5.5", "claude-sonnet-5.5", "gpt-6.1-sol"] {
            let error = standard.admits("copilot", model).unwrap_err().to_string();
            assert!(error.contains("strong-tier"), "{model}: {error}");
        }
        assert!(standard.admits("codex", "gpt-6.1-sol").is_ok());
        let copilot_only = json!({"backends":{"copilot":{"installed":true,"free_slots":2,
            "quota_free":1.0,"score":1.0,"models":["claude-opus-5.5","gpt-6.1-sol"]}}});
        assert!(
            !standard.available(&copilot_only),
            "a standard round counted Copilot"
        );
        assert!(
            standard.fact()["admits"]
                .as_str()
                .unwrap()
                .contains("never Copilot")
        );
        let strong = decide("x", "carrick-kernel", "", &[]);
        assert!(strong.admits("copilot", "claude-opus-5.5").is_ok());
        let both = json!({"backends":{
            "codex":{"installed":true,"free_slots":2,"quota_free":1.0,"score":1.0,"models":["gpt-6.1-sol"]},
            "copilot":{"installed":true,"free_slots":2,"quota_free":1.0,"score":1.0,"models":["claude-opus-5.5"]}}});
        assert!(strong.available(&both));
        assert!(
            !strong.fact()["admits"]
                .as_str()
                .unwrap()
                .contains("fallback")
        );
    }
}
