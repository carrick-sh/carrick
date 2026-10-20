//! Strict signed-gate comparison: a disappearing failure is not evidence of completion.
use crate::accept::{AcceptReceipt, StepResult};
use crate::ci_receipt::ReceiptError;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Serialize)]
pub struct SetDiff {
    pub base: BTreeSet<String>,
    pub candidate: BTreeSet<String>,
    pub new: BTreeSet<String>,
    pub fixed: BTreeSet<String>,
}
impl SetDiff {
    fn new(base: &[String], candidate: &[String]) -> Self {
        let base: BTreeSet<_> = base.iter().cloned().collect();
        let candidate: BTreeSet<_> = candidate.iter().cloned().collect();
        Self {
            new: candidate.difference(&base).cloned().collect(),
            fixed: base.difference(&candidate).cloned().collect(),
            base,
            candidate,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct StepDiff {
    pub name: String,
    pub started_tests: SetDiff,
    pub finished_binaries: SetDiff,
    pub unfinished_binaries: SetDiff,
    pub unitemized_failures: SetDiff,
    pub failed_tests: SetDiff,
}

#[derive(Debug, Serialize)]
pub struct SignedDiff {
    pub passed: bool,
    pub base: String,
    pub candidate: String,
    pub steps: Vec<StepDiff>,
    pub el1_failed_tests: SetDiff,
    pub el1_unexpected_failures: SetDiff,
    pub new: BTreeSet<String>,
    pub fixed: BTreeSet<String>,
}

fn steps(receipt: &AcceptReceipt) -> Result<BTreeMap<&str, &StepResult>, ReceiptError> {
    let mut result = BTreeMap::new();
    if receipt.schema_version != 1
        || receipt.phase != "signed"
        || receipt.profile != "no-docker"
        || receipt.steps.is_empty()
    {
        return Err(ReceiptError::Mismatch(
            "signed-diff requires nonempty signed/no-docker receipts".into(),
        ));
    }
    for step in &receipt.steps {
        if result.insert(step.name.as_str(), step).is_some() {
            return Err(ReceiptError::Mismatch(format!(
                "duplicate step {}",
                step.name
            )));
        }
    }
    Ok(result)
}

fn is_qualified_panic_location(after_panicked: &str) -> bool {
    let loc_token = match after_panicked.find(|c: char| c.is_whitespace()) {
        Some(idx) => &after_panicked[..idx],
        None => after_panicked,
    };
    let Some(loc_without_trailing_colon) = loc_token.strip_suffix(':') else {
        return false;
    };
    let mut parts: Vec<&str> = loc_without_trailing_colon.split(':').collect();
    if parts.len() < 2 {
        return false;
    }
    let last = parts.pop().unwrap_or("");
    if last.is_empty() || !last.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    if parts.len() >= 2 {
        let second_last = parts.pop().unwrap_or("");
        if second_last.is_empty() || !second_last.bytes().all(|b| b.is_ascii_digit()) {
            return false;
        }
    }
    let path = parts.join(":");
    !path.is_empty()
}

fn normalize_panic_header_line(line: &str) -> String {
    if line.matches("thread '").count() != 1
        || line.matches("' (").count() != 1
        || line.matches("panicked at ").count() != 1
        || line.matches(") panicked at ").count() != 1
    {
        return line.to_string();
    }
    let Some(start) = line.find("thread '") else {
        return line.to_string();
    };
    if !line[..start].chars().all(|c| c == ' ' || c == '\t') {
        return line.to_string();
    }
    let indent = &line[..start];
    let rest = &line[start + "thread '".len()..];
    let Some(quote_paren_idx) = rest.find("' (") else {
        return line.to_string();
    };
    let thread_name = &rest[..quote_paren_idx];
    let after_open_paren = &rest[quote_paren_idx + "' (".len()..];
    let Some(close_paren_idx) = after_open_paren.find(") panicked at ") else {
        return line.to_string();
    };
    let thread_id = &after_open_paren[..close_paren_idx];
    if thread_id.is_empty() || !thread_id.bytes().all(|b| b.is_ascii_digit()) {
        return line.to_string();
    }
    let after_panicked = &after_open_paren[close_paren_idx + ") panicked at ".len()..];
    if !is_qualified_panic_location(after_panicked) {
        return line.to_string();
    }
    format!("{indent}thread '{thread_name}' (<tid>) panicked at {after_panicked}")
}

fn normalize_probe_line(s: &str) -> String {
    if !s.contains("thread '") || !s.contains(") panicked at ") {
        return s.to_string();
    }
    let mut result = Vec::new();
    for line in s.split_inclusive('\n') {
        result.push(normalize_panic_header_line(line));
    }
    result.concat()
}

fn structured_failures(receipt: &AcceptReceipt) -> BTreeSet<String> {
    let mut keys = BTreeSet::new();
    for step in &receipt.steps {
        if !step.passed && step.failed_tests.is_empty() && step.unitemized_failures.is_empty() {
            keys.insert(format!("step:{}", step.name));
        }
    }
    for probe in &receipt.probe_diffs {
        keys.insert(format!(
            "probe:{}:{}:{}",
            probe.step,
            probe.probe,
            normalize_probe_line(&probe.line)
        ));
    }
    for cleanup in &receipt.cleanup_counts {
        if cleanup.remaining_count != 0 {
            keys.insert(format!("cleanup:{}", cleanup.step));
        }
    }
    for skipped in &receipt.skipped_steps {
        keys.insert(format!("skipped:{skipped}"));
    }
    if !receipt.clean_tree {
        keys.insert("dirty-checkout".into());
    }
    keys
}

/// Compare typed receipt fields only. Counts and binary completion are checked even
/// when every test in a baseline binary failed. Human `failures` strings are never keys.
pub fn compare(
    base: &AcceptReceipt,
    candidate: &AcceptReceipt,
) -> Result<SignedDiff, ReceiptError> {
    let base_steps = steps(base)?;
    let candidate_steps = steps(candidate)?;
    let mut result = SignedDiff {
        passed: false,
        base: base.head.clone(),
        candidate: candidate.head.clone(),
        steps: Vec::new(),
        el1_failed_tests: SetDiff::new(
            base.el1.as_ref().map_or(&[], |e| e.failed_tests.as_slice()),
            candidate
                .el1
                .as_ref()
                .map_or(&[], |e| e.failed_tests.as_slice()),
        ),
        el1_unexpected_failures: SetDiff::new(
            base.el1
                .as_ref()
                .map_or(&[], |e| e.unexpected_failures.as_slice()),
            candidate
                .el1
                .as_ref()
                .map_or(&[], |e| e.unexpected_failures.as_slice()),
        ),
        new: BTreeSet::new(),
        fixed: BTreeSet::new(),
    };
    let names: BTreeSet<_> = base_steps
        .keys()
        .chain(candidate_steps.keys())
        .copied()
        .collect();
    for name in names {
        let old = base_steps.get(name).copied();
        let next = candidate_steps.get(name).copied();
        if next.is_none() {
            result.new.insert(format!("missing-step:{name}"));
        }
        let field = |select: fn(&StepResult) -> &[String]| {
            SetDiff::new(old.map_or(&[], select), next.map_or(&[], select))
        };
        let step = StepDiff {
            name: name.into(),
            started_tests: field(|s| &s.started_tests),
            finished_binaries: field(|s| &s.finished_binaries),
            unfinished_binaries: field(|s| &s.unfinished_binaries),
            unitemized_failures: field(|s| &s.unitemized_failures),
            failed_tests: field(|s| &s.failed_tests),
        };
        for (label, diff) in [
            ("test", &step.failed_tests),
            ("unfinished", &step.unfinished_binaries),
            ("unitemized", &step.unitemized_failures),
        ] {
            result
                .new
                .extend(diff.new.iter().map(|v| format!("{label}:{name}:{v}")));
            result
                .fixed
                .extend(diff.fixed.iter().map(|v| format!("{label}:{name}:{v}")));
        }
        for (label, population) in [
            ("started", &step.started_tests),
            ("finished", &step.finished_binaries),
        ] {
            if population.candidate.len() < population.base.len() {
                result.new.insert(format!(
                    "population:{name}:{label}:{}<{}",
                    population.candidate.len(),
                    population.base.len()
                ));
            }
        }
        // A replacement binary must not conceal the disappearance of a completed one.
        for binary in &step.finished_binaries.fixed {
            result
                .new
                .insert(format!("missing-finished:{name}:{binary}"));
        }
        result.steps.push(step);
    }
    for (label, diff) in [
        ("el1-failed", &result.el1_failed_tests),
        ("el1-unexpected", &result.el1_unexpected_failures),
    ] {
        result
            .new
            .extend(diff.new.iter().map(|v| format!("{label}:{v}")));
        result
            .fixed
            .extend(diff.fixed.iter().map(|v| format!("{label}:{v}")));
    }
    if base.el1.is_some() && candidate.el1.is_none() {
        result.new.insert("missing-el1-comparison".into());
    }
    let old = structured_failures(base);
    let next = structured_failures(candidate);
    result.new.extend(next.difference(&old).cloned());
    result.fixed.extend(old.difference(&next).cloned());
    result.passed = result.new.is_empty();
    Ok(result)
}

impl SignedDiff {
    /// Markdown also serves as the durable CLI log and PR comment body.
    pub fn markdown(&self) -> String {
        let mut text = format!(
            "Signed gate: **{}**\n\nBase `{}` → candidate `{}`\n\n| Step | Started base → candidate | Finished base → candidate | Unfinished base → candidate | Unitemized base → candidate |\n| --- | ---: | ---: | ---: | ---: |\n",
            if self.passed { "PASS" } else { "FAIL" },
            self.base,
            self.candidate
        );
        for step in &self.steps {
            text.push_str(&format!(
                "| {} | {} → {} | {} → {} | {} → {} | {} → {} |\n",
                step.name,
                step.started_tests.base.len(),
                step.started_tests.candidate.len(),
                step.finished_binaries.base.len(),
                step.finished_binaries.candidate.len(),
                step.unfinished_binaries.base.len(),
                step.unfinished_binaries.candidate.len(),
                step.unitemized_failures.base.len(),
                step.unitemized_failures.candidate.len()
            ));
        }
        text.push_str("\nSet differences below are observations; FIXED requires the population checks above to pass.\n");
        for step in &self.steps {
            for (label, diff) in [
                ("failed_tests", &step.failed_tests),
                ("unfinished_binaries", &step.unfinished_binaries),
                ("unitemized_failures", &step.unitemized_failures),
            ] {
                text.push_str(&format!(
                    "\n`{}.{label}` base={:?} candidate={:?}; NEW={:?}; FIXED={:?}\n",
                    step.name, diff.base, diff.candidate, diff.new, diff.fixed
                ));
            }
        }
        for (label, diff) in [
            ("EL1 failed_tests", &self.el1_failed_tests),
            ("EL1 unexpected_failures", &self.el1_unexpected_failures),
        ] {
            text.push_str(&format!(
                "\n{label}: base={:?} candidate={:?}; NEW={:?}; FIXED={:?}\n",
                diff.base, diff.candidate, diff.new, diff.fixed
            ));
        }
        text.push_str(&format!("\nNEW={:?}\n\nFIXED={:?}\n", self.new, self.fixed));
        text
    }
}
