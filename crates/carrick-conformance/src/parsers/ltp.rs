//! LTP verdict parser, lifted from `ltp-check.sh`. Two-tier extraction over the
//! combined stdout+stderr:
//!   - Tier 1 (new `tst_test` API): the `Summary:` block (`passed/failed/broken`).
//!   - Tier 2 (old API): count per-line `TPASS/TFAIL/TBROK/TCONF` tokens (those
//!     tests print NO Summary, so a summary-only verdict would false-MATCH them).
//!
//! Regression mode remains count-based and collapses the side to one synthetic
//! `"summary"` id. Closure mode instead retains source/case assertion identities,
//! duplicate occurrences, and reconciles any framework summary against them.

use super::{AssertionCollector, Outcome, Raw, SuiteOutcome, SuiteResult, Totals, VerdictParser};
use regex::Regex;
use std::collections::BTreeMap;

pub struct LtpParser;

impl LtpParser {
    pub(crate) fn parse_closure(&self, raw: &Raw) -> SuiteResult {
        if raw.exit_code == 124 || raw.exit_code == 137 {
            return SuiteResult {
                totals: Totals::default(),
                result: SuiteOutcome::None,
                ids: BTreeMap::new(),
            };
        }

        let text = super::strip_carrick_banners(&raw.combined());
        let (
            Ok(modern),
            Ok(old),
            Ok(legacy),
            Ok(legacy_numbered),
            Ok(summary_count),
            Ok(summary_field),
        ) = (
            Regex::new(r"^(\S+\.c):(\d+):\s+(TPASS|TFAIL|TBROK|TCONF):\s*(.*)$"),
            Regex::new(r"^(\S+)\s+(\d+)\s+(TPASS|TFAIL|TBROK|TCONF)\s*:\s*(.*)$"),
            Regex::new(
                r"^(\S+)\s+\d+\s+TINFO\s*:\s+.*?\b(?:Test case|case)\s+(\d+)\b.*?\b(PASSED|FAILED)\b",
            ),
            Regex::new(r"^(\S+)\s+(\d+)\s+\S+\s*:\s+.*\b(PASSED|FAILED)\b"),
            Regex::new(r"^(passed|failed|broken|skipped)\s+(\d+)\s*$"),
            Regex::new(r"^(passed|failed|broken|skipped)\b"),
        )
        else {
            return SuiteResult::empty();
        };

        let mut assertions = AssertionCollector::default();
        let (mut passed, mut failed, mut broken, mut skipped) = (0usize, 0usize, 0usize, 0usize);
        let mut summary = [0usize; 4];
        let mut summary_fields = [0usize; 4];
        let mut summary_headers = 0usize;
        let mut malformed_summary_field = false;

        for line in text.lines() {
            if line.trim() == "Summary:" {
                summary_headers += 1;
                continue;
            }
            let trimmed = line.trim();
            if summary_headers > 0
                && let Some(caps) = summary_count.captures(trimmed)
            {
                let Some(n) = caps
                    .get(2)
                    .and_then(|value| value.as_str().parse::<usize>().ok())
                else {
                    malformed_summary_field = true;
                    continue;
                };
                match caps.get(1).map(|value| value.as_str()) {
                    Some("passed") => {
                        summary[0] += n;
                        summary_fields[0] += 1;
                    }
                    Some("failed") => {
                        summary[1] += n;
                        summary_fields[1] += 1;
                    }
                    Some("broken") => {
                        summary[2] += n;
                        summary_fields[2] += 1;
                    }
                    Some("skipped") => {
                        summary[3] += n;
                        summary_fields[3] += 1;
                    }
                    _ => {}
                }
                continue;
            }
            if summary_headers > 0 && summary_field.is_match(trimmed) {
                malformed_summary_field = true;
                continue;
            }

            let assertion = modern
                .captures(line)
                .and_then(|caps| closure_assertion(&caps, 1, 2, 3))
                .or_else(|| {
                    old.captures(line)
                        .and_then(|caps| closure_assertion(&caps, 1, 2, 3))
                })
                .or_else(|| {
                    legacy.captures(line).and_then(|caps| {
                        let binary = caps.get(1)?.as_str();
                        let case = caps.get(2)?.as_str();
                        let outcome = match caps.get(3)?.as_str() {
                            "PASSED" => Outcome::Ok,
                            "FAILED" => Outcome::Fail,
                            _ => return None,
                        };
                        Some((format!("ltp:{binary}:{case}"), outcome))
                    })
                })
                .or_else(|| {
                    legacy_numbered.captures(line).and_then(|caps| {
                        let binary = caps.get(1)?.as_str();
                        let case = caps.get(2)?.as_str();
                        let outcome = match caps.get(3)?.as_str() {
                            "PASSED" => Outcome::Ok,
                            "FAILED" => Outcome::Fail,
                            _ => return None,
                        };
                        Some((format!("ltp:{binary}:{case}"), outcome))
                    })
                });

            if let Some((id, outcome)) = assertion {
                match outcome {
                    Outcome::Ok => passed += 1,
                    Outcome::Fail => failed += 1,
                    Outcome::Broken => broken += 1,
                    Outcome::Conf => skipped += 1,
                    _ => {}
                }
                assertions.push(id, outcome);
            }
        }

        let totals = Totals {
            n: passed + failed + broken,
            passed,
            failed,
            broken,
            skipped,
        };
        let ids = assertions.into_ids();
        let summary_matches = summary_headers == 0
            || (summary_headers == 1
                && summary_fields == [1, 1, 1, 1]
                && !malformed_summary_field
                && summary == [passed, failed, broken, skipped]);

        let result = if ids.is_empty() || !summary_matches {
            SuiteOutcome::None
        } else if failed > 0 || broken > 0 || raw.exit_code != 0 {
            SuiteOutcome::Failure
        } else {
            SuiteOutcome::Success
        };

        SuiteResult {
            totals,
            result,
            ids,
        }
    }
}

fn closure_assertion(
    caps: &regex::Captures<'_>,
    binary_index: usize,
    case_index: usize,
    outcome_index: usize,
) -> Option<(String, Outcome)> {
    let binary = caps.get(binary_index)?.as_str();
    let case = caps.get(case_index)?.as_str();
    let outcome = match caps.get(outcome_index)?.as_str() {
        "TPASS" => Outcome::Ok,
        "TFAIL" => Outcome::Fail,
        "TBROK" => Outcome::Broken,
        "TCONF" => Outcome::Conf,
        _ => return None,
    };
    let descriptor = caps
        .get(outcome_index + 1)
        .map(|message| descriptor_slug(message.as_str()))
        .unwrap_or_default();
    let id = if descriptor.is_empty() {
        format!("ltp:{binary}:{case}")
    } else {
        format!("ltp:{binary}:{case}:{descriptor}")
    };
    Some((id, outcome))
}

/// Reduce a tst_res message to the stable DESCRIPTOR the closure id keys on.
///
/// tst_fd-family suites emit one assertion per fd type from the SAME
/// file:line; keying those rows positionally shifts every later ordinal
/// whenever one side's fd inventory differs, so unrelated fd types get
/// compared against each other (splice07/ioctl_ficlone04). The line text
/// itself names the fd type, so the id carries it — with the parts that
/// legitimately vary stripped:
///
/// - the outcome detail after the LAST " : " (a TPASS "… : EINVAL (22)"
///   and a divergent TFAIL "… : SUCCESS" must share one id so the pair
///   compares as semantic, not as two unexercised absences);
/// - digit runs (pids, sizes, timings) normalize to `N`;
/// - whitespace collapses to `_`, and the slug is length-bounded.
fn descriptor_slug(message: &str) -> String {
    let descriptor = match message.rsplit_once(" : ") {
        Some((head, _detail)) => head,
        None => message,
    };
    let mut slug = String::with_capacity(descriptor.len().min(64));
    let mut last_was_sep = true;
    let mut last_was_digit = false;
    for ch in descriptor.chars() {
        if slug.len() >= 64 {
            break;
        }
        if ch.is_ascii_digit() {
            if !last_was_digit {
                slug.push('N');
            }
            last_was_digit = true;
            last_was_sep = false;
            continue;
        }
        last_was_digit = false;
        if ch.is_whitespace() {
            if !last_was_sep {
                slug.push('_');
            }
            last_was_sep = true;
        } else {
            slug.push(ch);
            last_was_sep = false;
        }
    }
    while slug.ends_with('_') {
        slug.pop();
    }
    slug
}

impl VerdictParser for LtpParser {
    fn parse(&self, raw: &Raw) -> SuiteResult {
        // An explicit `timeout(1)` exit propagated as the child's code.
        if raw.exit_code == 124 || raw.exit_code == 137 {
            return SuiteResult {
                totals: Totals::default(),
                result: SuiteOutcome::None,
                ids: BTreeMap::new(),
            };
        }
        let text = super::strip_carrick_banners(&raw.combined());

        let (mut passed, mut failed, mut broken, mut conf, mut skipped) =
            (0usize, 0usize, 0usize, 0usize, 0usize);

        // Tier 1: the Summary block (`passed 5` / `failed 1` / `broken 0` /
        // `skipped N`). `skipped` is captured so a not-exercised run (all-zero
        // pass/fail/broken, nonzero skipped — e.g. a TCONF in a Docker container
        // that lacks cgroups/LTP_DEV) classifies as Conf, not a phantom Empty.
        let mut tier1 = false;
        if let Ok(re) = Regex::new(r"(?m)^(passed|failed|broken|skipped)\s+(\d+)\s*$") {
            for caps in re.captures_iter(&text) {
                let (Some(k), Some(v)) = (caps.get(1), caps.get(2)) else {
                    continue;
                };
                let n: usize = v.as_str().parse().unwrap_or(0);
                match k.as_str() {
                    "passed" => passed += n,
                    "failed" => failed += n,
                    "broken" => broken += n,
                    "skipped" => skipped += n,
                    _ => {}
                }
                tier1 = true;
            }
        }

        // Tier 2: old-API per-line `TPASS/TFAIL/TBROK/TCONF` token counting.
        if !tier1 {
            for line in text.lines() {
                if line.contains("TPASS") {
                    passed += 1;
                } else if line.contains("TFAIL") {
                    failed += 1;
                } else if line.contains("TBROK") {
                    broken += 1;
                } else if line.contains("TCONF") {
                    conf += 1;
                }
            }
        }

        // Tier 3: legacy block-report API — tests that print NEITHER a Summary
        // NOR `TPASS/TFAIL` tokens. Two forms, both gated on "no modern tokens
        // seen" so this never perturbs new-API output:
        //   (a) an explicit `... PASSED` / `... FAILED` word per case (fcntl16/
        //       19/20/21 on `TINFO` lines);
        //   (b) success signalled purely by a clean exit — the test ran (it
        //       emitted `TINFO`) and exited 0 with no failure token (fcntl11's
        //       Enter/Exit-block trail, mmap10's iteration log). A real crash
        //       exits non-zero (or 124/137, handled above) and stays Empty.
        if !tier1 && passed + failed + broken + conf == 0 {
            if text.contains("tst_exit: not found") {
                broken = 1;
            }
            for line in text.lines() {
                if line.contains("FAILED") {
                    failed += 1;
                } else if line.contains("PASSED") {
                    passed += 1;
                }
            }
            if passed + failed == 0 && raw.exit_code == 0 && text.contains("TINFO") {
                passed = 1; // old-API success-by-clean-exit
            }
        }

        let t = Totals {
            n: passed + failed + broken,
            passed,
            failed,
            broken,
            skipped,
        };

        let (summary, result) = if broken > 0 {
            (Outcome::Broken, SuiteOutcome::Failure)
        } else if failed > 0 {
            (Outcome::Fail, SuiteOutcome::Failure)
        } else if passed > 0 {
            (Outcome::Ok, SuiteOutcome::Success)
        } else if conf > 0 || skipped > 0 {
            // only TCONF / skipped-only Summary -> not exercised on this kernel
            (Outcome::Conf, SuiteOutcome::Success)
        } else {
            // No tokens at all and no clean-exit signal -> crashed before
            // producing a verdict.
            return SuiteResult {
                totals: t,
                result: SuiteOutcome::Empty,
                ids: BTreeMap::new(),
            };
        };

        let mut ids = BTreeMap::new();
        ids.insert("summary".to_string(), summary);

        SuiteResult {
            totals: t,
            result,
            ids,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// tst_fd-family suites emit ONE assertion per fd type from the SAME
    /// file:line. A positional (`#occurrence`) key shifts every later ordinal
    /// when one side's fd inventory differs, comparing unrelated fd types
    /// against each other (splice07/ioctl_ficlone04, ~194 rows). The closure
    /// id must therefore carry the per-line descriptor text so a missing fd
    /// type surfaces as exactly ONE unexercised pair while every shared fd
    /// type still pairs by identity.
    #[test]
    fn closure_ids_key_on_descriptor_not_ordinal() {
        let oracle = concat!(
            "splice07.c:56: TPASS: splice() on file -> pipe : EINVAL (22)\n",
            "splice07.c:56: TPASS: splice() on file -> unix socket : EINVAL (22)\n",
            "splice07.c:56: TPASS: splice() on file -> fanotify : EINVAL (22)\n",
        );
        // carrick lacks fanotify in the inventory but diverges on unix socket.
        let carrick = concat!(
            "splice07.c:56: TPASS: splice() on file -> pipe : EINVAL (22)\n",
            "splice07.c:56: TFAIL: splice() on file -> unix socket : SUCCESS\n",
        );
        let o = LtpParser.parse_closure(&raw(oracle));
        let c = LtpParser.parse_closure(&raw(carrick));
        // The shared descriptors pair by identity...
        let pipe_id = o
            .ids
            .keys()
            .find(|k| k.contains("pipe"))
            .expect("pipe id present")
            .clone();
        assert_eq!(o.ids.get(&pipe_id), Some(&Outcome::Ok));
        assert_eq!(c.ids.get(&pipe_id), Some(&Outcome::Ok), "{c:?}");
        // ...including the DIVERGENT one: same id, different outcome — the
        // outcome tail after the last " : " must not participate in the key.
        let sock_id = o
            .ids
            .keys()
            .find(|k| k.contains("unix_socket") || k.contains("unix socket"))
            .expect("unix socket id present")
            .clone();
        assert_eq!(o.ids.get(&sock_id), Some(&Outcome::Ok));
        assert_eq!(c.ids.get(&sock_id), Some(&Outcome::Fail), "{c:?}");
        // The missing fd type is absent from carrick under its OWN id; no
        // other id shifted.
        let fan_id = o
            .ids
            .keys()
            .find(|k| k.contains("fanotify"))
            .expect("fanotify id present")
            .clone();
        assert!(!c.ids.contains_key(&fan_id));
        assert_eq!(o.ids.len(), 3);
        assert_eq!(c.ids.len(), 2);
    }

    /// Variable data (pids, sizes, timings) in the descriptor must not split
    /// ids between the oracle and carrick runs: digit runs normalize.
    #[test]
    fn closure_ids_normalize_digit_runs() {
        let a = LtpParser.parse_closure(&raw(
            "kill02.c:100: TPASS: signal sent to pid 4711 : arrived
",
        ));
        let b = LtpParser.parse_closure(&raw("kill02.c:100: TPASS: signal sent to pid 9 : arrived
"));
        assert_eq!(
            a.ids.keys().collect::<Vec<_>>(),
            b.ids.keys().collect::<Vec<_>>()
        );
    }

    /// Identical descriptor lines still disambiguate ordinally.
    #[test]
    fn closure_ids_keep_occurrence_for_true_duplicates() {
        let r = LtpParser.parse_closure(&raw("loop.c:10: TPASS: iteration ok
loop.c:10: TPASS: iteration ok
"));
        assert_eq!(r.ids.len(), 2);
    }

    fn raw(s: &str) -> Raw {
        Raw {
            stdout: s.to_string(),
            stderr: String::new(),
            exit_code: 0,
            timed_out: false,
        }
    }

    #[test]
    fn tier1_summary_block() {
        let out = "tst_test.c:1: TINFO: ...\nSummary:\npassed   5\nfailed   1\nbroken   0\nskipped  0\nwarnings 0\n";
        let r = LtpParser.parse(&raw(out));
        assert_eq!(r.totals.passed, 5);
        assert_eq!(r.totals.failed, 1);
        assert_eq!(r.ids.get("summary"), Some(&Outcome::Fail));
        assert_eq!(r.result, SuiteOutcome::Failure);
    }

    #[test]
    fn tier1_all_pass() {
        let out = "Summary:\npassed   3\nfailed   0\nbroken   0\n";
        let r = LtpParser.parse(&raw(out));
        assert_eq!(r.ids.get("summary"), Some(&Outcome::Ok));
        assert_eq!(r.result, SuiteOutcome::Success);
        assert_eq!(r.totals.n, 3);
    }

    #[test]
    fn tier2_old_api_tokens() {
        let out = "foo    1  TPASS  :  ok\nfoo    2  TPASS  :  ok\nfoo    3  TFAIL  :  bad\n";
        let r = LtpParser.parse(&raw(out));
        assert_eq!(r.totals.passed, 2);
        assert_eq!(r.totals.failed, 1);
        assert_eq!(r.ids.get("summary"), Some(&Outcome::Fail));
    }

    #[test]
    fn tbrok_is_broken() {
        let out = "Summary:\npassed   0\nfailed   0\nbroken   1\n";
        let r = LtpParser.parse(&raw(out));
        assert_eq!(r.ids.get("summary"), Some(&Outcome::Broken));
    }

    #[test]
    fn empty_is_empty() {
        let r = LtpParser.parse(&raw("nothing here\n"));
        assert_eq!(r.result, SuiteOutcome::Empty);
    }

    #[test]
    fn missing_ltp_shell_helper_is_broken() {
        let mut out = raw("/opt/ltp/testcases/bin/test_ioctl: 59: tst_exit: not found\n");
        out.exit_code = 127;
        let r = LtpParser.parse(&out);
        assert_eq!(r.result, SuiteOutcome::Failure);
        assert_eq!(r.ids.get("summary"), Some(&Outcome::Broken));
    }

    #[test]
    fn skipped_only_summary_is_conf() {
        // clone303/madvise06/08: new-API run that SKIPPED (e.g. cgroup EROFS in
        // a container) -> Summary with only `skipped`, all else 0.
        let out = "tst_cgroup.c: TCONF: '/sys/fs/cgroup/ltp' read-only\nSummary:\npassed   0\nfailed   0\nbroken   0\nskipped  1\nwarnings 0\n";
        let r = LtpParser.parse(&raw(out));
        assert_eq!(r.ids.get("summary"), Some(&Outcome::Conf));
        assert_eq!(r.result, SuiteOutcome::Success);
        assert_eq!(r.totals.skipped, 1);
        assert_eq!(r.totals.n, 0);
    }

    #[test]
    fn old_api_passed_word_counts() {
        // fcntl16/19/20/21: legacy per-case `... PASSED` on TINFO lines, no
        // Summary and no TPASS token.
        let out = "fcntl16  0  TINFO  :  Test case 1: without mandatory locking PASSED\nfcntl16  0  TINFO  :  Test case 2: with mandatory record locking PASSED\nfcntl16  0  TINFO  :  Test case 3: mandatory locking with NODELAY PASSED\n";
        let r = LtpParser.parse(&raw(out));
        assert_eq!(r.totals.passed, 3);
        assert_eq!(r.ids.get("summary"), Some(&Outcome::Ok));
        assert_eq!(r.result, SuiteOutcome::Success);
    }

    #[test]
    fn old_api_failed_word_counts() {
        let out = "t  0  TINFO  :  Test case 1: PASSED\nt  0  TINFO  :  Test case 2: FAILED\n";
        let r = LtpParser.parse(&raw(out));
        assert_eq!(r.totals.failed, 1);
        assert_eq!(r.result, SuiteOutcome::Failure);
    }

    #[test]
    fn old_api_clean_exit_is_success() {
        // fcntl11/mmap10: only TINFO Enter/Exit-block (or iteration) trail, no
        // verdict token, exit 0 -> success by clean exit.
        let out = "mmap10  0  TINFO  :  use /dev/zero.\nmmap10  0  TINFO  :  start tests.\nmmap10  0  TINFO  :  use /dev/zero.\nmmap10  0  TINFO  :  start tests.\n";
        let r = LtpParser.parse(&Raw {
            stdout: out.to_string(),
            stderr: String::new(),
            exit_code: 0,
            timed_out: false,
        });
        assert_eq!(r.result, SuiteOutcome::Success);
        assert_eq!(r.totals.passed, 1);
    }

    #[test]
    fn tinfo_with_nonzero_exit_stays_empty() {
        // A crash mid-run (TINFO printed, then a non-zero exit, no verdict) must
        // NOT be rescued by the clean-exit arm.
        let out = "t  0  TINFO  :  start tests.\n";
        let r = LtpParser.parse(&Raw {
            stdout: out.to_string(),
            stderr: String::new(),
            exit_code: 1,
            timed_out: false,
        });
        assert_eq!(r.result, SuiteOutcome::Empty);
    }

    fn closure(s: &str) -> SuiteResult {
        LtpParser.parse_closure(&raw(s))
    }

    #[test]
    fn closure_distinguishes_equal_counts_with_different_assertions() {
        let c = closure(
            "a.c:10: TPASS: a\nb.c:20: TFAIL: b\nSummary:\npassed 1\nfailed 1\nbroken 0\nskipped 0\n",
        );
        let d = closure(
            "a.c:10: TFAIL: a\nb.c:20: TPASS: b\nSummary:\npassed 1\nfailed 1\nbroken 0\nskipped 0\n",
        );
        assert_eq!(
            (
                c.totals.n,
                c.totals.passed,
                c.totals.failed,
                c.totals.broken,
                c.totals.skipped,
            ),
            (
                d.totals.n,
                d.totals.passed,
                d.totals.failed,
                d.totals.broken,
                d.totals.skipped,
            )
        );
        assert_ne!(c.ids, d.ids);
        assert_eq!(c.ids["ltp:a.c:10:a#1"], Outcome::Ok);
    }

    #[test]
    fn closure_preserves_repeated_ltp_assertions() {
        let result = closure("loop.c:42: TPASS: iteration\nloop.c:42: TPASS: iteration\n");
        assert_eq!(result.ids.len(), 2);
        assert!(result.ids.contains_key("ltp:loop.c:42:iteration#2"));
    }

    #[test]
    fn closure_parses_old_and_legacy_numbered_assertions() {
        let result = closure(
            "oldbin  1  TPASS  : first\noldbin  2  TFAIL  : second\nlegacy  0  TINFO  : Test case 3: PASSED\nlegacy2  7  TINFO  : operation PASSED\n",
        );
        assert_eq!(result.ids["ltp:oldbin:1:first#1"], Outcome::Ok);
        assert_eq!(result.ids["ltp:oldbin:2:second#1"], Outcome::Fail);
        assert_eq!(result.ids["ltp:legacy:3#1"], Outcome::Ok);
        assert_eq!(result.ids["ltp:legacy2:7#1"], Outcome::Ok);
    }

    #[test]
    fn closure_rejects_summary_only_tbrok_tconf_and_count_mismatch() {
        for text in [
            "Summary:\npassed 0\nfailed 0\nbroken 1\nskipped 0\n",
            "Summary:\npassed 0\nfailed 0\nbroken 0\nskipped 1\n",
            "a.c:10: TPASS: a\nSummary:\npassed 2\nfailed 0\nbroken 0\nskipped 0\n",
            "only.c:1: TINFO: setup\n",
        ] {
            assert_ne!(closure(text).result, SuiteOutcome::Success, "{text}");
        }
    }

    #[test]
    fn closure_requires_each_summary_counter_exactly_once() {
        for text in [
            "a.c:10: TPASS: a\nSummary:\npassed 1\nfailed 0\nbroken 0\n",
            "a.c:10: TPASS: a\nSummary:\npassed 1\nfailed 0\nbroken 0\nskipped 0\nskipped 0\n",
            "a.c:10: TPASS: a\nSummary:\npassed 1\nfailed 0\nbroken 0\nskipped nope\n",
            "a.c:10: TPASS: a\nSummary:\npassed 1\nfailed 0\nbroken 0\nskipped 999999999999999999999999999999999999999\n",
        ] {
            assert_ne!(closure(text).result, SuiteOutcome::Success, "{text}");
        }
    }
}
