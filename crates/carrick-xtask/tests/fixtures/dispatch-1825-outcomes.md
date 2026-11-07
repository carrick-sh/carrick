# Dispatch outcome replay for independent review continuation (#1825)

`dispatch-1825-outcomes.json` provides deterministic known-answer outcome
comments shaped identically to `dispatch_loop`'s published GitHub outcome format
(server header lines, fenced `Outcome contract`, fenced `Publication receipt`,
fenced `Worker contract (claims for review)`, `Worker choices and reasons`, and
`Loop claims (unverified)`):

- `pr_1781_impl_done`: a `strong`-tier implementation round (`agy` + `codex`)
  ending `Done` with 2 commits pushed and an author worker self-review on the
  pushed head.
- `pr_1781_review_approved` and `pr_1781_review_changes_requested`: `standard`
  review-only rounds (0 commits pushed) ending `Done` with `APPROVED` vs
  `CHANGES REQUESTED` verdicts on that head.
- `pr_1781_fix_done` and `pr_1781_review2_changes_requested`: follow-up fix
  round advancing head SHA and second review round exercising incremental diff
  scoping (`prev_oid..head`) and the `UNATTENDED_ROUNDS` loop cap.
- `pr_1815_standard_impl_done`: a `standard`-tier implementation round (`agy`)
  ending `Done` to prove the reverse tier transition (`standard` -> `strong`).
- `pr_1740_ecosystem_impl_done` and `pr_1830_ecosystem_successor_done`:
  ecosystem-blocker (`#1506`) and split-successor (`#1829` split from `#1733`)
  `Done` implementation outcomes exercising sweep guard 19's signed-scoreboard
  wait.

In addition, `replay_1825_verdict_parsing_raw_capacity_and_recorded_1740_outcome`
replays the verbatim multi-worker GitHub outcome comment for PR #1740 from
`dispatch-1763-outcomes.json` (`pull/1740#issuecomment-6688992437`).
