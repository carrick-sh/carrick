# Dispatch outcome replay for independent review continuation (#1825)

`dispatch-1825-outcomes.json` preserves verbatim GitHub comment and pull-request
review records fetched from `carrick-sh/carrick` on 2026-11-07 across the PRs
named in #1825:

- `pr_1781_impl_done` (`pull/1781#issuecomment-6702442087`) and
  `pr_1781_author_self_review` (`pull/1781#pullrequestreview-5810156819`):
  strong-tier (`codex`) implementation `Done` at `9d4074d52ecb` on issue #1766,
  plus the author worker's own self-review.
- `pr_1781_review_approved_raw` (`pull/1781#issuecomment-6705253459`),
  `pr_1781_review_approved_pr_review` (`pull/1781#pullrequestreview-5811434384`),
  `pr_1781_fix_done` (`pull/1781#issuecomment-6706933303`), and
  `pr_1781_fix_self_review` (`pull/1781#pullrequestreview-5812195446`):
  0-commit standard-tier (`agy`) independent review on `9d4074d52ecb` and
  follow-up `Done` commit `30aa235c6f5d` on PR #1781.
- `pr_1747_standard_impl_done` (`pull/1747#issuecomment-6703627040`):
  standard-tier (`codex`) implementation `Done` at `758a9a5bfcbe` on issue
  #1730, exercising the reverse tier transition (`standard` -> `strong`).
- `pr_1772_impl_done` (`pull/1772#issuecomment-6702692575`),
  `pr_1772_author_self_review` (`pull/1772#pullrequestreview-5810278778`),
  `pr_1772_review_approved` (`pull/1772#issuecomment-6705065876`),
  `pr_1772_review_approved_pr_review` (`pull/1772#pullrequestreview-5811340120`),
  `pr_1768_review_approved` (`pull/1768#issuecomment-6705325112`), and
  `pr_1768_review_approved_pr_review` (`pull/1768#pullrequestreview-5811443732`):
  verbatim `Done` independent review rounds (with clean rebase commits and
  published `Verdict: APPROVE` reviews) proving a completed review round starts
  no second review.
- `pr_1823_impl_done` (`pull/1823#issuecomment-6705208170`),
  `pr_1823_author_self_review` (`pull/1823#pullrequestreview-5811391370`),
  `pr_1823_review_changes_requested_raw` (`pull/1823#issuecomment-6706235386`),
  and `pr_1823_review_changes_requested_pr_review`
  (`pull/1823#pullrequestreview-5812031991`): strong-tier implementation `Done`
  at `2084ef66f859` on issue #1821 followed by a 0-commit standard-tier (`agy`)
  independent review with `Verdict: CHANGES REQUESTED` (including a 2,000-char
  clipped worker-contract JSON preview).
- `pr_1765_ecosystem_impl_done` (`pull/1765#issuecomment-6703810050`),
  `pr_1805_ecosystem_impl_done` (`pull/1805#issuecomment-6700761758`),
  `pr_1805_signed_gate_fail` (`pull/1805#issuecomment-6706657532`), and
  `pr_1805_bot_scoreboard_prose` (`pull/1805#issuecomment-6702727729`):
  verbatim `Done` outcomes on ecosystem blockers `#1671` and `#1733`, plus
  recorded `Signed gate: **FAIL**` and bot-prose negative controls for sweep
  guard 19.

For the two pre-#1816 0-commit review outcomes (`6705253459` and `6706235386`),
the server originally demoted worker `done` to `Dispatch outcome: Failed`
(`nothing was pushed ... so done is reported as Failed`). The fixture preserves
the verbatim recorded comment bodies, and tests replay both the verbatim `Done`
review outcomes (`6705065876`, `6705325112`) and the post-#1816 `Done` header
projection of those 0-commit review outcomes.
