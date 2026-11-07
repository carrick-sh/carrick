# Review-round outcome replay, 2026-11-07

`dispatch-1813-outcomes.json` retains the original Failed outcome bodies
and owner triggers for PRs #1776, #1731 and #1800, fetched from GitHub.
The replay maps their PR endpoints to the existing transport fixture's
PR #800 after classifying each original trigger and checking its target.

#1776's APPROVE is a PR issue comment, retained verbatim with its source
URL. It starts with its verdict and explicitly identifies the reviewed
head. Coordinator summaries and worker JSON claims are not published
review evidence. Formal PR reviews bind their head with `commit_id`.

The original `review.md` files for #1731 and #1800 are not retained in
those comments. Their harvested-review inputs are reconstructed from the
recorded worker summaries, with an explicit verdict line. The fixture
labels this provenance; it does not claim to recover the original files.
The replay publishes this prose through the existing #1783 publisher,
checks worker attribution and the exact head, and requires a Done outcome
without any push. Separate witnesses exercise automatic publication when
the coordinator omits `publish`, missing/stale/pending verdicts and
refusal of a changed harvested head at checkpoint and outcome.

The original #1731 outcome records one publish request. #1783 invokes the
review publisher only after `publish_commits` returns `Ok(Some(pr))`.
That code-publication path requires the unchanged owned PR head to descend
from admitted main. The read-only review preserved the older head, so
that prerequisite rejected publication before the review was posted.
The automatic checkpoint also skipped an unchanged head. Review rounds
now validate the admitted PR/head and use the same review publisher
without entering commit publication; code rounds keep their existing path.
