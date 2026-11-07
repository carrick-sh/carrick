# Board known answers

These reduced GitHub JSON snapshots preserve the API field names used by the
reconciler. `running-887.json` reconstructs the issue #1812 report: issue #887
is open, its project status is Blocked, and its dispatch round is running.
`rules.json` contains controlled variations for each status rule and precedence
boundary. They are deterministic known answers, not a claim of live API capture.

The running issue set comes from successful `Dispatch issue N` guard steps in
active runs of `dispatch-worker.yml`. Review prose is interpreted only for an
exact `Verdict: APPROVE` line on a published review's current commit. Dispatch
outcomes use the existing server-part `Dispatch outcome: STATUS` parser on
workflow bot comments (`github-actions[bot]` or `carrick-workers[bot]`).
The newest director comment may name a blocker using `waits on #N`.
