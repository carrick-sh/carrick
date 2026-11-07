# Board known answers

These reduced GitHub JSON snapshots preserve the API field names used by the
reconciler. `issue-887.json` is an open issue whose project status is Blocked.
`rules.json` contains controlled variations for each status rule and precedence
boundary. They are deterministic known answers, not a claim of live API capture.

Review prose is interpreted only for an exact `Verdict: APPROVE` line on a
published review's current commit. The newest director comment may name a
blocker using `waits on #N`. Bot comments, including the retired Actions
dispatch outcomes still present on old issues, never set a status.
