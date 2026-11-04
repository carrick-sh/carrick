# Starved merge-group jobs: named infrastructure failure

The accompanying patch for #1603
adds cancellation diagnostics to the existing `ci-ok` path and preserves
`just ci-results` as its sole verdict. It leaves hosted macOS checks hosted.
Do not use this slice as evidence that merge-queue ejection is fixed.

## Cancellation cause

The check annotations for [macos-clippy](https://api.github.com/repos/carrick-sh/carrick/check-runs/126701119636/annotations)
and [macos-authority](https://api.github.com/repos/carrick-sh/carrick/check-runs/126701120224/annotations)
report that GitHub could not acquire a hosted runner after multiple attempts.
They also report macOS runner capacity constraints. This is a named hosted
runner acquisition failure, not evidence that code ran and failed.

The incident workflow has `cancel-in-progress` enabled only for pull requests;
the event was `merge_group`. Both jobs have a 60-minute execution timeout,
but never acquired a runner and ended after about 20 and 25 minutes.
The [PR timeline](https://api.github.com/repos/carrick-sh/carrick/issues/1583/timeline)
records `github-merge-queue[bot]` removing the PR at 17:10:38Z, after both
cancellations and the 16:57:35Z aggregate failure. Queue removal therefore
cannot explain these earlier cancellations. The run's `actor` and
`triggering_actor` identify who triggered the run, not who cancelled jobs.
The public API does not expose a separate cancellation actor; organization
audit access is unavailable here. The annotations identify the service's
runner acquisition failure directly; no repository cancellation source was
found. Do not attribute this to a user from the trigger identity.

Per the director's revised scope, report the infrastructure failure and keep
the existing failing aggregate. Do not retry inside `ci-ok`, bypass a failed
dependency, or move the hosted macOS checks. The patch remains for the director
to apply; it does not preserve queue membership during a hosted outage.

## Historical dry run

The unmodified full REST jobs response for run `41865736523` contains 29 jobs.
The GitHub connector's jobs wrapper omits assignment fields; the full REST
response was read instead. Both cancelled jobs have `runner_name: ""`,
`runner_id: 0`, and `steps: []`:

| Job | Job ID | Created | Completed | Queue interval |
|---|---|---|---|---|
| macos-clippy | 126701119636 | 16:20:39Z | 16:40:08Z | 19m 29s |
| macos-authority | 126701120224 | 16:20:39Z | 16:45:08Z | 24m 29s |

Their job-level `started_at` equals `created_at` despite no runner assignment;
that timestamp alone is **not** evidence of execution. Classification requires
an explicitly empty runner name and no started steps. Missing assignment or
step metadata fails closed. A failed job is never classified as an unassigned cancellation.

Reproduce without changing any run:

```sh
gh api 'repos/carrick-sh/carrick/actions/runs/41865736523/jobs?per_page=100' > jobs.json
just xtask ci-starved-jobs --jobs jobs.json
```

The tool refuses an incomplete page. It reports both macOS jobs as
`infrastructure-failure candidate`, includes their job timestamp interval, and reports
the incident's failed `ci-ok` as `fail`. This neither schedules a retry nor
excuses a failed dependency. The generic jobs payload proves lack of execution,
not cancellation cause: manual or concurrency cancellation can have the same
shape. The output marks cause unverified; the incident annotations above supply
the named hosted acquisition failure for this particular run.

## Review and verification

Fresh independent Sol review and paired main/candidate test evidence are
provided in the publishing handoff. Keep the PR draft until the director has
applied the workflow patch and published the review. No workflow files are
changed by this worker.
