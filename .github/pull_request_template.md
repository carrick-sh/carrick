<!-- Title: type(scope): subject (imperative, lowercase, no period). -->

<!-- Required for any non-docs PR (enforced by the linked-issue check):
     `Closes #N`, `Fixes #N`, `Resolves #N` or `Part of #N`; cross-repo
     `Closes carrick-sh/carrick-nt#N` works. Docs-only PRs and the
     `no-issue` label are exempt. Edit this line, then re-run the check. -->
Closes #

## Why
<!-- Root cause, Linux/host semantics, what broke for whom. -->

## What
<!-- Approach and any candid divergence from Linux. -->

## Verified
<!-- Red-first probe/test names (red on the pre-fix tree, green after),
     LTP case, oracle diff. Report errno numbers. -->

## Gate receipts
Report each gate as NEW / FIXED failures against the published main baseline
for the base SHA, not as a raw pass count.

| Gate | Artifact / run | Result vs main baseline |
|---|---|---|
| CI (`just ci` / hosted run) | | NEW: none / FIXED: none |
| Signed (`just accept`, HVF) | HEAD, SHA-256, CDHash | NEW: / FIXED: |
| KVM (`just test-kvm`) | | NEW: / FIXED: |

## Out-of-fence changes
- [ ] This PR changes nothing outside its issue's fence, **or** each
      out-of-fence change is listed here with its oracle line.
