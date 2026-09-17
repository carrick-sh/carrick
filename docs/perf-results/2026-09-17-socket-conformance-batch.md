# Socket conformance batch — 2026-09-17

Fresh ecosystem discovery selected socket receive and read-half shutdown as the
first kernel-backend coverage batch. The discovery population and remaining
priorities are recorded in [the discovery report](2026-09-17-ecosystem-discovery.md).

## Changes and red-first evidence

Added 29 public-kernel scripted tests: eight close/readiness tests and 21 receive
tests. The backend now has 123 tests, up from 94. Added two owner-level readiness
unit tests as well. These tests need no VM, Docker, or guest executable.

- Local SHUT_RD/SHUT_RDWR contributes EPOLLRDHUP, including descriptor aliases;
  SHUT_WR alone does not. Live-peer tests distinguish local read shutdown from
  peer exit and require an immediate event rather than repeated polling.
- Internet MSG_ERRQUEUE returns EAGAIN without consuming ordinary stream bytes;
  Unix sockets ignore the flag. Receive-header/iovec checks precede error-queue
  handling, while recvfrom address-length copyout follows successful receive.
- In-memory recvmsg clears absent ancillary output, returns MSG_CMSG_CLOEXEC,
  and ignores negative name length when the name pointer is null.
- In-zone promotion preserves SCTP protocol identity. TCP receives omit source
  addresses, including when the caller supplies an invalid source pointer;
  SCTP retains its source address and existing stream transport lifecycle.
  SCTP record boundaries and MSG_EOR remain unimplemented behavior gaps.

Against original source `00fb0920b`, four close tests and 12 of the initial 17
receive tests failed. Five receive controls passed. After the first fix, the
signed LTP witness exposed an introduced TCP source-pointer regression. Three
additional tests reproduced that regression and protocol-identity loss before
the correction; a fourth protects SCTP unread-close reset behavior. All 21
receive tests and the full kernel recipe pass. Native ARM64 Docker reductions
establish the pointer, copyout, ancillary, protocol, and close contracts.

## Fresh signed workload comparison

Final source: `892b10a8e` (full revision in `final-source-head.txt`).
The final focused run uses one worker, no retries, no automatic serial
confirmation, and zero cached oracle rows. All Carrick runs precede all Docker
runs. Eleven unique declared rows and unique run IDs were recorded under
`conf-35437`; stdout and stderr are retained for both sides.

| Witness | Before | Final Carrick / Docker |
| --- | --- | --- |
| ltp-epoll_wait05 | Missing RDHUP; 2.325 s | 1/1 / 1/1; 0.259 s / 0.210 s |
| ltp-recv01 | Empty error queue diverged | 5/5 / 5/5 |
| ltp-recvfrom01 | Address length and error queue diverged | 7/7 / 7/7 |
| ltp-recvmsg01 | Empty error queue diverged | 10/10 / 10/10 |
| CPython TCP long ancillary cases | Two failures | Both pass on both sides |

The epoll witness no longer incurs its missing-event two-second wait. These
single-run timings demonstrate the removed wait, not an ABBA performance
qualification or a general overhead claim.

CPython socket still has 21 failed assertions, all in its two SCTP recvmsg
classes. CPython SSL retains two pre-handshake-close failures. accept02,
io_submit04, send02, sendto01, and setsockopt02 still fail. The focused command
therefore exits 1; no baseline waivers or retry-to-green were used. Parsed
CPython pass totals vary with output classification, so the named failing and
fixed assertions are the acceptance boundary, not an aggregate pass percentage.

## Artifact and gate receipts

Local evidence: `target/conformance/eco-20260917/` (gitignored).

- Pinned product SHA-256: `e8c91323a43e3d9c937256291438818dcaac61580de010dbc03c20f4ba960895`.
- Pinned CDHash: `49b241f7c77c6805274bb777db1ad4a77d4a59ae`.
- LC_UUID: `77C1EBE4-6924-3B3C-9FA7-C60164068BF7`.
- Hypervisor entitlement and `__dof_carrick` recorded.
- Harness and manifest hashes remain those of the discovery run.

- Final `just ci`: exit 0; 5,491 passing test executions, five existing ignores.
- Final public `just conformance-probes`: exit 0. Executed 448 musl and 451 GNU
  generic cases with zero differences, plus dedicated/retained checks and the
  entitlement negative controls. Retained ARM64 sets: 33/33 per libc.
- Pinned smoke: 23/23 MATCH, fresh Docker oracle, exit 0.
- Pinned full strict closure: all 2,127 declared names, fresh Docker oracle,
  1,264 MATCH / 863 INCOMPLETE, exit 1. No release/full-closure acceptance.

The post-link script chooses its signature identifier from its temporary
filename, so another `just build` changes SHA/CDHash without changing LC_UUID.
The focused diagnostic above used the separately recorded `fc02e520...` signed
artifact. The final probe-tested `e8c91323...` artifact was preserved, restored
when no guest was alive, then used for smoke and full with `just --no-deps
conformance ...` to avoid another re-sign. Its hash remained unchanged through
those gates and final cleanup; its signature verifies. Both full-run and focused
transcripts confirm the four repaired LTP assertions. This signing-freshness
issue is recorded rather than silently equating distinct artifacts.

Full-run raw prefix: `conf-52434`. The same four rows become successful on both
sides; CPython socket retains exactly 21 failures in its two SCTP classes and
SSL retains exactly two pre-handshake-close failures. Of 863 incomplete rows,
777 have equal parsed side summaries and assertion pairs. There are 29 Carrick
failure-shaped rows with successful Docker counterparts and 14 Carrick cutoffs
with successful Docker counterparts. These are investigation populations, not
29 proven root causes or 14 proven hangs. Docker itself times out on shmctl05.

The audit finds two missing Carrick metadata records (`file_attr05` and
`finit_module01`): only 2,125 nonempty unique Carrick IDs versus 2,127 Docker IDs.
Their raw `conf-52434-c341/c342` transcripts exist, so they were not simply
unexecuted cases. A separate diagnostic (`conf-61475`) retains complete metadata
and shows shared missing-device/module setup outcomes. It does not repair or
replace the full ledger; the harness must retain execution errors and run
provenance instead of collapsing a lost RunOutput into a spawn-failure record.

## Remaining priorities after this batch

1. **Child-selector lifetime / ptrace11.** The full run adds a TBROK after its
   passing assertion, with `HVPatch child selector is stale or invalid` and child
   exit 127. A predetermined alternating sample (10 original + 10 current)
   reproduces the identical error twice on original `00fb0920b` and zero times
   on the current artifact. Since the current full run failed, the passing
   samples do not close it: it is a demonstrated pre-existing intermittent
   architectural defect. Receipts: `ptrace-attribution.json`, including
   original failures `conf-60699-c00` and `conf-60909-c00`.
2. **Blocking and scalability.** futex_cmp_requeue01 still truncates; preserve
   the original 100-versus-1,000-waiter reduction target. Newly observed 11-second
   diagnostic cutoffs in Go os/syscall and CPython compile are not yet attributed
   and must not be dismissed as timing noise. Their cutoff ratios are not
   completed-workload performance measurements.
3. **SCTP records and SSL close ordering.** Protocol identity is now retained,
   but SCTP remains a byte-stream approximation with 21 failing record/EOR
   assertions. The two SSL failures need their own reducer and ownership fix.
4. **Evidence integrity.** Enforce current probe-binary freshness and retain
   per-run error metadata. Source-hash-validated oracles alone did not prevent
   stale executables from producing misleading differences.

`pinned-full-audit.json` records exact populations and changed rows;
`audit-final.py` reproduces that audit. `final-cleanup.json` checks 8,686 run IDs
and finds no task processes or containers; no other Carrick guest titles remain.
All four registry/Docker image identities are unchanged before and after the
full run. The original ledger, intermediate regression, and rejected filtered
closure invocation remain preserved alongside final receipts.

The first probe-gate attempt encountered stale and missing test executables.
Rebuilt all 538 current-source ARM64 executables for each libc and recorded all
1,076 binary/source hash pairs. Stale exec/socket/memory probe differences
vanished with those rebuilt artifacts. That first attempt is not acceptance
evidence; its log remains preserved. The public probe gate's non-native AMD64
skips/report-only differences are not ARM64 closure or cross-platform proof.

The external workers were stopped before measurements. One orphaned worker
kernel test had used an unpartitioned recipe; its log was retained and its exact
process tree terminated. Acceptance uses the director-run partitioned recipes.
Unrelated user plans remain unchanged. No push was performed.

Follow-up: the [ptrace wait batch](2026-09-17-ptrace-wait-batch.md) adds 16
VM-free tests, fixes the stale-selector and waitid stop-kind defects, and
refreshes the full ecosystem ledger and remaining priorities.
