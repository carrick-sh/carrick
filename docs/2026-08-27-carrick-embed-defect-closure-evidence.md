# carrick-embed — closure evidence for the two carried defects

Date: 2026-08-27. Branch `feat/carrick-embed`.

The program directive named two defects to CLOSE rather than carry: the
`rlimitnproc` hang, and the x18 veneer readback returning 0. This records what
was actually established for each, on a named artifact, so neither has to be
re-derived.

## Artifact

| field | value |
|---|---|
| source HEAD | `b11acfdcfcd974c3696c6ec0092916a22bd8389d` |
| binary SHA-256 | `906419d40c8b56b13043ea917bea1b1d409472456dc61e54a861b9c3cf8bac9e` |
| CDHash=88babfd884c3e19ab6be494486c31cc6e23378a5 |
| hypervisor entitlement | present |
| `__dof_carrick` section | present |

## 1. `rlimitnproc` — CLOSED, oracle MATCH

**It was never oracle flakiness.** The probe hung the Docker oracle for an hour
and stranded live uid-47231 processes, and a poisoned uid then made every later
run fail, because `RLIMIT_NPROC` counts live processes per REAL uid across the
whole user namespace.

Root cause was in the PROBE: `fork` copies the descriptor table, so child D
inherited the parent's still-open write end of child C's release pipe. Closing
the parent's copy therefore never delivered EOF to C, `waitpid(C)` blocked, and
the only holder that could release it — D — was itself blocked and released only
afterwards. A deadlock between two children of one parent. A second latent
deadlock sat on the path a poisoned uid actually takes: a refused fork returns
-1, and a non-positive pid is a WILDCARD to `waitpid`.

Fixed in `b979367e6`: close inherited release fds in the child; guard the reap
on `pid > 0`; `PR_SET_PDEATHSIG`/SIGKILL so an externally killed probe cannot
orphan a child.

Verified on the artifact above, Docker and carrick run serially:

- carrick stdout diffed against the oracle's: **line-exact MATCH**, all ten
  booleans true, exit 0 on both sides.
- Repeat runs byte-identical on both sides.
- A privileged `--pid=host` sweep finds **0** leftover `rlimitnproc`
  processes after the runs.

Red-first evidence from the investigation: the pre-fix binary hung in Docker at
`reap_c_ok` with `fork_c_after_reap_ok=true`, the container had to be killed,
the sweep found 3 stranded uid-47231 processes, and the next run then reported
`fork_a_ok=false` — the poisoning observed directly rather than inferred.

Operational note worth keeping: `timeout` on `docker run` kills the CLI, not
the container. The hung container was still running minutes later.

## 2. x18 veneer readback returning 0 — NOT REPRODUCIBLE, hypothesis refuted, now self-diagnosing

`dynamic_x18_publication_is_veneered_and_executes_against_the_thread_slot`
failed once with `left: 0, right: 335544320` (the AArch64 `B` opcode).

- **Not reproducible**: 0/30 targeted attempts under load, plus repeated
  full-crate runs (126/126) since.
- **The leading hypothesis is REFUTED.** The suspicion was that
  `force_dynamic_shadow` leaked across tests in one process. It cannot:
  it is a field on `DirectLoadGroup` (`direct.rs:3017`), not a process-global,
  and every test builds its own group.

Rather than pay another blind cycle, the assertion is now SELF-DIAGNOSING: on
failure it reports the read word, the site VA, the mapping base, `x18_site`,
`dynamic_exec_is_shadowed`, and three neighbouring words. The message itself
was proven to render by temporarily flipping the expected constant.

A recurrence will therefore distinguish the three remaining candidates instead
of repeating `left: 0`: an all-zero page points at a writable `PT_LOAD`
replaced in place by a fresh anonymous `MAP_FIXED` mapping; a zero at only the
site says the patch landed elsewhere; `shadowed=true` says publication took the
shadow route.

**Honest status:** this is closed as far as evidence allows — the failure cannot
be reproduced and its most concrete explanation has been eliminated. It is not
claimed FIXED, because nothing was changed in the publication path.

## What this report does NOT claim

No phase of the carrick-embed program is complete. Gate B's concurrent mode is
red, so no phase receipt exists.
