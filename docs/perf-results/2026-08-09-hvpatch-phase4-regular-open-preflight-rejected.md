# HvPatch Phase 4 regular-open preflight experiment

Date: 2026-08-09

Status: **REJECTED; mechanism counts improved, end-to-end CPU and wall did
not. Phase 4 remains RED.** The candidate made a contained host fd/metadata
open precede `lookup_kind` for existing non-creating, non-truncating entries.
It removed 4.58% of Darwin `openat` calls and larger shares of associated
`close`/`fcntl`/`fstat64` calls inside Linux `openat`, but a retained two-block
ABBA measured +0.70% CPU and +0.26% wall. The implementation was removed.

## Hypothesis and semantic boundary

The caller census in
`2026-08-09-hvpatch-phase4-service-lowering.md` showed
`RootFsVfs::open_for_dispatch` performing `overlay.lookup_kind(path)` before
`open_raw_fd_with_metadata`. On the Darwin host backend both operations resolve
the same path and validate containment/exact spelling; the latter already
derives metadata from the fd served to the guest.

The experiment added a fail-closed backend operation for existing entries:

- sample the shared filesystem generation;
- normalize the path and reject a whiteout;
- use `fast_open_for_guest` for one contained, `O_NOFOLLOW`, exact-name open;
- derive regular-file metadata from that fd, or report a proven directory;
- reject socket markers, symlinks, FIFOs, misses, aliases, escapes, and any
  generation change to the existing layered path;
- retain the original create/truncate sequencing.

This preserved the one-VM/ASID design and changed no guest-process topology.

## Provenance

- Host: macOS 27.0 build `26A5388g`, arm64.
- Branch: `codex/hvpatch`; committed parent `258643a3`; candidate was an
  uncommitted source diff and is not present after this evidence checkpoint.
- Baseline signed binary SHA-256:
  `6605d8d1cf614ae2441b2d4559ab05bf0c5ef8630a136ef0a92369343698e09f`.
- Candidate signed binary SHA-256:
  `13bc9612ddda125386d0cd79810d91f64a04a2fe3c66f0355a85e36c0bb188ff`.
- Backend: `--exec-backend hvpatch`; filesystem: `--fs host`.
- Workload: `scripts/perf/fixtures/hvpatch-cold-go-build.sh` in
  `localhost:5005/carrick-go-conformance:1.24`, `--pull never`.
- Every arm printed exact `ok` and `BUILD_OK` and exited zero. Carrick and
  Docker were not run concurrently.

Retained raw evidence:

- `target/perf/hvpatch-phase4/fs-preflight-lowering-1.raw`, SHA-256
  `b84e6d9109a5b030a4a51d55d8492c71181a4e80fe19e9cc9a967aa90865be9d`;
- `target/perf/hvpatch-phase4/fs-preflight-abba-1.raw`, SHA-256
  `bfe70089af525052a3285facf4f5fcf05916524680db5d230f3bc38ad1a15a2f`.

## Correctness and red-first proof

The existing combined-fd unit test was strengthened to require zero
`lookup_kind` calls. It failed red with one call before the experiment and
passed after the early backend operation was wired. Host tests then covered a
regular file, a directory, a guest-rooted symlink, a FIFO, a containment
escape, and a Unicode-normalized alias.

Verification on the candidate:

- `cargo test -p carrick-runtime host_fast_open --lib`: 5 passed;
- `cargo test -p carrick-runtime
  open_for_dispatch_prefers_combined_host_fd_metadata --lib`: passed;
- `cargo test -p carrick-runtime --test integration`: 296 passed;
- `cargo check -p carrick-runtime`: passed;
- `cargo fmt` and `git diff --check`: passed;
- signed `just build`: passed.

These prove the scoped behavior shapes exercised, not full conformance. Because
the performance authority rejected the candidate, a full conformance run and
`just ci` on the candidate would not justify retaining it and were not run.

## Mechanism result

The candidate's fail-closed service-lowering capture was exact: 3,266 Linux
`openat`, 3,962 Linux `newfstatat`, and 1,933 Linux `mmap` windows had balanced
begin/completion/clear populations, `status=ok`, and zero join/DTrace errors.

Compared with the mean of the two immediately preceding same-instrument
baseline captures:

| Linux window | Darwin operation | Baseline mean | Candidate | Change |
|---|---|---:|---:|---:|
| `openat` (3,266) | `openat` | 34,369.5 | 32,794 | -4.58% |
| | `close` | 27,484.5 | 25,344 | -7.79% |
| | `fcntl` | 20,960.0 | 19,075 | -8.99% |
| | `fstat64` | 11,115.0 | 8,956 | -19.42% |

The mechanism moved in the predicted direction but captured only a fraction
of the 10.52 host-open amplification. `newfstatat` was effectively unchanged.

## Untraced ABBA authority

Pattern: `base candidate candidate base / base candidate candidate base`.
CPU is `/usr/bin/time -lp` user plus system. Each arm used an exact signed
binary path and a unique scoped `CARRICK_RUN_ID`.

| Block | Arm | Wall-s | User-s | System-s | CPU-s |
|---|---|---:|---:|---:|---:|
| r1 | baseline | 2.40 | 2.18 | 1.65 | 3.83 |
| r1 | candidate | 2.85 | 2.29 | 2.03 | 4.32 |
| r1 | candidate | 2.80 | 2.28 | 2.06 | 4.34 |
| r1 | baseline | 2.85 | 2.28 | 2.04 | 4.32 |
| r2 | baseline | 3.26 | 2.54 | 2.18 | 4.72 |
| r2 | candidate | 2.83 | 2.30 | 2.04 | 4.34 |
| r2 | candidate | 2.91 | 2.31 | 2.04 | 4.35 |
| r2 | baseline | 2.85 | 2.29 | 2.07 | 4.36 |

| Arm | n | Mean wall-s | Mean CPU-s |
|---|---:|---:|---:|
| baseline | 4 | 2.8400 | 4.3075 |
| candidate | 4 | 2.8475 | 4.3375 |

Candidate/baseline is 1.006965 CPU (+0.70%) and 1.002641 wall (+0.26%).
Median CPU is 4.34 seconds for both arms. The large baseline spread makes a
sub-percent direction especially non-citable; it is plainly not the campaign's
required at-least-10% opportunity and does not approach Phase 4's `<3.5`
CPU-second gate.

## Decision

Remove the behavior diff. Retain the typed CTF boundary, durable D scripts,
symbolized caller ledger, and this rejection. The next candidate must attack a
larger joined chain—particularly repeated resolver/stat work common to both
Linux `openat` and `newfstatat`—or return to whole-workload attribution if no
single semantics-preserving filesystem chain has at least 10% end-to-end
opportunity.
