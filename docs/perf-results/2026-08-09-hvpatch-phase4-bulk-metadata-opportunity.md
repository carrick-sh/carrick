# HvPatch Phase 4 Darwin bulk-metadata opportunity

Date: 2026-08-09

Status: **ATTRIBUTED; the trusted-dirfd `getattrlistbulk` cache shape is KILLED
for the cold Go build because it has zero same-process/ASID/dirfd stat hits.
Phase 4 remains RED.** The new typed argument companion makes the negative
result authoritative: all 664 Linux `getdents64` and 3,962 Linux `newfstatat`
services had balanced identity, argument, completion, and clear records, but
none of the stat dirfds had previously been enumerated by that guest process.

This does not reject `getattrlistbulk` for the separate fs-walk workload, where
`find` enumerates and stats directory children. It rejects carrying a
`TrustedHostDir`-local attribute cache into the Phase 4 cold-build campaign
without evidence that its consumer exists.

## Question

Can Carrick replace Darwin `readdir`/`getdirentries64` plus later scalar child
stats with one `getattrlistbulk(2)` call and serve those stats from metadata
attached to the already-trusted guest directory fd?

The existing design in
`docs/superpowers/specs/2026-08-02-fs-walk-endgame-design.md` projected this
for fs-walk. The cold build is a different workload and must establish its own
population before accepting the parser, cache, and invalidation complexity.

## Durable instrument and CTF improvement

`scripts/dtrace/hvpatch-phase4-bulk-metadata-opportunity.d` selects Linux
`getdents64` (61) and `newfstatat` (79) service windows and records:

- every Darwin syscall inside the selected window;
- service counts/durations and immediate selected-service transitions;
- guest PID, TID, ASID, syscall number, and guest fd/dirfd;
- whether a `newfstatat` dirfd was previously enumerated by the same guest
  process and ASID.

The runtime now publishes `hvpatch-syscall-args(nr, arg0, arg1, arg2, arg3)`
immediately after an enabled
`hvpatch-syscall-service-begin(guest_pid, guest_tid, asid, nr)` on the same host
thread. The args companion is suppressed unless the identity-bearing begin
probe fired, so a consumer cannot receive an identity-free argument row.
Linux fd ownership is keyed by guest PID + ASID; TID remains in output but is
not part of the fd-table key because Linux threads share a process fd table.

Live `dtrace -lvn` qualification on the exact signed binary reported five
`uint64_t` CTF arguments for `hvpatch-syscall-args`. The script also records
the live-qualified Darwin ABIs for `getattrlistbulk`, `getdirentries64`, and
`fstatat64`. Any missing args record, nested/orphaned/mismatched service,
active thread exit, empty selected population, timeout, or DTrace error fails
closed.

Perturbation is **HIGH**. Counts, joins, and rankings are citable; traced
durations are directional only. Any behavior candidate still requires an
untraced same-binary ABBA.

## Provenance

- Host: macOS 27.0 build `26A5388g`, arm64.
- Branch: `codex/hvpatch`; committed parent `a694c9d2`.
- Signed binary SHA-256:
  `a5078f1dfb7b41fb8371ca7262992545813468b4221ae2404965d857f84a32ad`.
- Script SHA-256:
  `129efacd42e09e11fdac74c24589e859af4abfce0a6942dfa65bbea5ff3c703f`.
- Backend: `--exec-backend hvpatch`; filesystem: `--fs host`.
- Workload: `scripts/perf/fixtures/hvpatch-cold-go-build.sh` in
  `localhost:5005/carrick-go-conformance:1.24`, `--pull never`.
- Exact workload output: `ok`, `BUILD_OK`; exit zero.
- Clean authoritative capture:
  `target/perf/hvpatch-phase4/bulk-metadata-opportunity-4.raw`, SHA-256
  `2312076f4a768188b42844a54cd04bdbca2041594fdbeee100d76723abd30ee1`.
- Carrick and Docker were not run concurrently; each run used a unique scoped
  `CARRICK_RUN_ID`.

Command shape:

```sh
CARRICK_RUN_ID=<scoped-id> target/release/carrick trace \
  --script scripts/dtrace/hvpatch-phase4-bulk-metadata-opportunity.d \
  --trace-out target/perf/hvpatch-phase4/bulk-metadata-opportunity-4.raw \
  -- run --name <scoped-id> --rm --raw --fs host \
  --exec-backend hvpatch --pull never \
  -v "$PWD/scripts/perf/fixtures:/fixture:ro" \
  localhost:5005/carrick-go-conformance:1.24 \
  /bin/sh /fixture/hvpatch-cold-go-build.sh
```

Rejected instrumentation receipts are not workload evidence:

- `bulk-metadata-opportunity-1.raw` is zero bytes: DTrace rejected an
  associative tuple read before its later clause established the type. The
  script now declares typed sentinels in `dtrace:::BEGIN`.
- capture 2 predates the raw-argument probe and could report only a broad
  same-task-after-any-getdents upper bound.
- capture 3 keyed the enumerated fd by guest TID as well as PID/ASID. It was a
  clean trace but an invalid Linux ownership model; capture 4 corrected the
  key to the process-scoped fd table.

## Exact population and lowering

All typed boundaries balance:

| Linux service | Begin | Args | Complete | Clear |
|---|---:|---:|---:|---:|
| `getdents64` (61) | 664 | 664 | 664 | 664 |
| `newfstatat` (79) | 3,962 | 3,962 | 3,962 | 3,962 |

The capture reported `status=ok`, zero nested/orphaned/mismatched windows, and
zero DTrace errors.

| Linux window | Darwin operation | Calls |
|---|---|---:|
| `getdents64` | `getdirentries64` | 154 |
| | `dup` / `close_nocancel` / `lseek` / `fstat64` / `fstatfs64` | 73 each |
| `newfstatat` | `openat` | 18,191 |
| | `close` | 14,470 |
| | `fstatat64` | 9,058 |
| | `fcntl` | 4,107 |
| | `fstat64` | 2,574 |
| | `flistxattr` | 1,440 |
| | `getdirentries64` / `open_nocancel` / `fstatfs64` | 409 each |

The traced service-duration sums were 120.4 ms for getdents64 and 1,316.1 ms
for newfstatat. They are perturbed and not end-to-end performance evidence, but
the ranking is unambiguous and agrees with the prior lowering ledger.

The decisive join is exact for the proposed cache shape:

| Population | Count |
|---|---:|
| `newfstatat` whose process/ASID/dirfd had been enumerated | **0** |
| `newfstatat` without an enumerated matching dirfd | **3,962** |

There is therefore no cold-build consumer for attributes attached only to the
enumerated `TrustedHostDir`. Implementing that cache cannot remove the scalar
metadata services measured here.

## Decision and next modern Darwin interface

Do not implement the trusted-dirfd `getattrlistbulk` cache in this Phase 4
cold-build campaign. Preserve it as a separately gated fs-walk candidate.

Select `getattrlistat(2)` for the next scout. It addresses the actual scalar
population regardless of prior enumeration, is dirfd-relative, and on this
SDK supports `FSOPT_NOFOLLOW_ANY` and `FSOPT_RESOLVE_BENEATH`. The scout must:

1. parse one packed record into a typed Darwin metadata result;
2. compare every returned field against `fstatat` over regular files,
   directories, symlinks, FIFOs, Unicode aliases, missing leaves, and
   containment escapes;
3. keep Carrick's private mode/owner/socket xattr pass when root markers do not
   prove plain metadata;
4. fall back on any missing returned attribute or semantic uncertainty;
5. publish mechanism counts through this typed PID/TID/ASID/args boundary and
   retain only after an untraced ABBA shows at least 10% CPU or wall opportunity.
