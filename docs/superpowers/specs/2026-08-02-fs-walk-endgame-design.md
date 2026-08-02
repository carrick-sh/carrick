# fs-walk endgame: the two levers left, and what each is worth

**Status:** design. **Lane:** Darwin `--fs host` (the shipped default).
**Goal served:** the directive that fs-walk reach ≤2x of native-arm64 Docker.

## 1. Where the workload stands, on both denominators

`find /usr/local/go -type f` (14,179 files), measured this session with
`scripts/perf/container-lifecycle-split.sh` and drained of teardown reapers
between samples (records in
`docs/perf-results/container-lifecycle-split.jsonl`):

| | carrick | docker | ratio |
|---|---|---|---|
| container lifecycle (no-op run) | 425 ms | 160 ms | 2.7x |
| in-guest window | 221 ms | 12 ms | 18.4x |
| **total wall** | **620 ms** | **163 ms** | **3.8x** |

Campaign start for the same command was ~1,541 ms in-guest (128x) and roughly
3.3 s total (~20x). **Never mix the denominators**: in-guest excludes container
create and teardown by construction, so teardown work moves total wall only.

## 2. What is left, attributed

**Create — 333 ms of `clonefileat`** (dtrace `-c` over a no-op run; the next
term is `read` at 32 ms). The per-run scratch is a COW clone of the
digest-keyed layer-cache tree; on APFS the cost is duplicating the image's
~26k-inode NAMESPACE, not its data. Parallelising the top-level clones across
four threads measured **NULL** (430 ms both arms, paired A/B) — APFS serialises
that work inside a volume. The clone must stop happening, not go faster.

**In-guest — 57% host kernel, 43% carrick dispatch** (1,069 vs 802 on-CPU
samples via `scripts/dtrace/native-cpu-attribution.d`; hand-rolled `ustack`
profiles are useless here — ~70 self-re-exec'd guest processes carry
independent ASLR slides, exactly the trap AGENTS.md documents). Per walk that
is ~128 ms kernel + ~97 ms carrick against Docker's 12 ms total.

**The consequence that sets the strategy:** even a *free* dispatch leaves the
host-syscall kernel term at ~10x Docker. The in-guest 2x bar is unreachable by
making carrick's own code cheaper; it requires issuing **fewer host syscalls
per guest operation**.

Guest-op census at HEAD (`target/perf/fswalk-amp7.raw`): 7,799 `fcntl`, 6,326
`close`, 4,769 `newfstatat`, 3,123 `getdents64`, 1,670 `openat` — and the stat
lane already serves ~1 host `fstatat` per guest stat, so there is no
amplification left to shave there. The remaining host calls are *irreducible
one-per-op* unless the work is batched.

## 3. Lever A — `getattrlistbulk(2)`: batch the stats into the enumeration

macOS returns name **plus full attributes** for many directory entries in one
call. `find`'s pattern is `getdents` then `stat` every child, so today one
directory of N children costs 1 enumeration + N stats. With a bulk read the
same directory costs ~1 call total.

- Populate a per-directory attribute cache when a **trusted** directory is
  materialised (the streamed-getdents path added this session), keyed by child
  name, carrying the fields `RealStat` needs (type, mode, uid/gid, size, ino,
  nlink, the three timestamps).
- Serve `try_trusted_dirfd_stat` from that cache; fall back to `fstatat` on any
  miss, on symlink/marker shapes, or when the metadata gate is closed.
- **Invalidation:** the cache lives in the directory's `TrustedHostDir` and is
  dropped on the same rewind that already refreshes the entry snapshot, plus
  the existing `fs_resolve_cache` generation — any guest write bumps it.
- **Risk, stated plainly:** this is hand-rolled binary parsing of a packed
  attribute buffer, and a field-offset bug produces *silently wrong stat
  results*, not a crash. It must land with a parity test that asserts, for a
  fixture tree covering regular/dir/symlink/FIFO/marker entries and files
  carrying mode and chown xattrs, that the bulk-derived `StatRecord` equals the
  `fstatat` one field for field.
- **Worth:** ~4.8k of ~13k host calls on this workload, concentrated in the
  kernel term. Estimated in-guest 221 ms → ~120-150 ms (18x → ~10-12x). It does
  **not** reach 2x alone.

## 4. Lever B — stop cloning the image per run

Serve reads directly from the shared, read-only cache tree and copy up on
write, so container create pays no per-run namespace duplication.

The layered machinery already exists (`RootFsVfs` merges a `rootfs` layer with
an `overlay`), but this session's trusted lanes assume *scratch-is-truth* and
explicitly refuse to arm when `rootfs.is_some()`. Naively enabling the layered
mode would therefore trade 333 ms of create for ~800 ms of in-guest — a net
loss. The design must teach the trusted lane to run over **two** dirfds:

- trust the cache tree's dirfd (it is immutable and shared — a *stronger*
  trust anchor than the scratch, and its containment holds for the process's
  life);
- consult the overlay dirfd first for the same component, which is one extra
  `fstatat` only for directories that have been written to (tracked by the
  existing per-directory interference bit, so untouched directories cost
  nothing);
- copy-up on the write paths, which already have a materialisation point.

**Worth:** the whole 333 ms create term, i.e. total wall 620 ms → ~290 ms
(3.8x → ~1.8x). **This is the lever that reaches the bar on total wall.**

## 5. Recommended order, and the honest ceiling

1. **Lever B first.** It is worth more (333 ms vs ~80-100 ms), it moves the
   number a user actually experiences, and it reaches the 2x bar on total wall.
2. **Lever A second**, for the in-guest bar, accepting that even with it the
   in-guest ratio lands around 10x and the remaining gap is APFS metadata cost
   versus Linux-on-VM ext4 — a filesystem difference, not a carrick defect.
3. State in any report which denominator is being quoted.

## 6. Gates (both levers)

`scripts/perf/container-lifecycle-split.sh` (lifecycle, in-guest and total
columns, reapers drained), the amplification census
(`scripts/dtrace/native-fs-amplification.d`), field-for-field stat parity
tests, `just ci`, and `just conformance-native smoke` — the last is
non-negotiable here: this session's only correctness regression
(`O_DIRECTORY|O_NOFOLLOW` returning ENOTDIR for a symlinked directory) was
caught by cpython-glob and by nothing else. Each lever ships default-ON with an
exact `=0` escape hatch, and a measured-null result is reverted, not parked.
