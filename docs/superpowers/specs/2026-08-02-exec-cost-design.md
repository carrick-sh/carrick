# Exec cost: the dominant term in a cold `go build`

**Status:** design, evidence committed (`78f86451`). **Lane:** native/DSR,
macOS arm64 (shipped default).

## 1. The measurement that reorders the campaign

| workload | carrick | docker | ratio |
|---|---|---|---|
| 61 execs of `/bin/true` | 1181 ms | 12 ms | **84x** |
| 20 execs of 20 MB `compile` | 2570 ms | 20 ms | **123x** |

~129 ms of carrick exec cost per Go tool process against Docker's ~1.05 ms. A
cold `go build` of a one-file main spawns ~61 tool processes, so **exec is
roughly 8 s of the ~10.4 s build — about 76%**, essentially all carrick
overhead. `/bin/true` at 19 ms shows a large size-independent floor on top of
the size-dependent part.

This supersedes the ranking that drove the codegen work. Emitted-code execution
is ~45% of build CPU and is the right target for a long-running guest; a BUILD
is many short processes, and the same executable pays full startup 61 times.

Phase split per exec, from carrick's own `dsr-cache-lifecycle` probes under
`dtrace -Z` (proportional, not wall): prepared-image build **9.6 ms**, validate
**8.0 ms**, capsule 0.16 ms, leaving ~111 ms in the parent's read and digest,
address-space setup, and translating the Go runtime's startup path. The
prepared-image path IS taken — no ineligibility is logged — so the child does
not re-read the ELF.

## 2. The SHA-256 term, and why the obvious fix is wrong

`sha2::sha256::compress256` is **6.99% of ALL CPU** on an exec-heavy workload —
44% of carrick's own userspace — from the full-file digest at
`native_darwin.rs:947`, recomputed for the same binary on all 61 execs.

**Tried and reverted:** gating that hash on its consumers
(`shared_translation_runtime_enabled`, `artifact_spike::enabled`,
`xlat_census::armed` — all opt-in, all OFF by default). Measured **3.1% faster**
on the 20-exec workload (2503 ms vs 2582 ms median, all samples separated), and
SHA-256 fell 6.99% → 4.24% of CPU.

It was reverted because it is not correct.
`native_prepared_resume_legacy_detects_changed_source_digest` fails, and it is
right to: the digest also feeds the "guest executable changed across native host
self-reexec" guard. With the gate, both sides compute the same sentinel, the
comparison is trivially satisfied, and the guard silently becomes a no-op. That
is a correctness regression traded for overhead, which is not a trade this
project makes.

A cheap stat stamp (dev/ino/size/mtime) would preserve the guard, but
`read_exec_file` serves from the in-memory VFS overlay, so there is no host
inode to stamp. Hashing only a prefix would detect the test's replacement and
miss a late-file change — a shortcut, not a fix.

## 3. The correct design

**Defer the digest to the path that actually uses it.** The guard only runs on
the LEGACY fallback (`select_resumed_image` with `prepared_image == None`); when
a prepared image is attached the child validates its checksum instead and the
digest comparison never executes. The parent already knows which case it is in,
because it sees whether `attach_prepared_image` returned `Some`.

So: build the prepared image first; if it succeeded, store no digest and skip
the hash; if it declined, compute the full digest exactly as today. Full
strength on the path that needs it, zero cost on the path that does not, and no
wire-format change if the sentinel is only ever paired with a prepared image.

The work is in ordering: today the digest is computed inside
`load_native_execve_image` (before capsule construction, where
`attach_prepared_image` runs), so the raw file bytes must stay reachable at the
point where the decision is known.

## 4. The larger lever behind it

Even with the hash gone, ~111 ms per exec remains, and the same binary pays it
61 times. The structural fix is a **container-lifetime cache of per-executable
exec work** — digest and prepared image, keyed like the shared-translation store
fixed in `9405aff5` — so `compile` pays once instead of 27 times. The
prepared-image build (9.6 ms) and validate (8.0 ms) phases are the directly
cacheable part; the address-space setup and startup translation need the warm
process itself, i.e. a zygote.

## 5. Gates for any of this

`just ci`, `just conformance-native smoke`, a paired A/B on both the 20-exec
microbenchmark AND the full build (they can disagree), and the exec-phase probe
split before/after. Note that `just test` must be run more than once per arm:
this session saw a fixed-address `HostCollision` in the dsr oracle fixtures
appear under concurrency and vanish in isolation, which is load sensitivity, not
a regression.
