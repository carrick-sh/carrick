# Original inotify09 instruction audit and architectural decision

2026-09-22. Decision: use linked native/DSR regions within the current HVPatch
kernel, preserving HVF fallback and current memory/task authority. The concrete
architecture, alternatives, implementation milestone and stop rules are in
[design.md](design.md). No product execution path or signed CLI changed in this
step, and no new performance improvement is claimed.

## What was executed

Two read-only Rust tools inspected the exact original LTP ELF and its libc.
`text-coverage` parses file-backed executable symbol ranges and invokes the
current research executor's classifier. `dsr-text-audit` takes those instruction
sites and invokes the recovered DSR decoder. Neither runs or rewrites the input
program. No Carrick or Linux guest was run. A stopped container supplied the
files and was removed afterward.

The DSR donor is `20add4f9f1138cbca98cc672182cb093d473ac72`, as qualified in
[dsr-reuse](../dsr-reuse/README.md). Its decoder and instruction vocabulary were
not changed. The new tool was added to that existing isolated research workspace;
no recovered translator became a product dependency.

Image: `localhost:5050/ltp@sha256:bc75ded40c5827f2ec9e1891edc23b988beae3f428f5be2c8fd7e3ee52fee80b`,
confirmed ARM64. Files copied from `/opt/ltp/testcases/bin/inotify09` and
`/usr/lib/aarch64-linux-gnu/libc.so.6`:

| Input | SHA-256 |
|---|---|
| Original inotify09 | `a106e657ae43e45925a1d88342ee9a638c6c6c8869b9ee619ac75f0a5c0dc68e` |
| libc.so.6 | `6e3cc56b98887cb3cc2a9fe78b6dd4610184aa27bd05d592cb287db93e82d494` |

The executable is a little-endian AArch64 ELF64 PIE, dynamically linked, with
symbols. The libc symbol lookup falls back to the dynamic symbol table.
The primary tool refuses absent symbols, empty/misaligned symbol ranges,
out-of-file ranges, ranges outside executable PT_LOAD segments, and non-AArch64
or non-ELF input. Range refusal is validation behavior, not an execution sandbox.

## Selected static coverage

| Object / symbol | Instruction sites | Small translator rejects | Recovered DSR decoder rejects |
|---|---:|---:|---:|
| inotify09 / verify_inotify | 905 | 349 | 0 |
| inotify09 / write_seek | 329 | 107 | 0 |
| inotify09 / __aarch64_ldadd4_acq_rel | 12 | 7 | 0 |
| libc / syscall | 15 | 2 | 0 |
| libc / inotify_add_watch | 7 | 2 | 0 |
| libc / inotify_rm_watch | 7 | 2 | 0 |
| libc / write | 51 | 15 | 0 |
| libc / lseek | 18 | 9 | 0 |
| **Total selected** | **1344** | **493** | **0** |

These are instruction **sites**, not execution counts. They exclude the rest of
the program, indirect call targets and most transitive callees. Zero decoder
rejections does not prove valid emission, linked execution, current-MM memory
access, precise signal recovery, or atomic correctness. The decoder can classify
an instruction as a sensitive operation requiring a helper or fused region.

The original watch function calls generic `syscall@plt`, so merely specializing
the two named libc inotify wrappers would miss this route. The two race functions
also contain 118 sites that DSR classifies as atomic memory accesses (including
acquire/release loads/stores), SIMD memory and ordinary calls. The atomic helper
contains an LSE add plus the LL/SC alternative; the latter yields two sensitive
exclusive actions. This audit does not determine which HWCAP-selected path runs.
The selected libc routines have three sensitive TLS-read sites. All must retain
Linux semantics in the actual adapter.

The small translator's longest linear accepted runs are only 17 instructions
in verify_inotify and 12 in write_seek. Linear length ignores branch edges and
cannot estimate dynamic fallback rate; it only reinforces that selected slices
are not an execution binding for the original program.

## Consequence for the goal

The selected bet removes repeated hardware transitions by keeping guest regions
native across synchronous calls. It reuses the existing kernel service, direct
host I/O, exact task/MM identity and scheduler. It requires the recovered DSR
instruction machinery rather than incremental growth of the fixture whitelist.

The next complete delivery is unchanged inotify09 on the current signed carrier,
with both race participants, code publication/revocation, native/HVF handoff and
observed native residence. A >=20% original completion-time screen in both
balanced blocks governs expansion; it is not the 1x goal. The latest full timing
remains 21.885 s versus Linux 5.980 s in [context-borrow](../context-borrow/README.md).
No static result in this directory changes that ratio.

## Reproduction and validation

From the active worktree, with the copied inputs under
`target/lease-cost/native-islands` and the recovered workspace from dsr-reuse:

```sh
RUSTC_WRAPPER= CARGO_TARGET_DIR=target cargo build --release \
  --manifest-path experiments/native-syscall-slice/Cargo.toml --bin text-coverage

target/release/text-coverage target/lease-cost/native-islands/inotify09 \
  verify_inotify write_seek __aarch64_ldadd4_acq_rel

target/release/text-coverage target/lease-cost/native-islands/libc.so.6 \
  syscall inotify_add_watch inotify_rm_watch write lseek

RUSTC_WRAPPER= cargo run --release \
  --manifest-path target/lease-cost/dsr-reuse/Cargo.toml -p dsr-text-audit -- \
  target/lease-cost/native-islands/inotify-coverage.json
```

The DSR comparison tool/package/workspace manifests and lockfile are archived
here to reproduce the research-workspace addition. Its dependency paths name the
active worktree and must be rebased when restoring elsewhere. The product graph
has no dependency on it. `text-coverage.rs` is a snapshot of the durable source
at `experiments/native-syscall-slice/src/bin/text-coverage.rs`.

Both new tools build and pass scoped Clippy with `-D warnings`; formatting
passes. Existing dependency warnings remain: eight unused-mut warnings in
kernel-example and one ignored-result warning in the retired mapped-memory
implementation. An initial lint invocation targeted the historical DSR package
itself and failed on its pre-existing host-authority calls and ignored result.
The new driver was separated into its own research package, allowing the new
code to be checked without weakening lints or modifying retired implementations.
The primary tool initially needed the same narrow host-fixture read annotation
as the existing experiment; its final annotation covers that read only.

Actual refusal controls: a missing symbol and the Mach-O Carrick binary fail
closed in text-coverage; empty JSON fails in the DSR comparison. An explicit
undefined AArch64 instruction produces one decoder rejection, proving that the
zero counts above are not a hard-coded success. Raw outputs/errors are retained.

The previously measured signed CLI remains SHA-256
`1142bb6dc6202ab3675dc6485b4f479e1d9425b2b75a293c948aef5e65db8918`.
No runtime library was relinked into it and it was not re-signed. The container
inventory is empty. Full CI, signed probe/semantic promotion and performance
acceptance were not run or claimed for this read-only diagnostic.

`binary-sha256.txt`, `decoder-source-sha256.txt`, `source-head.txt`, the lockfiles,
`image-identity.txt`, toolchain/host receipts and all JSON outputs identify the
inputs and tools. `campaign-dirt.txt` records the pre-existing shared campaign
state; source HEAD alone is not a clean-source claim. Original ELF files remain
under target and are not added as implementation source. `SHA256SUMS` covers
this evidence directory, excluding itself.
