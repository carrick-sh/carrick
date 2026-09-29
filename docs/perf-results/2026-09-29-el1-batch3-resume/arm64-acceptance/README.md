# ARM64 batch acceptance in progress

Source `f256ce2`: `RUSTC_WRAPPER= just ci` exited 0. The full sequential
recipe completed formatting, workspace Clippy, domain and compiler-backed
inventory checks, dependency policy, matrix/layering/portable checks,
workspace compilation, documentation, host tests and integration tests.
The compiler authority census remains the macOS subset. This source receipt
is not signed execution or batch acceptance.

Both standalone ARM64 Linux probe sets were rebuilt locally with Cargo on
this source: all 544 auto-discovered bins for musl and all 544 for GNU.
GNU used `aarch64-unknown-linux-gnu-gcc`; the guest-only musl crate uses its
configured ELF linker. No Docker or Carrick guest was run during these builds.
The input inventory records the combined source digest, source HEAD, each
probe source and executable SHA-256, and sizes. Every inventoried executable
was checked for ELF AArch64 machine identity. This inventory is the full
source-backed auto-bin population, not the smaller closure selection.

Signed batch population, fixed Python/Go repetitions, controlled native-Linux
ratios and remaining deterministic lifecycle obligations are still pending.
No historical failure is cleared by this source gate. X86 is user-deferred.

## Signed gate on e8db2fd51

`just --no-deps el1-gate` exited 0. The release CLI SHA stayed
`9d266e3aa63562d92764f6e3659f6be85e86aeb65691a862717ea1ed26c1b18a`.
The signed EL1 population passed 50 unique executions across nine artifacts;
the generic shards passed 912 unique probe/libc pairs (456 per libc), and
32 dedicated tests passed across four artifacts. Signed stages passed their
unentitled negative controls and reported zero remaining scoped processes.
The retained CLI harness passed 46 tests with one oracle-bless ignore; its
33 retained cases per ARM64 libc had zero reported Linux diffs. X86 skips
are outside the user-authorized current scope.

The LTP census exactly matches the 216 names selected by the recipe. It
contains 215 baseline MATCH classifications and one allowed DIFF: fanotify25
reports CONFIG_TRACING undefined and skips, while cached Linux passes. All
216 oracles were cached. Regression MATCH also permits differing assertion
counts and shared failures; this is not strict conformance or timing closure.
Both raw Carrick streams per LTP row are retained. No failure was waived here.

Inotify09 passed with EL1=1 (2.82s) and EL1=0 (40.67s). These sequential
same-host values compare execution routes, not overhead against native Linux.
A post-gate process census found no matching carrier/helper for the acceptance,
conf-15682, or el1-gate-0/1 run IDs. Final CLI SHA was independently matched.

Artifact limitation: the dedicated runner re-signs all package executables,
including unused generic shards. The generic signed receipts identify the
passing artifacts, but three current files no longer match those hashes.
The retained identity check records this; do not promote the current generic
files as the tested binaries. All nine EL1 and four dedicated current hashes
matched their receipts; byte copies are retained locally under
`target/el1-resume-b3/arm64-acceptance/tested-executables/<sha256>`.
Future final promotion must preserve generic tested bytes across signing.

The fixed Python/Go populations, controlled Linux ratios, remaining lifecycle
proofs and strict final conformance remain open. Batch 3 is not accepted.
