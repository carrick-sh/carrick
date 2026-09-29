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
