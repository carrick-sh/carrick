# Bounded Rustup Toolchain Installation and Auto-Install Guard

Apply `1648-bounded-rustup.patch` from the repository root to ensure GitHub Actions
jobs running on self-hosted macOS never let the rustup proxy auto-install the pinned
toolchain inside Cargo.

## Incident context

Signed gate run `41918049428` (#1585) sat for 2 hours 44 minutes in:
```sh
cargo run --locked -p carrick-xtask -- signed-gate execute
```
on `cloudmac-gate`. The process was the `rustup` proxy with no child: 8 tokio workers
and two open network sockets at 0% CPU. It was auto-installing the toolchain pinned in
`rust-toolchain.toml` and stalled on a socket read with no timeout. No test ran, and
the gate Mac was held for the entire duration until cancelled and re-dispatched (#1648).

## What the patch changes

1. **Explicit, bounded toolchain installation step:**
   - In `signed-gate.yml` (`gate` job), `ci.yml` (self-hosted macOS jobs: `macos-clippy`,
     `macos-authority`, `macos-build`, `macos-unit-a`, `macos-unit-b`, `macos-integration`),
     and `kernel-runtime.yml` (`hvf-kernel` and `hvf-closure`), the pinned toolchain is
     installed/verified via `rustup show active-toolchain` in an explicit step before any
     `cargo` invocation.
   - The step is bounded at 600 s using Python process management (`child.wait(timeout=600)`
     and `os.killpg(child.pid, signal.SIGKILL)`), matching the implementation established
     in #1574 for Cargo preparation.
   - On timeout or non-zero exit, it outputs an `::error title=Infrastructure::...` annotation
     and exits with status code 75 (infrastructure failure), classifying the error as a runner/host
     issue rather than a code test regression.

2. **Disable rustup auto-install during builds:**
   - On success, the step exports `RUSTUP_AUTO_INSTALL=0` to `$GITHUB_ENV`.
   - Any subsequent `cargo` or `rustc` command through the rustup proxy will fail fast
     instead of stalling on an un-timeouted network download if the toolchain is missing.

## Application and Verification

Apply the patch from the checkout root:
```sh
git apply docs/ci/patches/1648-bounded-rustup.patch
actionlint .github/workflows/*.yml
cargo test -p carrick-xtask --test self_hosted_toolchain
```
When landing, the director applies the patch to `.github/workflows/` and deletes the patch
file in accordance with the workflow patch retirement policy (#1611).
