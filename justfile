# Carrick task runner.
#
# The build/run recipes are CROSS-PLATFORM (macOS/HVF, Linux/KVM, FreeBSD/bhyve,
# NetBSD/NVMM): `_platform_features` selects the right backend feature set per host,
# and on macOS the build is codesigned (a bare `cargo build` strips the
# `com.apple.security.hypervisor` entitlement → every run fails HV_DENIED
# 0xfae94007; scripts/build-signed.sh re-signs it). Run `just --list` for all recipes.

# Per-host backend feature flags for `cargo build`/`cargo test` of carrick-cli.
# macOS uses the default features (+ codesign via build-signed.sh), so it is empty.
_platform_features := if os() == "macos" { "" \
} else if os() == "linux" { "--no-default-features --features syscall-shim,platform-linux" \
} else if os() == "freebsd" { "--no-default-features --features platform-freebsd" \
} else if os() == "netbsd" { "--no-default-features --features platform-netbsd" \
} else { "UNSUPPORTED-HOST" }

# Show the recipe list (default).
default:
    @just --list

# (off-macOS only) Emit the `-p <crate> …` set of THIS host's own workspace crates —
# carrick-cli plus its whole platform dep-closure (carrick-runtime, the shared
# carrick-x86/carrick-aarch64 engines, and the host's VMM backend: bhyve/kvm/nvmm),
# but NOT carrick-vmm-hvf (macOS-only; its build script needs cc/applevisor). The
# gate recipes below feed this list to `cargo {test,doc}` off-macOS so the
# platform's OWN crates are exercised without `--workspace` dragging in HVF or the
# macos-default features (a virtual workspace also rejects a root `--features`).
# Derived from `cargo tree` so it self-updates as crates are added/removed.
[private]
_platform_crates:
    @cargo tree -p carrick-cli {{_platform_features}} --prefix none 2>/dev/null | grep -oE '^carrick-[a-z0-9-]+' | sort -u | sed 's/^/-p /' | tr '\n' ' '

# Build the runnable release binary for the host (args go to cargo). macOS codesigns
# the HVF entitlement; Linux/FreeBSD/NetBSD do a plain build with the backend features.
build *ARGS:
    #!/usr/bin/env bash
    set -euo pipefail
    if [ "{{os()}}" = "macos" ]; then
        exec ./scripts/build-signed.sh {{ARGS}}
    fi
    exec cargo build --release -p carrick-cli {{_platform_features}} {{ARGS}}

# Build + sign, then run the signed binary (e.g. `just run run ubuntu:24.04 /bin/echo hi`).
run *ARGS: build
    ./target/release/carrick {{ARGS}}

# Fast unsigned debug build (cannot run a guest — for compile-checking only).
check *ARGS:
    cargo build -p carrick-cli {{_platform_features}} {{ARGS}}

# Compile-check the fuzz harness (a separate `[workspace]` excluded from the main
# build, so a bit-rotted target / a changed carrick-runtime ABI-decode entry
# point is otherwise invisible to CI). `cargo check` only — `cargo fuzz run`
# needs the nightly sanitizer toolchain; this just keeps the harness compiling.
check-fuzz:
    cargo check --manifest-path fuzz/Cargo.toml

# Install git hooks (.githooks/): fmt-check at commit, clippy gate at push.
install-hooks:
    git config core.hooksPath .githooks
    @echo "Installed hooks: pre-commit (fmt-check), pre-push (clippy). Bypass with --no-verify."

# No-panic lint gate (unwrap/expect/panic/todo denied) — matches CI.
# `--keep-going` reports clippy errors across ALL crates in one pass instead of
# stopping at the first failing crate (so a push surfaces the whole list at once).
clippy *ARGS:
    #!/usr/bin/env bash
    set -euo pipefail
    if [ "{{os()}}" = "macos" ]; then
        # macOS lints the whole workspace (HVF backend included) with default features.
        exec cargo clippy --workspace --all-targets --keep-going {{ARGS}} -- -D warnings
    fi
    # Off-macOS: lint carrick-cli + its platform dep-closure (carrick-runtime, the
    # shared x86/aarch64 engines, this host's VMM backend) under the backend feature
    # set, so the kvm/bhyve/nvmm code the macOS gate never sees is linted too. Scoping
    # to -p carrick-cli {{_platform_features}} keeps HVF/macos-defaults out (a root
    # --workspace --features is rejected on a virtual workspace).
    exec cargo clippy -p carrick-cli {{_platform_features}} --all-targets --keep-going {{ARGS}} -- -D warnings

# Typed-domain semgrep gate: blocks the bug SHAPES the newtypes exist to kill
# (raw wait-set complements, bit=signum masks, host pids in NsPid, hand-numbered
# private syscall numbers, function-local LINUX_* consts, inline errno
# negation). Skips with a warning if semgrep is not installed (brew install
# semgrep) so contributors without it are not blocked locally; CI should have it.
lint-domains:
    #!/usr/bin/env bash
    set -euo pipefail
    if ! command -v semgrep >/dev/null 2>&1; then
        echo "warning: semgrep not installed — skipping typed-domain gate (brew install semgrep)" >&2
        exit 0
    fi
    semgrep --config .semgrep/typed-domains.yml crates/ --severity ERROR --error --quiet


# Dependency license / bans / sources gate (matches CI). Enforces the deny.toml
# allowlist. Install once with `cargo install cargo-deny`.
deny:
    cargo deny check licenses bans sources

# Formatting check (matches CI).
fmt-check:
    cargo fmt --all -- --check

# Apply formatting.
fmt:
    cargo fmt --all

# Host unit/integration tests that do NOT need the HVF runtime or Docker.
test *ARGS:
    #!/usr/bin/env bash
    set -euo pipefail
    if [ "{{os()}}" = "macos" ]; then
        # Runtime tests exercise process-wide signal dispositions, custom-x18
        # transitions, and fork from the test harness. Running those cases on
        # parallel harness threads lets one oracle's temporary process state
        # corrupt another; keep the other workspace crates parallel and give
        # carrick-runtime a serial test process with identical coverage.
        cargo test --workspace --exclude carrick-runtime --lib {{ARGS}}
        exec env RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib {{ARGS}}
    fi
    # Off-macOS: run the lib tests of THIS host's own crates only (-p list from
    # _platform_crates) under the backend feature set — `--workspace --lib` would
    # pull in carrick-vmm-hvf + the macos-default features and fail to compile.
    pkgs="$(just --justfile {{justfile()}} _platform_crates)"
    exec cargo test $pkgs {{_platform_features}} --lib {{ARGS}}

# Rustdoc gate: broken intra-doc links / unclosed-tag lints fail the build (matches CI).
doc *ARGS:
    #!/usr/bin/env bash
    set -euo pipefail
    if [ "{{os()}}" = "macos" ]; then
        # macOS documents every workspace crate (HVF backend included).
        exec env RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --document-private-items {{ARGS}}
    fi
    # Off-macOS: document THIS host's own crates explicitly (-p list from
    # _platform_crates) under the backend feature set. The explicit -p list is
    # load-bearing: with only `-p carrick-cli … --no-deps`, rustdoc checks but does
    # NOT run on the backend crates, so broken intra-doc links in carrick-vmm-kvm/
    # bhyve/nvmm (cfg'd-empty on macOS, so the macOS gate never sees them) slip
    # through. --no-deps still keeps -D warnings off EXTERNAL crates.
    pkgs="$(just --justfile {{justfile()}} _platform_crates)"
    exec env RUSTDOCFLAGS="-D warnings" cargo doc $pkgs {{_platform_features}} --no-deps --document-private-items {{ARGS}}

# Host integration suites (no HVF/Docker); syscall_process is its own binary (matches CI).
# carrick-runtime and carrick-engine default to platform-macos (→ HVF), so off-macOS
# they need {{_platform_features}}; carrick-image has no platform features (left bare).
test-integration:
    #!/usr/bin/env bash
    set -euo pipefail
    if [ "{{os()}}" = "macos" ]; then
        cargo test -p carrick-runtime --test integration
        cargo test -p carrick-runtime --test syscall_process
        cargo test -p carrick-engine
        cargo test -p carrick-image
        exit 0
    fi
    # Off-macOS: same suites, but with the backend feature set on the crates that
    # default to platform-macos. (The `integration` suite has some macOS-only test
    # bodies that aren't cfg-gated and a couple of cases that need a prebuilt
    # fixtures/linux-aarch64-hello image — those fail/skip ENVIRONMENTALLY off-macOS,
    # not because of feature wiring.)
    cargo test -p carrick-runtime {{_platform_features}} --test integration
    cargo test -p carrick-runtime {{_platform_features}} --test syscall_process
    cargo test -p carrick-engine {{_platform_features}}
    cargo test -p carrick-image

# Run the full host CI gate locally (fmt · clippy · build · docs · tests) — the source of truth CI calls.
# Composes the now-OS-aware leaf recipes. The only OS difference is the `check` arg:
# on macOS `check --workspace` compiles every crate (HVF included); off-macOS a bare
# `check` (= `cargo build -p carrick-cli {{_platform_features}}`) is the right scope —
# `--workspace` there would drag in carrick-vmm-hvf (cc/applevisor) and fail.
ci:
    #!/usr/bin/env bash
    set -euo pipefail
    j() { just --justfile {{justfile()}} "$@"; }
    j fmt-check
    j clippy
    j lint-domains
    j deny
    j check-matrix
    if [ "{{os()}}" = "macos" ]; then
        j check --workspace
    else
        j check
    fi
    j doc
    j test
    j test-integration

# Unified language/LTP conformance harness vs Docker (needs Docker + signed binary).
# `just conformance` = full tier; `just conformance smoke` = fast gate; extra args pass
# through (e.g. `just conformance full --bless`, `just conformance full --ecosystem go`).
conformance TIER="full" *ARGS: build
    cargo run -p carrick-conformance -- --tier {{TIER}} {{ARGS}}

# Fast pre-merge regression gate: the smoke tier, non-zero exit on any regression.
conformance-quick: build
    cargo run -p carrick-conformance -- --tier smoke

# KVM/lima Docker-parity gate (Phase 5). Builds carrick IN-GUEST for platform-linux,
# then runs the smoke tier on the KVM lane vs the (backend-independent) docker oracles,
# consulting the layered KVM baseline overlay. Needs: `just lima-up` + Docker Desktop.
conformance-kvm *ARGS:
    #!/usr/bin/env bash
    set -euo pipefail
    bin="$(bash scripts/conformance/build-carrick-in-lima.sh | tail -1)"
    # --workers 3: each carrick run extracts a full rootfs into the guest's
    # ~/.carrick/scratch; 8 concurrent extractions overflow the 30 GiB lima
    # disk (node, the largest image, ENOSPCs). 3 fits comfortably and matches
    # the 6-vCPU guest better anyway (each run is a nested VM).
    # No explicit --baseline-overlay: the arm64 lima `kvm` lane auto-derives its
    # OWN overlay (baseline.kvm-arm64.jsonl), kept distinct from the amd64
    # `kvm-local` lane's baseline.kvm.jsonl so the two arches never cross-excuse.
    cargo run -p carrick-conformance -- --lane kvm --tier smoke --workers 3 \
        --carrick-bin "$bin" {{ARGS}}

# Re-render docs/support-matrix.md from the latest results (no run).
matrix:
    cargo run -p carrick-conformance -- --render-matrix

# Drift gate: docs/support-matrix.md must equal a fresh render of the checked-in
# baseline (scripts/conformance/baseline.jsonl). Deterministic, no conformance
# run — catches a hand-edited matrix or a baseline/render-logic change that
# forgot to re-render. Runs inside `just ci`.
check-matrix:
    cargo run -p carrick-conformance -- --check-matrix

# Deterministic, line-exact ABI probe gate vs Docker (the precise gate; self-skips).
# On the x86_64 fleet the AMD64 probe sets are built NATIVELY here (cheap: host
# rustc, no Docker/QEMU) so the gate has binaries to run; on macOS the aarch64 +
# Rosetta-amd64 sets are built out-of-band via scripts/build-probes.sh (Docker
# cross-build) — the harness only runs probes whose binaries exist, so an absent
# set just SKIPs that lane.
conformance-probes: build
    #!/usr/bin/env bash
    set -euo pipefail
    case "$(uname -m)" in
        x86_64|amd64) ./scripts/build-probes.sh ;;
    esac
    cargo test -p carrick-cli --test conformance {{_platform_features}} -- --nocapture

# Re-sign an already-built release binary (rarely needed on its own).
sign:
    codesign --force --sign - --entitlements scripts/entitlements.plist target/release/carrick

# Differential perf benchmark vs Docker (serial; needs Docker + signed binary).
# `just bench` = quick profile; `just bench full` = full profile.
bench PROFILE="quick":
    ./scripts/measure-perf.sh {{PROFILE}}

# Report-only native16k/HVF comparison over identical direct-ELF artifacts.
bench-backends PROFILE="quick":
    ./scripts/measure-perf.sh backends {{PROFILE}}

# Report-only legacy/mailbox HVF syscall-transport comparison over identical
# signed VMM commands and native-PIE guest artifacts.
bench-hvf-mailbox PROFILE="quick":
    ./scripts/measure-perf.sh hvf-mailbox {{PROFILE}}

# --- Linux / KVM aarch64 MVP (spec: hal-seam-kvm-mvp) ----------------------

# Build the freestanding hello-aarch64 KVM-MVP fixture (Mac-native: clang + rust-lld).
build-fixture:
    ./crates/carrick-vmm-kvm/fixtures/hello-aarch64/build.sh

# Build the static x86_64 musl M2 fixture (Mac-native: rustup + rust-lld, no C/Docker).
build-x86-fixture:
    ./crates/carrick-vmm-bhyve/fixtures/hello-x86_64/build.sh

# L1 cross-check: our owned crates compile for aarch64-linux AND the
# platform-linux closure links no HVF/applevisor (the C4-decouple proof).
# Runs on the Mac (no nested VM needed) — matches the CI cross-check job.
# `carrick-host-linux` (native-epoll host glue) is in the closure so an
# aarch64-linux compile break is caught here; its native unit tests run on the
# ubuntu CI runner (see .github/workflows/ci.yml `cross-check-linux`).
check-linux:
    cargo check --target aarch64-unknown-linux-gnu -p carrick-hal -p carrick-vmm-kvm -p carrick-host-linux
    ./scripts/closure-assert-no-hvf.sh

# Cross-check the FULL carrick-cli + carrick-runtime closure for
# x86_64-unknown-freebsd — including the C deps (ring via oci-client), so the
# whole platform-freebsd binary is covered, not just the no-HVF backend crates.
# `--all-targets` so the crates' #[test] modules compile too (a test-only break
# is still a break). The CALLER must export the FreeBSD cross C toolchain so
# ring's build.rs targets freebsd: CC_x86_64_unknown_freebsd /
# AR_x86_64_unknown_freebsd /
# CFLAGS_x86_64_unknown_freebsd="--target=x86_64-unknown-freebsdN --sysroot=<base.txz extract>".
# CI (.github/workflows/ci.yml) fetches the sysroot + sets these. `cargo check`
# does NOT link, so no FreeBSD linker is needed — only the cross C compiler.
check-freebsd:
    cargo check --target x86_64-unknown-freebsd --no-default-features --features platform-freebsd --all-targets -p carrick-cli -p carrick-runtime

# Cross-check the NetBSD/NVMM backend closure for x86_64-unknown-netbsd. NVMM's
# crate (carrick-vmm-nvmm) depends only on the shared backend/host crates — NOT
# carrick-runtime — so it cross-compiles WITHOUT ring's C deps or a NetBSD
# sysroot: `cargo check` needs only the std target (declared in
# rust-toolchain.toml). This catches an nvmm trait-signature break that CI
# previously could not see at all.
check-netbsd:
    cargo check --target x86_64-unknown-netbsd --all-targets -p carrick-vmm-nvmm

# Verify that no macOS/HVF dependencies exist in the platform-linux closure (L1 closure assertion).
closure-linux:
    ./scripts/closure-assert-no-hvf.sh

# LOCAL: native release build of carrick-vmm-kvm INSIDE the nested-KVM Linux VM.
# The full CLI can't cross-compile from macOS (ring/oci-client need a C cross
# toolchain), so the real Linux binary is built natively here.
build-linux:
    cargo build --release -p carrick-vmm-kvm

# ONE-TIME (Apple M3+/macOS 15+): create the lima `vz` nested-KVM Ubuntu VM that
# serves as the local L2 lane. qemu's HVF backend can't provide nested virt;
# Virtualization.framework (via lima vz) can. Mounts this repo into the guest.
lima-up:
    ./scripts/lima-up.sh

# TURNKEY L2 (run on the macOS host): build carrick-vmm-kvm natively inside the
# lima nested-KVM guest and run hello-aarch64 against real /dev/kvm. This is the
# MVP success gate on Apple Silicon. Run `just lima-up` once first.
kvm-smoke-lima:
    ./scripts/kvm-smoke-lima.sh

# LOCAL (L2): run the freestanding hello-aarch64 under carrick-vmm-kvm on real
# /dev/kvm and diff stdout + exit code against the oracle. This is the MVP
# success gate when you ALREADY have /dev/kvm (e.g. inside the nested-KVM VM, or
# a native Linux/aarch64 host). On a macOS host use `just kvm-smoke-lima` instead.
kvm-smoke: build-linux build-fixture
    #!/usr/bin/env bash
    set -euo pipefail
    fix=crates/carrick-vmm-kvm/fixtures/hello-aarch64
    bin=target/release/carrick-vmm-kvm
    got="$("$bin" run-elf "$fix/hello-aarch64")"
    code=$?
    if [[ "$got" != "$(cat "$fix/oracle.expected")" ]]; then
        echo "FAIL: output mismatch" >&2
        echo "  expected: $(cat "$fix/oracle.expected" | xxd)" >&2
        echo "  got:      $(printf '%s' "$got" | xxd)" >&2
        exit 1
    fi
    if [[ "$code" -ne 0 ]]; then
        echo "FAIL: exit code $code (expected 0)" >&2
        exit 1
    fi
    echo "OK: hello-aarch64 printed 'ok' and exited 0 under KVM."

# LOCAL, NON-GATING stretch: run a musl-static binary under carrick-vmm-kvm and
# RECORD the first syscall it dies on (scopes the full-Linux-backend spec).
# Never a pass/fail — logs the failing __NR_* and always exits 0.
musl-record BIN:
    #!/usr/bin/env bash
    set -uo pipefail
    bin=target/release/carrick-vmm-kvm
    echo "musl-record: running {{BIN}} under carrick-vmm-kvm (non-gating)..."
    RUST_LOG=carrick_vmm_kvm=debug "$bin" run-elf "{{BIN}}" || true
    echo "musl-record: see the last UnsupportedPlatform / ENOSYS syscall above."
    echo "musl-record: this is informational only — recorded, never gating."
    exit 0
