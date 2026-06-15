# Carrick task runner.
#
# Carrick needs the `com.apple.security.hypervisor` entitlement to run a guest,
# and `cargo build` strips the codesignature on macOS — so a bare cargo build
# produces a binary that fails every run with HV_DENIED (0xfae94007). These
# recipes always go through scripts/build-signed.sh so the binary is never
# left unsigned. Run `just` (or `just --list`) to see all recipes.

# Show the recipe list (default).
default:
    @just --list

# Build + codesign the release binary (the only runnable build; args go to cargo).
build *ARGS:
    ./scripts/build-signed.sh {{ARGS}}

# Build + sign, then run the signed binary (e.g. `just run run ubuntu:24.04 /bin/echo hi`).
run *ARGS: build
    ./target/release/carrick {{ARGS}}

# Fast unsigned debug build (cannot run a guest — for compile-checking only).
check *ARGS:
    cargo build {{ARGS}}

# Install git hooks (.githooks/): fmt-check at commit, clippy gate at push.
install-hooks:
    git config core.hooksPath .githooks
    @echo "Installed hooks: pre-commit (fmt-check), pre-push (clippy). Bypass with --no-verify."

# No-panic lint gate (unwrap/expect/panic/todo denied) — matches CI.
clippy *ARGS:
    cargo clippy --workspace --all-targets {{ARGS}} -- -D warnings

# Formatting check (matches CI).
fmt-check:
    cargo fmt --all -- --check

# Apply formatting.
fmt:
    cargo fmt --all

# Host unit/integration tests that do NOT need the HVF runtime or Docker.
test *ARGS:
    cargo test --workspace --lib {{ARGS}}

# Rustdoc gate: broken intra-doc links / unclosed-tag lints fail the build (matches CI).
doc *ARGS:
    RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --document-private-items {{ARGS}}

# Host integration suites (no HVF/Docker); syscall_process is its own binary (matches CI).
test-integration:
    cargo test -p carrick-runtime --test integration
    cargo test -p carrick-runtime --test syscall_process
    cargo test -p carrick-engine
    cargo test -p carrick-image

# Run the full host CI gate locally (fmt · clippy · build · docs · tests) — the source of truth CI calls.
ci: fmt-check clippy (check "--workspace") doc test test-integration

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
    cargo run -p carrick-conformance -- --lane kvm --tier smoke --workers 3 \
        --carrick-bin "$bin" --baseline-overlay scripts/conformance/baseline.kvm.jsonl {{ARGS}}

# Re-render docs/support-matrix.md from the latest results (no run).
matrix:
    cargo run -p carrick-conformance -- --render-matrix

# Deterministic, line-exact ABI probe gate vs Docker (the precise gate; self-skips).
conformance-probes: build
    cargo test -p carrick-cli --test conformance -- --nocapture

# Re-sign an already-built release binary (rarely needed on its own).
sign:
    codesign --force --sign - --entitlements scripts/entitlements.plist target/release/carrick

# Differential perf benchmark vs Docker (serial; needs Docker + signed binary).
# `just bench` = quick profile; `just bench full` = full profile.
bench PROFILE="quick":
    ./scripts/measure-perf.sh {{PROFILE}}

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
check-linux:
    cargo check --target aarch64-unknown-linux-gnu -p carrick-hal -p carrick-vmm-kvm
    ./scripts/closure-assert-no-hvf.sh

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

