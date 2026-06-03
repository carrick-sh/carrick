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

# Differential conformance suite vs Docker (needs Docker + signed binary; self-skips).
conformance: build
    cargo test -p carrick-cli --test conformance -- --nocapture

# Re-sign an already-built release binary (rarely needed on its own).
sign:
    codesign --force --sign - --entitlements scripts/entitlements.plist target/release/carrick

# Differential perf benchmark vs Docker (serial; needs Docker + signed binary).
# `just bench` = quick profile; `just bench full` = full profile.
bench PROFILE="quick":
    ./scripts/measure-perf.sh {{PROFILE}}
