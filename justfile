# Carrick task runner.
#
# The build/run recipes are CROSS-PLATFORM (macOS/HVF, Linux/KVM, FreeBSD/bhyve,
# NetBSD/NVMM): `_platform_features` selects the right backend feature set per host,
# and on macOS the build is codesigned (a bare `cargo build` strips the
# `com.apple.security.hypervisor` entitlement → every run fails HV_DENIED
# 0xfae94007; scripts/build-signed.sh re-signs it). Run `just --list` for all recipes.

# One compiler cache per host, inherited by cargo and all child gate commands.
# The same environment fragment is sourced by direct signed-script invocations.
# Evaluate the fragment once: six newline-delimited values share one tool
# resolution and one missing-tool notice, including recipes with dependencies.
_build_env := `sh -c '. scripts/lib/build-env.sh; printf "%s\n%s\n%s\n%s\n%s\n%s" "$CARRICK_CARGO_CACHE_CONFIG" "$CARRICK_SCCACHE_RESOLVED" "$SCCACHE_DIR" "$SCCACHE_CACHE_SIZE" "$CARRICK_SCCACHE_REQUEST" "$CARRICK_SCCACHE_SEARCH_PATH"'`
_build_env_fields := '(?s)^([^\n]*)\n([^\n]*)\n([^\n]*)\n([^\n]*)\n([^\n]*)\n([^\n]*)$'
export CARRICK_CARGO_CACHE_CONFIG := replace_regex(_build_env, _build_env_fields, '$1')
export CARRICK_SCCACHE_RESOLVED := replace_regex(_build_env, _build_env_fields, '$2')
export SCCACHE_DIR := replace_regex(_build_env, _build_env_fields, '$3')
export SCCACHE_CACHE_SIZE := replace_regex(_build_env, _build_env_fields, '$4')
export CARRICK_SCCACHE_REQUEST := replace_regex(_build_env, _build_env_fields, '$5')
export CARRICK_SCCACHE_SEARCH_PATH := replace_regex(_build_env, _build_env_fields, '$6')

# Shared checkout admission spans each foreground Cargo command.
_cargo := "cargo --config " + quote(CARRICK_CARGO_CACHE_CONFIG)
_admit := _cargo + " run --locked -p carrick-xtask -- worktree-run --"

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
    @{{_admit}} {{_cargo}} tree -p carrick-cli {{_platform_features}} --prefix none 2>/dev/null | grep -oE '^carrick-[a-z0-9-]+' | sort -u | sed 's/^/-p /' | tr '\n' ' '

# Build the runnable release binary for the host (args go to cargo). macOS codesigns
# the HVF entitlement; Linux/FreeBSD/NetBSD do a plain build with the backend features.
build *ARGS:
    #!/usr/bin/env bash
    set -euo pipefail
    just --justfile {{justfile()}} check-disk
    if [ "{{os()}}" = "macos" ]; then
        exec ./scripts/build-signed.sh {{ARGS}}
    fi
    exec {{_admit}} {{_cargo}} build --release -p carrick-cli {{_platform_features}} {{ARGS}}

# Build the runnable RELEASE binary with debug entitlements (get-task-allow) for
# lldb attaching. NOTE: this is an optimized release build that is merely
# DEBUGGABLE — it is not the debug profile, so `debug_assert!` is compiled out.
# For a guest run that actually evaluates `debug_assert!`, use
# `just build-debug-profile`.
build-debug *ARGS:
    #!/usr/bin/env bash
    set -euo pipefail
    if [ "{{os()}}" = "macos" ]; then
        exec ./scripts/build-signed.sh --debug {{ARGS}}
    fi
    exec {{_admit}} {{_cargo}} build -p carrick-cli {{_platform_features}} {{ARGS}}

# Build + sign the DEBUG PROFILE so `debug_assert!` is live in a guest run.
#
# Every other signed lane is a release build, so every `debug_assert!` on the
# HVPatch boot path — the stage-1 TTBR0 consistency check in
# `hvpatch/mod.rs`, among others — is compiled out and can never fire in any
# runnable configuration. Without this recipe those assertions are decoration:
# an invariant that looks guarded and is not. Slow, and never a perf or
# conformance artifact; use it to make a boot-path invariant actually assert.
build-debug-profile *ARGS:
    {{_admit}} just --justfile {{justfile()}} _build-debug-profile {{ARGS}}

[private]
_build-debug-profile *ARGS:
    #!/usr/bin/env bash
    set -euo pipefail
    {{_admit}} {{_cargo}} build -p carrick-cli {{_platform_features}} {{ARGS}}
    if [ "{{os()}}" = "macos" ]; then
        codesign -f -s - --entitlements scripts/entitlements-debug.plist target/debug/carrick
        codesign -d --entitlements - target/debug/carrick 2>&1 | grep -q hypervisor \
            || { echo "build-debug-profile: hypervisor entitlement missing after signing" >&2; exit 1; }
        echo "built + signed (debug profile, debug_assert live): target/debug/carrick"
    fi

# Build + sign, then run the signed binary (e.g. `just run run ubuntu:24.04 /bin/echo hi`).
run *ARGS: build
    {{_admit}} ./target/release/carrick {{ARGS}}

# Build/sign the exact HVF artifact, prove its entitlement/DOF identity, then
# enforce one run-ID-scoped Carrick carrier in every supported topology. This is
# intentionally red while `carrick exec` still starts a peer VM/carrier.
carrier-topology-gate *ARGS: build
    python3 scripts/conformance/carrier-topology-gate.py {{ARGS}}

# Reclaim clean landed idle managed worktrees; keep unmanaged/busy checkouts.
# Guards cover repo entry points; arbitrary launches are outside admission.
worktree-gc *ARGS:
    {{_admit}} {{_cargo}} run --locked -p carrick-xtask -- worktree-gc {{ARGS}}

# Hold checkout admission for a foreground worker or command.
worktree-run +CMD:
    {{_admit}} {{CMD}}

# Show compiler cache statistics (CARRICK_SCCACHE=0 disables build caching).
build-cache:
    @if [ -n "$CARRICK_SCCACHE_RESOLVED" ]; then "$CARRICK_SCCACHE_RESOLVED" --show-stats; fi

# Run the Carrick xtask maintenance tool.
xtask *ARGS:
    {{_admit}} {{_cargo}} run --locked -p carrick-xtask -- {{ARGS}}

# Host flock; cancels on runner death or TERM/INT/HUP; cleanup failure releases with error.
# One five-second cleanup deadline; owner SIGKILL releases immediately.
# Darwin cannot contain detached descendants closing every scope fd; see docs/host-lease-containment-follow-up.md.
[positional-arguments]
lease MODE +CMD:
    #!/usr/bin/env bash
    set -euo pipefail
    lease_mode="$1"
    shift
    exec {{_admit}} {{_cargo}} run --locked -p carrick-xtask -- host-lease --mode "$lease_mode" -- "$@"

# Run the host and/or signed landing gate under an exclusive host lease (no Docker).
accept *ARGS:
    {{_admit}} {{_cargo}} run --locked -p carrick-xtask -- accept --profile no-docker {{ARGS}}

# Run `just accept` (no Docker) on the remote gate Mac and fetch the receipt.
remote-accept *ARGS:
    {{_admit}} {{_cargo}} run --locked -p carrick-xtask -- remote-accept {{ARGS}}

# Linux publisher: exact-SHA build plus immutable, mode-preserving .tar.gz artifact.
fixtures-publish SHA:
    {{_admit}} {{_cargo}} run --locked -p carrick-xtask -- fixtures publish --sha {{quote(SHA)}}

# Restore the transferred artifact after checkout cleanup; signed jobs hold gate admission.
fixtures-restore BUNDLE:
    {{_admit}} {{_cargo}} run --locked -p carrick-xtask -- fixtures restore --bundle {{quote(BUNDLE)}}

# Verify a fixture archive by input identity before restoration on the gate host.
fixtures-verify BUNDLE:
    {{_admit}} {{_cargo}} run --locked -p carrick-xtask -- fixtures verify --bundle {{quote(BUNDLE)}}

# Provision fresh-worktree guest artifacts before signed execution.
land-provision *ARGS:
    just --justfile {{justfile()}} xtask provision {{ARGS}}

# Fast unsigned debug build (cannot run a guest — for compile-checking only).
check *ARGS:
    {{_admit}} {{_cargo}} build -p carrick-cli {{_platform_features}} {{ARGS}}

# Compile-check the fuzz harness (a separate `[workspace]` excluded from the main
# build, so a bit-rotted target / a changed carrick-runtime ABI-decode entry
# point is otherwise invisible to CI). `cargo check` only — `cargo fuzz run`
# needs the nightly sanitizer toolchain; this just keeps the harness compiling.
check-fuzz:
    {{_admit}} {{_cargo}} check --manifest-path fuzz/Cargo.toml

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
        exec {{_admit}} {{_cargo}} clippy --workspace --all-targets --keep-going {{ARGS}} -- -D warnings
    fi
    # Off-macOS: lint carrick-cli + its platform dep-closure (carrick-runtime, the
    # shared x86/aarch64 engines, this host's VMM backend) under the backend feature
    # set, so the kvm/bhyve/nvmm code the macOS gate never sees is linted too. Scoping
    # to -p carrick-cli {{_platform_features}} keeps HVF/macos-defaults out (a root
    # --workspace --features is rejected on a virtual workspace).
    exec {{_admit}} {{_cargo}} clippy -p carrick-cli {{_platform_features}} --all-targets --keep-going {{ARGS}} -- -D warnings

# Typed-domain semgrep gate: blocks the bug SHAPES the newtypes exist to kill
# (raw wait-set complements, bit=signum masks, host pids in NsPid, hand-numbered
# private syscall numbers, function-local LINUX_* consts, inline errno
# negation). Narrow Semgrep rules plus a checked proc_macro2 token helper deny
# syscall, dynamic lookup, assembly, import aliases, and local host-API
# redeclarations outside exact reviewed boundary modules, including macro token
# groups without hand-lexing comments or literals. The launcher fails closed
# while giving Semgrep a deterministic offline environment and an explicit
# writable log path. The compiler census remains the semantic authority: it
# checks this host's product profiles and reports all other required profiles
# pending; a partial local pass is not matrix completeness.
lint-domains: lint-domains-source
    cargo run --locked -p carrick-xtask -- authority-debt

# Host-independent domain checks; live compiler capture runs separately.
lint-domains-source:
    python3 scripts/conformance/check-next-strategy.py
    # Every test target is in exactly one gate lane (Cargo metadata), derived
    # lanes are consumed by their recipes, named-lane targets are named.
    {{_admit}} {{_cargo}} run --locked -p carrick-xtask -- test-lanes check
    {{_admit}} {{_cargo}} run --locked -p carrick-xtask -- probe-coverage
    {{_admit}} {{_cargo}} test -p carrick-xtask --test probe_coverage
    ./scripts/closure-assert-vmfree-schedule.sh
    ./scripts/lint-domains.sh
    # The self-tests run FIRST and in the same gate as --check: every one of
    # these scanners keys at least one rule on an exact source PATH, so a crate
    # move can leave a rule matching nothing while --check still exits 0. The
    # self-test fixtures are the only thing that notices (Task 2.9 moved
    # `kernel/crash_capture.rs` into carrick-kernel and the CrashQuorum rule
    # went vacuous under a green `just ci`).
    python3 scripts/migrate/check-task-participant-witnesses.py --self-test
    python3 scripts/migrate/check-mm-authority.py --self-test
    python3 scripts/migrate/check-dispatch-lock-authority.py --self-test
    python3 scripts/migrate/check-serial-host-tests.py --self-test
    # Discovery and structural rules run their negative fixture suites
    # before their production checks. Keep the list named
    # so adding unrelated script tests does not silently change this gate.
    python3 -m unittest scripts/tests/test_host_authority_transitions.py scripts/tests/test_runtime_aborts.py scripts/tests/test_runtime_global_state.py scripts/tests/test_authority_debt_retirement.py
    cargo test --locked -p carrick-xtask --test authority_debt
    python3 -m unittest scripts/tests/test_conformance_contract_policy.py
    {{_admit}} {{_cargo}} run -p carrick-conformance-contract --bin check-contracts -- --root .
    # All-feature metadata includes dependencies for other hosts and optional
    # features that this host's build never fetched. Populate the locked cache
    # before the offline personality-boundary graph check on fresh runners.
    {{_admit}} {{_cargo}} fetch --locked
    {{_admit}} {{_cargo}} metadata --locked --offline --all-features --format-version 1 > target/cargo-metadata.json
    # Nested fixture workspaces (fixtures/*/Cargo.lock) sit outside the root
    # workspace, so the --locked gates above never resolve them; without this
    # step lock drift surfaced only at `just fixtures-publish`. No compile, so it
    # costs a lock resolution per fixture.
    ./scripts/check-fixture-lockfiles.sh
    {{_admit}} {{_cargo}} run -p carrick-conformance-contract --bin check-personality-boundary -- --root . --metadata-file target/cargo-metadata.json
    python3 -m unittest scripts/tests/test_check_contract_change.py
    python3 scripts/migrate/check-task-participant-witnesses.py --check
    python3 scripts/migrate/check-mm-authority.py --check
    python3 scripts/migrate/check-host-authority-transitions.py --static
    cargo run --locked -p carrick-xtask -- authority-debt --source-only
    python3 scripts/migrate/check-serial-host-tests.py



# Dependency license / bans / sources gate (matches CI). Enforces the deny.toml
# allowlist. Install once with `cargo install cargo-deny`.
deny:
    {{_cargo}} deny check licenses bans sources

# Free space must be checked BEFORE a build, not discovered during one.
#
# On 2026-09-04 this container reached 13 GiB free (99.3% used) with no warning:
# 104 agent worktrees had regenerated ~500 GiB of `target/`, and the first symptom
# was builds and guest runs failing for unrelated-looking reasons. A disk that is
# nearly full does not announce itself — it corrupts a link step, truncates a
# conformance log, or makes an HVF guest die somewhere unhelpful, and the hours go
# into debugging the symptom. So this fails CLOSED with a named error, in the same
# spirit as `check-frame-pointers`.
#
# Both thresholds are one APFS container here: `/`, `/System/Volumes/Data`,
# `/Volumes/CaseSensitive` and `/Volumes/carrick` all share the same free pool, so
# checking the repo's own filesystem covers every lane.
#
#   CARRICK_DISK_FLOOR_GIB   hard-fail below this (default 20)
#   CARRICK_DISK_WARN_GIB    warn below this (default 75)
#   CARRICK_DISK_GUARD=0     escape hatch for a deliberate run near the edge

# Fail if free disk is below the floor; warn in the band above it.
check-disk:
    #!/usr/bin/env bash
    set -euo pipefail
    if [ "${CARRICK_DISK_GUARD:-1}" = "0" ]; then
        echo "disk: guard disabled (CARRICK_DISK_GUARD=0)"
        exit 0
    fi
    floor="${CARRICK_DISK_FLOOR_GIB:-20}"
    warn="${CARRICK_DISK_WARN_GIB:-75}"
    # POSIX -P reports 1024-byte blocks; int($4/1048576) converts to GiB and rounds DOWN.
    free="$(df -Pk . | awk 'NR==2 {print int($4/1048576)}')"
    if [ "$free" -lt "$floor" ]; then
        echo "error: only ${free} GiB free (floor ${floor} GiB)" >&2
        echo "       A near-full disk fails as a corrupt link, a truncated gate log," >&2
        echo "       or a guest dying somewhere unrelated — not as ENOSPC." >&2
        echo "       Reclaim agent build output:  just worktree-gc" >&2
        echo "       Override for one run:        CARRICK_DISK_GUARD=0 just ..." >&2
        exit 1
    fi
    if [ "$free" -lt "$warn" ]; then
        echo "disk: ${free} GiB free — below the ${warn} GiB mark; 'just worktree-gc' to reclaim"
    else
        echo "disk: ${free} GiB free"
    fi

# Frame pointers must actually reach rustc, or `dtrace`'s `ustack()` silently
# fabricates call stacks (see the rationale in `.cargo/config.toml`). A
# `RUSTFLAGS` environment variable REPLACES `[build] rustflags` wholesale rather
# than appending, so exporting it is the one way to lose them without noticing.
check-frame-pointers:
    #!/usr/bin/env bash
    set -euo pipefail
    if ! grep -q 'force-frame-pointers' .cargo/config.toml; then
        echo "error: .cargo/config.toml no longer sets -C force-frame-pointers" >&2
        echo "       dtrace ustack() cannot walk carrick without it, and it fails" >&2
        echo "       by inventing plausible-looking stacks rather than erroring." >&2
        exit 1
    fi
    if [ -n "${RUSTFLAGS:-}" ] && ! printf '%s' "${RUSTFLAGS}" | grep -q 'force-frame-pointers'; then
        echo "error: RUSTFLAGS is set and omits -C force-frame-pointers" >&2
        echo "       RUSTFLAGS REPLACES [build] rustflags in .cargo/config.toml," >&2
        echo "       so this build would silently drop frame pointers:" >&2
        echo "         RUSTFLAGS=${RUSTFLAGS}" >&2
        echo "       Add -C force-frame-pointers=yes, or unset RUSTFLAGS." >&2
        exit 1
    fi
    echo "frame pointers: enforced"

# Formatting check (matches CI).
fmt-check:
    {{_admit}} {{_cargo}} fmt --all -- --check

# Apply formatting.
fmt:
    {{_admit}} {{_cargo}} fmt --all

# The kernel semantics inner loop: no VM, codesign, or Docker. Full `just test`
# also runs the serial host tests; run it and the signed gates before pushing.
test-kernel *ARGS:
    {{_admit}} {{_cargo}} test -p carrick-fd-core -p carrick-el1-abi --lib {{ARGS}}
    {{_admit}} {{_cargo}} test -p carrick-kernel --lib --features test-support {{ARGS}} -- --skip serial_host
    just --justfile {{justfile()}} test-kernel-semantics {{ARGS}}

# Bounded fd, kernel connect/wake and terminal clear protocols (<=2 preemptions).
# Pipe venue lock/wake model waits for N1; see the M2 handoff.
test-loom:
    {{_admit}} {{_cargo}} test --locked -p carrick-fd-core --features loom --lib loom_models
    {{_admit}} {{_cargo}} test --locked -p carrick-kernel --features loom --lib loom_models
    {{_admit}} {{_cargo}} test --locked -p carrick-runtime --features loom --lib terminal_clear_loom

# The scripted kernel-semantics suites alone (crates/carrick-kernel-example):
# two-process Linux semantics against the public kernel API with no VMM, no
# codesign, no Docker and no host-specific state, so they run natively on ANY
# host the kernel compiles for. Hosted CI runs this on a Linux aarch64 runner
# (`kernel-linux-native` in .github/workflows/ci.yml) as the fast, independent
# semantics signal beside the macOS job. Measured 2026-09-17 in the lima
# aarch64 VM: 94 tests, 0 failures, ~5 s.
test-kernel-semantics *ARGS:
    {{_admit}} {{_cargo}} test -p carrick-kernel-example --tests {{ARGS}}

# Host unit/integration tests that do NOT need the HVF runtime or Docker.
test-mm-owner *ARGS:
    cargo test --locked -p carrick-core -p carrick-core-abi --lib
    cargo test --locked -p carrick-core --doc
    cargo test --locked -p carrick-core --test x86_acceleration {{ARGS}}

test *ARGS:
    #!/usr/bin/env bash
    set -euo pipefail
    python3 -c 'import fcntl, os; [fcntl.fcntl(fd, fcntl.F_SETFL, fcntl.fcntl(fd, fcntl.F_GETFL) & ~os.O_NONBLOCK) for fd in (0, 1, 2)]' 2>/dev/null || true
    ulimit -n 65536 2>/dev/null || ulimit -n "$(ulimit -Hn)" 2>/dev/null || true
    cargo test -p carrick-el1 --doc mm_portal
    # Shared owner witnesses and X1 use host-owned descriptors; no VM/Docker.
    just --justfile {{justfile()}} test-mm-owner {{ARGS}}
    if [ "{{os()}}" = "macos" ]; then
        # Runtime tests exercise process-wide signal dispositions, custom-x18
        # transitions, and fork from the test harness. Running those cases on
        # parallel harness threads lets one oracle's temporary process state
        # corrupt another; keep the other workspace crates parallel and give
        # carrick-runtime a serial test process with identical coverage.
        # `--bins` is load-bearing, not tidiness: `carrick-cli` is a bin-only
        # crate (no [lib], no src/lib.rs), so with `--lib` alone `cargo test`
        # SILENTLY skips it and its 135 in-file tests never ran in any gate --
        # including `perf_stats`'s golden-fixture contract, the only thing
        # keeping the Rust and Python paired-statistics implementations in
        # agreement. `--lib` on a lib-less package is not an error, it is a
        # no-op, which is why this went unnoticed.
        # NOT added: carrick-cli's `tests/` integration targets. `cli.rs` and
        # `fs_backend_flag.rs` drive the cargo-built binary via assert_cmd and
        # run no guest (adding `--test cli --test fs_backend_flag` here is a
        # follow-up; the recipe body is unchanged in this commit). The others
        # (`conformance.rs`, `perf_runner.rs`, `trace_profile.rs`) shell out to the
        # SIGNED `target/release/carrick` and run real guests or dtrace. This recipe
        # is defined as the tests that do NOT need the HVF runtime or Docker;
        # those belong to a guest-capable lane (`just conformance*`,
        # `cargo test -p carrick-cli --test <name>`).
        {{_admit}} {{_cargo}} test --workspace --exclude carrick-runtime --exclude carrick-kernel --exclude carrick-cli --exclude carrick-host --exclude carrick-vfs --exclude carrick-vmm-hvf --lib --bins {{ARGS}}
        # Integration targets (`tests/*.rs`) are invisible to `--lib --bins`;
        # a test moved out of `src/` used to leave every gate silently. The
        # host-lane selection is DERIVED from Cargo metadata: every test target
        # not declared in another lane under `[package.metadata.carrick.test-lanes]`
        # (carrick-xtask `test_lanes.rs`) runs here, and `lint-domains-source`
        # runs `test-lanes check`, which fails on any target no gate runs.
        selections="$({{_admit}} {{_cargo}} run -q --locked -p carrick-xtask -- test-lanes args --lane host)"
        # Every selection runs; the recipe fails after the last one, naming each red.
        red=()
        while IFS= read -r selection; do
            [ -n "$selection" ] || continue
            {{_admit}} {{_cargo}} test --no-fail-fast $selection {{ARGS}} -- --skip serial_host </dev/null || red+=("$selection")
            env RUST_TEST_THREADS=1 {{_admit}} {{_cargo}} test --no-fail-fast $selection {{ARGS}} serial_host </dev/null || red+=("$selection (serial_host)")
        done <<< "$selections"
        if [ "${#red[@]}" -ne 0 ]; then
            printf 'test: red host-lane selection: %s\n' "${red[@]}" >&2
            exit 1
        fi
        # The authenticated jit-shape builders/parsers have measured >1 MiB
        # debug frames. Several tests need two in one body; libtest's ~2 MiB
        # default has repeatedly been tipped over by unrelated additions. Keep
        # the explicit 8 MiB budget already used by their bounded-stack tests,
        # scoped to the bin-only CLI test process rather than every workspace
        # crate (see `test(debug): bound the jit-shape publication test's stack`).
        # carrick-cli includes tests that fork and mutate process-wide env vars
        # (e.g. supervisor_perf), so serialize test execution to avoid host fork races.
        env RUST_MIN_STACK=8388608 RUST_TEST_THREADS=1 {{_admit}} {{_cargo}} test -p carrick-cli --bin carrick {{ARGS}}
        # carrick-host needs the same serial treatment, for the same reason and
        # one more. Its `guest_cpu` tests `libc::fork()` from the harness and
        # drive a real SIGSTOP/waitpid handshake with the child; its
        # `ulock::imp::reexec_tests` fork too. `guest_cpu`'s own `TEST_LOCK`
        # cannot cover that: wait/reap is PROCESS-wide, so a fork test in
        # another module is free to observe or reap a child `guest_cpu` is
        # mid-handshake with, and the rightful parent then blocks forever on a
        # stop that was already consumed. Observed on 2026-08-16: four
        # `guest_cpu` cases sat >11 minutes at 0% CPU with the forked child
        # parked in `raise(SIGSTOP)` (`guest_cpu.rs:1672`) and the run only
        # completed after a debugger attach resumed it — an indefinite gate
        # hang, not a slow test.
        env RUST_TEST_THREADS=1 {{_admit}} {{_cargo}} test -p carrick-host --lib {{ARGS}}
        # Parallel cache churn previously measured 47 host opens against an
        # expected 15; exact budgets and process-wide state stay serial.
        # carrick-vfs runs parallel tests with --skip serial_host, followed by
        # its process-global and budget tests serially under RUST_TEST_THREADS=1.
        {{_admit}} {{_cargo}} test -p carrick-vfs --lib {{ARGS}} -- --skip serial_host
        env RUST_TEST_THREADS=1 {{_admit}} {{_cargo}} test -p carrick-vfs --lib {{ARGS}} serial_host
        # carrick-kernel runs parallel tests with --skip serial_host, followed by
        # its harness-fork and shared-state tests serially under RUST_TEST_THREADS=1.
        {{_admit}} {{_cargo}} test -p carrick-kernel --lib --features test-support {{ARGS}} -- --skip serial_host
        env RUST_TEST_THREADS=1 {{_admit}} {{_cargo}} test -p carrick-kernel --lib --features test-support {{ARGS}} serial_host
        # Runtime's test injections are fixture-owned, but carrier/prepare tests
        # still share process-wide VM lifecycle windows. Artifact/preemption
        # tests mutate env, signal tests fork/reap host children, and owner-boundary
        # tests probe closed fd numbers. Stage-1 rollback tests assert reuse from
        # the process-wide root-slot pool. Keep the crate serial for these reasons.
        env RUST_TEST_THREADS=1 {{_admit}} {{_cargo}} test -p carrick-runtime --lib {{ARGS}}
        # The VM-free HVF trap surface (capabilities, mapping plan, ESR
        # decoders, EL1 vector layout). Its VM-booting half is the signed
        # `just test-hvf-trap-engine`; this target must never reach hv_vm_create.
        {{_admit}} {{_cargo}} test -p carrick-runtime --test trap_hvf {{ARGS}}
        # carrick-vmm-hvf is serial for a THIRD reason, and it is structural
        # rather than a test-hygiene lapse: the carrier is process-global by
        # design, so its alias registry, replay mappings, global-frame owner
        # table and IPA allocator are one carrier's worth of state shared by
        # every test in the process. Two tests on different harness threads
        # therefore see each other's rows -- one clearing the alias registry
        # makes another's `alias_backing_is_live` false -- and the loser fails.
        # Measured: ~1 in 6 parallel runs failed, in a DIFFERENT test each
        # time; serializing the 35 tests that name the alias registry on a
        # shared lock made it WORSE (9 of 15), because it only re-ordered the
        # interleavings and exposed the frame-owner and custody registries
        # too. Serial: 0 of 8. A per-registry lock would have to cover every
        # carrier global to work, which is what one test process already is.
        env RUST_TEST_THREADS=1 {{_admit}} {{_cargo}} test -p carrick-vmm-hvf --lib {{ARGS}}
        exit 0
    fi
    # Off-macOS: run the lib tests of THIS host's own crates only (-p list from
    # _platform_crates) under the backend feature set — `--workspace --lib` would
    # pull in carrick-vmm-hvf + the macos-default features and fail to compile.
    # CLI/runtime/host have the same process-global state on every host; keep
    # their complete test processes serial, as above. The remaining package
    # selection still comes from the platform closure, including all its bins.
    pkgs="$(just --justfile {{justfile()}} _platform_crates | sed -E 's/-p carrick-(cli|runtime|host) //g')"
    # Runtime's self dev-dependency previously enabled these test doubles for
    # the whole selection. Keep them explicit when its test target is separate.
    {{_admit}} {{_cargo}} test $pkgs {{_platform_features}} --features carrick-kernel/test-support,carrick-vfs/test-support --lib --bins {{ARGS}} -- --skip serial_host
    env RUST_TEST_THREADS=1 {{_admit}} {{_cargo}} test $pkgs {{_platform_features}} --features carrick-kernel/test-support,carrick-vfs/test-support --lib --bins {{ARGS}} serial_host
    env RUST_MIN_STACK=8388608 RUST_TEST_THREADS=1 {{_admit}} {{_cargo}} test -p carrick-cli {{_platform_features}} --bin carrick {{ARGS}}
    env RUST_TEST_THREADS=1 {{_admit}} {{_cargo}} test -p carrick-host --lib {{ARGS}}
    # Runtime still has process-wide carrier lifecycle, root-slot pool, env and
    # host-fork tests; fixture-owned injections alone do not make it parallel-safe.
    env RUST_TEST_THREADS=1 {{_admit}} {{_cargo}} test -p carrick-runtime {{_platform_features}} --lib {{ARGS}}
    # Derived host-lane integration targets, as on macOS; packages whose
    # default features select platform-macos get this host's backend features.
    selections="$({{_admit}} {{_cargo}} run -q --locked -p carrick-xtask -- test-lanes args --lane host --platform-features "{{_platform_features}}")"
    # Every selection runs; the recipe fails after the last one, naming each red.
    red=()
    while IFS= read -r selection; do
        [ -n "$selection" ] || continue
        {{_admit}} {{_cargo}} test --no-fail-fast $selection {{ARGS}} -- --skip serial_host </dev/null || red+=("$selection")
        env RUST_TEST_THREADS=1 {{_admit}} {{_cargo}} test --no-fail-fast $selection {{ARGS}} serial_host </dev/null || red+=("$selection (serial_host)")
    done <<< "$selections"
    if [ "${#red[@]}" -ne 0 ]; then
        printf 'test: red host-lane selection: %s\n' "${red[@]}" >&2
        exit 1
    fi

# Every KVM-lane test target (`kvm` in `[package.metadata.carrick.test-lanes]`,
# derived by `carrick-xtask test-lanes`), plus carrick-vmm-kvm's own lib/bin
# tests. Linux x86_64 with a usable /dev/kvm only: the recipe refuses anywhere
# else, and exports CARRICK_REQUIRE_KVM=1 so a test that would skip on a
# missing device or fixture fails instead. Run by `just accept --profile
# linux-portable` (kvm-tests) and the KVM job in kernel-runtime.yml.
test-kvm *ARGS:
    #!/usr/bin/env bash
    set -euo pipefail
    if [ "{{os()}}" != "linux" ] || [ "{{arch()}}" != "x86_64" ]; then
        echo "test-kvm: needs Linux x86_64 with /dev/kvm (this host: {{os()}}/{{arch()}})" >&2
        exit 1
    fi
    if ! { [ -c /dev/kvm ] && [ -r /dev/kvm ] && [ -w /dev/kvm ]; }; then
        echo "test-kvm: /dev/kvm is missing or not read/write for $(id -un)" >&2
        exit 1
    fi
    export CARRICK_REQUIRE_KVM=1
    # live_vcpu_x86's M2 case runs this static musl fixture (needs the
    # x86_64-unknown-linux-musl target; see docs/perf-results/2026-10-04-x86-kvm-lane-health.md).
    RUSTFLAGS='-C linker=rust-lld -C linker-flavor=ld.lld -C relocation-model=static -C link-arg=--no-pie' \
        {{_cargo}} build --release \
        --manifest-path crates/carrick-vmm-bhyve/fixtures/hello-x86_64/Cargo.toml \
        --target x86_64-unknown-linux-musl
    {{_admit}} {{_cargo}} test --locked -p carrick-vmm-kvm --lib --bins {{ARGS}}
    selections="$({{_admit}} {{_cargo}} run -q --locked -p carrick-xtask -- test-lanes args --lane kvm --platform-features "{{_platform_features}}")"
    red=()
    while IFS= read -r selection; do
        [ -n "$selection" ] || continue
        {{_admit}} {{_cargo}} test --locked --no-fail-fast $selection {{ARGS}} </dev/null || red+=("$selection")
    done <<< "$selections"
    if [ "${#red[@]}" -ne 0 ]; then
        printf 'test-kvm: red kvm-lane selection: %s\n' "${red[@]}" >&2
        exit 1
    fi

# Rustdoc gate: broken intra-doc links / unclosed-tag lints fail the build (matches CI).
doc *ARGS:
    #!/usr/bin/env bash
    set -euo pipefail
    if [ "{{os()}}" = "macos" ]; then
        # macOS documents every workspace crate (HVF backend included).
        exec env RUSTDOCFLAGS="-D warnings" {{_admit}} {{_cargo}} doc --workspace --no-deps --document-private-items {{ARGS}}
    fi
    # Off-macOS: document THIS host's own crates explicitly (-p list from
    # _platform_crates) under the backend feature set. The explicit -p list is
    # load-bearing: with only `-p carrick-cli … --no-deps`, rustdoc checks but does
    # NOT run on the backend crates, so broken intra-doc links in carrick-vmm-kvm/
    # bhyve/nvmm (cfg'd-empty on macOS, so the macOS gate never sees them) slip
    # through. --no-deps still keeps -D warnings off EXTERNAL crates.
    pkgs="$(just --justfile {{justfile()}} _platform_crates)"
    exec env RUSTDOCFLAGS="-D warnings" {{_admit}} {{_cargo}} doc $pkgs {{_platform_features}} --no-deps --document-private-items {{ARGS}}

# Host integration suites (no HVF/Docker); syscall_process is its own binary (matches CI).
# carrick-runtime and carrick-engine default to platform-macos (→ HVF), so off-macOS
# they need {{_platform_features}}; carrick-image has no platform features (left bare).
test-integration:
    #!/usr/bin/env bash
    set -euo pipefail
    if [ "{{os()}}" = "macos" ]; then
        {{_admit}} {{_cargo}} test -p carrick-runtime --test integration
        # The kernel/dispatch half of that suite: every case that names no
        # carrier and no image store moved here with the code it exercises.
        {{_admit}} {{_cargo}} test -p carrick-kernel --test integration
        # The P5 blocking-host-I/O ratchet scans `dispatch/{net,fs,mod}.rs`
        # by path, so it lives in the crate that owns them. It has no crate
        # dependency at all -- it reads source and asserts.
        {{_admit}} {{_cargo}} test -p carrick-kernel --test io_blocking_guard
        {{_admit}} {{_cargo}} test -p carrick-runtime --test syscall_process
        # `PreparedRun::execute(self)` single-use contract is a compile_fail
        # doctest; `just test`'s `--lib --bins` never runs doctests.
        {{_admit}} {{_cargo}} test -p carrick-runtime --doc prepare
        # `carrick-cli`'s trace_profile suite: the D-program contracts and the
        # DSRPROF1/DSRPROF2 stream parsers. It ran in NO gate until 2026-08-06
        # -- `just test`'s `--lib --bins` reaches carrick-cli's in-file tests
        # but never its `tests/` directory, and this recipe listed only the
        # runtime/engine/image suites. Same house trap the `--bins` comment in
        # `test` describes. It needs no HVF, guest, or Docker: every case
        # parses fixtures or asserts on argument validation.
        {{_admit}} {{_cargo}} test -p carrick-cli --test trace_profile
        {{_admit}} {{_cargo}} test -p carrick-cli --test fs_backend_flag
        {{_admit}} {{_cargo}} test -p carrick-cli --test cli
        {{_admit}} {{_cargo}} test -p carrick-engine
        {{_admit}} {{_cargo}} test -p carrick-image
        # carrick-conformance-next's shard consistency tests (materialized
        # shard lists vs probe-inventory.json, cached-oracle completeness,
        # baseline-gap derivation) need no HVF or Docker, but ran in NO gate
        # until 2026-09-01: `conformance-probes` filters the signed binaries to
        # `generic_probe_shard_`/`case_`, so a stale expectation sat unnoticed
        # at HEAD. Skip only the guest-running tests here.
        {{_admit}} {{_cargo}} test -p carrick-conformance-next \
            --test probes_shard_0 --test probes_shard_1 --test probes_shard_2 \
            -- --skip generic_probe_shard_ --skip case_
        exit 0
    fi
    # Off-macOS: same suites, but with the backend feature set on the crates that
    # default to platform-macos. (The `integration` suite has some macOS-only test
    # bodies that aren't cfg-gated and a couple of cases that need a prebuilt
    # fixtures/linux-aarch64-hello image — those fail/skip ENVIRONMENTALLY off-macOS,
    # not because of feature wiring.)
    {{_admit}} {{_cargo}} test -p carrick-runtime {{_platform_features}} --test integration
    # carrick-kernel takes no `platform-*` feature: its host-OS edges are
    # `cfg(target_os)` dependency tables, so the same invocation is correct on
    # every host.
    {{_admit}} {{_cargo}} test -p carrick-kernel --test integration
    {{_admit}} {{_cargo}} test -p carrick-kernel --test io_blocking_guard
    {{_admit}} {{_cargo}} test -p carrick-runtime {{_platform_features}} --test syscall_process
    {{_admit}} {{_cargo}} test -p carrick-cli {{_platform_features}} --test trace_profile
    {{_admit}} {{_cargo}} test -p carrick-cli {{_platform_features}} --test fs_backend_flag
    {{_admit}} {{_cargo}} test -p carrick-cli {{_platform_features}} --test cli
    # syscall-shim belongs to the runtime dependency, not the engine API.
    {{_admit}} {{_cargo}} test -p carrick-engine {{replace(_platform_features, "syscall-shim", "carrick-runtime/syscall-shim")}}
    {{_admit}} {{_cargo}} test -p carrick-image

# Run the full host CI gate locally (fmt · clippy · build · docs · tests) — the source of truth CI calls.
# Composes the now-OS-aware leaf recipes. The only OS difference is the `check` arg:
# on macOS `check --workspace` compiles every crate (HVF included); off-macOS a bare
# `check` (= `cargo build -p carrick-cli {{_platform_features}}`) is the right scope —
# `--workspace` there would drag in carrick-vmm-hvf (cc/applevisor) and fail.
ci:
    #!/usr/bin/env bash
    set -euo pipefail
    j() { just --justfile {{justfile()}} "$@"; }
    j check-disk
    j check-frame-pointers
    j fmt-check
    j clippy
    j lint-domains
    j deny
    j check-matrix
    j check-layering
    j check-kernel-portable
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
    {{_admit}} {{_cargo}} run -p carrick-conformance -- --tier {{TIER}} {{ARGS}}

# Fast pre-merge regression gate: the smoke tier, non-zero exit on any regression.
# Same `hvf` lane as `just conformance` — the local signed binary running whatever
# backend carrick defaults to. No lane selects a backend; there is only one.
# Verdicts here are load-coupled — run it on a quiet machine or you will bisect
# onto the wrong commit.
conformance-quick *ARGS: build
    {{_admit}} {{_cargo}} run -p carrick-conformance -- --tier smoke {{ARGS}}

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
    {{_admit}} {{_cargo}} run -p carrick-conformance -- --lane kvm --tier smoke --workers 3 \
        --carrick-bin "$bin" {{ARGS}}

# Re-render docs/support-matrix.md from the latest results (no run).
matrix:
    {{_admit}} {{_cargo}} run -p carrick-conformance -- --render-matrix

# Drift gate: docs/support-matrix.md must equal a fresh render of the checked-in
# baseline (scripts/conformance/baseline.jsonl). Deterministic, no conformance
# run — catches a hand-edited matrix or a baseline/render-logic change that
# forgot to re-render. Runs inside `just ci`.
check-matrix:
    {{_admit}} {{_cargo}} run -p carrick-conformance -- --check-matrix

# Generate fresh syscall inventory from carrick-abi.
inventory *ARGS:
    {{_admit}} {{_cargo}} run -p carrick-conformance-contract --bin generate-inventory -- {{ARGS}}

# Contract-driven conformance investigation CLI.
investigate *ARGS:
    {{_admit}} {{_cargo}} run -p carrick-investigation --bin investigate -- {{ARGS}}

# Layering gate: carrick-vfs / carrick-kernel never depend upward; no VMM
# depends on the kernel
# (docs/superpowers/plans/2026-09-13-extract-carrick-vfs-and-carrick-kernel.md);
# and the product selection (root `default-members`, what `just build`
# resolves) enables no `test-support` on carrick-kernel / carrick-hal.
check-layering:
    ./scripts/closure-assert-layering.sh

# VM-free scenario scheduling is test-only; verify the release product closure
# excludes its entire harness, then run the deterministic replay controls.
test-vmfree-schedule:
    ./scripts/closure-assert-vmfree-schedule.sh
    {{_admit}} {{_cargo}} test -p carrick-kernel-example --test schedule_replay

# VMM-less compile of the Carrick kernel: the public crate must build for a
# target that has no Hypervisor.framework at all
# (docs/superpowers/plans/2026-09-13-extract-carrick-vfs-and-carrick-kernel.md, Task 2.10).
#
# In `ci`, right after `check-layering`: the layering gate proves the DEPENDENCY
# graph carries no HVF, and this proves the SOURCE compiles without it. Both are
# cheap and neither runs a guest, so they sit together ahead of the build gates.
#
# The kernel's own unit tests and the semantics suites are part of the portable
# surface too: they compile for the same VMM-less target, so a Darwin-only
# `sockaddr_in.sin_len` or a macOS-gated helper in a test is caught here, not on
# the Linux runner. (Measured 2026-09-17 in the lima aarch64 VM: the semantics
# suites pass natively on Linux; the kernel lib lane passes 1957/1964 there —
# the seven host-specific failures, named in .github/workflows/ci.yml, are the
# follow-up that lets the Linux job run the lib lane too.)
check-kernel-portable:
    {{_admit}} {{_cargo}} check -p carrick-kernel --lib --tests --features test-support --target aarch64-unknown-linux-gnu
    {{_admit}} {{_cargo}} check -p carrick-kernel-example --tests --target aarch64-unknown-linux-gnu

# Deterministic, line-exact ABI probe gate vs Docker (the precise gate; self-skips).
# On the x86_64 fleet the AMD64 probe sets are built NATIVELY here (cheap: host
# rustc, no Docker/QEMU) so the gate has binaries to run; on macOS the aarch64 +
# Rosetta-amd64 sets are built out-of-band via scripts/build-probes.sh (Docker
# cross-build) — the harness only runs probes whose binaries exist, so an absent
# set just SKIPs that lane.
# The EL1 landing gate (docs/superpowers/specs/2026-09-24-zone-the-workloads.md):
# one signed artifact, its identity recorded, then the signed EL1 guest tests,
# the probe gate, the LTP file/inotify set and the inotify09 screen, with no
# rebuild or re-sign in between (re-signing changes the artifact).
el1-gate: build
    {{_admit}} {{_cargo}} run --locked -p carrick-xtask -- accept --phase signed --profile full

conformance-probes: build
    #!/usr/bin/env bash
    set -euo pipefail
    case "$(uname -m)" in
        x86_64|amd64) ./scripts/build-probes.sh ;;
    esac
    if [[ "$(uname -s):$(uname -m)" == "Darwin:arm64" ]]; then
        # The deterministic arm64 rows run in-process against committed Docker
        # oracles. Only live-oracle and process-poisoning exceptions retain the
        # old signed-binary harness while their embed blockers remain open.
        ./scripts/test-signed.sh carrick-conformance-next generic_probe_shard_ --nocapture
        cp target/test-results/carrick-conformance-next-signed-artifacts.jsonl \
          target/test-results/conformance-probes-generic-signed-artifacts.jsonl
        ./scripts/test-signed.sh carrick-conformance-next case_ --nocapture
        cp target/test-results/carrick-conformance-next-signed-artifacts.jsonl \
          target/test-results/conformance-probes-dedicated-signed-artifacts.jsonl
        {{_admit}} {{_cargo}} test -p carrick-cli --test conformance_cli_contract \
          conformance_default_run_contract -- --exact --nocapture
        retained_filter="$(paste -sd, scripts/conformance/retained-generic-probes.txt)"
        CARRICK_PROBE_LANE=arm64 CARRICK_PROBE_FILTER="$retained_filter" \
          {{_admit}} {{_cargo}} test -p carrick-cli --test conformance {{_platform_features}} -- --nocapture
    else
        {{_admit}} {{_cargo}} test -p carrick-cli --test conformance {{_platform_features}} -- --nocapture
    fi

# Verify the frozen 2,127-suite discovery surface against the current clean
# source tree, signed Carrick binary, manifest, and live image identities.
conformance-closure-scope:
    python3 scripts/conformance/closure-scope.py check scripts/conformance/closure-scope.json

# Strict macOS/aarch64 proof gate: build every selected musl+GNU source and run
# both libc sets as gating HVPatch differentials. Closure mode rejects skips,
# missing artifacts, filters, alternate backends, and an unavailable oracle.
conformance-probes-closure: build
    #!/usr/bin/env bash
    set -uo pipefail
    ./scripts/build-probes.sh --closure-arm64 || exit $?
    generic_status=0
    CARRICK_PROBE_MODE=closure CARRICK_PROBE_LANE=arm64 CARRICK_EXEC_BACKEND=hvpatch \
      {{_admit}} {{_cargo}} test -p carrick-cli --test conformance conformance_probes -- --exact --nocapture \
      || generic_status=$?
    dedicated_status=0
    python3 scripts/conformance/closure-probe-scenarios.py || dedicated_status=$?
    if (( generic_status != 0 || dedicated_status != 0 )); then
      printf 'closure probe phases failed: generic=%d dedicated=%d\n' \
        "$generic_status" "$dedicated_status" >&2
      exit 1
    fi

# Gate B: run the two-container conformance suite (sequential and concurrent)
# in THIS carrier on the signed artifact.
gate-containers: build
    #!/usr/bin/env bash
    set -euo pipefail
    ./scripts/build-probes.sh --closure-arm64
    CARRICK_PROBE_MODE=closure CARRICK_PROBE_LANE=arm64 CARRICK_EXEC_BACKEND=hvpatch \
    CARRICK_PROBE_SCENARIO_LIBC=musl {{_admit}} {{_cargo}} test -p carrick-cli --test conformance \
      conformance_container_gate -- --exact --nocapture

# Guest-running tests of the embedding crate, from SIGNED cargo test
# executables. A cargo test binary is the process that calls hv_vm_create, so
# it needs the hypervisor entitlement ITSELF — `just build` signs only
# target/release/carrick, and a bare `cargo test -p carrick-embed` dies
# HV_DENIED (0xfae94007). scripts/test-signed.sh builds the crate's test
# executables with --no-run, signs each through the shipped binary's post-link
# path (scripts/lib/post-link-sign.sh), proves the entitlement, runs them under
# RUST_TEST_THREADS=1 (one VM per process), then runs an UNENTITLED negative
# control that must classify HV_DENIED as EmbedError::Entitlement. HV_DENIED
# is a failure here, never a skip. ARGS go straight to the libtest executables
# (`just test-embed captured_ --nocapture`; no `--` separator). Depends on
# `build`: the CLI-parity test compares the library against
# target/release/carrick. Needs HVF + the docker.io/library/ubuntu:24.04
# image, so it is an opt-in guest lane like conformance-quick — deliberately
# NOT part of `just ci`.
test-embed *ARGS: build
    ./scripts/test-signed.sh carrick-embed {{ARGS}}

# Guest-running tests of carrick-vmm-hvf from SIGNED cargo test executables.
test-hvf *ARGS:
    ./scripts/test-signed.sh carrick-vmm-hvf {{ARGS}}

# HVF trap-engine tests (`crates/carrick-vmm-hvf/tests/trap_engine_hvf.rs`):
# bring up a real VM via `new_hvf_trap_engine`, load the staged root onto a
# live persistent-executor vCPU (production's first executor load) and run
# tiny guests through the mailbox vectors (EL1 getpid fast path, its
# closed-gate and no-shim controls, unseeded gettid forwarding). They moved out of carrick-runtime's `trap_hvf`, which self-skipped
# on HV_DENIED and so "passed" unsigned without running. Every test is
# `#[ignore]`d (a bare `cargo test` never selects it) and panics on HV_DENIED;
# scripts/test-signed.sh signs the package's test executables, runs the
# `trap_engine_hvf_` set with `--ignored` (each test re-execs itself in a
# fresh process: one VM per process), then runs the package's UNENTITLED
# negative control (`unsigned_executable_maps_hv_denied_to_entitlement`).
test-hvf-trap-engine:
    ./scripts/test-signed.sh carrick-vmm-hvf trap_engine_hvf_ --ignored --nocapture

# Guest-running tests of carrick-conformance-next from SIGNED cargo test executables.
test-conformance-next *ARGS: build
    ./scripts/test-signed.sh carrick-conformance-next {{ARGS}}

# Re-sign an already-built release binary (rarely needed on its own).
sign:
    codesign --force --sign - --entitlements scripts/entitlements.plist target/release/carrick

# Differential perf benchmark vs Docker (serial; needs Docker + signed binary).
# `just bench` = quick profile; `just bench full` = full profile.
bench PROFILE="quick":
    ./scripts/measure-perf.sh {{PROFILE}}

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

# Build the freestanding CPL0 kernel image for x86_64 KVM tests.
build-cpl0:
    #!/usr/bin/env bash
    set -euo pipefail
    case "$(uname -s):$(uname -m)" in
        Linux:x86_64|Linux:amd64)
            cargo build -p carrick-x86-cpl0 --release --target x86_64-unknown-none
            ;;
    esac

# Run KVM VMM unit and integration tests, building the CPL0 image on x86_64 first.
kvm-tests *ARGS: build-cpl0
    cargo test -p carrick-vmm-kvm {{ARGS}}

# L1 cross-check: our owned crates compile for aarch64-linux AND the
# platform-linux closure links no HVF/applevisor (the C4-decouple proof).
# Runs on the Mac (no nested VM needed) — matches the CI cross-check job.
# `carrick-host-linux` (native-epoll host glue) is in the closure so an
# aarch64-linux compile break is caught here; its native unit tests run on the
# ubuntu CI runner (see .github/workflows/ci.yml `cross-check-linux`).
check-linux:
    {{_admit}} {{_cargo}} check --target aarch64-unknown-linux-gnu -p carrick-hal -p carrick-vmm-kvm -p carrick-host-linux
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
    {{_admit}} {{_cargo}} check --target x86_64-unknown-freebsd --no-default-features --features platform-freebsd --all-targets -p carrick-cli -p carrick-runtime

# Cross-check the NetBSD/NVMM backend closure for x86_64-unknown-netbsd. NVMM's
# crate (carrick-vmm-nvmm) depends only on the shared backend/host crates — NOT
# carrick-runtime — so it cross-compiles WITHOUT ring's C deps or a NetBSD
# sysroot: `cargo check` needs only the std target (declared in
# rust-toolchain.toml). This catches an nvmm trait-signature break that CI
# previously could not see at all.
check-netbsd:
    {{_admit}} {{_cargo}} check --target x86_64-unknown-netbsd --all-targets -p carrick-vmm-nvmm

# Verify that no macOS/HVF dependencies exist in the platform-linux closure (L1 closure assertion).
closure-linux:
    ./scripts/closure-assert-no-hvf.sh

# LOCAL: native release build of carrick-vmm-kvm INSIDE the nested-KVM Linux VM.
# The full CLI can't cross-compile from macOS (ring/oci-client need a C cross
# toolchain), so the real Linux binary is built natively here.
build-linux:
    {{_admit}} {{_cargo}} build --release -p carrick-vmm-kvm

# ONE-TIME (Apple M3+/macOS 15+): create the lima `vz` nested-KVM Ubuntu VM that
# serves as the local L2 lane. qemu's HVF backend can't provide nested virt;
# Virtualization.framework (via lima vz) can. Mounts this repo into the guest.
lima-up:
    ./scripts/lima-up.sh

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

# aarch64 BSD test VMs on this Mac (spec: docs/superpowers/specs/2026-07-22-aarch64-bsd-vm-lanes-design.md)
bsdvm-fetch VM:
    python3 scripts/bsdvm.py fetch {{VM}}

bsdvm-provision VM *ARGS:
    python3 scripts/bsdvm.py provision {{VM}} {{ARGS}}

bsdvm-up VM:
    python3 scripts/bsdvm.py up {{VM}}

bsdvm-down VM:
    python3 scripts/bsdvm.py down {{VM}}

bsdvm-ps:
    python3 scripts/bsdvm.py ps

# Run a command on a guest (or open a login shell with no ARGS). Prefer this
# over hand-rolled `ssh -p 220x root@127.0.0.1`: it pins bsdvm's own
# known_hosts (so re-provisioning a guest can't wedge you with "Host key
# verification failed") and applies the guest's toolchain env prefix.
bsdvm-ssh VM *ARGS:
    python3 scripts/bsdvm.py ssh {{VM}} {{ARGS}}

bsdvm-gate VM STAGE="stage0":
    python3 scripts/bsdvm.py gate {{VM}} {{STAGE}}

bsdvm-acceptance:
    python3 scripts/bsdvm.py ladder freebsd-arm64:stage0 netbsd-arm64:stage0 freebsd-arm64:stage1 netbsd-arm64:stage1

# Check that changed guest surfaces have matching conformance contract evidence
check-contract-change base head="HEAD":
    python3 scripts/conformance/check-contract-change.py --root . --base {{base}} --head {{head}}

# Hosted CI setup stays here with the checks it supports. Rustup reads the
# repository pin, components and targets; no second toolchain version in YAML.
# Fetch the event base before the probe ratchet, including the full push range.
ci-probe-coverage-base:
    #!/usr/bin/env bash
    set -euo pipefail
    if [ "${CI_EVENT:?}" = "push" ]; then
      BEFORE="${CARRICK_PROBE_COVERAGE_BASE:-}"
      if [ -z "$BEFORE" ] || [ "$BEFORE" = "0000000000000000000000000000000000000000" ]; then
        echo "::error::Push event base commit (github.event.before) is unavailable or all-zero (new branch without base)"
        exit 1
      fi
      echo "Fetching push base commit $BEFORE"
      git fetch --no-tags origin "$BEFORE"
    elif [ "${CI_EVENT:?}" = "pull_request" ]; then
      BASE="${CARRICK_PROBE_COVERAGE_BASE:-}"
      if [ -z "$BASE" ]; then
        echo "::error::Pull request base SHA is missing"
        exit 1
      fi
      echo "Fetching PR base commit $BASE"
      git fetch --no-tags origin "$BASE"
    elif [ "${CI_EVENT:?}" = "merge_group" ]; then
      BASE="${CARRICK_PROBE_COVERAGE_BASE:-}"
      if [ -z "$BASE" ]; then
        echo "::error::Merge group base SHA is missing"
        exit 1
      fi
      echo "Fetching merge group base commit $BASE"
      git fetch --no-tags origin "$BASE"
    fi

ci-toolchain:
    rustup show active-toolchain

ci-install-semgrep:
    #!/usr/bin/env bash
    set -euo pipefail
    python3 -m venv "${RUNNER_TEMP:?}/semgrep"
    "$RUNNER_TEMP/semgrep/bin/pip" install semgrep
    echo "$RUNNER_TEMP/semgrep/bin" >> "${GITHUB_PATH:?}"

ci-install-linux-cross:
    timeout 600 sh -c 'sudo apt-get -o Acquire::Retries=5 -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30 -o Acquire::ftp::Timeout=30 update && sudo apt-get -o Acquire::Retries=5 -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30 -o Acquire::ftp::Timeout=30 install -y gcc-aarch64-linux-gnu'

ci-install-freebsd-cross:
    timeout 600 sh -c 'sudo apt-get -o Acquire::Retries=5 -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30 -o Acquire::ftp::Timeout=30 update && sudo apt-get -o Acquire::Retries=5 -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30 -o Acquire::ftp::Timeout=30 install -y clang llvm'

# Keep the permanent archive: release mirrors eventually remove old sysroots.
ci-freebsd-sysroot:
    #!/usr/bin/env bash
    set -euo pipefail
    archive="$(mktemp)"
    trap 'rm -f "$archive"' EXIT
    mkdir -p "${FBSD_SYSROOT:?}"
    curl -fSL "https://archive.freebsd.org/old-releases/amd64/${FBSD_VERSION:?}/base.txz" -o "$archive"
    tar -xf "$archive" -C "$FBSD_SYSROOT" ./usr/include ./usr/lib ./lib

# These tests use the real host epoll backend but no KVM device or guest.
test-host-linux:
    {{_admit}} {{_cargo}} test -p carrick-host-linux

# Limits belong to the shell that starts the tests; a separate setup step
# cannot raise their soft limit. Preserve the hosted macOS fd headroom.
ci-macos-test recipe:
    #!/usr/bin/env bash
    set -euo pipefail
    sudo sysctl -w kern.maxfiles=524288 kern.maxfilesperproc=524288 || true
    ulimit -n 65536 || ulimit -n "$(ulimit -Hn)" || true
    echo "RLIMIT_NOFILE: soft=$(ulimit -Sn) hard=$(ulimit -Hn)"
    exec just --justfile {{justfile()}} {{recipe}}

# Only PRs may skip checks. Null-delimited paths and disabled rename detection
# ensure deleting/renaming code into docs cannot hide a source change. Empty
# diffs conservatively run everything; an invalid base fails the filter.
ci-changes:
    #!/usr/bin/env bash
    set -euo pipefail
    heavy=true
    if [[ "${CI_EVENT:?}" == pull_request ]]; then
        paths="$(mktemp)"
        trap 'rm -f "$paths"' EXIT
        git diff --no-renames --name-only -z "${CI_BASE:?}...HEAD" > "$paths"
        if [[ -s "$paths" ]]; then
            heavy=false
            while IFS= read -r -d '' path; do
                case "$path" in docs/*|*.md) ;; *) heavy=true; break ;; esac
            done < "$paths"
        fi
    fi
    # Draft PRs defer the hosted macOS jobs: the macOS runner pool is small and
    # shared with the merge queue. Marking the PR ready reruns them; merge_group
    # and push runs always include them.
    macos=true
    if [[ "${CI_EVENT}" == pull_request && "${CI_DRAFT:-false}" == true ]]; then
        macos=false
    fi
    echo "heavy=$heavy" >> "${GITHUB_OUTPUT:?}"
    echo "macos=$macos" >> "${GITHUB_OUTPUT:?}"
    echo "Run hosted checks: $heavy (macOS: $macos)"

# Fail closed: GitHub considers skipped required jobs successful on their own.
# ci-ok depends on every job; only the filter can license a docs-only PR skip.
ci-results:
    #!/usr/bin/env bash
    set -euo pipefail
    jq -e --arg event "${CI_EVENT:?}" '
      .changes.result == "success" and
      (length > 1) and
      (if .changes.outputs.heavy == "true" and .changes.outputs.macos == "true" then
         del(.changes) | all(.[]; .result == "success")
       elif .changes.outputs.heavy == "true" and .changes.outputs.macos == "false" and $event == "pull_request" then
         del(.changes)
         | (with_entries(select(.key | startswith("macos-"))) | all(.[]; .result == "skipped"))
           and (with_entries(select(.key | startswith("macos-") | not)) | all(.[]; .result == "success"))
       elif .changes.outputs.heavy == "false" and $event == "pull_request" then
         del(.changes) | all(.[]; .result == "skipped")
       else false end)
    ' <<< "${CI_NEEDS:?}"
