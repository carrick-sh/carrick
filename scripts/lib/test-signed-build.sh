#!/usr/bin/env bash
# Build half of scripts/test-signed.sh (#2013), sourced by test-signed-body.sh
# in the CARRICK_SIGNED_PHASE=build phase, under the shared carrick lease:
# fixture verification, the package's test executables, selection, signing
# and the unentitled negative-control copy. Nothing here boots a guest.
# It hands the execution phase its inputs through $phase_state, lists every
# executable it will run in $phase_state/artifacts (the driver captures and
# later re-verifies their identity) and exits; guests run only under gate.
# Its inputs (pkg, filters, flags, scratch, receipt_tmp) are the body's.
# shellcheck disable=SC2154

# Guest fixtures come from a Linux-published bundle. Rebuilding here would
# replace the proven executable identity and require toolchains on cloudmac.
# Also verify on direct test-embed/conformance-next invocations, before signing
# or executing any test. The inherited lease covers this verification too.
# The bundle is admitted by fixture input identity: unrelated commits and dirty
# sources keep it valid, any fixture input change refuses it. Evidence records
# HEAD, the working tree, dirtiness and the input identity.
case "$pkg" in
    carrick-embed|carrick-conformance-next)
        fixture_receipt="$(mktemp "${TMPDIR:-/tmp}/carrick-test-signed-fixtures.XXXXXX")"
        scratch+=("$fixture_receipt")
        cargo run --locked -p carrick-xtask -- fixtures verify --receipt "$fixture_receipt"
        jq -c '. + {schema:"carrick.signed-embed-test.v1",record_type:"fixture_validation"}' \
            "$fixture_receipt" >>"$receipt_tmp"
        ;;
esac

# The probe's Rust test is a distinct Linux executable, not its normal storm
# binary. Build it for every conformance-next signed invocation so case_ gates
# cannot accidentally run a stale witness after the helper changes.
if [ "$pkg" = "carrick-conformance-next" ]; then
    witness_json="$(mktemp "${TMPDIR:-/tmp}/forkexecstorm-witness-build.XXXXXX")"
    scratch+=("$witness_json")
    (cd conformance-probes && cargo test --locked --release \
        --target aarch64-unknown-linux-musl --bin forkexecstorm \
        --no-run --message-format=json) >"$witness_json"
    witness_exe="$(jq -ers '[.[] | select(.reason == "compiler-artifact" and .target.name == "forkexecstorm" and .profile.test == true and .executable != null)] | if length == 1 then .[0].executable else error("expected one forkexecstorm test executable") end' "$witness_json")"
    mkdir -p target/embed-fixtures
    witness_path=target/embed-fixtures/forkexecstorm-witness-aarch64
    cp "$witness_exe" "$witness_path"
    witness_sources='{}'
    for source in src/bin/forkexecstorm.rs src/lib.rs Cargo.toml Cargo.lock; do
        digest="$(shasum -a 256 "conformance-probes/$source" | awk '{print $1}')"
        witness_sources="$(jq -nc --argjson sources "$witness_sources" --arg path "$source" --arg digest "$digest" '$sources + {($path): $digest}')"
    done
    jq -nc --arg elf_sha256 "$(shasum -a 256 "$witness_path" | awk '{print $1}')" \
        --argjson sources "$witness_sources" \
        '{schema:"forkexecstorm-witness-v1",target:"aarch64-unknown-linux-musl",elf_sha256:$elf_sha256,sources:$sources}' \
        >"$witness_path.json"
    echo "test-signed: forkexecstorm witness $(cat "$witness_path.json")"
fi

if [ "$pkg" = "carrick-conformance-next" ]; then
    # This dedicated numeric ELF witness is not a generic blessed probe.
    # Rebuild it here so the public signed gate never depends on a manual
    # fixture build. Its compiled fingerprint detects a stale executable.
    libpython_map_fixture="crates/carrick-conformance-next/tests/fixtures/libpython-map"
    libpython_map_source_sha256="$(shasum -a 256 "$libpython_map_fixture/src/main.rs" | cut -d ' ' -f 1)"
    CARRICK_LIBPYTHON_MAP_SOURCE_SHA256="$libpython_map_source_sha256" \
        CARGO_TARGET_DIR="$PWD/target/libpython-map" \
        cargo build --locked --manifest-path "$libpython_map_fixture/Cargo.toml" \
        --target aarch64-unknown-linux-musl --release
    directory_fixture="crates/carrick-conformance-next/tests/fixtures/directory-copyout"
    directory_source_sha256="$(shasum -a 256 "$directory_fixture/src/main.rs" | cut -d ' ' -f 1)"
    CARRICK_DIRECTORY_COPYOUT_SOURCE_SHA256="$directory_source_sha256" \
        CARGO_TARGET_DIR="$PWD/target/directory-copyout" \
        cargo build --locked --manifest-path "$directory_fixture/Cargo.toml" \
        --target aarch64-unknown-linux-musl --release
    elf_errno_fixture="crates/carrick-conformance-next/tests/fixtures/elf-exec-errno"
    elf_errno_source_sha256="$(shasum -a 256 "$elf_errno_fixture/src/main.rs" | cut -d ' ' -f 1)"
    CARRICK_ELF_FIXTURE_SOURCE_SHA256="$elf_errno_source_sha256" \
        CARGO_TARGET_DIR="$PWD/target/elf-exec-errno" \
        cargo build --locked --manifest-path "$elf_errno_fixture/Cargo.toml" \
        --target aarch64-unknown-linux-musl --release
fi

# 1. Build (never run) the package's test executables and collect their
#    paths. Only the package's OWN test-profile artifacts carry
#    `profile.test == true` plus an `executable`; dependencies compile with
#    `test: false`. The JSON goes to a file first so a build failure stops the
#    script (a process substitution's exit status would not).
json_log="$(mktemp "${TMPDIR:-/tmp}/carrick-test-signed-build.XXXXXX")"
scratch+=("$json_log")
# CARRICK_TEST_TARGET names one Cargo integration-test target. Always build
# the existing negative control too; it must remain present in narrow runs.
cargo_target_flags=()
if [ -n "${CARRICK_TEST_TARGET:-}" ]; then
    cargo_target_flags=(--test "$CARRICK_TEST_TARGET")
    case "$pkg" in
        carrick-vmm-hvf) cargo_target_flags+=(--lib) ;;
        *) cargo_target_flags+=(--test entitlement_negative) ;;
    esac
fi
# Render compiler diagnostics to stderr so build failures reach the gate log;
# compiler-artifact records still go to the JSON executable inventory.
cargo test --locked -p "$pkg" ${cargo_target_flags[@]+"${cargo_target_flags[@]}"} ${cargo_feature_flags[@]+"${cargo_feature_flags[@]}"} --release --no-run --message-format=json-render-diagnostics >"$json_log"
exes=()
while IFS= read -r exe; do
    [ -n "$exe" ] && exes+=("$exe")
done < <(jq -r 'select(.reason == "compiler-artifact" and .profile.test == true and .executable != null) | .executable' "$json_log")
if [ "${#exes[@]}" -eq 0 ]; then
    echo "test-signed: cargo produced no test executables for $pkg" >&2
    exit 1
fi

# Select before signing; libtest listing does not create a VM.
test_signed_select_executables

# 3. Sign each executable in place through the shared post-link path, and
#    PROVE the entitlement is on the file before trusting it.
for exe in "${sign_exes[@]}"; do
    scratch+=("$exe.raw.$$" "$exe.tmp.$$")
    carrick_post_link_sign "$exe" "$exe" "$entitlements"
    if ! test_signed_has_entitlement "$exe"; then
        echo "test-signed: $exe does not carry com.apple.security.hypervisor after signing" >&2
        exit 1
    fi
    echo "test-signed: signed $exe"
done

if [ "$has_exact" -eq 1 ]; then
    rebuilt_args=()
    replaced_filter=0
    for arg in "$@"; do
        if [ "$replaced_filter" -eq 0 ] && [ "$arg" = "$requested_filter" ]; then
            rebuilt_args+=("$exact_name")
            replaced_filter=1
        else
            rebuilt_args+=("$arg")
        fi
    done
    set -- "${rebuilt_args[@]}"
    echo "test-signed: resolved exact filter $requested_filter -> $exact_name"
fi

# Negative control. The executable carrying the negative test is copied
# and re-signed ad-hoc WITHOUT the entitlement — byte-for-byte the state
# of a bare `cargo test` binary. Signing belongs to this build phase; the
# execution phase runs it and must see EmbedError::Entitlement.
noent="$carrier.noent.$$"
cp -f "$carrier" "$noent"
codesign --force --sign - "$noent"
if test_signed_has_entitlement "$noent"; then
    rm -f "$noent"
    echo "test-signed: $noent still carries the hypervisor entitlement; the negative control would prove nothing" >&2
    exit 1
fi

# Hand the execution phase its inputs. Paths are absolute Cargo outputs.
printf '%s\n' "${run_exes[@]}" >"$phase_state/run_exes"
printf '%s\n' "${sign_exes[@]}" >"$phase_state/sign_exes"
cp "$selected" "$phase_state/selected"
{
    printf 'carrier=%q\n' "$carrier"
    printf 'negative_test_name=%q\n' "$negative_test_name"
    printf 'noent=%q\n' "$noent"
} >"$phase_state/vars"
: >"$phase_state/args"
if [ "$#" -gt 0 ]; then
    printf '%s\0' "$@" >"$phase_state/args"
fi
printf '%s\n' "${sign_exes[@]}" "$noent" >"$phase_state/artifacts"
# The build phase's receipt rows (header, fixture validation) open the
# execution phase's receipt; nothing is published from this phase.
mv "$receipt_tmp" "$phase_state/receipt-prefix.jsonl"
receipt_tmp=""
echo "test-signed: build phase complete (${#sign_exes[@]} signed executable(s)); guests run in the execution phase under gate"
exit 0
