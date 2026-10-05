# PR 1 native macOS validation

Run from the repository root on native Apple Silicon macOS, at the reviewed
`work/inv-pr1` commit. Run sequentially on a quiet host, with no guests alive
while building. No Docker oracle is used. Signed tests require the cached
`ubuntu:24.04` image and the existing fixture/signing prerequisites.

The following commands stop on failure, print EXIT codes and retain full logs.
The live census JSON is diagnostic output, not an accepted inventory. Each
signed run preserves its artifact/entitlement/negative-control/cleanup receipt
before the next run replaces the canonical receipt.

```bash
mkdir -p target/cloudmac-inv-pr1
inv_pr1_base="$(git merge-base HEAD github/main)"
run_inv_pr1_check() {
    inv_pr1_name="$1"
    shift
    if "$@" > "target/cloudmac-inv-pr1/$inv_pr1_name.log" 2>&1; then
        inv_pr1_exit=0
    else
        inv_pr1_exit=$?
    fi
    printf '%s EXIT=%s\n' "$inv_pr1_name" "$inv_pr1_exit"
    return "$inv_pr1_exit"
}
run_inv_pr1_signed() {
    inv_pr1_signed_name="$1"
    shift
    run_inv_pr1_check "$inv_pr1_signed_name" "$@" || return "$?"
    cp target/test-results/carrick-embed-signed-artifacts.jsonl \
       "target/cloudmac-inv-pr1/$inv_pr1_signed_name.signed.jsonl"
}

# Native compile: checks the changed HVF persistent-pool argument and teardown.
run_inv_pr1_check native-compile cargo check --locked \
    -p carrick-cli -p carrick-runtime -p carrick-vmm-hvf || exit "$?"
run_inv_pr1_check capture-fixtures-compile cargo check --locked \
    -p carrick-embed --features test-support \
    --test two_container_capture_identity --test capture_identity_lifecycle || exit "$?"

# Execute all three native profiles explicitly, then check their owner ceilings.
run_inv_pr1_check macos-cli-default python3 scripts/migrate/check-host-authority-transitions.py \
    --profiles macos-cli-default || exit "$?"
run_inv_pr1_check macos-runtime-default python3 scripts/migrate/check-host-authority-transitions.py \
    --profiles macos-runtime-default || exit "$?"
run_inv_pr1_check macos-hvf-default python3 scripts/migrate/check-host-authority-transitions.py \
    --profiles macos-hvf-default || exit "$?"
run_inv_pr1_check macos-authority-debt cargo run --locked -p carrick-xtask -- \
    authority-debt --base "$inv_pr1_base" || exit "$?"

# VM-free identity witnesses on the native target (do not require signing).
run_inv_pr1_check watchdog-scope cargo test --locked -p carrick-runtime --lib \
    serial_host_watchdog_scope_survives_unprepared_and_successive_carriers \
    -- --test-threads=1 || exit "$?"
run_inv_pr1_check two-container-scope cargo test --locked -p carrick-runtime --lib \
    two_container_abort_keeps_scope_across_successive_carriers || exit "$?"
run_inv_pr1_check census-scope cargo test --locked -p carrick-runtime --lib \
    snapshot_uses_the_supplied_launch_identity || exit "$?"

# Build and sign once. Subsequent test-embed invocations retain this CLI binary.
run_inv_pr1_check signed-build just build || exit "$?"
shasum -a 256 target/release/carrick > target/cloudmac-inv-pr1/cli-before.sha256

run_inv_pr1_signed kernel-abort env CARRICK_RUN_ID=inv-pr1-kernel-abort \
    CARRICK_TEST_SIGNED_FEATURES=test-support just --no-deps test-embed \
    a_container_that_will_not_finish_aborts_with_a_post_mortem --exact --nocapture || exit "$?"
run_inv_pr1_signed successive-carriers env CARRICK_RUN_ID=inv-pr1-successive \
    CARRICK_TEST_SIGNED_FEATURES=test-support just --no-deps test-embed \
    successive_live_carriers_publish_and_retire_their_capture_scope --exact --nocapture || exit "$?"
run_inv_pr1_signed two-container-capture env CARRICK_RUN_ID=inv-pr1-two-container \
    CARRICK_TEST_SIGNED_FEATURES=test-support just --no-deps test-embed \
    two_live_containers_abort_with_the_common_carrier_scope --exact --nocapture || exit "$?"

# Real persistent-pool teardown: require one nonempty EL1 census with the
# shared carrier cleanup identity, while the EL1 region was still mapped.
mkdir -p target/cloudmac-inv-pr1/el1-census
run_inv_pr1_signed el1-census-teardown env CARRICK_RUN_ID=inv-pr1-el1-census \
    CARRICK_EL1_CENSUS="$PWD/target/cloudmac-inv-pr1/el1-census" \
    CARRICK_TEST_SIGNED_FEATURES=test-support just --no-deps test-embed \
    explicit_carrier_runs_two_isolated_containers --exact --nocapture || exit "$?"
run_inv_pr1_check el1-census-assert jq -s -e \
    'length == 1 and .[0].schema == 1 and .[0].run_id == "inv-pr1-el1-census" and .[0].el1_counters == true and (.[0].rows | length > 0)' \
    target/cloudmac-inv-pr1/el1-census/*.json || exit "$?"

# OWNER-RUN in a separate terminal: attaches sudo -n lldb and saves a core.
# Arguments go directly to libtest; there is no extra -- separator.
run_inv_pr1_signed wedge-capture-ladder env CARRICK_RUN_ID=inv-pr1-wedge \
    CARRICK_TEST_SIGNED_FEATURES=test-support just --no-deps test-embed \
    a_carrier_that_cannot_consume_its_abort_is_captured_and_named \
    --exact --ignored --nocapture || exit "$?"

shasum -a 256 target/release/carrick > target/cloudmac-inv-pr1/cli-after.sha256
run_inv_pr1_check cli-unchanged cmp target/cloudmac-inv-pr1/cli-before.sha256 \
    target/cloudmac-inv-pr1/cli-after.sha256 || exit "$?"
```

The signed harness itself fails unless scoped cleanup proves zero remaining
processes and the unentitled negative control classifies `HV_DENIED` correctly.
Native compile, live macOS profiles and these signed executions remain pending
on the Linux worker. The director still owns the final stacked acceptance gate.
