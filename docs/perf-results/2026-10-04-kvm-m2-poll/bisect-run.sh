#!/bin/bash
set -u
revision=$(git rev-parse HEAD)
evidence=${M2_EVIDENCE:-/tmp/carrick-m2-evidence}
mkdir -p "$evidence"
export CARGO_BUILD_JOBS=2
export CARRICK_RUN_ID="m2-${revision:0:12}"
unset CARGO_TARGET_DIR
fixture=crates/carrick-vmm-bhyve/fixtures/hello-x86_64
(cd "$fixture" && cargo build --offline --release --target x86_64-unknown-linux-musl) > "$evidence/$revision.build-fixture.log" 2>&1 || exit 125
readelf -h "$fixture/target/x86_64-unknown-linux-musl/release/carrick-hello-x86_64" > "$evidence/$revision.elf-header"
grep -q 'EXEC (Executable file)' "$evidence/$revision.elf-header" || exit 125
cargo test --locked -p carrick-vmm-kvm --test live_vcpu_x86 --no-run > "$evidence/$revision.build-test.log" 2>&1 || exit 125
results=()
for sample in 1 2; do
 cargo test --locked -p carrick-vmm-kvm --test live_vcpu_x86 test_m2_musl_static_hello -- --exact --nocapture > "$evidence/$revision.$sample.log" 2>&1
 result=$?
 if grep -q 'SKIP:' "$evidence/$revision.$sample.log"; then exit 125; fi
 results+=("$result")
done
printf '%s %s %s\n' "$revision" "${results[0]}" "${results[1]}" | tee -a "$evidence/results"
if [ "${results[0]}" != "${results[1]}" ]; then echo "FLAKY $revision" | tee -a "$evidence/results"; exit 125; fi
if [ "${results[0]}" = 0 ]; then exit 0; fi
if grep -q 'M2 stdout mismatch' "$evidence/$revision.1.log"; then exit 1; fi
exit 125
