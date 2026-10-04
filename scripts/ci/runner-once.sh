#!/usr/bin/env bash
# Only short-lived JIT input reaches this guest. No registration credential.
set -euo pipefail
umask 077
[[ $(id -un) == runner ]] || exit 1
# mkdir is the durable one-use admission: even concurrent SSH calls lose here.
mkdir /home/runner/.carrick-ci-consumed
IFS= read -r jit
[[ -n $jit && ${#jit} -lt 1048576 ]] || exit 1
rm -f /home/runner/.ssh/authorized_keys
# The detached child owns JIT in memory. No cloud-init data or JIT file.
(
  trap '' HUP
  cd /home/runner/actions-runner
  export PATH="/home/runner/.cargo/bin:$PATH"
  export CARGO_BUILD_JOBS=2
  export SCCACHE_DIR=/home/runner/.cache/sccache
  export SCCACHE_CACHE_SIZE=2G
  export RUSTC_WRAPPER=/usr/local/bin/sccache
  export ACTIONS_RUNNER_HOOK_JOB_STARTED=/usr/local/bin/carrick-ci-admit-job
  set +e
  ./run.sh --jitconfig "$jit"
  result=$?
  printf '%s\n' "$result" > /home/runner/runner.exit
) </dev/null > /home/runner/runner.log 2>&1 &
disown
printf 'one-job runner launched\n'
