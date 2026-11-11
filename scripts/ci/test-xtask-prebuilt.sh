#!/usr/bin/env bash
# Known-answer tests for xtask-prebuilt.sh in a scratch git repo.
set -euo pipefail
script=$(cd "$(dirname "$0")" && pwd)/xtask-prebuilt.sh
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
cd "$scratch"
git init -q repo && cd repo
git config user.email t@t && git config user.name t
echo lock-a > Cargo.lock
git add Cargo.lock && git commit -qm one
key=$("$script" build-key)

make_artifact() { # <dir>
    mkdir -p "$1"
    printf '#!/bin/sh\nexit 0\n' > "$1/carrick-xtask"
    chmod +x "$1/carrick-xtask"
    sha256sum "$1/carrick-xtask" > "$1/carrick-xtask.sha256"
    printf '%s\n' "$key" > "$1/carrick-xtask.key"
}
expect() { # <name> <want-status> <dir>
    local env_file=$scratch/env status=0
    : > "$env_file"
    GITHUB_ENV=$env_file timeout 20 "$script" verify "$3" > "$scratch/out" 2>&1 || status=$?
    if [[ $status -ne $2 ]]; then
        echo "FAIL $1: status $status, want $2"; cat "$scratch/out"; exit 1
    fi
    if [[ $2 -eq 0 ]]; then
        grep -q '^using prebuilt carrick-xtask [0-9a-f]\{64\}$' "$scratch/out" || { echo "FAIL $1: no log line"; exit 1; }
        grep -q "^CARRICK_XTASK_PREBUILT=$3/carrick-xtask$" "$env_file" || { echo "FAIL $1: env not exported"; exit 1; }
    else
        [[ ! -s $env_file ]] || { echo "FAIL $1: env exported on rejection"; exit 1; }
    fi
    echo "ok $1"
}

make_artifact "$scratch/good";    expect "good artifact accepted" 0 "$scratch/good"
make_artifact "$scratch/k";       echo other-commit-key > "$scratch/k/carrick-xtask.key"
expect "wrong commit key rejected" 1 "$scratch/k"
make_artifact "$scratch/l";       echo lock-b > Cargo.lock
expect "wrong Cargo.lock hash rejected" 1 "$scratch/l"
echo lock-a > Cargo.lock
make_artifact "$scratch/t";       echo '# tampered' >> "$scratch/t/carrick-xtask"
expect "tampered binary rejected" 1 "$scratch/t"
make_artifact "$scratch/s";       rm "$scratch/s/carrick-xtask.sha256"
expect "missing sha file rejected" 1 "$scratch/s"
expect "missing artifact rejected" 1 "$scratch/absent"
git commit -qm two --allow-empty
expect "new commit rejects old artifact" 1 "$scratch/good"
