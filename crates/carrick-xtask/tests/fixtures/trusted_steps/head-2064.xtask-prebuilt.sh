#!/usr/bin/env bash
# Reuse a carrick-xtask binary built once per workflow run (#2058).
#
#   xtask-prebuilt.sh build-key        print <commit>-<sha256 Cargo.lock>-<os>-<arch>
#   xtask-prebuilt.sh verify <dir>     accept <dir>/carrick-xtask only if its
#                                      key file equals this checkout's key and
#                                      its recorded SHA-256 matches the bytes
#
# A binary from another commit, lockfile or platform is never accepted: on any
# mismatch this exits non-zero and the caller builds from source as before.
set -euo pipefail

build_key() {
    local commit lock
    commit=$(git rev-parse HEAD)
    lock=$(sha256sum Cargo.lock | cut -d' ' -f1)
    printf '%s-%s-%s-%s\n' "$commit" "$lock" "$(uname -s)" "$(uname -m)"
}

reject() {
    echo "::warning::prebuilt carrick-xtask not used: $*; building from source" >&2
    exit 1
}

verify() {
    local dir=$1 bin key want have
    bin=$dir/carrick-xtask
    [[ -f $bin ]] || reject "no binary in $dir"
    [[ -f $dir/carrick-xtask.sha256 ]] || reject "no recorded sha256"
    [[ -f $dir/carrick-xtask.key ]] || reject "no build key"
    key=$(build_key)
    [[ $(cat "$dir/carrick-xtask.key") == "$key" ]] || reject "build key differs from this checkout ($key)"
    want=$(cut -d' ' -f1 "$dir/carrick-xtask.sha256")
    have=$(sha256sum "$bin" | cut -d' ' -f1)
    [[ -n $want && $want == "$have" ]] || reject "sha256 mismatch"
    chmod +x "$bin"
    [[ -x $bin ]] || reject "binary is not executable"
    echo "using prebuilt carrick-xtask $have"
    if [[ -n ${GITHUB_ENV:-} ]]; then
        echo "CARRICK_XTASK_PREBUILT=$bin" >> "$GITHUB_ENV"
    fi
}

case ${1:-} in
    build-key) build_key ;;
    verify) [[ $# -eq 2 ]] || { echo "usage: $0 verify <dir>" >&2; exit 2; }; verify "$2" ;;
    *) echo "usage: $0 build-key | verify <dir>" >&2; exit 2 ;;
esac
