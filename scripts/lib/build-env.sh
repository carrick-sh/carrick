#!/bin/sh
# Shared build environment, sourced by just and the signed entry points.
# Configure Cargo itself: exporting an automatic RUSTC_WRAPPER would also
# inject it into fixture admission and test processes. Their environment
# policy deliberately rejects ambient compiler wrappers.
if [ "${CARRICK_SCCACHE:-1}" = 0 ]; then
    unset RUSTC_WRAPPER
    CARRICK_CARGO_CACHE_CONFIG='build.rustc-wrapper=""'
else
    if [ -z "${RUSTC_WRAPPER:-}" ]; then
        unset RUSTC_WRAPPER
    fi
    # Escape the default executable path as a TOML basic string. An explicit
    # RUSTC_WRAPPER still takes precedence under Cargo's normal rules.
    carrick_cache_wrapper=$(printf '%s' "$HOME/.cargo/bin/sccache" | sed 's/\\/\\\\/g; s/"/\\"/g')
    CARRICK_CARGO_CACHE_CONFIG="build.rustc-wrapper=\"$carrick_cache_wrapper\""
fi
if [ -z "${SCCACHE_DIR:-}" ]; then
    if [ -d /Volumes/carrick/dev ]; then
        SCCACHE_DIR=/Volumes/carrick/dev/.sccache
    elif [ -d /Volumes/CaseSensitive/carrick ]; then
        SCCACHE_DIR=/Volumes/CaseSensitive/carrick/.sccache
    else
        SCCACHE_DIR="$HOME/dev/.sccache"
    fi
fi
SCCACHE_CACHE_SIZE="${SCCACHE_CACHE_SIZE:-10G}"
export CARRICK_CARGO_CACHE_CONFIG SCCACHE_DIR SCCACHE_CACHE_SIZE

# Direct signed entry points source this file; just uses the same option in
# its Cargo command prefix. exec callers must pass the option explicitly.
cargo() {
    command cargo --config "$CARRICK_CARGO_CACHE_CONFIG" "$@"
}
