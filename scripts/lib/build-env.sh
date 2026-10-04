#!/bin/sh
# Shared build environment, sourced by just and the signed entry points.
# Only compiler caching changes here: never linker flags or post-link signing.
if [ "${CARRICK_SCCACHE:-1}" = 0 ]; then
    RUSTC_WRAPPER=
else
    RUSTC_WRAPPER="${RUSTC_WRAPPER:-$HOME/.cargo/bin/sccache}"
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
export RUSTC_WRAPPER SCCACHE_DIR SCCACHE_CACHE_SIZE
