#!/bin/sh
# Shared build environment, sourced by just and the signed entry points.
# Configure Cargo itself: exporting an automatic RUSTC_WRAPPER would also
# inject it into fixture admission and test processes. Their environment
# policy deliberately rejects ambient compiler wrappers.
carrick_cache_bin=${CARRICK_SCCACHE_BIN:-sccache}
if [ "${CARRICK_SCCACHE:-1}" = 0 ]; then
    # Disable only our automatic Cargo option. Ambient wrapper variables must
    # remain visible to fixture policy, which rejects even an empty value.
    CARRICK_CARGO_CACHE_CONFIG='build.rustc-wrapper=""'
    CARRICK_SCCACHE_RESOLVED=
    CARRICK_SCCACHE_REQUEST=
elif [ "${CARRICK_CARGO_CACHE_CONFIG+x}" != x ] ||
     [ "${CARRICK_SCCACHE_REQUEST:-}" != "$carrick_cache_bin" ] ||
     [ "${CARRICK_SCCACHE_SEARCH_PATH:-}" != "$PATH" ]; then
    # Resolve once, then let nested just/signed invocations inherit the choice.
    # A missing optional cache must not prevent bootstrapping the task runner.
    CARRICK_SCCACHE_REQUEST=$carrick_cache_bin
    CARRICK_SCCACHE_RESOLVED=$(command -v "$carrick_cache_bin" 2>/dev/null) || CARRICK_SCCACHE_RESOLVED=
    if [ -n "$CARRICK_SCCACHE_RESOLVED" ] && [ -f "$CARRICK_SCCACHE_RESOLVED" ] && [ -x "$CARRICK_SCCACHE_RESOLVED" ]; then
        case "$CARRICK_SCCACHE_RESOLVED" in
            /*) ;;
            *) CARRICK_SCCACHE_RESOLVED="$PWD/$CARRICK_SCCACHE_RESOLVED" ;;
        esac
        # Escape the executable as a TOML basic string. Ambient RUSTC_WRAPPER
        # retains Cargo's normal precedence and fixture-policy visibility.
        carrick_cache_wrapper=$(printf '%s' "$CARRICK_SCCACHE_RESOLVED" | sed 's/\\/\\\\/g; s/"/\\"/g')
        CARRICK_CARGO_CACHE_CONFIG="build.rustc-wrapper=\"$carrick_cache_wrapper\""
    else
        CARRICK_SCCACHE_RESOLVED=
        CARRICK_CARGO_CACHE_CONFIG='build.rustc-wrapper=""'
        printf 'build-cache: %s unavailable; building without compiler cache\n' "$carrick_cache_bin" >&2
    fi
fi
CARRICK_SCCACHE_RESOLVED=${CARRICK_SCCACHE_RESOLVED:-}
CARRICK_SCCACHE_SEARCH_PATH=$PATH
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
export CARRICK_CARGO_CACHE_CONFIG CARRICK_SCCACHE_RESOLVED SCCACHE_DIR SCCACHE_CACHE_SIZE
export CARRICK_SCCACHE_REQUEST CARRICK_SCCACHE_SEARCH_PATH

# Direct signed entry points source this file; just uses the same option in
# its Cargo command prefix. exec callers must pass the option explicitly.
cargo() {
    command cargo --config "$CARRICK_CARGO_CACHE_CONFIG" "$@"
}
