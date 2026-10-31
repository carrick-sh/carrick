#!/bin/sh
# Job-completed hook (`ACTIONS_RUNNER_HOOK_JOB_COMPLETED`) for the persistent
# self-hosted macOS HVF runner (#1225).
#
# Runs after each job finishes (whether steps passed, failed, or were
# cancelled) to prune `$GITHUB_WORKSPACE/target` and clear `$RUNNER_TEMP`
# contents immediately (rather than waiting for the next job's runner startup
# cleanup) so build trees and per-job temporary artifacts never linger across
# runs. All directory variables are guarded strictly against unset, empty,
# whitespace-only, non-canonical, root/top-level, overlapping, or symlinked
# values before touching the filesystem.
set -eu

PATH=/usr/bin:/bin
export PATH

NL='
'

fail_cleanup() {
    echo "hvf-job-completed: $*" >&2
    exit 1
}

if [ "$#" -ne 0 ]; then
    fail_cleanup "unexpected arguments"
fi

is_nonempty() {
    case "$1" in
        *"$NL"*) return 1 ;;
        *[![:space:]]*) return 0 ;;
        *) return 1 ;;
    esac
}

is_clean_abs_path() {
    is_nonempty "$1" || return 1
    case "$1" in
        /*) ;;
        *) return 1 ;;
    esac
    case "$1/" in
        *'//'* | *'/./'* | *'/../'*) return 1 ;;
    esac
    return 0
}

require_safe_dir() {
    var_name=$1
    is_set=$2
    dir_path=$3
    if [ "$is_set" != x ] || ! is_nonempty "$dir_path"; then
        fail_cleanup "required directory variable $var_name is unset or empty"
    fi
    case "$dir_path" in
        /*/*) ;;
        *) fail_cleanup "$var_name must be an absolute path beneath a parent root: $dir_path" ;;
    esac
    if ! is_clean_abs_path "$dir_path"; then
        fail_cleanup "$var_name must be a clean canonical-form path: $dir_path"
    fi
    if [ -L "$dir_path" ]; then
        fail_cleanup "$var_name must not be a symbolic link: $dir_path"
    fi
    if [ ! -d "$dir_path" ]; then
        fail_cleanup "$var_name does not name an existing directory: $dir_path"
    fi
}

require_positive_int_if_set() {
    var_name=$1
    is_set=$2
    val=$3
    if [ "$is_set" = x ]; then
        if ! is_nonempty "$val"; then
            fail_cleanup "$var_name is set but empty"
        fi
        case "$val" in
            *[!0-9]*) fail_cleanup "$var_name must contain digits only: $val" ;;
        esac
        if [ "$val" -lt 1 ]; then
            fail_cleanup "$var_name must be a positive integer: $val"
        fi
    fi
}

require_safe_dir GITHUB_WORKSPACE "${GITHUB_WORKSPACE+x}" "${GITHUB_WORKSPACE-}"
require_safe_dir RUNNER_TEMP "${RUNNER_TEMP+x}" "${RUNNER_TEMP-}"

if [ "$GITHUB_WORKSPACE" = "$RUNNER_TEMP" ]; then
    fail_cleanup "GITHUB_WORKSPACE and RUNNER_TEMP must be distinct directories"
fi
case "$RUNNER_TEMP/" in
    "$GITHUB_WORKSPACE/"*)
        fail_cleanup "RUNNER_TEMP must not reside inside GITHUB_WORKSPACE: $RUNNER_TEMP"
        ;;
esac
case "$GITHUB_WORKSPACE/" in
    "$RUNNER_TEMP/"*)
        fail_cleanup "GITHUB_WORKSPACE must not reside inside RUNNER_TEMP: $GITHUB_WORKSPACE"
        ;;
esac

require_positive_int_if_set GITHUB_RUN_ID "${GITHUB_RUN_ID+x}" "${GITHUB_RUN_ID-}"
require_positive_int_if_set GITHUB_RUN_ATTEMPT "${GITHUB_RUN_ATTEMPT+x}" "${GITHUB_RUN_ATTEMPT-}"

target_dir="$GITHUB_WORKSPACE/target"
case "$target_dir" in
    "$GITHUB_WORKSPACE"/target) ;;
    *) fail_cleanup "unexpected target path expansion: $target_dir" ;;
esac
if [ -L "$target_dir" ]; then
    fail_cleanup "refusing to remove symlinked target path: $target_dir"
fi
if [ -e "$target_dir" ]; then
    find "$target_dir" -type d -exec chmod u+w {} +
    rm -rf -- "$target_dir"
    if [ -e "$target_dir" ] || [ -L "$target_dir" ]; then
        fail_cleanup "failed to remove target directory: $target_dir"
    fi
fi

if [ -L "$RUNNER_TEMP" ] || [ ! -d "$RUNNER_TEMP" ]; then
    fail_cleanup "RUNNER_TEMP ceased to be a non-symlink directory: $RUNNER_TEMP"
fi
find "$RUNNER_TEMP" -type d -exec chmod u+w {} +
find "$RUNNER_TEMP" -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +
if [ -L "$RUNNER_TEMP" ] || [ ! -d "$RUNNER_TEMP" ]; then
    fail_cleanup "RUNNER_TEMP missing after cleanup: $RUNNER_TEMP"
fi
for leftover in "$RUNNER_TEMP"/* "$RUNNER_TEMP"/.[!.]* "$RUNNER_TEMP"/..?*; do
    if [ -e "$leftover" ] || [ -L "$leftover" ]; then
        fail_cleanup "failed to remove temporary entry in RUNNER_TEMP: $leftover"
    fi
done

echo "hvf-job-completed: pruned $target_dir and cleared $RUNNER_TEMP"
