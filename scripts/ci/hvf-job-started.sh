#!/bin/sh
# Job-start hook (`ACTIONS_RUNNER_HOOK_JOB_STARTED`) for the persistent
# self-hosted macOS HVF runner (#1225).
#
# 1. Policy authorization: Rust (`carrick-xtask ci-scaler admit-job`) owns
#    workflow/event/ref/actor policy. A failed hook alone still allows
#    conditional (`always()`, `failure()`, `!cancelled()`) workflow steps to
#    execute, so any authorization or context-guard failure kills the
#    session-isolated (`setsid`) runner process group (`kill -KILL 0`).
# 2. Strict empty-variable and path guards: unset, empty, whitespace-only,
#    relative, root, top-level, traversal, overlapping, or symlinked
#    workspace/temp/override paths fail closed before touching the filesystem.
# 3. Leftover `target/` reclamation + up-front disk admission: any stale
#    `$GITHUB_WORKSPACE/target` from an interrupted run is removed safely, then
#    free space on `$GITHUB_WORKSPACE` is checked against
#    `CARRICK_HVF_MIN_FREE_GIB` (default 40 GiB, matching
#    `remote_accept::MIN_FREE_DISK_KIB`) so low-disk runs fail clearly at
#    admission rather than mid-build.
# 4. Per-job `sccache` socket isolation: when `GITHUB_ENV` is set and
#    `SCCACHE_SERVER_UDS` is unset, exports `SCCACHE_SERVER_UDS` under
#    `$RUNNER_TEMP` so concurrent runners on the host never share TCP 4226.
set -eu

NL='
'

reject_job() {
    echo "hvf-job-started: $*" >&2
    exec /bin/kill -KILL 0
}

fail_admission() {
    echo "hvf-job-started: $*" >&2
    exit 1
}

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

require_auth_var() {
    if [ "$2" != x ] || ! is_nonempty "$3"; then
        reject_job "required authorization variable $1 is unset or empty"
    fi
}

require_safe_dir() {
    var_name=$1
    is_set=$2
    dir_path=$3
    if [ "$is_set" != x ] || ! is_nonempty "$dir_path"; then
        fail_admission "required directory variable $var_name is unset or empty"
    fi
    case "$dir_path" in
        /*/*) ;;
        *) fail_admission "$var_name must be an absolute path beneath a parent root: $dir_path" ;;
    esac
    if ! is_clean_abs_path "$dir_path"; then
        fail_admission "$var_name must be a clean canonical-form path: $dir_path"
    fi
    if [ -L "$dir_path" ]; then
        fail_admission "$var_name must not be a symbolic link: $dir_path"
    fi
    if [ ! -d "$dir_path" ]; then
        fail_admission "$var_name does not name an existing directory: $dir_path"
    fi
}

if [ "${CARRICK_XTASK+x}" = x ]; then
    is_clean_abs_path "$CARRICK_XTASK" || reject_job "CARRICK_XTASK is empty or not a clean absolute path"
    xtask=$CARRICK_XTASK
else
    xtask=/usr/local/bin/carrick-xtask
fi

if [ "${CARRICK_CI_POLICY_FILE+x}" = x ]; then
    is_clean_abs_path "$CARRICK_CI_POLICY_FILE" || reject_job "CARRICK_CI_POLICY_FILE is empty or not a clean absolute path"
    policy_file=$CARRICK_CI_POLICY_FILE
else
    policy_file=/etc/carrick-ci/policy
fi

require_auth_var GITHUB_REPOSITORY "${GITHUB_REPOSITORY+x}" "${GITHUB_REPOSITORY-}"
require_auth_var GITHUB_EVENT_NAME "${GITHUB_EVENT_NAME+x}" "${GITHUB_EVENT_NAME-}"
require_auth_var GITHUB_ACTOR "${GITHUB_ACTOR+x}" "${GITHUB_ACTOR-}"
require_auth_var GITHUB_TRIGGERING_ACTOR "${GITHUB_TRIGGERING_ACTOR+x}" "${GITHUB_TRIGGERING_ACTOR-}"
require_auth_var GITHUB_WORKFLOW_REF "${GITHUB_WORKFLOW_REF+x}" "${GITHUB_WORKFLOW_REF-}"
require_auth_var GITHUB_REF "${GITHUB_REF+x}" "${GITHUB_REF-}"
require_auth_var GITHUB_SHA "${GITHUB_SHA+x}" "${GITHUB_SHA-}"
require_auth_var GITHUB_RUN_ID "${GITHUB_RUN_ID+x}" "${GITHUB_RUN_ID-}"
require_auth_var GITHUB_RUN_ATTEMPT "${GITHUB_RUN_ATTEMPT+x}" "${GITHUB_RUN_ATTEMPT-}"
if [ "$GITHUB_EVENT_NAME" = "pull_request_review" ]; then
    require_auth_var GITHUB_EVENT_PATH "${GITHUB_EVENT_PATH+x}" "${GITHUB_EVENT_PATH-}"
fi

if [ ! -f "$xtask" ] || [ ! -x "$xtask" ]; then
    reject_job "xtask binary is missing or not executable: $xtask"
fi

if ! "$xtask" ci-scaler admit-job --policy-file "$policy_file"; then
    reject_job "job-start policy rejected workflow, event, ref, or actor"
fi

require_safe_dir GITHUB_WORKSPACE "${GITHUB_WORKSPACE+x}" "${GITHUB_WORKSPACE-}"
require_safe_dir RUNNER_TEMP "${RUNNER_TEMP+x}" "${RUNNER_TEMP-}"

if [ "$GITHUB_WORKSPACE" = "$RUNNER_TEMP" ]; then
    fail_admission "GITHUB_WORKSPACE and RUNNER_TEMP must be distinct directories"
fi
case "$RUNNER_TEMP/" in
    "$GITHUB_WORKSPACE/"*)
        fail_admission "RUNNER_TEMP must not reside inside GITHUB_WORKSPACE: $RUNNER_TEMP"
        ;;
esac
case "$GITHUB_WORKSPACE/" in
    "$RUNNER_TEMP/"*)
        fail_admission "GITHUB_WORKSPACE must not reside inside RUNNER_TEMP: $GITHUB_WORKSPACE"
        ;;
esac
case "$xtask/" in
    "$GITHUB_WORKSPACE/"* | "$RUNNER_TEMP/"*)
        fail_admission "CARRICK_XTASK must not reside inside GITHUB_WORKSPACE or RUNNER_TEMP"
        ;;
esac
case "$policy_file/" in
    "$GITHUB_WORKSPACE/"* | "$RUNNER_TEMP/"*)
        fail_admission "CARRICK_CI_POLICY_FILE must not reside inside GITHUB_WORKSPACE or RUNNER_TEMP"
        ;;
esac

if [ "${CARRICK_HVF_MIN_FREE_GIB+x}" = x ]; then
    if ! is_nonempty "$CARRICK_HVF_MIN_FREE_GIB"; then
        fail_admission "CARRICK_HVF_MIN_FREE_GIB is set but empty"
    fi
    min_free_gib=$CARRICK_HVF_MIN_FREE_GIB
else
    # Matches remote_accept::MIN_FREE_DISK_KIB (40 GiB) above hvf-kernel's
    # measured ~31.34 GiB peak target/ footprint (#348, #1225).
    min_free_gib=40
fi
case "$min_free_gib" in
    '' | *[!0-9]*)
        fail_admission "CARRICK_HVF_MIN_FREE_GIB must be a positive integer GiB value: $min_free_gib"
        ;;
esac
if [ "$min_free_gib" -lt 1 ]; then
    fail_admission "CARRICK_HVF_MIN_FREE_GIB must be at least 1 GiB: $min_free_gib"
fi

if [ "${SCCACHE_SERVER_UDS+x}" = x ]; then
    if ! is_clean_abs_path "$SCCACHE_SERVER_UDS"; then
        fail_admission "SCCACHE_SERVER_UDS is empty or not a clean absolute path"
    fi
fi

if [ "${GITHUB_ENV+x}" = x ]; then
    if ! is_clean_abs_path "$GITHUB_ENV"; then
        fail_admission "GITHUB_ENV is empty or not a clean absolute path"
    fi
    if [ -L "$GITHUB_ENV" ] || [ -d "$GITHUB_ENV" ]; then
        fail_admission "GITHUB_ENV must not be a symlink or directory: $GITHUB_ENV"
    fi
    env_parent=${GITHUB_ENV%/*}
    : "${env_parent:=/}"
    if [ ! -d "$env_parent" ]; then
        fail_admission "GITHUB_ENV parent directory does not exist: $env_parent"
    fi
fi

# Reclaim any stale build tree from an interrupted prior run before checking
# disk headroom, refusing symlink swaps on `$GITHUB_WORKSPACE/target`.
target_dir="$GITHUB_WORKSPACE/target"
case "$target_dir" in
    "$GITHUB_WORKSPACE"/target) ;;
    *) fail_admission "unexpected target path expansion: $target_dir" ;;
esac
if [ -L "$target_dir" ]; then
    fail_admission "refusing to remove symlinked target path: $target_dir"
fi
if [ -e "$target_dir" ]; then
    find "$target_dir" -type d -exec chmod u+w {} +
    rm -rf -- "$target_dir"
    if [ -e "$target_dir" ] || [ -L "$target_dir" ]; then
        fail_admission "failed to remove stale target directory: $target_dir"
    fi
fi

avail_kib=$(df -Pk "$GITHUB_WORKSPACE" | awk 'NR == 2 { print $4 }')
case "$avail_kib" in
    '' | *[!0-9]*)
        fail_admission "failed to read available KiB from df -Pk for $GITHUB_WORKSPACE"
        ;;
esac
avail_gib=$(awk -v k="$avail_kib" 'BEGIN { printf "%d\n", int(k / 1048576) }')
if ! awk -v k="$avail_kib" -v min_gib="$min_free_gib" 'BEGIN { exit !(k >= min_gib * 1048576) }'; then
    echo "::error title=HVF disk admission failed::free disk space on $GITHUB_WORKSPACE is ${avail_gib} GiB (${avail_kib} KiB), below the ${min_free_gib} GiB minimum"
    fail_admission "free disk space on $GITHUB_WORKSPACE is ${avail_gib} GiB (${avail_kib} KiB), below the ${min_free_gib} GiB minimum"
fi

if [ "${GITHUB_ENV+x}" = x ] && [ "${SCCACHE_SERVER_UDS+x}" != x ]; then
    printf 'SCCACHE_SERVER_UDS=%s/sccache.sock\n' "$RUNNER_TEMP" >> "$GITHUB_ENV"
fi

echo "hvf-job-started: disk admission passed (${avail_gib} GiB free >= ${min_free_gib} GiB minimum on $GITHUB_WORKSPACE)"
