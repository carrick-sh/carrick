#!/bin/sh
# Job-start hook (`ACTIONS_RUNNER_HOOK_JOB_STARTED`) for the persistent
# self-hosted macOS HVF runner (#1225).
#
# 1. Policy authorization: Rust (`/usr/local/bin/carrick-xtask ci-scaler
#    admit-job`) owns workflow/event/ref/actor policy against
#    `/etc/carrick-ci/policy`. Both paths are hardcoded in production (never
#    read from the runner's `.env` or job environment) and verified to be
#    root-owned regular files without group/other write permission before
#    execution.
#    A nonzero hook exit alone still allows conditional (`always()`,
#    `failure()`, `!cancelled()`) workflow steps to execute, so any
#    binary/policy ownership failure, missing authorization variable, or policy
#    rejection runs `kill -KILL 0`. Unlike one-shot `setsid` JIT launches, the
#    persistent `launchd` service provides no separate per-job session, so
#    `kill -KILL 0` terminates the runner's process group including
#    `Runner.Listener` before any step can run; slice 2 pairs this with
#    `KeepAlive` in the launchd plist and restricts the runner group's
#    "Selected workflows" to `kernel-runtime.yml@refs/heads/main`.
# 2. Strict empty-variable and path guards: unset, empty, whitespace-only,
#    relative, root, top-level, traversal, overlapping, or symlinked
#    `GITHUB_WORKSPACE` / `RUNNER_TEMP` paths fail closed before touching the
#    filesystem.
# 3. Leftover `target/` reclamation: any stale `$GITHUB_WORKSPACE/target` from
#    an interrupted prior run is removed safely without following symlinks.
#    Up-front disk free-space admission lives in the workflow, and post-job
#    `target/` and `$RUNNER_TEMP` cleanup lives in `hvf-job-completed.sh`.
set -eu

PATH=/usr/bin:/bin
export PATH

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

xtask=/usr/local/bin/carrick-xtask
policy_file=/etc/carrick-ci/policy
expected_owner_uid=0
test_mode=0

# GitHub's runner invokes ACTIONS_RUNNER_HOOK_JOB_STARTED with zero arguments;
# only the test harness passes CLI path/owner overrides.
while [ "$#" -gt 0 ]; do
    test_mode=1
    case "$1" in
        --test-xtask)
            [ "$#" -ge 2 ] || reject_job "--test-xtask requires a path argument"
            xtask=$2
            shift 2
            ;;
        --test-policy-file)
            [ "$#" -ge 2 ] || reject_job "--test-policy-file requires a path argument"
            policy_file=$2
            shift 2
            ;;
        --test-owner-uid)
            [ "$#" -ge 2 ] || reject_job "--test-owner-uid requires a uid argument"
            expected_owner_uid=$2
            shift 2
            ;;
        *)
            reject_job "unexpected argument: $1"
            ;;
    esac
done

case "$expected_owner_uid" in
    '' | *[!0-9]*)
        reject_job "expected owner uid must be a non-negative integer: $expected_owner_uid"
        ;;
esac

uname_s=$(uname -s)

require_owner_only_file() {
    label=$1
    file_path=$2
    need_exec=$3
    if ! is_clean_abs_path "$file_path"; then
        reject_job "$label is empty or not a clean absolute path: $file_path"
    fi
    if [ -L "$file_path" ]; then
        reject_job "$label must not be a symbolic link: $file_path"
    fi
    if [ ! -f "$file_path" ]; then
        reject_job "$label is missing or not a regular file: $file_path"
    fi
    if [ "$need_exec" = 1 ] && [ ! -x "$file_path" ]; then
        reject_job "$label is not executable: $file_path"
    fi
    if [ "$uname_s" = Darwin ]; then
        owner_mode=$(stat -f '%u:%Lp' "$file_path") || reject_job "cannot stat $label: $file_path"
    else
        owner_mode=$(stat -c '%u:%a' "$file_path") || reject_job "cannot stat $label: $file_path"
    fi
    file_uid=${owner_mode%%:*}
    file_mode=${owner_mode#*:}
    case "$file_uid" in
        '' | *[!0-9]*) reject_job "unexpected owner uid from stat for $label: $owner_mode" ;;
    esac
    case "$file_mode" in
        '' | *[!0-7]*) reject_job "unexpected mode from stat for $label: $owner_mode" ;;
    esac
    if [ "$file_uid" -ne "$expected_owner_uid" ]; then
        reject_job "$label must be owned by uid $expected_owner_uid (got uid $file_uid): $file_path"
    fi
    if [ "$(( 0$file_mode & 022 ))" -ne 0 ]; then
        reject_job "$label must not be group- or other-writable (mode $file_mode): $file_path"
    fi
}

require_not_in_job_dir() {
    label=$1
    file_path=$2
    if [ "${GITHUB_WORKSPACE+x}" = x ] && is_clean_abs_path "$GITHUB_WORKSPACE"; then
        case "$file_path/" in
            "$GITHUB_WORKSPACE/"*)
                reject_job "$label must not reside inside GITHUB_WORKSPACE: $file_path"
                ;;
        esac
    fi
    if [ "${RUNNER_TEMP+x}" = x ] && is_clean_abs_path "$RUNNER_TEMP"; then
        case "$file_path/" in
            "$RUNNER_TEMP/"*)
                reject_job "$label must not reside inside RUNNER_TEMP: $file_path"
                ;;
        esac
    fi
}

require_owner_only_file "xtask binary" "$xtask" 1
require_owner_only_file "policy file" "$policy_file" 0
require_not_in_job_dir "xtask binary" "$xtask"
require_not_in_job_dir "policy file" "$policy_file"

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

if [ "$test_mode" = 1 ]; then
    if ! "$xtask" ci-scaler admit-job --policy-file "$policy_file" --test-policy-owner-uid "$expected_owner_uid"; then
        reject_job "job-start policy rejected workflow, event, ref, or actor"
    fi
else
    if ! "$xtask" ci-scaler admit-job --policy-file "$policy_file"; then
        reject_job "job-start policy rejected workflow, event, ref, or actor"
    fi
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
        fail_admission "xtask binary must not reside inside GITHUB_WORKSPACE or RUNNER_TEMP"
        ;;
esac
case "$policy_file/" in
    "$GITHUB_WORKSPACE/"* | "$RUNNER_TEMP/"*)
        fail_admission "policy file must not reside inside GITHUB_WORKSPACE or RUNNER_TEMP"
        ;;
esac

# Reclaim any stale build tree from an interrupted prior run, refusing symlink
# swaps on `$GITHUB_WORKSPACE/target`.
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

echo "hvf-job-started: admitted job for $GITHUB_REPOSITORY ($GITHUB_EVENT_NAME on $GITHUB_REF)"
