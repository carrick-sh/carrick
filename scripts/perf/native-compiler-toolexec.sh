#!/bin/sh
set -eu

tool=$1
shift
printf '%s\0' 'TOOLEXEC1' "$tool" "$@" '' >>"${CARRICK_TOOLEXEC_LOG:?}"
exec "$tool" "$@"
