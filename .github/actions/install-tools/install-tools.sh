#!/usr/bin/env bash
# Helper for .github/actions/install-tools (#1873). Two subcommands:
#
#   resolve  Map REQUESTED_TOOLS to exact versions from PINNED_TOOLS. On a
#            self-hosted runner, a tool already on PATH whose `--version` is
#            exactly "<tool> <version>" is reused and not downloaded, so an
#            upstream release-download outage cannot fail the job. Everything
#            else is listed as tool@version for install-action, together with
#            a fresh private HOME, TMPDIR and CARGO_HOME under RUNNER_TEMP.
#   publish  Check every downloaded tool landed in the private HOME at the
#            exact pinned version, then prepend its directory via GITHUB_PATH.
#
# Every tool installed here is a single binary named after the tool, printing
# "<tool> <version>" as the first line of `<tool> --version`.
set -euo pipefail

fail() {
  printf '::error title=Infrastructure::install-tools: %s\n' "$*"
  exit 1
}

# Print the first line of `<path> --version`, or nothing if it fails.
version_line() {
  local out
  out=$("$1" --version 2>/dev/null) || return 0
  printf '%s\n' "${out%%$'\n'*}"
}

# Bash 3.2 (macOS /bin/bash) has no associative arrays: scan the table.
pinned_version() {
  local entry
  for entry in ${PINNED_TOOLS}; do
    if [[ "${entry%%=*}" == "$1" ]]; then
      printf '%s\n' "${entry#*=}"
      return 0
    fi
  done
}

resolve() {
  : "${RUNNER_TEMP:?}" "${GITHUB_OUTPUT:?}" "${PINNED_TOOLS:?}"
  local requested="${REQUESTED_TOOLS//,/ }"
  local tool version found got download=() seen=" "
  for tool in ${requested}; do
    case "${tool}" in
      *@*) fail "'${tool}': versions come only from the action's table; pass the bare name" ;;
    esac
    version=$(pinned_version "${tool}")
    [[ -n "${version}" ]] || fail "'${tool}' is not in the pinned table (${PINNED_TOOLS})"
    [[ "${seen}" != *" ${tool} "* ]] || continue
    seen+="${tool} "
    if [[ "${RUNNER_ENVIRONMENT:-}" == self-hosted ]] && found=$(type -P "${tool}"); then
      got=$(version_line "${found}")
      if [[ "${got}" == "${tool} ${version}" ]]; then
        echo "${tool} ${version}: reusing preinstalled ${found} (self-hosted; no download)"
        continue
      fi
      echo "${tool}: ${found} reports '${got}', not '${tool} ${version}'; downloading the pinned build"
    fi
    download+=("${tool}@${version}")
  done
  [[ "${seen}" != " " ]] || fail "no tools requested"

  local list=""
  if [[ ${#download[@]} -gt 0 ]]; then
    list=$(IFS=,; printf '%s' "${download[*]}")
    local root
    root=$(mktemp -d "${RUNNER_TEMP}/install-tools.XXXXXX")
    mkdir -p "${root}/home" "${root}/tmp" "${root}/cargo"
    echo "downloading ${list} with private HOME/TMPDIR/CARGO_HOME under ${root}"
    {
      echo "home=${root}/home"
      echo "tmpdir=${root}/tmp"
      echo "cargo-home=${root}/cargo"
    } >>"${GITHUB_OUTPUT}"
  fi
  echo "download=${list}" >>"${GITHUB_OUTPUT}"
}

publish() {
  : "${GITHUB_PATH:?}" "${DOWNLOADED_TOOLS:?}" "${PRIVATE_HOME:?}"
  # The private CARGO_HOME has no bin/, so install-action installs into
  # <HOME>/.install-action/bin (main.sh's cargo_bin fallback).
  local bin_dir="${PRIVATE_HOME}/.install-action/bin"
  local entry tool version got
  for entry in ${DOWNLOADED_TOOLS//,/ }; do
    tool="${entry%@*}"
    version="${entry#*@}"
    [[ -x "${bin_dir}/${tool}" ]] || fail "${tool} was not installed at ${bin_dir}/${tool}"
    got=$(version_line "${bin_dir}/${tool}")
    [[ "${got}" == "${tool} ${version}" ]] ||
      fail "${bin_dir}/${tool} reports '${got}', expected '${tool} ${version}'"
    echo "${tool} ${version}: installed at ${bin_dir}/${tool}"
  done
  echo "${bin_dir}" >>"${GITHUB_PATH}"
}

case "${1:-}" in
  resolve) resolve ;;
  publish) publish ;;
  *) fail "usage: install-tools.sh resolve|publish" ;;
esac
