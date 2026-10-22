#!/usr/bin/env bash
# Install Ubuntu packages for a hosted CI job from an actions/cache directory
# (#615). A restored, complete cache installs its exact .deb set offline, so a
# crawling archive mirror cannot fail the job. A miss resumes from whatever a
# partial cache already holds: apt keeps verified .deb files in the archive
# directory and fetches only the rest, so a throttled mirror converges across
# runs. The set is marked complete only after every package downloaded.
#
# Usage: apt-cached-install.sh CACHE_DIR PACKAGE...
set -euo pipefail
dir=$1
shift
want=$(printf '%s\n' "$@")
apt_net=(-o Acquire::Retries=5 -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30)
mkdir -p "$dir"
# The cache action saves as the runner user, including after a timed-out
# download, so hand the directory back on every exit.
trap 'sudo chown -R "$(id -u):$(id -g)" "$dir"' EXIT
if [[ -f $dir/complete && $(cat "$dir/complete") == "$want" ]]; then
  echo "apt-cached-install: cache hit for $*; installing without the mirror"
else
  echo "apt-cached-install: cache miss for $*; resuming $(find "$dir" -maxdepth 1 -name '*.deb' | wc -l) cached .deb files"
  sudo rm -f "$dir/complete"
  mkdir -p "$dir/partial"
  timeout 600 sudo apt-get "${apt_net[@]}" update
  timeout 600 sudo apt-get "${apt_net[@]}" install -y --download-only \
    -o Dir::Cache::archives="$dir" "$@"
  printf '%s\n' "$want" | sudo tee "$dir/complete" > /dev/null
fi
# Local .deb paths resolve against each other and the installed system, so no
# package lists (and no `apt-get update`) are needed on a hit.
shopt -s nullglob
debs=("$dir"/*.deb)
shopt -u nullglob
if ((${#debs[@]})); then
  sudo apt-get install -y --no-download "${debs[@]}"
fi
