#!/bin/sh
# Build glibc-linked Linux/aarch64 perf workloads. These are intentionally
# separate from conformance-probes' static musl fixtures so dynamic-loader and
# libc/interposer behavior can be measured explicitly.
set -e
cd "$(dirname "$0")/.."

docker run --rm --platform linux/arm64 \
  -v "$PWD/perf-dynamic:/p" -w /p \
  gcc:14 sh -c '
    set -e
    mkdir -p target/aarch64-linux-gnu/release
    for src in src/*.c; do
      name=$(basename "$src" .c)
      gcc -O2 -std=c11 -Wall -Wextra -o "target/aarch64-linux-gnu/release/$name" "$src"
    done
  '

echo "dynamic perf workloads built: perf-dynamic/target/aarch64-linux-gnu/release/"
find perf-dynamic/target/aarch64-linux-gnu/release \
  -maxdepth 1 -type f ! -name '*.*' -exec basename {} \; 2>/dev/null | sort || true
