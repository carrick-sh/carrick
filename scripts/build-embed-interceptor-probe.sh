#!/bin/sh
# Build the one deterministic raw-syscall fixture used by carrick-embed's
# signed interceptor tests. This container must exit before any HVF guest runs.
set -eu
cd "$(dirname "$0")/.."

case "$(uname -m)" in
    arm64|aarch64) ;;
    *)
        echo "build-embed-interceptor-probe: requires an arm64 host" >&2
        exit 2
        ;;
esac

source_path="$PWD/fixtures/embed-interceptor-probe/probe.c"
output_dir="$PWD/target/embed-fixtures"
output_path="$output_dir/interceptor-probe-aarch64"
mkdir -p "$output_dir"

docker run --rm --platform linux/arm64 \
    -v "$source_path:/src/probe.c:ro" \
    -v "$output_dir:/out" \
    alpine:3.20 sh -ec '
        apk add --no-cache build-base binutils file >/dev/null
        cc -static -O2 -Wall -Wextra -Werror /src/probe.c -o /out/interceptor-probe-aarch64
        readelf -h /out/interceptor-probe-aarch64 |
            grep -Eq "Machine:[[:space:]]+AArch64"
        if readelf -l /out/interceptor-probe-aarch64 | grep -q INTERP; then
            echo "interceptor probe unexpectedly has a dynamic interpreter" >&2
            exit 1
        fi
        file /out/interceptor-probe-aarch64 |
            grep -Eq "ELF 64-bit.*ARM aarch64.*statically linked"
    '

chmod 0755 "$output_path"
file "$output_path" | grep -Eq 'ELF 64-bit.*ARM aarch64.*statically linked'
echo "build-embed-interceptor-probe: wrote $output_path"
