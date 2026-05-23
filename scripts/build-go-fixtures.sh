#!/bin/sh
# Build the Go integration fixture binary as a static AArch64 Linux ELF
# inside a pinned arm64 Go container (no host cross-compiler or Go install needed).
# Output lands in fixtures/go-aarch64-hello/target/release/.
set -e
cd "$(dirname "$0")/.."
mkdir -p fixtures/go-aarch64-hello/target/release
docker run --rm --platform linux/arm64 \
  -v "$PWD/fixtures/go-aarch64-hello:/g" -w /g \
  golang:1.24-bookworm sh -c '
    CGO_ENABLED=1 GOOS=linux GOARCH=arm64 go build -buildmode=pie -ldflags "-linkmode external -extldflags -static-pie" -o target/release/carrick-linux-aarch64-go-hello src/main.go
  '
echo "Go fixture built: fixtures/go-aarch64-hello/target/release/carrick-linux-aarch64-go-hello"
