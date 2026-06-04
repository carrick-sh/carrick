# Self-contained Go std-library conformance image for carrick.
#
# Bakes the std-test binaries INTO a golang base, built with the
# carrick-compatible external-static-pie recipe. Because they compile inside
# this image, their baked GOROOT is /usr/local/go — the same GOROOT present in
# the rootfs — so source-relative reads (example_test.go, ../../lib/time/
# zoneinfo.zip), tzdata, and the source tree all resolve from the normal fs
# backend when run via `carrick run`. No bind mounts, no scratch loader tar.
#
# Build (arm64, the arch carrick executes):
#   docker build --platform linux/arm64 -t localhost:5005/carrick-go-conformance:1.24 \
#     docker/go-conformance
#   docker push localhost:5005/carrick-go-conformance:1.24
#
# Run a package's tests under carrick (cwd = the package source dir so the
# test's relative file reads resolve):
#   CARRICK_INSECURE_REGISTRIES=localhost:5005 \
#   carrick run --raw -w /usr/local/go/src/sync \
#     localhost:5005/carrick-go-conformance:1.24 \
#     /conformance/sync.test -test.run Test -test.short -test.v
FROM golang:1.24-bookworm
ENV CGO_ENABLED=1 GOOS=linux GOARCH=arm64
# Prebuild a `.test` binary for EVERY std package that has tests (full
# conformance coverage). Packages without test files produce no binary (skipped);
# any that fail the static-pie compile are tolerated and dropped, so the image
# build never fails on a single package. Internal/vendor/cmd are excluded.
RUN set -eux; \
    mkdir -p /conformance; \
    cd /usr/local/go/src; \
    for p in $(go list std | grep -vE '^(internal/|vendor/|cmd/)'); do \
      n=$(echo "$p" | tr / _); \
      go test -c -buildmode=pie \
        -ldflags "-linkmode external -extldflags -static-pie" \
        -o "/conformance/$n.test" "./$p" 2>/dev/null || true; \
      [ -s "/conformance/$n.test" ] || rm -f "/conformance/$n.test"; \
    done; \
    chmod -R a+rx /conformance; \
    echo "prebuilt $(ls /conformance | wc -l) std .test binaries"
WORKDIR /usr/local/go/src
