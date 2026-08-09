#!/bin/sh
# Canonical HvPatch Phase 4 cold-build correctness and process-population fixture.
# Keep this byte-identical between Carrick and the native-arm64 Docker oracle.
set -eu

cd /tmp
rm -rf hvpatch-p4-gocache hvpatch-p4-main hvpatch-p4-main.go
printf 'package main\nfunc main(){println("ok")}\n' > hvpatch-p4-main.go
GOMAXPROCS=4 GOCACHE=/tmp/hvpatch-p4-gocache \
    /usr/local/go/bin/go build -p=4 -o hvpatch-p4-main ./hvpatch-p4-main.go
./hvpatch-p4-main
echo BUILD_OK
