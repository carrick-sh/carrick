#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fixture_dir="$repo_root/fixtures/linux-aarch64-hello"
target="aarch64-unknown-linux-musl"
sysroot="$(rustc --print sysroot)"
host="$(rustc -vV | awk '/^host:/ { print $2 }')"
lld="$sysroot/lib/rustlib/$host/bin/rust-lld"

if ! rustup target list --installed | grep -qx "$target"; then
  echo "missing Rust target: $target" >&2
  echo "install it with: rustup target add $target" >&2
  exit 2
fi

if [[ ! -x "$lld" ]]; then
  echo "missing rust-lld at $lld" >&2
  exit 2
fi

out_dir="$fixture_dir/target/$target/release"
mkdir -p "$out_dir"
tmp_dir="$(mktemp -d "$out_dir/carrick-linux-aarch64-fixtures.XXXXXX")"
trap 'rm -rf "$tmp_dir"' EXIT

build_fixture() {
  local source="$1"
  local name="$2"
  local object="$tmp_dir/$name.o"
  local artifact_tmp="$tmp_dir/$name"
  local artifact="$out_dir/$name"

  rustc "$fixture_dir/src/$source" \
    --target "$target" \
    --edition 2024 \
    -C panic=abort \
    -C opt-level=z \
    --emit=obj \
    -o "$object"

  "$lld" -flavor gnu \
    -static \
    --entry=_start \
    --gc-sections \
    -o "$artifact_tmp" \
    "$object"

  mv -f "$artifact_tmp" "$artifact"
  file "$artifact"
}

build_pie_fixture() {
  local source="$1"
  local name="$2"
  local object="$tmp_dir/$name.o"
  local artifact_tmp="$tmp_dir/$name"
  local artifact="$out_dir/$name"

  rustc "$fixture_dir/src/$source" \
    --target "$target" \
    --edition 2024 \
    -C panic=abort \
    -C opt-level=z \
    -C relocation-model=pic \
    --emit=obj \
    -o "$object"

  # Produce a static-PIE ELF: ET_DYN with no PT_INTERP, so the loader sees
  # the same shape as Alpine's busybox without needing a dynamic linker.
  "$lld" -flavor gnu \
    -static \
    -pie \
    --no-dynamic-linker \
    --entry=_start \
    --gc-sections \
    -o "$artifact_tmp" \
    "$object"

  mv -f "$artifact_tmp" "$artifact"
  file "$artifact"
}

build_fixture "main.rs" "carrick-linux-aarch64-hello"
build_fixture "cat_motd.rs" "carrick-linux-aarch64-cat-motd"
build_fixture "argv_echo.rs" "carrick-linux-aarch64-argv-echo"
build_fixture "timerfd_epoll.rs" "carrick-linux-aarch64-timerfd-epoll"
build_fixture "ppoll_eventfd.rs" "carrick-linux-aarch64-ppoll-eventfd"
build_fixture "pselect_eventfd.rs" "carrick-linux-aarch64-pselect-eventfd"
build_fixture "process_bootstrap.rs" "carrick-linux-aarch64-process-bootstrap"
build_fixture "futex.rs" "carrick-linux-aarch64-futex"
build_fixture "rseq.rs" "carrick-linux-aarch64-rseq"
build_fixture "membarrier.rs" "carrick-linux-aarch64-membarrier"
build_fixture "scheduler.rs" "carrick-linux-aarch64-scheduler"
build_fixture "prctl.rs" "carrick-linux-aarch64-prctl"
build_fixture "getcpu.rs" "carrick-linux-aarch64-getcpu"
build_fixture "flock_motd.rs" "carrick-linux-aarch64-flock-motd"
build_fixture "nanosleep.rs" "carrick-linux-aarch64-nanosleep"
build_fixture "clock_nanosleep.rs" "carrick-linux-aarch64-clock-nanosleep"
build_fixture "madvise.rs" "carrick-linux-aarch64-madvise"
build_fixture "shared_mmap_fork.rs" "carrick-linux-aarch64-shared-mmap-fork"
build_fixture "statx_motd.rs" "carrick-linux-aarch64-statx-motd"
build_fixture "openat2_motd.rs" "carrick-linux-aarch64-openat2-motd"
build_fixture "faccessat2_motd.rs" "carrick-linux-aarch64-faccessat2-motd"
build_fixture "sendfile_motd.rs" "carrick-linux-aarch64-sendfile-motd"
build_fixture "preadv_motd.rs" "carrick-linux-aarch64-preadv-motd"
build_fixture "splice_motd.rs" "carrick-linux-aarch64-splice-motd"
build_fixture "sync_motd.rs" "carrick-linux-aarch64-sync-motd"
build_fixture "pwrite64_motd.rs" "carrick-linux-aarch64-pwrite64-motd"
build_fixture "pwritev_motd.rs" "carrick-linux-aarch64-pwritev-motd"
build_fixture "ftruncate_motd.rs" "carrick-linux-aarch64-ftruncate-motd"
build_fixture "utimensat_motd.rs" "carrick-linux-aarch64-utimensat-motd"
build_fixture "mkdirat_motd.rs" "carrick-linux-aarch64-mkdirat-motd"
build_fixture "unlinkat_motd.rs" "carrick-linux-aarch64-unlinkat-motd"
build_fixture "renameat_motd.rs" "carrick-linux-aarch64-renameat-motd"
build_fixture "fchmod_motd.rs" "carrick-linux-aarch64-fchmod-motd"
build_fixture "fchown_motd.rs" "carrick-linux-aarch64-fchown-motd"
build_fixture "truncate_motd.rs" "carrick-linux-aarch64-truncate-motd"
build_fixture "symlinkat_motd.rs" "carrick-linux-aarch64-symlinkat-motd"
build_fixture "linkat_motd.rs" "carrick-linux-aarch64-linkat-motd"
build_fixture "errno_matrix.rs" "carrick-linux-aarch64-errno-matrix"
build_fixture "signal_basic.rs" "carrick-linux-aarch64-signal-basic"
build_fixture "signal_default.rs" "carrick-linux-aarch64-signal-default"
build_fixture "pipe_fork_poll.rs" "carrick-linux-aarch64-pipe-fork-poll"
build_fixture "pipe_bidi.rs" "carrick-linux-aarch64-pipe-bidi"
build_fixture "pipe_dup3.rs" "carrick-linux-aarch64-pipe-dup3"
build_fixture "nested_pipe.rs" "carrick-linux-aarch64-nested-pipe"
build_fixture "thread_stress.rs" "carrick-linux-aarch64-thread-stress"
build_fixture "inet_connect.rs" "carrick-linux-aarch64-inet-connect"
build_fixture "write_hi_to_fd1.rs" "carrick-linux-aarch64-write-hi-to-fd1"
build_fixture "pipe_dup3_exec.rs" "carrick-linux-aarch64-pipe-dup3-exec"
build_fixture "read_then_write_via_stdio.rs" "carrick-linux-aarch64-read-then-write-via-stdio"
build_fixture "two_pipes_dup3_exec.rs" "carrick-linux-aarch64-two-pipes-dup3-exec"
build_fixture "udp_dns.rs" "carrick-linux-aarch64-udp-dns"
build_fixture "udp_dns_debian.rs" "carrick-linux-aarch64-udp-dns-debian"
build_pie_fixture "pie_hello.rs" "carrick-linux-aarch64-pie-hello"

cargo metadata \
  --manifest-path "$fixture_dir/Cargo.toml" \
  --format-version 1 \
  >/dev/null

build_fixture "fork_bench.rs" "carrick-linux-aarch64-fork-bench"
