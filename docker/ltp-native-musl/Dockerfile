# Build pinned LTP source inside a Linux/amd64 container executed by Carrick's
# native backend. Compiler concurrency is explicitly bounded to keep FreeBSD
# host memory/process pressure predictable. Individual unsupported syscall
# directories are recorded rather than hiding them behind aggregate make -k.
FROM ubuntu:24.04 AS builder
ARG CARRICK_DNS=1.1.1.1
# Bounded by the source-image driver. Eight Carrick-native cc1 reducers used
# ~1.6 GiB RSS and zero swap on the 8-CPU/32-GiB FreeBSD build rig while
# delivering 5.25x throughput versus serial execution.
ARG LTP_BUILD_JOBS=8

# Keep package acquisition independent of the source archive so Kaniko can
# reuse the expensive apt layer when the pinned archive tooling changes.
RUN printf 'nameserver %s\n' "$CARRICK_DNS" >/etc/resolv.conf \
 && apt-get -o Acquire::ForceIPv4=true update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      autoconf automake binutils build-essential busybox-static ca-certificates file linux-libc-dev musl-tools pkg-config \
 && rm -rf /var/lib/apt/lists/*

COPY ltp.tar /tmp/ltp.tar
RUN mkdir /src \
 && tar -xf /tmp/ltp.tar -C /src \
 && rm /tmp/ltp.tar \
 && ln -s ../linux /usr/include/x86_64-linux-musl/linux \
 && ln -s ../x86_64-linux-gnu/asm /usr/include/x86_64-linux-musl/asm \
 && ln -s ../asm-generic /usr/include/x86_64-linux-musl/asm-generic

# Separate the expensive stages so a late syscall-directory failure never
# forces apt, autotools, configure, or the common library to run again.
RUN cd /src \
 && make autotools \
 && CC=musl-gcc AR=ar RANLIB=ranlib LDFLAGS=-static-pie ./configure \
      --host=x86_64-linux-musl --prefix=/opt/ltp

RUN make -C /src/lib -j"${LTP_BUILD_JOBS}" \
 && for lib in ipc newipc numa sigwait swap vdso; do make -C "/src/libs/$lib" -j1; done \
 && find /src/lib /src/libs -type f -name '*.a' -exec touch {} +

# LTP's generic trunk rule is a single `set -e; for dir ...` shell recipe: GNU
# make's -j/-k cannot parallelize it, and one expected failure stops traversal.
# Enumerate leaf Makefiles instead, then run bounded batches. Shared libraries
# are built and touched in the prior layer, so leaf makes neither race common
# archives nor retrigger their directory-mtime prerequisites. Every leaf is
# attempted exactly once and writes an isolated failure record.
RUN cd /src \
 && rm -rf /tmp/ltp-build-skips.d \
 && mkdir -p /tmp/ltp-build-skips.d \
 && : >/tmp/ltp-build-leaves \
 && for makefile in $(find testcases/kernel/syscalls -mindepth 2 -type f -name Makefile | sort); do \
      dir=${makefile%/Makefile}; \
      child=$(find "$dir" -mindepth 2 -type f -name Makefile -print -quit); \
      if [ -z "$child" ]; then printf '%s\n' "$dir" >>/tmp/ltp-build-leaves; fi; \
    done \
 && jobs="${LTP_BUILD_JOBS}" \
 && batch=0 active=0 pids= \
 && while IFS= read -r dir; do \
      batch=$((batch + 1)); \
      (if ! make -C "$dir" -j1; then \
         printf '%s\n' "$dir" >"/tmp/ltp-build-skips.d/$batch"; \
       fi) & \
      pids="$pids $!"; \
      active=$((active + 1)); \
      if [ "$active" -ge "$jobs" ]; then \
        for pid in $pids; do wait "$pid"; done; \
        active=0; pids=; \
      fi; \
    done </tmp/ltp-build-leaves \
 && for pid in $pids; do wait "$pid"; done \
 && find /tmp/ltp-build-skips.d -type f -exec cat {} + | sort >/tmp/ltp-build-skips \
 && mkdir -p /artifact/opt/ltp/testcases/bin /artifact/bin /artifact/tmp \
 && find testcases/kernel/syscalls -mindepth 2 -maxdepth 2 -type f -perm /111 \
      -exec cp -t /artifact/opt/ltp/testcases/bin {} + \
 && cp /bin/busybox /artifact/bin/busybox \
 && ln -s busybox /artifact/bin/sh \
 && ln -s busybox /artifact/bin/zcat \
 && cp /tmp/ltp-build-skips /artifact/opt/ltp/static-musl-build-skips

FROM scratch
COPY --from=builder /artifact /
CMD ["/opt/ltp/testcases/bin/getpid01"]
