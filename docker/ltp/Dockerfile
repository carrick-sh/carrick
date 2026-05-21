# LTP (Linux Test Project) syscall conformance image for carrick.
#
# Builds the LTP syscall testcases for arm64 and installs them under /opt/ltp.
# The SAME image is used two ways by the conformance harness:
#   1. as the Linux oracle  — `docker run ltp <test>`
#   2. as carrick's rootfs  — `carrick run <registry>/ltp <test>`
# so a divergence in a given LTP test pinpoints a carrick syscall gap.
#
# We build only testcases/kernel/syscalls to keep the image small and the
# build tractable; the surface is widened test-by-test as conformance climbs.
FROM ubuntu:24.04 AS build

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        git ca-certificates build-essential autoconf automake \
        pkg-config flex bison m4 \
    && rm -rf /var/lib/apt/lists/*

# Pin to a release tag for reproducibility.
ARG LTP_REF=20240930
RUN git clone --depth 1 --branch ${LTP_REF} https://github.com/linux-test-project/ltp.git /src
WORKDIR /src

RUN make autotools \
    && ./configure --prefix=/opt/ltp \
    && make -C testcases/kernel/syscalls -j"$(nproc)" \
    && make -C testcases/kernel/syscalls install \
    && make -C runtest install || true \
    && make -C pan install || true

# Runtime image: just the built testcases + a shell. Keep ubuntu:24.04 base so
# the dynamic loader / libc match what carrick already exercises.
FROM ubuntu:24.04
COPY --from=build /opt/ltp /opt/ltp
ENV PATH=/opt/ltp/testcases/bin:$PATH
WORKDIR /opt/ltp/testcases/bin
# Must run as root: LTP syscall tests require uid 0, and carrick runs its guest
# as root — the oracle has to match the guest's credentials or every test that
# checks euid would diverge spuriously. This image is a local conformance
# fixture, never deployed.
# nosemgrep: dockerfile.security.last-user-is-root.last-user-is-root -- intentional: conformance fixture must match carrick's root guest, never deployed
USER root
CMD ["/bin/sh"]
