# Reproducible Node.js/V8/libuv conformance image for carrick.
#
# The image keeps the source trees and the binaries built from those exact
# trees. It can be used as a Docker oracle or as a carrick rootfs through the
# same /usr/local/bin/nodejs-conformance entrypoint.
#
# Build for the architecture carrick executes:
#   docker build --platform linux/arm64 \
#     -t localhost:5005/carrick-nodejs-conformance:24.16.0-26.2.0 \
#     docker/nodejs-conformance
#
# Push for carrick's OCI pull path:
#   docker push localhost:5005/carrick-nodejs-conformance:24.16.0-26.2.0
# Node 26.2.0's embedded V8 needs a newer C++ toolchain than bookworm's GCC 12
# for its Turboshaft static_assert-in-discarded-if-constexpr pattern.
FROM debian:trixie

ARG NODE24_REF=v24.16.0
ARG NODE26_REF=v26.2.0
ARG LIBUV_REF=v1.52.1
ARG NODE_BUILD_JOBS=

ENV DEBIAN_FRONTEND=noninteractive \
    NODE24_REF=${NODE24_REF} \
    NODE26_REF=${NODE26_REF} \
    LIBUV_REF=${LIBUV_REF} \
    NODE_BUILD_JOBS=${NODE_BUILD_JOBS} \
    NODEJS_CONFORMANCE_IN_IMAGE=1 \
    PATH=/opt/nodejs-conformance/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
      ca-certificates git curl xz-utils \
      python3 python-is-python3 make gcc g++ pkg-config perl \
      cmake ninja-build autoconf automake libtool; \
    rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    mkdir -p /opt/node-src /opt/nodejs-conformance/bin; \
    git clone --depth 1 --branch "${NODE24_REF}" https://github.com/nodejs/node.git /opt/node-src/v24; \
    cd /opt/node-src/v24; \
    ./configure --prefix=/opt/nodejs-conformance/node-v24; \
    build_jobs="${NODE_BUILD_JOBS:-$(nproc)}"; \
    make -j"${build_jobs}"; \
    make install; \
    ln -sf /opt/node-src/v24/out/Release/node /opt/nodejs-conformance/bin/node24; \
    test -d /opt/node-src/v24/deps/v8

RUN set -eux; \
    git clone --depth 1 --branch "${NODE26_REF}" https://github.com/nodejs/node.git /opt/node-src/v26; \
    cd /opt/node-src/v26; \
    ./configure --prefix=/opt/nodejs-conformance/node-v26; \
    build_jobs="${NODE_BUILD_JOBS:-$(nproc)}"; \
    make -j"${build_jobs}"; \
    make install; \
    ln -sf /opt/node-src/v26/out/Release/node /opt/nodejs-conformance/bin/node26; \
    test -d /opt/node-src/v26/deps/v8

RUN set -eux; \
    git clone --depth 1 --branch "${LIBUV_REF}" https://github.com/libuv/libuv.git /opt/libuv-src; \
    cmake -S /opt/libuv-src -B /opt/libuv-src/build \
      -G Ninja \
      -DCMAKE_BUILD_TYPE=Release \
      -DBUILD_TESTING=ON \
      -DLIBUV_BUILD_TESTS=ON; \
    cmake --build /opt/libuv-src/build --parallel; \
    find /opt/libuv-src -type f \( -name 'uv_run_tests_a' -o -name 'run-tests' \) -perm -111 -print -quit | grep .

COPY nodejs-conformance /usr/local/bin/nodejs-conformance
COPY fixtures /opt/nodejs-conformance/fixtures

RUN set -eux; \
    chmod +x /usr/local/bin/nodejs-conformance; \
    /opt/nodejs-conformance/bin/node24 --version; \
    /opt/nodejs-conformance/bin/node26 --version; \
    printf '{"node24_ref":"%s","node26_ref":"%s","libuv_ref":"%s"}\n' \
      "${NODE24_REF}" "${NODE26_REF}" "${LIBUV_REF}" \
      > /opt/nodejs-conformance/metadata.json

WORKDIR /opt/nodejs-conformance
ENTRYPOINT ["/usr/local/bin/nodejs-conformance"]
CMD ["--help"]
