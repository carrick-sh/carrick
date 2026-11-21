# CPython 3.12 + its matching Lib/test suite, baked into the stdlib path.
#
# The official python:3.12 image SHIPS WITHOUT the `test` package (it is stripped
# to keep the image small), so the carrick-vs-Docker regrtest parity harness
# (scripts/cpython-parity.py) had nothing to run. Earlier we bind-mounted a host
# copy at /opt/cpy, but that copy lived in /tmp and kept getting wiped, and a
# leaf bind-mount over the stdlib dir is invisible to carrick's parent readdir.
#
# Baking the suite into the image instead is durable (survives /tmp cleanup),
# reproducible (pinned to the interpreter's exact version), and needs NO mount —
# `python3 -m test <module>` discovers the bundled `test` package from the normal
# stdlib path on BOTH Docker and carrick, so the two sides run byte-identical
# test code by construction.
#
# Build:  docker build --platform linux/arm64 -t cpython-test:3.12.13 docker/cpython-test
# Use linux/amd64 for x86_64.
# Then push to carrick's registry so `carrick run` can pull it:
#         docker tag  cpython-test:3.12.13 localhost:5050/cpython-test:3.12.13
#         docker push localhost:5050/cpython-test:3.12.13
ARG CPYTHON_VERSION=3.12.13
# Pin the official multi-architecture image index. The build platform selects
# its linux/amd64 or linux/arm64 manifest from that immutable index.
FROM python:${CPYTHON_VERSION}@sha256:dd4fe98ab39f91e936f8e7e7a65a3ce59ecfb11e32f9a125b3132779920ba7f7

ARG CPYTHON_VERSION

# Docker's ADD fetches the release archive at build time. The checksum binds the
# baked Lib/test tree to the exact upstream v3.12.13 source bytes rather than
# trusting a mutable URL or the build cache.
ADD --checksum=sha256:ae96425e4b395ea2ebf1c1753ffa71ccdbbc0f715bd675646f5188ca5c8c7609 \
    https://github.com/python/cpython/archive/refs/tags/v${CPYTHON_VERSION}.tar.gz \
    /tmp/cpython-src.tgz

RUN set -eux; \
    test "$(python3 --version)" = "Python ${CPYTHON_VERSION}"; \
    py_lib="$(python3 -c 'import sysconfig; print(sysconfig.get_path("stdlib"))')"; \
    tar -xzf /tmp/cpython-src.tgz -C /tmp "cpython-${CPYTHON_VERSION}/Lib/test"; \
    rm -rf "${py_lib}/test"; \
    mv "/tmp/cpython-${CPYTHON_VERSION}/Lib/test" "${py_lib}/test"; \
    rm -rf /tmp/cpython-src.tgz "/tmp/cpython-${CPYTHON_VERSION}"; \
    # Fail the build loudly if the suite didn't land where -m test will find it.
    python3 -c "import test, test.support; print('cpython test suite at', test.__path__[0])"; \
    test -f "${py_lib}/test/_test_multiprocessing.py"
