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
# Then push to carrick's registry so `carrick run` can pull it:
#         docker tag  cpython-test:3.12.13 localhost:5050/cpython-test:3.12.13
#         docker push localhost:5050/cpython-test:3.12.13
ARG CPYTHON_VERSION=3.12.13
# The lane's oracle is canonical linux/arm64. Pin the architecture-specific
# official image manifest as well as the version so a moving convenience tag
# cannot silently change libc/userspace underneath the declared suites.
FROM python:${CPYTHON_VERSION}@sha256:1cdca4a722dc7efb5f63c002a0bcf458e99cb1cbbe04d92493438f24642ba700

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
