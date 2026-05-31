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
# Build:  docker build --build-arg CPYTHON_VERSION=3.12.13 -t cpython-test:3.12.13 docker/cpython-test
# Then push to carrick's registry so `carrick run` can pull it:
#         docker tag  cpython-test:3.12.13 localhost:5050/cpython-test:3.12.13
#         docker push localhost:5050/cpython-test:3.12.13
FROM python:3.12

# Pin to the interpreter's exact version (must equal `python3 --version` of the
# base image) so the test code matches the runtime it exercises.
ARG CPYTHON_VERSION=3.12.13

# Docker's ADD fetches the URL at build time — the network access is sandboxed in
# the build, not run on the host, and the layer is content-addressed/cached.
ADD https://github.com/python/cpython/archive/refs/tags/v${CPYTHON_VERSION}.tar.gz /tmp/cpython-src.tgz

RUN set -eux; \
    py_lib="$(python3 -c 'import sysconfig; print(sysconfig.get_path("stdlib"))')"; \
    tar -xzf /tmp/cpython-src.tgz -C /tmp "cpython-${CPYTHON_VERSION}/Lib/test"; \
    rm -rf "${py_lib}/test"; \
    mv "/tmp/cpython-${CPYTHON_VERSION}/Lib/test" "${py_lib}/test"; \
    rm -rf /tmp/cpython-src.tgz "/tmp/cpython-${CPYTHON_VERSION}"; \
    # Fail the build loudly if the suite didn't land where -m test will find it.
    python3 -c "import test, test.support; print('cpython test suite at', test.__path__[0])"; \
    test -f "${py_lib}/test/_test_multiprocessing.py"
