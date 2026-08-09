ARG BASE_IMAGE=localhost:5005/carrick-go-conformance@sha256:357a08793e683c6a174d3955c704a5194e825f38fcdcb91d1d4ee2bccd6b188b
FROM ${BASE_IMAGE}

RUN apt-get update \
    && apt-get install -y --no-install-recommends bpftrace \
    && rm -rf /var/lib/apt/lists/*
