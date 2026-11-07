# x86: Go startup exits 2 when fcntl on standard input returns ENOSYS

Issue creation was attempted through the connected GitHub integration and
rejected with HTTP 403, `Resource not accessible by integration`. This is an
unpublished issue draft, not a filed defect. Searches for `cannot open standard
fds` and Go/fcntl found no matching root-startup issue. #1678 concerns forked
children; #1722 and #1756 already cover the dynamic-loader gaps.

At main `71c57e106688ba954a5a9947c9868f8a92160660`, a direct Go launch on
real KVM exits 2 before it can report its version. Under `just lease gate`,
after separately pulling the public amd64 image:

```sh
CARRICK_REQUIRE_KVM=1 RUST_LOG=carrick=debug \
CARRICK_RUN_ID=i1793-launch-20261107T015148-go-version \
CARRICK_EL1_CENSUS=/absolute/evidence/census \
timeout --foreground --signal=KILL 120s target/release/carrick \
  run --rm --json --platform linux/amd64 --pull never \
  --entrypoint /usr/local/go/bin/go golang:1.24 version < /dev/null
```

First stderr lines:

```text
runtime: unexpected error while checking standard file descriptor 0, errno=38
fatal error: cannot open standard fds
```

The stack names `runtime.checkfds`, `runtime/fds_unix.go:34`. JSON records
`exit_code=2`, backend `kvm-x86-cpl0`. The syscall census records native nr 72
(`fcntl`, canonical 25) refused once, caller=root, allowlisted=false.
The direct `go run /tmp/hello.go` row separately has the same failure and exit 2.
This precedes ARM's #887 entry-binding fatal at fork/exec. Other census refusals
remain undiagnosed.

Source hypothesis: `crates/carrick-personality-linux/src/crossing.rs:302` on
that main declares Fcntl with x86=false. The descriptor family needs the shared
venue and exact authority; the missing venue/owner binding needs diagnosis.
No Carrick fix was attempted. Do not add a host replay for in-zone objects.

Evidence: `followup/direct/go-{version,run}.{command,out,err}` and the associated
`direct/census/` records, retained in the followup archive if packed. Product
SHA-256: `4fb38788da79ed8aefcea942cc45fc2ad4287d4a83dfe19a7e7cbdf3dbd76365`.
Source is unchanged from admitted main. KVM VM creation and the one-test CLI OCI
resolver witness passed. Docker is unavailable.

Acceptance: a red-first production x86 CPL0 witness serves Go's valid standard
descriptor fcntl check through shared descriptor authority; `go version` prints
its version on KVM. Preserve Linux EBADF for an actually closed descriptor.
