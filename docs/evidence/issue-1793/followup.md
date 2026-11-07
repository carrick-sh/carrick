# KVM launch diagnosis and direct ecosystem attempts

The blanket launch failure is narrowed: Alpine `/bin/echo hi` passes on real
KVM. BusyBox (the public glibc variant) reaches CPL0 and exits 127. Direct Go
reaches its runtime but exits 2 on a standard-descriptor `fcntl` check. Dynamic
Python startup fails before any Python code runs. Node's version attempt times
out during setup, and its child-process attempt is rejected before boot by the
carrier's initial-image memory budget. These are earlier, different
observations from ARM's fork/exec fatal, Python exit crash, and V8 code-range
failure. They do **not** establish that #887 is HVF-only: its trigger remains
unreached on x86.

This continues the [original blocked report](README.md), preserving its raw
attempts and limits. No Carrick implementation was changed or fixed here.

All fresh raw evidence is stored byte-for-byte in
[followup.tar.gz](followup.tar.gz). Paths such as `identity.txt`, `direct/`,
`minimal/`, `images/` and `*.log` below are relative to its `followup/` directory.
For example:

```sh
mkdir -p /tmp/carrick-1793-evidence
tar -xzf docs/evidence/issue-1793/followup.tar.gz -C /tmp/carrick-1793-evidence
cat /tmp/carrick-1793-evidence/followup/direct/status.tsv
```

The archive was compared against the original loose files before packing them
away; earlier workers' loose evidence stays in place unchanged.

## Artifact and method

Both earlier commits were preserved; rebasing onto admitted main reported
already up to date. The followup product was rebuilt using exactly:

```sh
cargo build -p carrick-cli --no-default-features --features platform-linux --release
```

The product SHA-256 is
`4fb38788da79ed8aefcea942cc45fc2ad4287d4a83dfe19a7e7cbdf3dbd76365`.
This differs from the prior runner's binary. `identity.txt` records the new
host, successful real KVM API/VM creation and no source/Cargo diff against
`71c57e106688ba954a5a9947c9868f8a92160660`. The product was restored after
building the test target; its digest remained the same.

Every build and live run reused the job's inherited VM-local gate lease through
`just lease gate`; `CARRICK_REQUIRE_KVM=1` was set for guest runs. Public image
pulls were separate, all successful; their identities/configs/manifests are
retained. No Docker ran alongside Carrick.

The [diagnostic runner](launch-diagnostics.sh) bounds every CLI attempt to
120 seconds, captures both streams, enables `RUST_LOG=carrick=debug`, assigns
run IDs, collects a terminal syscall census, and runs scoped cleanup.
Known answers demonstrate exit 7 and separate stdout/stderr capture, and a
one-second timeout returns 137. The runner is an ad hoc investigation, not a
new conformance gate. Its elapsed column includes observation sleeps and debug
capture attempts, so it is **not** a precise runtime or performance comparison.

The fresh ecosystem run invokes the actual executable with `--entrypoint`,
bypassing the glibc shell which blocked the prior harness. `go run` receives
the same hello-world through a read-only bind mount; it needs no shell to
write the source. Each row is a single attempt, with no retry-until-green.
JSON output is supplemental: guest output can precede the JSON, and its
`stdout`/`stderr` fields alone do not capture all streamed guest output.

## Results compared with ARM

ARM reference: the [retained owner scoreboard](arm-baseline.md) at the same
admitted main. “Not measured” means the requested language operation never
ran, even though its startup failure was measured.

| Workload | KVM result / CLI exit | First error or observation | Comparison with ARM |
|---|---|---|---|
| Go `go version` | FAIL / 2 | `runtime: unexpected error while checking standard file descriptor 0, errno=38` | Different: ARM prints version; KVM dies during `runtime.checkfds`. |
| Go `go run hello.go` | FAIL / 2; build/fork not measured | Same Go startup error | Different first failure: no #887 `entry_binding` reason or `at=` location. |
| CPython start | FAIL at loader / 127; Python not measured | Empty stderr; census refuses `mmap`, `writev`, `readlinkat` | Different: ARM starts successfully. |
| CPython thread | FAIL at loader / 127; thread not measured | Empty stderr; inspect matching census | Different: ARM prints `thread-ok`. |
| CPython `os.fork()` | FAIL at loader / 127; fork not measured | Empty stderr; inspect matching census | Different first failure: ARM produces output then exit SIGSEGV (#1733). |
| CPython subprocess | FAIL at loader / 127; subprocess not measured | Empty stderr; inspect matching census | Different first failure: ARM produces output then exit SIGSEGV (#1733). |
| Node version | Not measured / 137 (120-second deadline) | Empty streams; sampled layer-cache extraction before boot | Cannot compare V8 or #887: no guest execution witness. |
| Node child process | FAIL before boot / 125; JavaScript not measured | `carrick: filesystem backend error: failed to run x86 image: trap engine failed: hypervisor operation failed: initial image exceeds carrier memory budget` | Different: #1715, before ARM's V8 code-range failure (#1791). |

Each case's `*.command`, `*.out`, `*.err`, census and cleanup are retained with
its run ID in `direct/status.tsv`. The earlier eight rows remain **not measured**
as originally reported; these direct attempts do not retroactively change them.

## What the diagnostics establish

Alpine prints `hi`, exit 0, with backend `kvm-x86-cpl0` and ten guest entries.
BusyBox exits 127 after 27 guest entries and a `root_exit` physical crossing.
This proves its 127 is after carrier boot and guest execution, not image pull
or Carrick's pre-entrypoint “not found” classification. Its terminal census
records one refused native mmap (9) and writev (20). Python similarly has a
CPL0 execution witness and root-exit receipt. The empty streams alone did not
prove this; the JSON and census do.

Existing open issues cover the loader gaps: [#1722](https://github.com/carrick-sh/carrick/issues/1722)
(x86 fd-backed MAP_PRIVATE) and [#1756](https://github.com/carrick-sh/carrick/issues/1756)
(x86 IPC venue, including refused writev diagnostics). #1714 tracks the broader
loader bring-up. BusyBox's config explicitly identifies a glibc image. The
observed refusal populations match those issues; exact loader error text cannot
be recovered from a refused writev in this run. No duplicate issue was filed.

Node's `initial image exceeds carrier memory budget` is already tracked in
[#1715](https://github.com/carrick-sh/carrick/issues/1715). The exact error is
emitted by `Cpl0Carrier::initial_extent_bytes_for` in
`crates/carrick-vmm-kvm/src/cpl0_boot.rs`, before the image can boot. No duplicate
issue or budget increase was made. The prior Node version timeout is not
silently relabelled as this later error; it retained empty streams.

Go's census identifies refused native fcntl 72 (canonical 25), and the bundled
Go source `runtime/fds_unix.go` confirms `checkfds` calls
`fcntl(fd, F_GETFD, 0)`. The missing shared x86 descriptor venue/authority needs
diagnosis. A search found no matching root-startup issue. Issue creation was
attempted but the integration returned HTTP 403, `Resource not accessible by
integration`; [the unpublished defect draft](go-startup-issue.md) includes the
command, error, artifact and acceptance criterion. No issue number is claimed.

Public pulls completed before the ecosystem attempts. Python setup snapshots
show a cached layer source and a scratch destination simultaneously open at
`usr/libexec/gcc/x86_64-linux-gnu/14/cc1plus`, blocked in
`balance_dirty_pages`, with no KVM descriptors yet. This locates that sampled
delay in prelaunch rootfs copying. Later Go snapshots already have Go's fatal
output and terminal JSON, no live debug endpoint/KVM fd, and continuing host
filesystem I/O: a live CLI alone is not proof the guest remains running.
Node version reached its 120-second deadline with empty streams. Its setup
snapshots show a compressed blob open alongside a `.carrick-layer-cache/.building-*`
directory, no KVM descriptor and no debug socket: its sampled delay is first
layer-cache extraction, rather than boot. Python's later cached-tree copy is
a separate observed setup cost. The whole deadline cannot be attributed from
the early snapshots alone. No throughput ratio or new rootfs defect is asserted
without an oracle. Clippy compilation overlapped the later Node setup attempts;
these are correctness/startup diagnostics, not a quiet-host performance claim.

## Existing KVM OCI coverage and checks

`crates/carrick-cli/tests/x86_kvm_run.rs` contains
`image_path_and_shebang_entrypoints_use_the_shared_resolver`: a real KVM test
that loads a local OCI archive and exercises PATH, shebang rewriting and a
synthetic PT_INTERP loader. It passed on this clone: **1 passed, 0 failed,
0 ignored, 85 filtered out**. It does not launch a public glibc image or test
real shared-library mmap startup. KVM's lower-level carrier tests use ELF or
instruction fixtures; this focused CLI witness is the pertinent OCI boundary.
The full `just test-kvm` gate was not run, so #1794 is not claimed resolved.

The contract-change check against admitted main and source-only authority-debt
check passed (1266 counters). Formatting, shell syntax, and the required
pre-push hook (`sh .githooks/pre-push`, running `just clippy`) passed too.
Clippy retained a Linux warning about the pre-existing macOS-only
`libc::proc_listallpids` entry in `clippy.toml`; the hook exited 0.
Each fresh run's scoped cleanup reports zero remaining matching processes;
the timeout waiter survived and reaped its direct child. This does not repair
the earlier worker's documented reaping gap or assert a global zombie census.
No Rust crate or macOS/KVM/HAL implementation was
changed, so crate regular/serial partitions, cross-check-macos and check-linux
are not change-required gates. The focused live CLI test above was run to
answer the brief. Whole-workspace lint/kernel gates remain for CI. Docker and
HVF are unavailable on this Linux clone; no oracle or signed verdict is claimed.
