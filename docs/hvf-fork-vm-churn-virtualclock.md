# HVF Virtual-Clock And LTP kill10

Status: **fixed in the runtime; pacing workaround removed**.
Owner areas:

- `crates/carrick-hvf/src/trap.rs`: HVF VM creation and fork rebuild.
- `crates/carrick-hvf/src/host_signal.rs`: host signal masks and pending signal
  capture.
- `crates/carrick-runtime/src/namespace/pid.rs`: pid namespace publication.
- `crates/carrick-runtime/src/dispatch/signal.rs`: cross-process signal sender
  identity.

This note records the publish-safe diagnosis. We did not need Ghidra or private
HVF reverse engineering for the final fix; public Hypervisor API behavior,
process samples/backtraces, and Carrick's own runtime invariants were enough.

## LTP Contract

The failing LTP case is `kill10` from the pinned LTP `20240930` source. It builds
one master, two manager process groups by default, and ten children per manager.
The master sends `SIGUSR1` to each manager process group. Children then repeatedly
send `SIGUSR2` to their manager with `kill(getppid(), SIGUSR2)` until the manager
replies with `SIGUSR2`.

The manager's `SIGUSR2` handler is `SA_SIGINFO` and validates
`siginfo_t.si_pid` against the manager's fork checklist. `si_pid == 0` is always
wrong for that handler: Linux should report the child pid that sent the signal.

## What Was Ruled Out

The original symptom looked like an HVF VM-churn bug: under fork storms, samples
and lldb showed Apple's private `com.apple.virtualization.thread.virtual-clock`
thread involved while Carrick processes were wedged. That made a pacing or
"parent keeps VM" mitigation tempting.

Empirical public-API probes did not support a plain VM-churn explanation:

- A standalone Rust HVF reducer using `applevisor-sys` could repeatedly create,
  run, destroy, fork, and recreate VMs without reproducing the failure.
- Adding a live vCPU run loop to the reducer still did not reproduce.
- Flooding a single HVF process with host signals was also stable.
- The `CARRICK_FORK_PARENT_KEEPS_VM` prototype was falsified: a child forked
  while the parent kept a live VM could not clear the inherited state. Child-side
  HVF destroy calls reported `HV_NO_DEVICE`, and `hv_vm_create` still returned
  `HV_BUSY`.

So the parent-keeps prototype and default pacing were discarded. The runtime now
uses the normal symmetric fork teardown/rebuild path without sleeps.

## Root Causes

There were three real bugs in the path to conformance.

### 1. HVF Private Threads Inherited Carrick Guest Signal Handling

The live `kill10` catch showed HVF's private virtual-clock thread running through
Carrick's routed host signal handler. That is not a Carrick guest vCPU, and it
must not receive guest-routed asynchronous signals.

Fix: wrap every `VirtualMachine::with_config(...)` call in a guard that blocks
Carrick guest-routed host signals while HVF creates private helper threads, then
restore Carrick's thread mask immediately after VM creation. Synchronous host
fault/assertion signals, `SIGKILL`, `SIGSTOP`, `SIGCHLD`, and `SIGPIPE` are not
masked.

### 2. Namespace Member Publication Exposed Half-Filled Slots

`NsSharedRegion::register()` claimed a slot by publishing `host_pid` first, then
stored `ns_pid`. Readers scan `host_pid` with Acquire and then read `ns_pid`, so
a concurrent signal delivery could translate a real child host pid to namespace
pid `0`.

Fix: claim a slot with an unpublished sentinel, fill `ns_pid`,
`parent_host_pid`, `exit_status`, and `flags`, then release-store the real
`host_pid` last. Forward and reverse lookups, orphan marking, and supervisor
scans skip the sentinel.

### 3. Cross-Process kill() Sender Identity Used A Lossy Host Side Channel

For ordinary cross-process standard signals, Carrick used host `kill()` and then
later synthesized Linux `siginfo_t` from a per-signum "last sender host pid"
recorded by the host signal handler. Under `kill10`'s signal flood that side
channel still produced `si_pid=0` intermittently.

Fix: for positive targets known to be members of Carrick's private pid
namespace, route catchable standard signals through Carrick's existing xsignal
ring. The ring carries sender namespace pid and uid directly. Process-group
signals and non-namespace/external host targets still use host `kill()`.

Standard signals may coalesce on ring overflow; real-time signals remain on the
existing queued xsignal path and are not treated as coalescible.

## Current Verification

Focused runtime checks:

- `cargo test -p carrick-runtime namespace_member_xsig_policy_routes_catchable_standard_signals -- --nocapture`
- `cargo test -p carrick-runtime namespace::pid::tests -- --nocapture`
- `cargo test -p carrick-hvf hvf_private_signal_mask_guard_restores_current_thread_mask -- --nocapture`
- `cargo check -p carrick-runtime -p carrick-hvf`
- `./scripts/build-signed.sh`

Direct LTP stress:

- 40/40 direct `kill10` attempts passed with no pacing code present.

Harness gate:

- `CARRICK_INSECURE_REGISTRIES=localhost:5050 target/release/carrick-conformance --suite ltp-kill10 --no-image-refresh`
- Result: `OK: no regressions`

Adjacent probe checks:

- `forksleepfork`
- `sigpairrace`
- `xprocsigign`
- `siginfo`
- `killtarget`
- `killgroup`
- `killrt`
- `killchld`

All matched Docker Linux.
