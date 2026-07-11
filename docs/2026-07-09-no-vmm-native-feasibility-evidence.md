# No-VMM Native Feasibility Evidence

Date: 2026-07-09
Host: macOS Apple Silicon
Spec: docs/superpowers/specs/2026-07-09-no-vmm-direct-execution-design.md
Plan: docs/superpowers/plans/2026-07-09-no-vmm-native-feasibility-probes.md

## Current Status

Updated: 2026-07-10

Current verdict: **`native16k` is viable as an experimental same-ISA native
backend; `linux4k` is an explicit, incomplete compatibility profile.** The
original page-size probe below correctly disproved direct 4K protection on a
16K Darwin host. It did not disprove a 16K-native profile or a guarded 4K
compatibility path.

The latest full native campaign measured:

```text
native16k musl gating:       355/374 PASS (94.9%), 19 gaps
native16k glibc report-only: 348/374 PASS, 26 gaps
native16k strict LTP parity: 829/1492 suites (55.6%)
```

The LTP percentage is deliberately conservative: each counted suite exercised
at least one assertion, had no Carrick failure or broken assertion, and matched
a likewise-clean Docker arm64 result. Raw differential parity was 1318/1492,
but that includes equal failures and unexercised cases.

`native16k` is the preferred profile and executes guest memory instructions
directly with 16K page geometry. `linux4k` presents 4K Linux geometry on the
16K host and uses a guarded slow path for a bounded set of mixed-page data
accesses. It may reject mixed executable pages, mixed shared-file aliases, or
unsupported guarded AArch64 instructions. Neither profile silently falls back
to HVF.

## Command

```sh
cargo run --manifest-path bench-native/Cargo.toml --bin native_exec_probe -- all
```

## Output

```text
probe=page-size status=fail host_page_size=16384 linux_guest_page_size=4096
probe=fixed-map status=pass addr=0x700000000000 len=16384 child_exit=0
probe=subpage-protect status=fail host_page_size=16384 child_exit=93 meaning=mprotect_rejected_subpage_range
probe=execmem status=pass mode=rw-to-rx return=42
probe=brk-trap status=pass child_exit=0
probe=branch-gateway status=pass return=77 branch_word=0x14000010
probe=fault-discriminator status=pass guest_fault_exit=90 host_fault_exit=91
```

## Gate Interpretation

- `page-size`: blocked. This host reports 16K Darwin pages, so the initial 4K Linux guest page-size contract cannot be represented directly by the native design as written.
- `fixed-map`: pass. A child process reserved the planned guest window at a fixed address and exited cleanly.
- `subpage-protect`: blocked. On this 16K-page Darwin host, `mprotect(ptr+4096, 4096, PROT_NONE)` in the probe child did not produce exact 4K protection or a widened observable fault. Darwin rejected the subpage request outright (`child_exit=93`, `meaning=mprotect_rejected_subpage_range`). That is still load-bearing evidence: exact Linux 4K behavior on 16K host pages cannot rely on metadata-only tracking, and mixed pages need either a measured slow path or a typed failure.
- `execmem`: pass. Same-ISA code written by Rust executed after an RW-to-RX transition and returned the expected value.
- `brk-trap`: pass. Darwin signal/ucontext delivery exposed enough register state for the probe child to complete and exit cleanly.
- `branch-gateway`: pass. The patched AArch64 branch island redirected execution to the gateway and produced the expected return value.
- `fault-discriminator`: pass. Process-local state distinguished guest-window and host faults by exit code in the probe child.

## Initial Verdict

verdict: blocked for direct `linux4k`; not blocked for `native16k`

The first failed gate was `page-size`, and the `subpage-protect` probe added
direct evidence that Darwin does not supply a 4K-on-16K protection primitive.
That blocks a design which directly applies 4K Linux protections to host
memory. The subsequent implementation split the problem into a direct
`native16k` profile and an explicit guarded `linux4k` compatibility profile.
The runtime must not widen unsupported 4K permissions or route `linux4k` to
HVF.

## Follow-up implementation evidence

Date: 2026-07-09

The runtime now has an explicit Darwin-native backend boundary. Requests for
`--exec-backend=native` resolve only for same-ISA `linux/arm64` and retain the
selected page profile through image loading, syscall dispatch, and fault
handling. `native16k` uses direct host mappings. `linux4k` carries
`Linux4kOn16k` geometry into the guarded mixed-page bridge. Unsupported cases
return a typed native diagnostic; no HVF fallback is attempted.

The 4K-on-16K mapping policy is also explicit. The classifier allows only:

- uniform 16K host pages on the direct host fast path;
- private/composable data pages as `Composed16k`;
- data-only mixed permissions as `MixedGuarded`.

It rejects executable mixed pages because this build has no instruction
instrumentation for sub-16K executable permission enforcement, and it rejects
mixed shared-file backing until alias/writeback coherence exists. It also
rejects non-16K/4K geometries with a typed unsupported diagnostic.

Initial focused verification (2026-07-09):

```text
$ cargo test -p carrick-runtime --test integration tty_ioctls_handle_pgrp_sid_and_controlling_terminal_calls
test syscall_fs_open::tty_ioctls_handle_pgrp_sid_and_controlling_terminal_calls ... ok
test result: ok. 1 passed; 0 failed; 295 filtered out

$ cargo test -p carrick-runtime --test integration tty_ioctls_handle_pgrp_sid_and_controlling_terminal_calls
# same command run from a PTY-backed harness
test syscall_fs_open::tty_ioctls_handle_pgrp_sid_and_controlling_terminal_calls ... ok
test result: ok. 1 passed; 0 failed; 295 filtered out

$ cargo test -p carrick-runtime --test integration real_tty
test syscall_fs_open::tiocgpgrp_on_real_tty_uses_host_value_not_bootstrap ... ok
test syscall_fs_open::tiocspgrp_on_real_tty_calls_host_not_fake ... ok
test syscall_fs_open::tiocgsid_on_real_tty_uses_host_value_not_bootstrap ... ok
test result: ok. 3 passed; 0 failed; 293 filtered out

$ cargo test -p carrick-runtime explicit_native_linux4k_reaches_darwin_native_backend_boundary --lib
test execute::exit_code_tests::explicit_native_linux4k_reaches_darwin_native_backend_boundary ... ok
test result: ok. 1 passed; 0 failed; 555 filtered out

$ cargo test -p carrick-runtime page_profile::tests::linux4k_policy --lib
test page_profile::tests::linux4k_policy_allows_composed_private_data_pages ... ok
test page_profile::tests::linux4k_policy_allows_guarded_data_permissions ... ok
test page_profile::tests::linux4k_policy_rejects_composed_shared_file_pages_with_diagnostic ... ok
test page_profile::tests::linux4k_policy_rejects_mixed_executable_pages_with_diagnostic ... ok
test page_profile::tests::linux4k_policy_rejects_unsupported_geometry_with_diagnostic ... ok
test result: ok. 5 passed; 0 failed; 551 filtered out
```

Current probe confirmation:

```text
$ cargo run --manifest-path bench-native/Cargo.toml --bin native_exec_probe -- subpage-protect
native_exec_probe: native execution feasibility probe failed
probe=subpage-protect status=fail host_page_size=16384 child_exit=93 meaning=mprotect_rejected_subpage_range
```

Remaining blocker: executable 4K-on-16K mixed pages still require a real
enforcement mechanism, such as guarded mixed pages with enough AArch64
load/store emulation or explicit code instrumentation. Until that exists, the
native backend must continue rejecting those mappings instead of widening them
to 16K host permissions.

## Address-layout and conformance campaign evidence

Date: 2026-07-09

Current XNU source makes a second compatibility boundary explicit: an arm64
64-bit Mach-O must reserve a hard 4 GiB `__PAGEZERO`. A forked host test also
confirmed that deallocating a low subrange does not permit a later fixed mapping
there. The native backend rejects any image with a required mapped region below
`0x1_0000_0000`. PIE/`ET_DYN` is the practical supported path, although a
high-address `ET_EXEC` image can work; an incompatible low-address image needs
PIE or an address-virtualizing backend.

The native conformance campaign now builds Linux-valid AArch64 PIE artifacts.
For musl, Rust's self-contained non-PIE startup selection is disabled and the
system compiler driver selects musl `rcrt1.o` with `-static-pie`; Rust's bundled
static library directory remains on the link path. The builder verifies
`ET_DYN` and executes a smoke probe inside Linux before accepting the campaign.
This distinction matters: forcing `-pie` onto the ordinary static CRT produced
an ELF that Carrick's eager relocator could run but real Linux correctly
crashed.

Focused byte-identical proof:

```text
Linux arm64: devnullseek static PIE -> exit 0
native16k:   devnullseek static PIE -> exit 0, output matches Linux
linux4k:     devnullseek static PIE -> exit 0, output matches Linux
```

Static musl probes are bind-mounted into the requested OCI image and executed
as the container command. They do not pass through the image's glibc `/bin/sh`,
`base64`, or `chmod`; that bootstrap path corrupted dynamic-loader state under
`linux4k` before many static probes started. The bind transport preserves the
image rootfs while keeping the probe itself as the first guest ELF. Docker still
runs the byte-identical artifact as the independent Linux oracle.

Initial matched-transport probe baselines (2026-07-09):

```text
native16k musl gating:       277/373 MATCH, 96 semantic gaps
native16k glibc report-only: 273/374 MATCH, 101 semantic gaps
linux4k musl gating:         266/373 MATCH, 107 semantic gaps
linux4k glibc report-only:     0/374 MATCH, 374 loader/runtime gaps
amd64:                         skipped because native is same-ISA only
```

The campaign then ran every gating probe instead of failing at image mapping.
Of those 96 initial `native16k` failures, 45 terminated at the native backend's
missing `CloneThread` outcome. At that time, fourteen failures were
`linux4k`-only and three were `native16k`-only. The remaining shared gaps were
signal/process lifecycle, ptrace, vDSO, and other runtime semantics; they were
not page-zero or linker failures.

## Current Conformance Evidence

The 2026-07-10 round-5 native16k campaign used 420 static-musl PIE probes and
420 glibc PIE probes. Carrick ran every selected case before any live Docker
cache miss; classification ran after both execution phases. The authoritative
results are:

```text
musl gating:       355/374 PASS (94.9%)
glibc report-only: 348/374 PASS
```

The 19 musl gaps are:

```text
accounting childsubreaper clone3args execthreads forkfpreclaim
getrandomvdso getrandomvdsofork getrandomvdsoloop itimer keydeny
ltpcheckpointexec memmap mprotectexec pidnsroot sigchld sigwaitalarm
sysvsem vdsosymbols waitidcputime
```

An exhaustive native16k LTP run selected all 1492 full-tier manifest suites.
It produced 1318 raw Docker-parity verdicts and 829 strict clean matches
(55.6%). Five cases timed out. The strict count excludes both-side failures,
broken setup, and cases that exercised no assertions.

References:

- XNU arm64 Mach-O page-zero validation:
  https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/mach_loader.c#L3700-L3760
- Rust relocation-model and static PIE selection:
  https://doc.rust-lang.org/rustc/codegen-options/index.html#relocation-model
- Rust target option for static position-independent executables:
  https://doc.rust-lang.org/stable/nightly-rustc/rustc_target/spec/struct.TargetOptions.html#structfield.static_position_independent_executables
