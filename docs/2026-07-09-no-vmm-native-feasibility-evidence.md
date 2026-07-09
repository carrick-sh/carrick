# No-VMM Native Feasibility Evidence

Date: 2026-07-09
Host: macOS Apple Silicon
Spec: docs/superpowers/specs/2026-07-09-no-vmm-direct-execution-design.md
Plan: docs/superpowers/plans/2026-07-09-no-vmm-native-feasibility-probes.md

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

## Verdict

verdict: blocked

The first failed gate is `page-size`, and the new `subpage-protect` probe adds direct evidence that Darwin does not supply the needed 4K-on-16K protection primitive here. On this host, the direct native design cannot honor Carrick's initial 4K Linux guest page-size contract without a measured mixed-page slow path or an explicit typed failure path; it must not route `linux4k` to HVF and it must not claim native execution is viable on 16K Darwin pages.

## Follow-up implementation evidence

Date: 2026-07-09

The runtime now has an explicit Darwin-native backend boundary. A request for
`--exec-backend=native --native-page-profile=linux4k` resolves to the native
Darwin plan for same-ISA `linux/arm64`, carries the selected
`Linux4kOn16k` geometry, and fails at the native backend launch boundary with an
unsupported diagnostic. That boundary is intentional: no HVF fallback is
attempted, and the message names the selected profile and page sizes.

The 4K-on-16K mapping policy is also explicit. The classifier allows only:

- uniform 16K host pages on the direct host fast path;
- private/composable data pages as `Composed16k`;
- data-only mixed permissions as `MixedGuarded`.

It rejects executable mixed pages because this build has no instruction
instrumentation for sub-16K executable permission enforcement, and it rejects
mixed shared-file backing until alias/writeback coherence exists. It also
rejects non-16K/4K geometries with a typed unsupported diagnostic.

Current focused verification:

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
