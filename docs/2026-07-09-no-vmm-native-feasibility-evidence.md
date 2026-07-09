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
