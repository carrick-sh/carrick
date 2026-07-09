# Task 5 Report: Patchable Branch Gateway Probe

Status: DONE

Branch: `codex/architecture-evidence-gates`

## Scope

Implemented exactly Task 5 in the excluded `bench-native` crate:

- added the branch-gateway probe body to `bench-native/src/native_exec_probe/trap.rs`
- wired only `branch-gateway` from the stub arm to the real implementation in
  `bench-native/src/native_exec_probe/mod.rs`
- left `fault-discriminator` and `all` stubbed
- kept all changes out of production runtime / HVF / HAL / backend-selection code

## Implementation

The probe now:

1. reads the host page size with `sysconf(_SC_PAGESIZE)`
2. `mmap`s one RW anonymous page
3. encodes an AArch64 `b` from the page base to a gateway stub at `base + 64`
4. writes the branch instruction at offset 0
5. writes the gateway payload bytes for `mov w0, #77; ret`
6. clears the icache for the written region
7. flips the page to RX with `mprotect`
8. calls the page entry as `extern "C" fn() -> u32`
9. reports `pass` only when the returned value is `77`

The local `libc` crate in this checkout does not expose
`libc::sys_icache_invalidate`, so I used the probe-local C shim described in the
task brief:

- added `carrick_probe_clear_icache(void *start, size_t len)` to
  `bench-native/native_exec_probe/ucontext_arm64.c`
- included `<libkern/OSCacheControl.h>` there
- called the shim from Rust with the same pointer and length

## Red -> Green evidence

Red, before the change:

```sh
cargo run --manifest-path bench-native/Cargo.toml --bin native_exec_probe -- branch-gateway
```

Observed result:

```text
native_exec_probe: branch-gateway probe is implemented in Task 5
```

Green, after the change and after focused formatting:

```sh
cargo run --manifest-path bench-native/Cargo.toml --bin native_exec_probe -- branch-gateway
```

Observed result:

```text
probe=branch-gateway status=pass return=77 branch_word=0x14000010
```

## Formatting

Ran focused formatting for the excluded crate:

```sh
cargo fmt --manifest-path bench-native/Cargo.toml
```

## Files changed

- `bench-native/native_exec_probe/ucontext_arm64.c`
- `bench-native/src/native_exec_probe/mod.rs`
- `bench-native/src/native_exec_probe/trap.rs`
- `.superpowers/sdd/task-5-report.md`

## Notes / concerns

- The existing `bench-native` native static archive was stale on the first local
  green attempt, so the first build after adding the C shim still linked the old
  object archive and missed `_carrick_probe_clear_icache`. A local
  `cargo clean --manifest-path bench-native/Cargo.toml` fixed that and the next
  acceptance run passed. A fresh checkout/build should not have that stale-archive
  issue.
- This task intentionally does not implement `fault-discriminator` or `all`.
