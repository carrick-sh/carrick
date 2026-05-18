# Debugging Carrick with lldb

This guide is for narrowing HVF / guest-execution bugs. It assumes you
have a working `cargo build --release` and macOS Hypervisor.framework
entitlements.

## One-liners

```sh
# Tier A — run the hello fixture and capture the trap stream:
CARRICK_TRACE_REGS=1 CARRICK_TRACE_MAPS=1 \
  ./target/release/carrick run-elf \
    fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-hello \
    --max-traps 8

# Tier B — run Alpine busybox with diagnostic trace:
./scripts/debug-tier-b.sh

# Tier B under lldb with breakpoints pre-armed:
./scripts/lldb-tier-b.sh busybox
```

## `carrick debug` and the lldb plugin

The CLI now exposes a `debug` subcommand for ad-hoc inspection that pairs
with the lldb Python plugin (`scripts/carrick_lldb.py`):

```sh
# Decode a syndrome on the command line (matches the lldb command exactly):
./target/release/carrick debug decode-esr 0x92000035

# Print the plugin path (for `command script import` from lldb):
./target/release/carrick debug lldb-plugin

# Pretty-print the JSON dump that `run --debug-state-path` produces:
./target/release/carrick debug inspect-state /tmp/carrick-debug-state.json
```

Run carrick with `--debug-state-path` to drop a JSON layout dump for the
plugin:

```sh
./target/release/carrick run docker.io/library/alpine:latest \
    --max-traps 30 \
    --debug-state-path /tmp/carrick-debug-state.json \
    /bin/busybox echo hello
```

Once the JSON is on disk, attach lldb (via `./scripts/lldb-tier-b.sh` or
hand-rolled) and use the `carrick` command from the plugin:

```
(lldb) carrick load-state /tmp/carrick-debug-state.json
(lldb) carrick info                       # summary
(lldb) carrick mappings                   # guest stage-2 regions
(lldb) carrick gva 0x80000c2ab4           # guest VA → region
(lldb) carrick decode-esr 0x92000035      # syndrome decoder
(lldb) carrick where                      # live host-side register summary
```

The plugin also auto-loads the JSON from
`$CARRICK_DEBUG_STATE_PATH`, `/tmp/carrick-debug-state.json`, or
`./carrick-debug-state.json` if any of those exist — so once you set
the env var, `carrick info` works without an explicit `load-state`.

## Trace knobs

Set in the environment of `carrick run` / `carrick run-elf`:

| Variable                | Effect                                                              |
|-------------------------|---------------------------------------------------------------------|
| `CARRICK_TRACE_REGS=1`  | At every syscall trap entry, dump `(pc, esr_el1, elr_el1, spsr_el1, sp_el0, far_el1, x0..x5, x8)` plus the HVF exit virtual/physical address. At every `complete_syscall` boundary, dump `(return_value, pc, elr_el1)`. |
| `CARRICK_TRACE_MAPS=1`  | At HVF VM setup, log every `(guest_start, mapped_size, payload_size, perms)` triple as it lands in stage-2. |
| `CARRICK_TRACE_TRAPS=1` | (older flag, runtime layer) — print every dispatched syscall before the dispatcher handles it. |

Pair with `--max-traps N` to cap how far you let the guest run. For
diagnosing an early-startup wall, start with `--max-traps 4` and bump up.

## lldb workflow

`scripts/lldb-tier-b.sh` wraps the release rebuild + entitlement re-sign
+ lldb launch:

```sh
./scripts/lldb-tier-b.sh hello       # debug a single static fixture
./scripts/lldb-tier-b.sh busybox     # debug the Tier B Alpine demo
./scripts/lldb-tier-b.sh -- <args>   # arbitrary `carrick` invocation
```

It sources `scripts/carrick.lldb`, which pre-arms:

- A breakpoint on `carrick::trap::HvfTrapEngine::run_until_syscall`
  (auto-continue — useful as a trace point if you turn auto-continue off).
- A breakpoint on `carrick::trap::hvf_error` — fires whenever HVF
  reports an error during VM/vCPU setup or mapping.
- Signal handlers for `SIGABRT` / `SIGSEGV` / `SIGBUS` set to stop.
- Breakpoints on `abort` and `__assert_rtn` — useful when HVF panics
  inside libsystem.

Convenience commands (loaded by `scripts/carrick.lldb`):

```
(lldb) carrick-regs        # all 31 GPRs + PC + SP
(lldb) carrick-bt          # backtrace, 24 frames
(lldb) carrick-mappings    # self.inner.mappings vector
(lldb) carrick-hvf-state   # combined PC/ELR/SPSR/FAR dump
```

## Attach-on-spawn (advanced)

If you want lldb to attach to a `carrick` child process spawned by a
parent test runner (e.g. cargo-test under HVF), use the Python helper
from `macos-vm-lldb-debug` skill:

```sh
python3 ~/.claude/skills/macos-vm-lldb-debug/scripts/attach_on_spawn.py \
    --child-name carrick \
    -- cargo test --release --test cli some_test
```

## Decoding ESR_EL1 syndromes

The `CARRICK_TRACE_REGS=1` output includes the live `ESR_EL1`. The
exception class field (bits 31:26) tells you what kind of fault you're
on:

| EC value | Meaning                                           |
|----------|---------------------------------------------------|
| `0x07`   | Trapped access to SVE/SIMD/FP — `CPACR_EL1.FPEN` is too restrictive |
| `0x15`   | SVC (real EL0 syscall, your dispatcher will see it) |
| `0x16`   | HVC (our vector stub bounced an exception into HVF — look at ESR_EL1's saved EC) |
| `0x20`   | Instruction abort from a lower EL — guest tried to fetch from an unmapped page |
| `0x24`   | Data abort from a lower EL — guest tried to read/write unmapped memory |
| `0x25`   | Data abort from same EL — likely vector handler reading its own page wrong |

For data aborts (`EC=0x24`), the bottom 6 bits of `ISS` give the DFSC
(Data Fault Status Code):

| DFSC value | Meaning                                            |
|------------|----------------------------------------------------|
| `0x04`     | Address size fault, level 0                        |
| `0x05`     | Translation fault, level 1                         |
| `0x07`     | Translation fault, level 3                         |
| `0x0D`     | Permission fault, level 1                          |
| `0x21`     | Alignment fault                                    |
| `0x30`     | TLB conflict abort                                 |
| `0x35`     | External abort on translation table walk, level 1  |
| `0x3D`     | External abort on translation table walk, level 1, with parity |

DFSC `0x35` (external abort on TT walk) typically means HVF couldn't
fetch the stage-2 page-table entry for the requested IPA. Likely
causes: the IPA is outside the configured `set_ipa_size` window, the
mapping was never created, or HVF rejected the underlying
`memory_create` size silently.

## Known gotchas

- **`cargo build --release` strips the codesignature.** Every rebuild
  needs `codesign --force --sign - --entitlements scripts/entitlements.plist
  target/release/carrick` before the binary can use Hypervisor.framework
  again. `scripts/debug-tier-b.sh` and `scripts/lldb-tier-b.sh` do this
  automatically.
- **`CARRICK_TRACE_REGS` reads sys regs via the applevisor crate.** This
  is fine for ESR_EL1 / FAR_EL1 / ELR_EL1 / SPSR_EL1, but values are
  consistent only between vCPU exits — don't trust them mid-step.
- **`FAR_EL1` is sticky across SVC traps.** SVC doesn't update `FAR_EL1`,
  so during a sequence of syscalls, `FAR_EL1` keeps whatever value the
  last data/instruction abort wrote. Cross-reference with `ESR_EL1`'s
  EC to know whether `FAR_EL1` is current.
- **Apple Silicon HVF stage-2 RW-only mappings can silently mis-translate
  on macOS 26.** We escalate RW→RWX in `src/trap.rs::hvf_perms` to work
  around this. If you find a region with `perms=r+w-x-` that still
  faults, that's the workaround failing — re-check.
- **`max_ipa_size()` is advertised at 40 bits on M-series; default IPA
  is 36.** We call `VirtualMachineConfig::set_ipa_size(max_ipa)` at VM
  init so guest IPAs up to ~1 TiB are mappable.
