# Native page profile design

Date: 2026-07-09

## Summary

The no-VMM Darwin-native execution lane should support two page profiles:

- `native`: Linux-visible page size equals the host-native Darwin page size.
  On Apple Silicon Macs today this is 16 KiB. This is the preferred direct
  native path because Darwin VM protections, mapping granularity, and guest
  visible page size agree.
- `linux4k`: Linux-visible page size is 4 KiB. This is the compatibility path
  for ordinary 4K-shaped Linux containers and binaries.

The key decision is that `linux4k` is an exact compatibility requirement, not an
approximation. On a 16K-page Darwin host, exact `linux4k` cannot be implemented
by the direct native backend with ordinary `mmap`/`mprotect` plus signal
handlers alone. A disallowed 4K subpage access inside a readable 16K host page
would not fault, so Carrick would miss the violation. Therefore the first
`linux4k` implementation for macOS remains the existing HVF backend. A future
direct-native 4K profile would require a separate proof mechanism such as DBT
or comprehensive memory-access instrumentation.

This still satisfies the product direction: prefer no-VMM native execution with
16K pages when the image can run in that profile, and support 4K containers by
falling back to an exact 4K backend instead of silently widening semantics.

## Source-backed facts

- Linux exposes runtime page size through `_SC_PAGESIZE` / `_SC_PAGE_SIZE`, and
  Linux/arm64 can be built with different page sizes. Android documents
  arm64 16K kernels via `CONFIG_ARM64_16K_PAGES` instead of
  `CONFIG_ARM64_4K_PAGES`.
- Apple tells native Apple Silicon applications to read page size dynamically,
  and notes that Rosetta matches the Intel environment, including 4K pages for
  translated processes. That does not give a public 4K-page mode for native
  arm64 processes.
- `mprotect` changes protections for whole pages containing the requested
  range. On Darwin, the page granularity is the host kernel's page granularity.

References:

- Apple WWDC20, "Port your Mac app to Apple silicon":
  https://developer.apple.com/videos/play/wwdc2020/10214/
- AOSP, "16 KB page size":
  https://source.android.com/docs/core/architecture/16kb-page-size/16kb
- Android Developers, "Support 16 KB page sizes":
  https://developer.android.com/guide/practices/page-sizes
- Linux `sysconf(3)`:
  https://man7.org/linux/man-pages/man3/sysconf.3.html
- Apple `mprotect(2)` man page:
  https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/mprotect.2.html

## Goals

- Prefer direct native execution with 16K pages when it is compatible with the
  image and requested runtime semantics.
- Preserve exact Linux 4K behavior for containers that need it.
- Make page size an explicit runtime profile instead of a hidden backend
  assumption.
- Avoid silently exposing 16K semantics to a 4K-shaped container.
- Keep HVF as the release-quality 4K compatibility path on macOS.
- Keep the native backend trusted-code-only and experimental.

## Non-goals

- Do not claim direct native Darwin can provide exact 4K page protections on a
  16K host without another enforcement mechanism.
- Do not emulate arbitrary guest memory reads and writes from Darwin signal
  handlers.
- Do not switch the default macOS backend away from HVF for existing containers.
- Do not use Rosetta to solve `linux/arm64` direct native page size. Rosetta is
  relevant to translated x86 processes, not same-ISA native arm64 execution.
- Do not make 16K compatibility a global statement about a whole distribution
  unless every startup object and runtime mapping policy is covered.

## Page profile vocabulary

Carrick should introduce a page-profile concept at the execution-policy level:

```rust
enum NativePageProfile {
    NativeHost,
    Linux4kExact,
}
```

`NativeHost` means:

- guest-visible page size equals `host_page_size`;
- `AT_PAGESZ`, `sysconf(_SC_PAGESIZE)`, and Carrick's Linux page-size reporting
  surface the host page size;
- `mmap`, `munmap`, `mprotect`, guard pages, executable mappings, and fault
  classification are performed at host page granularity;
- on current Apple Silicon hosts, the expected profile is 16 KiB.

`Linux4kExact` means:

- guest-visible page size is exactly 4096;
- 4K Linux `mmap`, `munmap`, `mprotect`, guard-page, `SIGSEGV`, and `SIGBUS`
  behavior must be preserved;
- on Darwin native execution with 16K host pages, this profile resolves to HVF
  until a separate direct-native enforcement mechanism is proved.

The name should avoid implying that the fallback is less Linux-like. For a
4K-shaped container, `Linux4kExact` is the correct Linux behavior.

## User-facing policy

The CLI should separate execution backend selection from page profile selection:

```text
--exec-backend=auto|hvf|native
--native-page-profile=auto|native|linux4k
```

Environment equivalents:

```text
CARRICK_EXEC_BACKEND=auto|hvf|native
CARRICK_NATIVE_PAGE_PROFILE=auto|native|linux4k
```

Policy matrix:

| Backend | Page profile | Behavior |
|---|---|---|
| `auto` | `auto` | Prefer direct native with `NativeHost` when compatibility checks pass; otherwise use HVF with `Linux4kExact`. |
| `auto` | `native` | Use direct native `NativeHost` if compatibility checks pass; otherwise fail with a page-profile diagnostic. |
| `auto` | `linux4k` | Use HVF on macOS unless a future exact direct-native 4K profile exists. |
| `native` | `auto` | Use direct native `NativeHost` if compatibility checks pass; otherwise fail. Do not silently fall back to HVF after the user explicitly requested native. |
| `native` | `native` | Force direct native `NativeHost`; fail on incompatible image or runtime mapping request. |
| `native` | `linux4k` | Fail on 16K Darwin hosts with a diagnostic that exact 4K direct native is unavailable. |
| `hvf` | any | Use HVF. `native` profile is rejected because HVF is not the native page-profile experiment. |

Diagnostics should name the first failed reason:

```text
native page profile rejected: PT_LOAD alignment 4096 is smaller than host page size 16384
native page profile rejected: guest mprotect requested 4K-granular permissions inside one 16K host page
linux4k exact profile selected: using hvf backend on darwin
```

## Compatibility classifier

`auto` needs a conservative classifier. It should prefer native 16K only when
Carrick can prove enough compatibility before starting guest execution.

Inputs:

- host page size from `sysconf(_SC_PAGESIZE)` or `vm_page_size`;
- requested platform, initially only `linux/arm64`;
- main ELF `PT_LOAD` alignment and virtual-address/file-offset congruence;
- `PT_INTERP` loader ELF alignment when present;
- statically discoverable startup shared objects when Carrick can safely resolve
  them from the image rootfs;
- explicit image or run configuration labels;
- user override flags.

Initial labels:

```text
sh.carrick.native-page-profile=native
sh.carrick.native-page-profile=linux4k
```

Classifier outcomes:

```rust
enum PageProfileDecision {
    NativeHost { host_page_size: usize, evidence: Vec<PageProfileEvidence> },
    Linux4kExact { reason: PageProfileRejectReason },
    Reject { reason: PageProfileRejectReason },
}
```

The classifier should be conservative:

- If every required startup object is host-page aligned and no 4K-only mapping
  requirement is visible, `auto` may choose `NativeHost`.
- If any startup object has a smaller required alignment than the host page
  size, `auto` chooses `Linux4kExact`.
- If the classifier cannot inspect a required startup object, `auto` chooses
  `Linux4kExact` unless the user explicitly requests `native`.
- If a runtime `mmap` or `mprotect` request later proves incompatible with
  `NativeHost`, direct native fails the run with a clear diagnostic. It must not
  widen protections silently.

## NativeHost semantics

In `NativeHost` mode, Carrick presents a Linux personality whose page size is
the host page size.

Required behavior:

- Auxv `AT_PAGESZ` equals `host_page_size`.
- Linux `sysconf(_SC_PAGESIZE)` / `getpagesize()` emulation returns
  `host_page_size`.
- Anonymous `mmap` length and placement are rounded as Linux would round for a
  kernel with that page size.
- `munmap` and `mprotect` require host-page-compatible ranges.
- File-backed mappings honor host-page alignment and reject mappings that would
  need smaller-granularity protection or fault behavior.
- Fault reports and signal delivery use host-page granularity.

This is not "4K Linux but faster." It is a Linux page-size profile analogous to
running on a 16K-page arm64 Linux kernel. The compatibility promise is therefore
limited to binaries and containers that tolerate that profile.

## Linux4kExact semantics

In `Linux4kExact` mode, Carrick preserves the current common Linux container
contract:

- Auxv `AT_PAGESZ` is 4096.
- Linux page-size syscalls and libc-facing values report 4096.
- `mmap`, `munmap`, and `mprotect` operate at 4K granularity.
- Adjacent 4K subpages inside the same 16K host page may have different Linux
  permissions.
- Invalid 4K subpage accesses produce the correct Linux fault behavior.
- File-backed mappings, partial unmaps, guard pages, stack growth, and
  SIGBUS-past-EOF behavior remain 4K-shaped.

On macOS/Apple Silicon, exact `Linux4kExact` support should route to HVF. The
existing HVF path already gives Carrick a guest page-table world with 4K Linux
semantics independent of the host page size.

## Why direct-native 4K is not phase-1

A metadata-only 4K subpage map is not sufficient.

Example:

```text
Darwin host page: 0x10000..0x13fff, host page size 16K
Linux subpages:
  0x10000..0x10fff  PROT_READ
  0x11000..0x11fff  PROT_NONE
  0x12000..0x12fff  PROT_READ
  0x13000..0x13fff  PROT_READ
```

If the host page remains readable so the three readable Linux subpages work,
an access to the `PROT_NONE` 4K subpage succeeds at the hardware/Darwin level.
No signal is delivered, so Carrick cannot classify or reject the access.

If Carrick makes the whole 16K host page `PROT_NONE`, valid accesses to the
three readable Linux subpages fault too. A signal handler can observe the fault,
but it cannot generally emulate and resume arbitrary native load/store
instructions with minimal overhead and complete correctness. That is DBT or
instruction-emulation territory, not the minimal-overhead direct-native lane.

Therefore direct-native 4K requires one of these future mechanisms:

- dynamic binary translation for guest memory accesses;
- static or dynamic instrumentation that guards every memory access that might
  touch mixed-protection host pages;
- a new host facility that exposes 4K protection granularity to native arm64
  processes;
- returning to a VMM or another page-table-owning execution vehicle.

Until one of those exists and is proved, exact 4K support means HVF fallback.

## Runtime data model

Add page profile to the run specification after design review:

```rust
struct RunSpec {
    // existing fields
    page_profile: PageProfileRequest,
}

enum PageProfileRequest {
    Auto,
    Native,
    Linux4k,
}
```

The selected execution plan should include:

```rust
struct ExecutionPlan {
    backend: ExecBackend,
    page_profile: SelectedPageProfile,
    diagnostics: Vec<PageProfileEvidence>,
}
```

The native memory backend should store:

```rust
struct NativePageGeometry {
    host_page_size: usize,
    linux_page_size: usize,
    profile: NativePageProfile,
}
```

All code that currently assumes one Linux page size in native mode should read
from `NativePageGeometry`.

## Error handling

Native profile rejection is not a generic launch failure. It should be a typed
compatibility result that the CLI can display and that tests can assert.

Examples:

```text
error: native execution rejected this image
reason: linux4k required because /lib/ld-linux-aarch64.so.1 has PT_LOAD p_align=4096
resolution: rerun with --exec-backend=hvf or rebuild the image for 16K page compatibility
```

```text
error: native execution rejected runtime mapping
reason: mprotect requested 4K-granular protection inside a 16K host page
resolution: rerun with --native-page-profile=linux4k
```

If `--exec-backend=auto --native-page-profile=auto` selects HVF, the CLI should
report it in verbose mode but not treat it as an error.

## Testing strategy

Unit tests:

- classifier accepts a synthetic 16K-aligned ELF set;
- classifier rejects a 4K-aligned interpreter with `Linux4kExact`;
- explicit `native` rejects instead of falling back;
- explicit `linux4k` resolves to HVF on Darwin;
- runtime mapping request with 4K-only protection rejects in `NativeHost`.

Probe tests:

- keep `native_exec_probe page-size` as the host fact source;
- add a classifier probe that reports `host_page_size`, requested profile, and
  selected backend;
- add synthetic ELF fixtures with 4K and 16K `PT_LOAD` alignment.

Integration tests:

- `--exec-backend=auto --native-page-profile=auto` on a known 4K image chooses
  HVF and preserves current conformance behavior;
- a known 16K-compatible smoke image chooses native when native execution is
  enabled;
- `--exec-backend=native --native-page-profile=linux4k` fails clearly on
  Apple Silicon 16K hosts;
- no test may treat a silent 16K widening of a 4K image as success.

## Success criteria

The next implementation phase is successful when:

- page-profile selection is explicit in the run plan;
- default Carrick behavior for existing containers remains exact 4K through HVF;
- native direct execution automatically selects 16K only for images that pass
  compatibility checks;
- explicit native requests fail with actionable diagnostics rather than
  silently falling back;
- the no-VMM native backend has a clear path to support 16K-compatible images
  without weakening Linux4K exactness for existing workloads.

## Follow-up design work

The next design artifact should be an implementation plan for page-profile
selection, not direct-native 4K subpage emulation. Direct-native 4K should stay
a separate research topic with its own feasibility gates because it changes the
core execution model from "run host-native instructions directly" to
"mediate guest memory accesses."
