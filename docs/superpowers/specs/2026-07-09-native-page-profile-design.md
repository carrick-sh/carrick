# Native page profile design

Date: 2026-07-09

## Summary

The no-VMM Darwin-native execution lane should support two direct-native page
profiles:

- `native16k`: Linux-visible page size equals the host-native Darwin page size.
  On Apple Silicon Macs today this is 16 KiB. This is the preferred fast path
  because Darwin VM protections, mapping granularity, and guest-visible page
  size agree.
- `linux4k-on-16k`: Linux-visible page size is 4 KiB while the host Darwin page
  size remains 16 KiB. This is the compatibility path for ordinary 4K-shaped
  Linux containers and binaries, and it still avoids HVF.

The key decision is that `linux4k-on-16k` is a direct-native implementation
requirement, not a route back to HVF. It must balance correctness, robustness,
and speed:

- fast path: keep ordinary uniform 16K host pages mapped with native Darwin
  protections;
- avoidance path: lay out mappings to prevent mixed 4K state inside one 16K
  host page when padding or alignment is cheaper than trapping;
- precise slow path: when mixed 4K state is unavoidable, use a colder
  per-page enforcement mechanism that preserves Linux semantics or fails
  explicitly.

Metadata plus signal handlers alone is not sufficient. A disallowed 4K subpage
access inside a readable 16K host page would not fault, so Carrick would miss
the violation. The design must therefore treat mixed pages as special objects
with an enforcement strategy, not as ordinary host-readable pages with extra
metadata.

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
- Preserve exact Linux 4K behavior for containers that need it without routing
  that decision to HVF.
- Make page size an explicit runtime profile instead of a hidden backend
  assumption.
- Avoid silently exposing 16K semantics to a 4K-shaped container.
- Keep HVF available as an explicitly selected backend, but keep native
  page-profile selection inside the native backend.
- Keep the native backend trusted-code-only and experimental.

## Non-goals

- Do not claim metadata-only subpage tracking is enough for exact 4K behavior
  on a 16K host.
- Do not emulate arbitrary guest memory reads and writes from Darwin signal
  handlers on the hot path.
- Do not switch the default macOS backend away from HVF for existing containers
  until the native page-profile selector and mixed-page slow path have their own
  gates.
- Do not use Rosetta to solve `linux/arm64` direct native page size. Rosetta is
  relevant to translated x86 processes, not same-ISA native arm64 execution.
- Do not make 16K compatibility a global statement about a whole distribution
  unless every startup object and runtime mapping policy is covered.

## Page profile vocabulary

Carrick should introduce a page-profile concept at the execution-policy level:

```rust
enum NativePageProfile {
    Native16k,
    Linux4kOn16k,
}
```

`Native16k` means:

- guest-visible page size equals `host_page_size`;
- `AT_PAGESZ`, `sysconf(_SC_PAGESIZE)`, and Carrick's Linux page-size reporting
  surface the host page size;
- `mmap`, `munmap`, `mprotect`, guard pages, executable mappings, and fault
  classification are performed at host page granularity;
- on current Apple Silicon hosts, the expected profile is 16 KiB.

`Linux4kOn16k` means:

- guest-visible page size is exactly 4096;
- 4K Linux `mmap`, `munmap`, `mprotect`, guard-page, `SIGSEGV`, and `SIGBUS`
  behavior must be preserved;
- host mappings are still Darwin 16K mappings;
- uniform 16K host pages use direct host mappings;
- mixed 16K host pages use a precise slow path or fail with a typed diagnostic.

The name should make the implementation constraint visible. `Linux4kOn16k` is
not less Linux-like than `Native16k`; for a 4K-shaped container, it is the
correct Linux behavior.

## User-facing policy

The CLI should separate execution backend selection from page profile selection:

```text
--exec-backend=auto|hvf|native
--native-page-profile=auto|native16k|linux4k
```

Environment equivalents:

```text
CARRICK_EXEC_BACKEND=auto|hvf|native
CARRICK_NATIVE_PAGE_PROFILE=auto|native16k|linux4k
```

Policy matrix:

| Backend | Page profile | Behavior |
|---|---|---|
| `auto` | `auto` | If native execution is enabled, prefer direct native `Native16k` when compatibility checks pass; otherwise use direct native `Linux4kOn16k`. Do not route page-profile selection to HVF. |
| `auto` | `native16k` | Use direct native `Native16k` if compatibility checks pass; otherwise fail with a page-profile diagnostic. |
| `auto` | `linux4k` | Use direct native `Linux4kOn16k`. Fail only when the mixed-page engine cannot preserve a required 4K semantic. |
| `native` | `auto` | Prefer direct native `Native16k`; select direct native `Linux4kOn16k` when the image needs 4K. |
| `native` | `native16k` | Force direct native `Native16k`; fail on incompatible image or runtime mapping request. |
| `native` | `linux4k` | Force direct native `Linux4kOn16k`; fail on unsupported mixed-page cases rather than widening semantics. |
| `hvf` | any | Use HVF because the user selected HVF. This is outside native page-profile selection. |

Diagnostics should name the first failed reason:

```text
native16k profile rejected: PT_LOAD alignment 4096 is smaller than host page size 16384
linux4k-on-16k selected: mixed 4K protections will use guarded mixed-page enforcement
linux4k-on-16k rejected: executable mixed page requires unsupported instruction instrumentation
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
sh.carrick.native-page-profile=native16k
sh.carrick.native-page-profile=linux4k
```

Classifier outcomes:

```rust
enum PageProfileDecision {
    Native16k { host_page_size: usize, evidence: Vec<PageProfileEvidence> },
    Linux4kOn16k { reason: PageProfileSelectionReason },
    Reject { reason: PageProfileRejectReason },
}
```

The classifier should be conservative:

- If every required startup object is host-page aligned and no 4K-only mapping
  requirement is visible, `auto` may choose `Native16k`.
- If any startup object has a smaller required alignment than the host page
  size, `auto` chooses `Linux4kOn16k`.
- If the classifier cannot inspect a required startup object, `auto` chooses
  `Linux4kOn16k` unless the user explicitly requests `native16k`.
- If a runtime `mmap` or `mprotect` request later proves incompatible with
  `Native16k`, the process can demote the affected region to `Linux4kOn16k`.
  It must not widen protections silently.

## Native16k semantics

In `Native16k` mode, Carrick presents a Linux personality whose page size is
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

## Linux4kOn16k semantics

In `Linux4kOn16k` mode, Carrick preserves the current common Linux container
contract while still running same-ISA guest instructions natively:

- Auxv `AT_PAGESZ` is 4096.
- Linux page-size syscalls and libc-facing values report 4096.
- `mmap`, `munmap`, and `mprotect` operate at 4K granularity.
- Adjacent 4K subpages inside the same 16K host page may have different Linux
  permissions.
- Invalid 4K subpage accesses produce the correct Linux fault behavior.
- File-backed mappings, partial unmaps, guard pages, stack growth, and
  SIGBUS-past-EOF behavior remain 4K-shaped.

The implementation is adaptive. Most pages should remain on a direct host
mapping fast path. Only pages whose four 4K Linux subpages cannot share one
16K host mapping state become mixed pages.

## Adaptive enforcement model

The page engine tracks every 16K host page that intersects guest memory:

```rust
enum HostPageState {
    Uniform16k(UniformMapping),
    Composed16k(ComposedMapping),
    MixedGuarded(MixedPage),
    Unsupported(UnsupportedReason),
}
```

`Uniform16k` is the preferred state:

- all four 4K Linux subpages have the same backing class;
- all four have compatible permissions;
- no subpage has a distinct fault boundary;
- the host page can be mapped and protected directly.

`Composed16k` is still fast enough for many compatibility cases:

- the Linux subpages differ in file offset or source backing, but can be
  materialized into one private 16K host page with uniform permissions;
- private file mappings and anonymous copy-on-write pages are good candidates;
- shared writable mappings are not composed unless writeback and alias
  coherence are proved.

`MixedGuarded` is the precise slow path:

- the 16K host page is protected so ordinary hardware access faults;
- the signal handler verifies the fault is in guest mode and in a mixed page;
- a limited AArch64 memory-instruction emulator performs the allowed 4K access
  against Carrick-owned subpage backing and advances the guest PC;
- unsupported instructions, executable mixed pages, or hot mixed pages that
  exceed a configured fault budget produce typed diagnostics.

`Unsupported` is a correctness state, not a crash:

- Carrick refuses to run or refuses the mapping transition;
- the diagnostic names the mapping, profile, and missing enforcement capability.

The intended performance shape is:

```text
ordinary 16K-compatible pages       -> Uniform16k, no extra tax
4K-shaped but composable pages       -> Composed16k, copy/materialize tax only
rare mixed guard or tail pages       -> MixedGuarded, signal/emulation tax
unsupported exact-4K requirement     -> fail clearly
```

## Why metadata-only 4K is unsound

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

- guarded mixed pages with enough AArch64 load/store emulation for the cold
  mixed cases Carrick chooses to support;
- static or dynamic instrumentation for code that touches mixed pages;
- layout and composition rules that avoid mixed host pages in hot regions;
- a new host facility that exposes 4K protection granularity to native arm64
  processes.

The phase-1 `linux4k-on-16k` implementation should start with the first and
third mechanisms: avoid mixed pages when possible, compose compatible private
pages, and guard/emulate cold mixed pages with a strict unsupported-case
diagnostic.

## Runtime data model

Add page profile to the run specification after design review:

```rust
struct RunSpec {
    // existing fields
    page_profile: PageProfileRequest,
}

enum PageProfileRequest {
    Auto,
    Native16k,
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
resolution: run with --native-page-profile=linux4k or rebuild the image for 16K page compatibility
```

```text
error: native linux4k mapping unsupported
reason: mprotect requested 4K-granular protection inside a 16K host page
detail: mixed executable page requires instruction instrumentation not implemented by this build
```

If `--exec-backend=auto` selects HVF for a reason outside this page-profile
decision, the CLI may report that separately. The page-profile selector itself
must not choose HVF as its `linux4k` implementation.

## Testing strategy

Unit tests:

- classifier accepts a synthetic 16K-aligned ELF set as `Native16k`;
- classifier selects `Linux4kOn16k` for a 4K-aligned interpreter;
- explicit `native16k` rejects a 4K-shaped image instead of demoting;
- explicit `linux4k` selects direct-native `Linux4kOn16k` on Darwin;
- runtime mapping request with 4K-only protection demotes the affected host page
  to a mixed-page state or rejects with `Unsupported`.

Probe tests:

- keep `native_exec_probe page-size` as the host fact source;
- add a classifier probe that reports `host_page_size`, requested profile, and
  selected backend;
- add synthetic ELF fixtures with 4K and 16K `PT_LOAD` alignment;
- add a mixed-page probe that proves a disallowed 4K subpage inside an otherwise
  readable 16K host page does not silently succeed.

Integration tests:

- `--exec-backend=native --native-page-profile=auto` on a known 4K image chooses
  direct-native `Linux4kOn16k`;
- a known 16K-compatible smoke image chooses native when native execution is
  enabled;
- `--exec-backend=native --native-page-profile=linux4k` preserves a simple
  mixed-permission 4K guard page inside a 16K host page;
- unsupported mixed executable pages fail clearly;
- no test may treat a silent 16K widening of a 4K image as success.

## Success criteria

The next implementation phase is successful when:

- page-profile selection is explicit in the run plan;
- direct-native execution automatically selects 16K only for images that pass
  compatibility checks;
- direct-native execution selects `Linux4kOn16k` for ordinary 4K-shaped images;
- uniform pages stay on the 16K host mapping fast path;
- mixed pages either use a measured slow path or fail with a typed diagnostic;
- explicit `native16k` requests fail with actionable diagnostics rather than
  widening semantics;
- the no-VMM native backend supports both 16K-compatible images and 4K-shaped
  images without using HVF as the page-profile escape hatch.

## Follow-up design work

The next design artifact should be an implementation plan for page-profile
selection plus the first mixed-page enforcement slice. It should not attempt a
complete arbitrary-instruction emulator in one pass. The first slice should
prove:

- uniform 16K pages remain fast;
- the classifier can select `Native16k` or `Linux4kOn16k`;
- a simple mixed 4K guard-page case is caught and handled without silently
  widening permissions;
- unsupported mixed cases fail with clear diagnostics.

## Implementation boundary as of 2026-07-09

The first implementation slice has landed the policy vocabulary, page geometry
threading, native execution-plan selection, and an explicit Darwin-native
backend boundary. The boundary is deliberately a launch gate, not a runnable
native engine:

- `--exec-backend=native` is accepted only for same-ISA guests on macOS.
- Cross-ISA native requests are rejected before launch.
- `--native-page-profile=linux4k` selects `Linux4kOn16k` directly; it is not
  routed to HVF.
- The Darwin-native backend receives the selected profile and returns a typed
  unsupported diagnostic naming `platform`, `profile`, `host_page_size`, and
  `linux_page_size`.
- The existing macOS default remains HVF unless native is explicitly requested.

The current 4K-on-16K policy boundary is intentionally conservative:

| Mapping shape | Current decision |
|---|---|
| Uniform 16K host page | Supported as direct host fast path |
| Private/composable data subpages | Supported as `Composed16k` |
| Mixed shared-file backing | Unsupported until alias/writeback coherence exists |
| Data-only mixed permissions | Supported as `MixedGuarded` policy state |
| Mixed executable permissions | Unsupported until instruction instrumentation exists |
| Unsupported geometry | Unsupported with explicit geometry diagnostic |

`MixedGuarded` is a policy state, not a claim that arbitrary native load/store
instruction emulation is complete. The backend must reject any mapping that
needs executable sub-16K enforcement until an implementation can prove that
instruction fetch and data access semantics are preserved.

The PTY-sensitive integration gate has also been hardened. The stdio ioctl test
now asserts the bootstrap fallback when run headless and the host tty passthrough
when run under a PTY, while the separate real-pty helper tests continue to prove
that Carrick does not return synthetic bootstrap pgrp/sid values for real ttys.

Authoritative evidence for this boundary lives in
[`docs/2026-07-09-no-vmm-native-feasibility-evidence.md`](../../2026-07-09-no-vmm-native-feasibility-evidence.md).
