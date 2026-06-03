# Rosetta glibc `linux/amd64` handoff

Branch: `feat/rosetta-glibc-amd64`

Design/plan:

- `docs/superpowers/specs/2026-06-01-rosetta-glibc-amd64-design.md`
- `docs/superpowers/plans/2026-06-01-rosetta-glibc-amd64.md`

Status date: 2026-06-02

## Current status

The Carrick-owned Rosetta glibc bring-up items in this handoff are implemented
and verified. `linux/amd64` glibc-dynamic shell workloads run through Apple's
Linux Rosetta interpreter; the conformance harness now has an amd64 Rosetta lane
for that supported scope. Static-musl x86_64 probes are intentionally outside
the current Rosetta runtime scope and self-skip in the harness.

One translated-code workload gap remains documented, not fixed here:

- `dash` fd-input long-token parsing fails only in dash's fd-input parser path.

The prior `gpgv` bad-signature gap is fixed in this continuation. The root
cause was Carrick's syscall guest-memory copy path selecting one high-VA alias
mapping for an entire buffer even when the live stage-1 owner changed inside the
range. That wrote correct `read(2)` bytes into the old backing for the tail of a
64 KiB buffer, while Rosetta read the newer backing and saw zeros. The copy
helpers now reselect backing at 4 KiB stage-1 boundaries.

The full `apt-get update` surface fetched all four InRelease files with no
signature error before it was stopped after a separate hang
(`rosetta-apt-update-aliasfix-1780418888-40044`, rc 137). Treat the direct
`gpgv` and synthetic clearsign checks below as the completed secure-verification
fix; the remaining apt hang should be tracked separately if it persists.

## Completed in this pass

### High-VA syscall copy segmentation for gpgv

Fixed `gpgv` bad signature validation under amd64 Rosetta. Carrick's guest
memory copy helpers formerly called `mapping_for_range[_mut]` once for the whole
syscall buffer. Rosetta can create overlapping high-VA alias regions where a
single 64 KiB buffer crosses a live stage-1 owner boundary. In the canonical
InRelease run, bytes through `0x5555555c2fff` belonged to the old mapping, but
the tail beginning at `0x5555555c3000` translated to the newer mapping. Carrick
wrote the correct tail bytes into the old backing, and translated `gpgv` read
zeros from the new one.

The fix walks syscall memory copies in 4 KiB stage-1 chunks, reselects the
mapping for each chunk from the live stage-1 IPA, and preflights checked writes
so permission failures do not become partial writes. A regression test covers a
range that would previously select only the start owner and now crosses into the
new owner. The test module now also has a fake stage-1 copy planner with
deterministic backing buffers: it proves the tail bytes land in the live owner
backing after a stage-1 owner boundary, and that a checked write fails before
mutating the writable prefix when the tail owner is read-only.

Validation:

- `cargo test -p carrick-hvf --lib guest_copy_chunks_reselect_stage1_owner_across_alias_boundary -- --nocapture`
- `cargo test -p carrick-hvf --lib fake_stage1 -- --nocapture`
- `cargo test -p carrick-hvf --lib trap::thread_sibling_tests -- --nocapture`
- `cargo test -p carrick-hvf --lib mapping_lookup -- --nocapture`
- `cargo test -p carrick-hvf --lib -- --nocapture --test-threads=1`
- `cargo fmt --all -- --check`
- `git diff --check`
- `./scripts/build-signed.sh`
- canonical InRelease direct `gpgv`:
  `rosetta-gpgv-aliasfix-1780418798-36608` returned rc 0 with `GOODSIG` and
  `VALIDSIG`, wrote 254968 bytes, and produced the Docker-good cleartext SHA256
  `26758a13cecfaff9ff274d31ea9a4633674a999bd130c09f6ecd66a4b8071184`.
- targeted read-buffer trace:
  `trace-read-subrange-aliasfix-1780418821-37179` returned rc 0, produced the
  same good hash, had `0` `MISMATCH` lines, and shows the old bad tail now
  split at `0x5555555c3000` with `map_start=0x5555555c3000`,
  `map_ipa=0x1846600000`, and `MATCH` through the `0x5555555c3f4f` sample.
  The configured subrange at offset `0xf0b0`, length `3920`, remained fully
  nonzero.
- controlled synthetic clearsign threshold:
  `rosetta-clearsign-aliasfix-1780418876-39855` verified
  `thresh_65536.asc` with rc 0, `GOODSIG`/`VALIDSIG`, 65536-byte cleartext, and
  a Docker-matching SHA256
  `4786e1840499b4ac230e44a119c18f287c9d93b626ff0b408b33a434d2c36cfd`.

### Futex PI for Rosetta glibc

Fixed `FUTEX_LOCK_PI_PRIVATE` returning ENOSYS. Carrick now supports the
uncontended/private PI operations Rosetta glibc uses:

- `FUTEX_LOCK_PI_PRIVATE`: records the guest-visible owner TID and returns 0.
- `FUTEX_TRYLOCK_PI_PRIVATE`: returns `EDEADLK` when already owned by self and
  `EAGAIN` for a different owner.
- `FUTEX_UNLOCK_PI_PRIVATE`: requires self ownership, clears the word, and wakes
  one waiter if a futex table is present.

The owner word uses the same guest-visible TID as `gettid(2)`, including the
single-thread namespace PID case caught by the `futexpilock` probe.

Validation:

- `cargo test -p carrick-runtime --test integration futex_ -- --nocapture`
- live amd64 grep workload:
  `printf 'alpha\nbeta\n' | grep alpha` exits 0 with no compatibility report
  entries.
- `cargo test -p carrick-cli --test conformance conformance_probes -- --nocapture`
  now passes `arm64:futexpilock`.

### Host xattr list semantics

Fixed the former `ls -la /` ENODATA diagnostics. Root and no-xattr host-backed
paths now return an empty Linux xattr list instead of propagating macOS
`ENOATTR`/`ENODATA` through `listxattr`.

Validation:

- `cargo test -p carrick-runtime --lib host_guest_xattr_api_hides_all_internal_carrick_names -- --nocapture`
- `cargo test -p carrick-runtime --test integration xattr -- --nocapture`
- `target/release/carrick run --platform linux/arm64 --fs host ubuntu:24.04 /bin/ls -la /`
- `target/release/carrick run --platform linux/amd64 --fs host ubuntu:24.04 /bin/ls -la /`

Both `ls` runs list root without ENODATA messages.

### Lock-in tests for earlier Rosetta fixes

Added or strengthened regression coverage for the previous fork/signal/high-VA
work:

- fork child snapshots now assert `TTBR1_EL1` and `ACTLR_EL1` are preserved.
- high-VA mapping lookup has direct tests for stage-1-IPA ownership and
  newest-first fallback.
- page-table tests assert a sub-16 KiB high-VA alias does not overwrite the
  adjacent L3 descriptor.

Validation:

- `cargo test -p carrick-hvf --lib mapping_lookup -- --nocapture`
- `cargo test -p carrick-hvf --lib child_copies_all_other_gprs_and_sysregs -- --nocapture`
- `cargo test -p carrick-mem --lib alias -- --nocapture`

Existing rt_sigreturn layout and dispatcher coverage remains in:

- `crates/carrick-abi/src/lib.rs`
- `crates/carrick-runtime/tests/integration/syscall_signal.rs`

### Conformance lane and probe build path

`crates/carrick-cli/tests/conformance.rs` now runs deterministic shell cases in
two lanes:

- `arm64`
- `amd64-rosetta`

The amd64 lane self-skips if Rosetta for Linux is not installed and sets
`CARRICK_ACCEPT_ROSETTA_TERMS=1` when running Carrick.

`scripts/build-probes.sh` now builds:

- full `aarch64-unknown-linux-musl` probe set
- explicit arch-neutral x86_64 smoke subset: `futexpilock`

The full static x86_64 probe set is not built because many probes are
AArch64-specific.

Validation:

- `scripts/build-probes.sh`
- `cargo test -p carrick-cli --test conformance conformance -- --exact --nocapture`
- `cargo test -p carrick-cli --test conformance conformance_probes -- --nocapture`

### Rosetta documentation refresh

`docs/rosetta.md` was rewritten to remove the stale "TTBR1 / upper-half is next"
frontier and replace it with current architecture, supported scope, verification
commands, and known translated-code limitations.

### Syscall-copy alias tracing

Added `guest-mem-*` USDT probes and `scripts/trace-guest-mem-copy.d` so Carrick
can prove, at syscall-copy time, whether the mapping selected for a guest buffer
matches the guest's live high-VA stage-1 translation. The trace reports:

- copy direction, guest VA, byte count, selected mapping, and live stage-1 IPA
- `MATCH` when `addr - mapping_start == stage1_ipa - mapping_ipa`
- `MISMATCH` when Carrick would copy through a different backing than the guest
  will read
- `NOSTAGE` for non-high-VA/bootstrap mappings where no stage-1 comparison is
  expected
- checksum/head/tail fingerprints of the copied payload, avoiding DTrace reads
  from guest VAs

`scripts/trace-write-buffers.d` adds a write-specific view: it pairs
`syscall-entry`/`syscall-return` with the guest-memory probes, tracks a per-fd
logical offset, and samples start/25%/50%/75%/last stage-1 offsets for each
guest write-buffer range.

Validation:

- `cargo test -p carrick-hvf --lib guest_mem_probe_digest -- --nocapture`
- `cargo test -p carrick-hvf --lib guest_mem_probe_points -- --nocapture`
- `carrick trace --script scripts/trace-guest-mem-copy.d ...` on the reduced
  dash and gpgv workloads
- `carrick trace --script scripts/trace-write-buffers.d ...` on reduced
  `gpgv --output`

## Current known limitations

### dash fd-input long-token parser

Current evidence:

- `carrick trace` on a reduced fd-input script shows dash reads the full
  1366-byte script from fd 0 in one `read(2)` returning 1366.
- dash then reports `Syntax error: Unterminated quoted string`.
- The identical fd-input stream parses correctly in `bash` and prints `1350`.
- `dash -c` parses the same long token and prints `1350`.
- No compatibility report entries or guest faults were observed.
- Docker Desktop amd64 with `UseVirtualizationFramework=true` and
  `UseVirtualizationFrameworkRosetta=true` parses the identical fd-input stream
  and prints `1350`.
- A privileged Docker/Rosetta `bpftrace` baseline, with tracefs/debugfs mounted
  inside the container, shows the matching kernel event shape:
  `read(fd=0, count=8192) -> 1366`, then `read(fd=0, count=8192) -> 0`.
- The comparable `carrick trace` run shows the same syscall shape:
  `read(fd=0, count=8192) -> 1366`, then EOF. The difference is after syscall
  delivery: Docker/Rosetta prints `1350`; Carrick/Rosetta reports the dash
  syntax error.
- `scripts/trace-guest-mem-copy.d` on run id
  `trace-mem-dash-1780411328-76634` shows the fd-input `read(2)` checked write
  into `0x555555574ac0` was a high-VA `MATCH`:
  `va_off=0x2ac0`, `ipa_off=0x2ac0`. The payload fingerprint starts with the
  expected `q='aaaaa` bytes and ends with the expected `${#q}` print tail.

Conclusion: this is localized to dash's translated fd-input token accumulation
path under Carrick/Rosetta, not Carrick's read buffer, file content, or the
prior stale stage-1/stage-2 alias class, and not a general Apple Rosetta
fd-input parser failure.

### Historical apt / gpgv secure-verification evidence (pre-fix)

Before the high-VA syscall copy segmentation fix, `apt-get update` under amd64
Rosetta failed secure verification. Reduced evidence:

- pre-fix amd64 Carrick/Rosetta direct `gpgv --status-fd` on
  `archive.ubuntu.com/ubuntu/dists/noble/InRelease` reported `BADSIG`.
- arm64 Carrick on the same URL reports `GOODSIG` and `VALIDSIG`.
- Docker Desktop amd64 with Apple Virtualization Framework Rosetta reports
  `GOODSIG` and `VALIDSIG`.
- A privileged Docker/Rosetta `bpftrace` baseline can compare syscall events
  directly against `carrick trace`: `gpgv` opens and reads
  `/tmp/InRelease` through 64 KiB `read(2)` chunks ending in EOF, and opens and
  reads `ubuntu-archive-keyring.gpg` through `read(2)` as well.
- The comparable `carrick trace` run shows the same target file read shape for
  the final `gpgv` process: keyring `read(2) -> 3607`, `InRelease` reads
  `65536 + 65536 + 65536 + 59242` bytes then EOF, followed by full keyring reads
  ending in EOF. Carrick reported `BADSIG` while Docker/Rosetta reported
  `GOODSIG` and `VALIDSIG`.
- `LC_ALL=C` is not a workaround. Docker/Rosetta still validates successfully;
  Carrick/Rosetta changes failure mode to `ERRSIG`/`NO_PUBKEY` with invalid
  packet diagnostics.
- The amd64 and arm64 Carrick runs read identical input hashes:
  - `InRelease`: `cdb2f31d809f589719a53c6ad15f255b27569c4059542ada282aaa21b8e164b0`
  - `ubuntu-archive-keyring.gpg`: `80a36b0a6de2f69f49d2df75ef473ccde121e9e190b9ea01d20a4f63778d5c31`
- `carrick trace` shows `gpgv` reads both files through `read(2)`, not
  file-backed mmap, and there are no unhandled or partial syscalls.
- `GCRYPT_DISABLE_HWF=all` does not change the failure.
- `scripts/trace-guest-mem-copy.d` on run id
  `trace-mem-gpgv-1780411459-82811` reproduced `BADSIG` while reporting zero
  `MISMATCH` events, 2608 `MATCH` events, and 362 `NOSTAGE` events. The final
  `gpgv` process's checked-write buffers for the keyring and InRelease all
  matched their live high-VA stage-1 backing, including:
  - keyring `3607` bytes at `0x5555555ade10`: `va_off=0xbe10`,
    `ipa_off=0xbe10`
  - InRelease `65536 + 65536 + 65536 + 59242` bytes at `0x5555555b3f50`:
    `va_off=0x11f50`, `ipa_off=0x11f50`
  - later keyring `1203` bytes at `0x5555555e44f0`: `va_off=0x4f0`,
    `ipa_off=0x4f0`
- A host-built amd64 glibc probe using `libgcrypt.so.20` computes the same
  SHA256 for `/tmp/InRelease` under Docker/Rosetta and Carrick/Rosetta, both
  with normal libgcrypt feature selection and with `GCRYPT_DISABLE_HWF=all`:
  `cdb2f31d809f589719a53c6ad15f255b27569c4059542ada282aaa21b8e164b0`.
- `gpgv --output /tmp/plain ... /tmp/InRelease` is a sharper reduced symptom:
  Docker/Rosetta writes a `254968`-byte cleartext payload with SHA256
  `26758a13cecfaff9ff274d31ea9a4633674a999bd130c09f6ecd66a4b8071184`;
  Carrick/Rosetta writes the same length but SHA256
  `915703fbea4f697f2c0577e70fbe00cd461c71daedc2c118c525bf245f2ffa2b`.
  The live zero-based first byte diff is at cleartext byte `61567`, where
  Carrick has NUL bytes and Docker has normal ASCII package-index text.
- Capturing Carrick's bad cleartext output showed exactly three large NUL runs:
  `(61567, 3920)`, `(127103, 3920)`, and `(192639, 3920)`. They are spaced
  exactly 64 KiB apart. In each bad 8 KiB write, the NUL window starts at chunk
  offset `4223` and length `3920`.
- `rosetta-gpgv-output-route-1780414034-47501` compared
  `gpgv --output /tmp/plain` with `gpgv --output - > /tmp/plain_stdout` in the
  same Carrick run. Both routes returned `rc=1`, both wrote the same
  `254968`-byte payload, and `cmp` reported the two files were byte-identical
  with SHA256 `915703fbea4f697f2c0577e70fbe00cd461c71daedc2c118c525bf245f2ffa2b`.
  The same route split in Docker/Rosetta returned `rc=0` for both routes and
  produced the good SHA256
  `26758a13cecfaff9ff274d31ea9a4633674a999bd130c09f6ecd66a4b8071184` for both.
  That removes gpgv's direct output-file open path and shell redirection as the
  differentiating branch.
- `scripts/trace-write-buffers.d` on run id
  `trace-write-point2-gpgv-1780413633-35877` shows the corrupted output write
  buffers are already wrong when Carrick copies them from guest memory. The bad
  8 KiB output chunks recur at cleartext offsets `57344`, `122880`, and
  `188416`; their traced guest-buffer checksums differ from the Docker-cleartext
  oracle while head/tail still match. For each bad chunk, the selected mapping
  and stage-1 sample points all report `MATCH`.
- After the exact NUL-window offsets showed that the original midpoint sample
  missed the corrupted subrange by 128 bytes, `guest_mem_probe_points` was
  widened to sample start/25%/50%/75%/last. The rerun
  `trace-write-qpoints-gpgv-1780414298-53945` reproduced the canonical bad hash
  and sampled inside the NUL window for each bad 8 KiB write. The 75% sample
  point (`va_off=0x1d90`, `ipa_off=0x1d90`) still reported `MATCH` for the bad
  chunks at `57344`, `122880`, and `188416`; the trace had `0` `MISMATCH`
  point events.
- A gpgv-only `--output -` trace with host-mounted input/keyring
  (`trace-write-stdout-gpgv-1780414094-48592`) still reproduced `BADSIG` and
  showed stdout fd `1` write buffers reporting `MATCH` at the sampled points.
  The host-mounted path changes gpgv's internal buffering and the exact bad
  hash, so it is not the canonical oracle, but the captured output remains the
  same 64 KiB-near zero-window family: direct and stdout outputs are
  byte-identical, with NUL runs at `(61615, 3872)`, `(127151, 3872)`, and
  `(192687, 3872)`.
- vDSO was driven down with debug modes:
  - `CARRICK_DISABLE_VDSO=1` on
    `rosetta-gpgv-novdso-1780415392-92724` aborts before `gpgv`; Rosetta asserts
    that it cannot find the vDSO ELF header in auxv, so Carrick cannot simply
    omit vDSO for Rosetta.
  - `CARRICK_VDSO_MODE=no-getrandom` on
    `rosetta-gpgv-vdso-nogetrandom-1780415547-337` produced the canonical
    bad hash `915703f...`.
  - `CARRICK_VDSO_MODE=no-fastpaths` on
    `rosetta-gpgv-vdso-nofast-1780415647-5730` aborts because Rosetta requires
    `__kernel_clock_getres`.
  - `CARRICK_VDSO_MODE=clock-syscalls` on
    `rosetta-gpgv-vdso-clocksys-1780415795-11917` produced the canonical
    bad hash.
  Conclusion: Rosetta requires the vDSO header and clock symbols, but the
  getrandom export and Carrick's clock fastpaths are not the gpgv corruption
  cause.
- TSO was driven down. `CARRICK_DISABLE_TSO=1` on
  `rosetta-gpgv-notso-1780415994-25776` produced
  `915703f...` and the same NUL windows. Docker/Rosetta validates successfully
  even though its `PR_SET_MEM_MODEL, TSO` calls return `EINVAL`, while Carrick
  accepts them; disabling the hardware ACTLR write did not change the symptom.
- The Carrick event shape around direct `gpgv` is close to the Docker/Rosetta
  bpftrace baseline. `trace-rosetta-events-gpgv-direct-1780416440-38247` saw
  `mmap=163`, `mprotect=12`, `munmap=3`, `getrandom=83`, `prctl=2`,
  `prlimit64=1`, one private `futex` wake, and no `clone`, `mremap`, or
  `membarrier` in the final gpgv process. Docker's privileged bpftrace baseline
  produced good output with the same mmap/mprotect/munmap/prlimit families and
  84 `getrandom` returns. The one extra Docker `getrandom(4)` and Carrick's one
  futex wake are not leading causes because no-getrandom and no-TSO runs remain
  bad, and the corruption is deterministic.
- The stage-1/stage-2 alias class has now been checked at three levels:
  - The output buffer mapping is `va=0x5555555e4000`, `ipa=0x1827a00000`,
    `size=0x24000`; alias map and PTE walks report `rc=0`, no later
    overlapping `mprotect`/`munmap`, and no `pt-pause`/alias failures.
  - `trace-write-direct-gpgv-1780416562-40834` shows the selected mapping and
    stage-1 samples for each bad write all report `MATCH`.
  - The EL0/EL1 maintenance trampoline was corrected from local
    `tlbi vmalle1` to inner-shareable `tlbi vmalle1is`; the post-fix run
    `rosetta-gpgv-tlbi-is-1780416786-50213` produced the canonical bad
    hash. The TLBI opcode fix is real correctness work, but not this symptom.
- `trace-watch-gpgv-1780417056-61342` set
  `CARRICK_WATCH_ADDR=0x5555555e5d90`, an address inside the recurring bad
  window. That word was already zero before Carrick dispatched the bad writes at
  `57344`, `122880`, and `188416`, and returned to nonzero values in the
  neighboring chunks.
- `trace-subrange-gpgv-1780417349-76494` used the opt-in subrange USDT probe
  with `CARRICK_GUEST_MEM_SUB_OFFSET=4223` and
  `CARRICK_GUEST_MEM_SUB_LEN=3920`. For bad writes `57344`, `122880`, and
  `188416`, the exact subrange had `sum=0`, `head=0`, `tail=0`, and
  `nonzero=0`. Neighboring chunks at `49152`, `65536`, `114688`, `131072`,
  `180224`, and `196608` had nonzero checksums and `nonzero=3920`.
- A tiny clear-signed-message extractor is not affected. The host extractor
  matches Docker/gpgv's good cleartext hash, and
  `rosetta-awk-cleartext-1780417444-78435` produced byte-identical
  Docker/Rosetta and Carrick/Rosetta outputs with SHA256
  `26758a13cecfaff9ff274d31ea9a4633674a999bd130c09f6ecd66a4b8071184`.
  That retires a generic cleartext parsing/output hypothesis and leaves the
  failure in gpgv's translated verifier/emitter path.
- `rosetta-gpgv-output-matrix-1780417712-90896` split gpgv's output behavior:
  Docker reported `GOODSIG`/`VALIDSIG` for captured output, `/dev/null`, and no
  explicit output; Carrick reported `BADSIG` for all three. Therefore the
  cleartext writer is not required to trigger the bad signature result.
- Detached verification passed under Carrick when the clearsigned message is
  split into a Docker-valid detached signature fixture. The initial LF-terminated
  extraction failed under Docker and Carrick, so it was not a valid control.
  After dropping the final LF, Docker and Carrick both reported
  `GOODSIG`/`VALIDSIG`; the visible rerun was
  `rosetta-gpgv-detached-good-1780418000-97241`. That moves the failure out of
  RSA/signature verification and into clearsigned-message parsing/
  canonicalization.
- `rosetta-clearsign-sweep-1780417799-93186` generated throwaway host-signed
  clearsigned fixtures with a temporary key and verified them through
  Docker/Rosetta and Carrick/Rosetta. Carrick passed small payloads
  (`32768`, `49152`, `57344`) with byte-identical output. At synthetic payloads
  around `61440`-`64000`, Carrick emitted byte-identical cleartext but reported
  `NODATA`. At `65000` and above, Carrick produced the same near-64 KiB zero
  window family; the controlled first window was `(61663, 3824)`, with more
  windows every `65536` bytes. Docker reported `GOODSIG`/`VALIDSIG` throughout.
  `rosetta-clearsign-threshold-1780417857-94578` narrowed that boundary.
- `rosetta-gpgv-verbose-thresh-1780418070-99523` added `--verbose` on the
  controlled fixtures. At `64000`, Carrick reported `NODATA`,
  `block_filter: 1st length byte missing`, and `cleartext signature without
  data`. At `65000`, it reported `unexpected armor: -----END PGP SIGNATURE-----`
  and no signature. At `65536`, it found the signature packet but reported
  `BADSIG`. Docker reported `GOODSIG`/`VALIDSIG` for all three. That shows the
  clearsigned parser loses armor/signature state before the zero-window output
  corruption becomes a plain digest mismatch.
- `trace-watch-input-gpgv-1780417961-96696` watched the original InRelease input
  buffer at `0x5555555b3f50 + 61567 = 0x5555555c2fcf`. The watched input word
  stayed nonzero through the bad output writes at `49152`, `57344`, and
  `65536`, while previous output-buffer watch/subrange traces showed the
  output window was already zero before `write(2)`. That makes input delivery
  and later input-buffer clobbering unlikely; the bad data is produced while
  gpgv canonicalizes/constructs the clearsigned payload.

Corrected conclusion: the earlier output-write and input-watch traces ruled out
the output syscall path, but the decisive `read(2)` buffer trace showed the
first 64 KiB InRelease read crossed a live stage-1 owner boundary. The source
subrange beginning at `0x5555555c3000` translated to the newer alias mapping
while Carrick's whole-range copy had selected the older mapping from the range
start. That is the same broad stage-1/stage-2 alias class as earlier memory
bugs, but the failing edge is host-to-guest syscall copying across a mixed-owner
range. Chunking copies at the 4 KiB stage-1 granule fixes the direct gpgv
failure and the controlled clearsign threshold fixture.

## Verification

Current targeted verification after the high-VA syscall-copy fix:

- `cargo fmt --all -- --check`
- `cargo test -p carrick-hvf --lib guest_copy_chunks_reselect_stage1_owner_across_alias_boundary -- --nocapture`
- `cargo test -p carrick-hvf --lib mapping_lookup -- --nocapture`
- `cargo test -p carrick-hvf --lib -- --nocapture`
- `./scripts/build-signed.sh`
- `rosetta-gpgv-aliasfix-1780418798-36608`: direct InRelease `gpgv` rc 0,
  `GOODSIG`/`VALIDSIG`, output hash
  `26758a13cecfaff9ff274d31ea9a4633674a999bd130c09f6ecd66a4b8071184`.
- `trace-read-subrange-aliasfix-1780418821-37179`: direct InRelease `gpgv` rc
  0, good hash, `0` trace `MISMATCH` lines, split at `0x5555555c3000` into the
  newer mapping, and nonzero `0xf0b0..+3920` subrange bytes.
- `rosetta-clearsign-aliasfix-1780418876-39855`: controlled
  `thresh_65536.asc` rc 0, `GOODSIG`/`VALIDSIG`, Docker-matching hash
  `4786e1840499b4ac230e44a119c18f287c9d93b626ff0b408b33a434d2c36cfd`.
- `rosetta-apt-update-aliasfix-1780418888-40044`: full `apt-get update`
  fetched all four InRelease files with no signature error in stdout/stderr, but
  was stopped after a separate hang and exited 137.

Earlier diagnostic runs that led to the fix:

- live direct gpgv runs:
  - `rosetta-gpgv-vdso-nogetrandom-1780415547-337`
  - `rosetta-gpgv-vdso-clocksys-1780415795-11917`
  - `rosetta-gpgv-notso-1780415994-25776`
  - `rosetta-gpgv-tlbi-is-1780416786-50213`
  - `trace-watch-gpgv-1780417056-61342`
  - `trace-subrange-gpgv-1780417349-76494`
  - `rosetta-awk-cleartext-1780417444-78435`
  - `rosetta-gpgv-output-matrix-1780417712-90896`
  - `rosetta-gpgv-detached-good-1780418000-97241`
  - `rosetta-clearsign-sweep-1780417799-93186`
  - `rosetta-clearsign-threshold-1780417857-94578`
  - `rosetta-gpgv-verbose-thresh-1780418070-99523`
  - `trace-watch-input-gpgv-1780417961-96696`

Earlier broad branch gates in this handoff remain:

- `scripts/build-probes.sh`
- `cargo test -p carrick-hvf --lib guest_mem_probe_digest -- --nocapture`
- `cargo test -p carrick-hvf --lib guest_mem_probe_points -- --nocapture`
- `cargo test -p carrick-mem --lib linux_auxv_can_omit_sysinfo_ehdr_for_vdso_debug_control -- --nocapture`
- `cargo test -p carrick-mem --lib vdso_image_can_omit_getrandom_export_for_rosetta_debugging -- --nocapture`
- `cargo test -p carrick-mem --lib vdso_image_can_omit_fastpath_exports_for_rosetta_debugging -- --nocapture`
- `cargo test -p carrick-mem --lib vdso_image_can_route_clock_exports_to_syscalls_for_rosetta_debugging -- --nocapture`
- `cargo test -p carrick-runtime --lib vdso_debug_control_is_opt_out -- --nocapture`
- `cargo test -p carrick-runtime --lib hardware_tso_debug_control_only_suppresses_requested_tso -- --nocapture`
- `cargo test -p carrick-mem --lib el1_maintenance_bytes_emit_tlbi_then_hvc1 -- --nocapture`
- `cargo test -p carrick-runtime --test integration futex_ -- --nocapture`
- `cargo test -p carrick-runtime --lib host_guest_xattr_api_hides_all_internal_carrick_names -- --nocapture`
- `cargo test -p carrick-runtime --test integration xattr -- --nocapture`
- `cargo test -p carrick-hvf --lib mapping_lookup -- --nocapture`
- `cargo test -p carrick-hvf --lib child_copies_all_other_gprs_and_sysregs -- --nocapture`
- `cargo test -p carrick-mem --lib alias -- --nocapture`
- `cargo test -p carrick-cli --test conformance conformance -- --exact --nocapture`
- `cargo test -p carrick-cli --test conformance conformance_probes -- --nocapture`

Live amd64 checks used scoped `CARRICK_RUN_ID`s and cleaned only their own run
ids with `scripts/sudo/kill.sh "$RUN_ID"`.

Safety branch from the earlier rebase remains:
`feat/rosetta-glibc-amd64-prerebase`.
