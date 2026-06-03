# Carrick Rosetta linux/amd64 support

Status date: 2026-06-02

Carrick can run glibc-dynamic `linux/amd64` OCI images on Apple Silicon by
launching Apple's installed Linux Rosetta interpreter inside the guest. The
supported target is ordinary dynamic amd64 userspace from images such as
`ubuntu:24.04`; static-musl amd64 probes are not part of the supported Rosetta
scope yet.

## Running

Use an explicit platform and accept the Apple Rosetta terms for the run:

```sh
CARRICK_ACCEPT_ROSETTA_TERMS=1 \
  CARRICK_RUN_ID="cr-manual-$$" \
  target/release/carrick run --platform linux/amd64 --fs host ubuntu:24.04 /bin/uname -m
```

Expected output is `x86_64`. Native arm64 remains the default platform and
reports `aarch64`.

Always set a unique `CARRICK_RUN_ID` for live debugging and clean up only that
run id with `scripts/sudo/kill.sh "$CARRICK_RUN_ID"`.

## Architecture

The `--platform linux/amd64` path selects the amd64 OCI manifest, then redirects
the initial x86-64 ELF load and amd64 `execve` loads to Apple's
`/Library/Apple/usr/libexec/oah/RosettaLinux/rosetta` interpreter. Carrick does
not bundle Apple bytes; it reads the user's installed Rosetta binary at runtime.

Rosetta runs as AArch64 Linux userspace inside Carrick's HVF guest. It JITs
x86-64 code and translates x86-64 syscalls before they reach Carrick, so
Carrick's dispatcher still sees AArch64 Linux syscall numbers.

The Rosetta-specific kernel surface Carrick provides includes:

- Rosetta license/info ioctls on `/proc/self/exe`.
- `prctl(PR_SET_MEM_MODEL, TSO)` by setting `ACTLR_EL1.EnTSO` for hardware x86
  TSO.
- `uname`/platform reporting for amd64 guests.
- 48-bit TTBR0 and TTBR1 stage-1 configuration so Rosetta can use both lower and
  x86-64 high-half canonical addresses.
- High-VA aliases that map guest VAs above the HVF IPA ceiling into a low IPA
  arena while preserving the guest VA in stage-1.
- Standard AArch64 `rt_sigreturn` restoration from `ucontext.uc_mcontext` at
  the current SP, which is the shape Rosetta rebuilds after x86 signal handlers.
- Fork/clone vCPU snapshots that preserve `TTBR1_EL1` and `ACTLR_EL1`, so child
  guests keep the high-half root and TSO state.

## Fixed bring-up gaps

These are no longer frontier work:

- TTBR1 / upper-half support is implemented and restored across fork.
- High-VA file and anonymous aliases map only the guest-requested stage-1 length;
  HVF's 16 KiB host granule is rounded separately.
- High-VA syscall buffer lookup resolves by the guest's live stage-1 IPA before
  falling back to newest-first VA lookup, so overlapping alias metadata cannot
  send copies to a stale backing.
- `FUTEX_LOCK_PI_PRIVATE`, `FUTEX_TRYLOCK_PI_PRIVATE`, and
  `FUTEX_UNLOCK_PI_PRIVATE` have an uncontended/private fast path. The lock word
  records the same guest-visible TID that `gettid(2)` returns.
- Host-backed `listxattr` reports an empty list for "no xattrs", matching Linux
  and removing the former `ls -la /` ENODATA diagnostics.

## Conformance

The conformance harness has two lanes:

- `arm64`: existing native shell cases and the full static aarch64-musl probe
  gate.
- `amd64-rosetta`: glibc-dynamic shell cases against `ubuntu:24.04`. This lane
  self-skips if Rosetta for Linux is not installed.

The static-musl probe gate intentionally skips `amd64-rosetta` because Apple's
Linux Rosetta path does not currently run the x86_64 static-musl probe set. The
probe build script still builds an explicit arch-neutral x86_64 smoke binary
(`futexpilock`) so the cross-target build path stays exercised.

Useful gates:

```sh
scripts/build-probes.sh
cargo test -p carrick-cli --test conformance conformance -- --exact --nocapture
cargo test -p carrick-cli --test conformance conformance_probes -- --nocapture
cargo test -p carrick-runtime --test integration futex_ -- --nocapture
cargo test -p carrick-mem --lib alias -- --nocapture
cargo test -p carrick-hvf --lib mapping_lookup -- --nocapture
```

## Known limitations

Two amd64 Rosetta workloads remain outside the fixed syscall/data-path set.
Both have clean Carrick compatibility reports. Docker Desktop on this host is
configured for Apple Virtualization Framework Rosetta
(`UseVirtualizationFramework=true`, `UseVirtualizationFrameworkRosetta=true`)
and passes both reduced controls, so the current evidence points at
Carrick/Rosetta interaction rather than a general upstream Rosetta-on-Linux
failure.

### dash fd-input long-token parsing

`dash` misparses a long parser token when reading script text from a file
descriptor under Carrick/Rosetta. A 1350-byte quoted token from fd input reports
`Syntax error: Unterminated quoted string`.

Fresh trace evidence with `carrick trace`:

- dash reads the full 1366-byte script from fd 0 in one `read(2)` returning 1366.
- The same fd input parses correctly in `bash` and prints `1350`.
- The same long token parses correctly in `dash -c`, so dash's argv parser is
  not the failing path.
- Docker Desktop amd64 with Rosetta parses the same fd input and prints `1350`.
- A privileged Docker/Rosetta `bpftrace` baseline shows
  `read(fd=0, count=8192) -> 1366`, then EOF, matching the Carrick trace data
  path shape.
- `carrick trace` shows the same `read(fd=0, count=8192) -> 1366`, then EOF
  sequence; only Carrick/Rosetta's translated dash parse result differs.
- `scripts/dtrace/trace-guest-mem-copy.d` compares Carrick's selected syscall-copy
  mapping against the guest's live high-VA stage-1 translation. For the failing
  fd-input read, the checked write into `0x555555574ac0` is a `MATCH`
  (`va_off=0x2ac0`, `ipa_off=0x2ac0`) and the payload fingerprint matches the
  expected long-token script edges.

This localizes the issue to dash's translated fd-input token accumulation path,
not Carrick's read buffer or file contents, not the prior stale stage-1/stage-2
alias class, and not a general Apple Rosetta fd-input parser failure.

### apt / gpgv secure verification

The reduced `gpgv` secure-verification failure is fixed on this branch. Before
the fix, `apt-get update` under amd64 Rosetta downloaded InRelease files but
failed secure verification with apt's "Good signature, but could not determine
key fingerprint" error. A reduced direct check showed the sharper symptom:

- pre-fix amd64 Carrick/Rosetta: direct `gpgv --status-fd` on the downloaded
  `archive.ubuntu.com/ubuntu/dists/noble/InRelease` reported `BADSIG`.
- arm64 Carrick on the same URL reports `GOODSIG` and `VALIDSIG`.
- Docker Desktop amd64 with Apple Virtualization Framework Rosetta reports
  `GOODSIG` and `VALIDSIG`.
- A privileged Docker/Rosetta `bpftrace` baseline shows `gpgv` opening and
  reading `/tmp/InRelease` and `ubuntu-archive-keyring.gpg` through `read(2)`,
  which matches the syscall family seen in `carrick trace`.
- The direct `carrick trace` comparison matches the target read sequence:
  `InRelease` is read as `65536 + 65536 + 65536 + 59242` bytes then EOF, and
  the keyring is read through full `read(2)` passes ending in EOF. The
  divergence remains in translated userspace after those bytes are delivered.
- `LC_ALL=C` did not make Carrick/Rosetta validate the signature; Docker/Rosetta
  still reported `GOODSIG`/`VALIDSIG`, while Carrick/Rosetta reported
  `ERRSIG`/`NO_PUBKEY` with invalid packet diagnostics.
- The amd64 and arm64 Carrick runs read identical SHA256 inputs:
  `InRelease` is `cdb2f31d809f589719a53c6ad15f255b27569c4059542ada282aaa21b8e164b0`,
  and `ubuntu-archive-keyring.gpg` is
  `80a36b0a6de2f69f49d2df75ef473ccde121e9e190b9ea01d20a4f63778d5c31`.
- `carrick trace` shows `gpgv` reads the keyring and InRelease through `read(2)`
  buffers, not file-backed mmap, and no unhandled/partial syscall is reported.
- `scripts/dtrace/trace-guest-mem-copy.d` reproduced `BADSIG` while reporting zero
  `MISMATCH` events. The checked high-VA syscall-copy buffers for the keyring and
  InRelease reads all matched the live stage-1 backing, including the keyring
  `3607`-byte read and the InRelease
  `65536 + 65536 + 65536 + 59242`-byte read sequence.
- A host-built amd64 glibc `libgcrypt.so.20` SHA256 probe agrees with
  `sha256sum` under Carrick/Rosetta, so the broad libgcrypt digest path is not
  the reduced failure.
- `gpgv --output /tmp/plain ... /tmp/InRelease` writes the same cleartext length
  as Docker/Rosetta (`254968` bytes), but Carrick's output hash differs. The
  live zero-based first byte diff is at cleartext byte `61567`, where Carrick
  has NUL bytes instead of normal ASCII package-index text.
- The canonical Carrick bad output has exactly three large NUL runs:
  `(61567, 3920)`, `(127103, 3920)`, and `(192639, 3920)`. They are spaced
  exactly 64 KiB apart. Inside each bad 8 KiB output write, the NUL window
  starts at chunk offset `4223` and has length `3920`.
- Comparing `gpgv --output /tmp/plain` with `gpgv --output - > /tmp/plain_stdout`
  shows the two output routes are byte-identical under Carrick/Rosetta and bad,
  while the same route split is byte-identical and good under Docker/Rosetta.
  That rules out gpgv's direct output-file path and shell redirection as the
  differentiating branch.
- vDSO was driven down with debug modes. Removing the vDSO header made Rosetta
  assert before `gpgv`; removing the `__kernel_getrandom` export produced
  the canonical bad hash; removing all fastpath exports made Rosetta assert on
  missing `__kernel_clock_getres`; and routing clock symbols through syscall
  stubs produced the canonical bad hash. Rosetta requires the vDSO header
  and clock symbols, but Carrick's getrandom and clock vDSO fastpaths are not
  the gpgv corruption cause.
- TSO was driven down. `CARRICK_DISABLE_TSO=1` produced the canonical bad
  hash and the same NUL windows. Docker/Rosetta validates successfully even
  though its `PR_SET_MEM_MODEL, TSO` calls return `EINVAL`; Carrick accepting the
  request and toggling ACTLR is not the differentiating cause.
- A direct `carrick trace` event-shape run saw the final gpgv process perform
  `mmap=163`, `mprotect=12`, `munmap=3`, `getrandom=83`, `prctl=2`,
  `prlimit64=1`, one private `futex` wake, and no `clone`, `mremap`, or
  `membarrier`. A privileged Docker/Rosetta bpftrace baseline produced good
  output with the same mmap/mprotect/munmap/prlimit families and 84
  `getrandom` returns. The small event-count differences are not leading causes
  because the no-getrandom and no-TSO runs remain bad.
- `scripts/dtrace/trace-write-buffers.d` shows the recurring bad output chunks
  (`57344`, `122880`, `188416`) are already corrupted in the guest buffer before
  Carrick performs the host `write(2)`. The selected mapping and
  start/25%/50%/75%/last stage-1 samples for those write buffers all report
  `MATCH`, including the 75% sample that lands inside the canonical NUL window
  of each bad 8 KiB write.
- The output buffer alias itself looks coherent: alias map and PTE walks report
  success, there are no overlapping later `mprotect`/`munmap` operations, and
  no page-table pause or alias failures are reported. Correcting the EL0/EL1
  maintenance trampoline from local `tlbi vmalle1` to inner-shareable
  `tlbi vmalle1is` did not change the gpgv symptom.
- The watchpoint run on `0x5555555e5d90`, an address inside the recurring bad
  window, shows the word is already zero before Carrick dispatches each bad
  write. The opt-in subrange probe
  (`CARRICK_GUEST_MEM_SUB_OFFSET=4223`, `CARRICK_GUEST_MEM_SUB_LEN=3920`) shows
  the exact bad subrange has `sum=0`, `head=0`, `tail=0`, and `nonzero=0` for
  writes `57344`, `122880`, and `188416`, while neighboring chunks have nonzero
  checksums and `nonzero=3920`.
- A tiny clear-signed-message extractor is not affected. The same AWK extractor
  produces byte-identical Docker/Rosetta and Carrick/Rosetta outputs with the
  good cleartext SHA256
  `26758a13cecfaff9ff274d31ea9a4633674a999bd130c09f6ecd66a4b8071184`.
  That rules out a generic cleartext parser/output path and keeps the remaining
  failure inside gpgv's translated verifier/emitter path.
- Captured output was not required for the bad signature result. Docker reported
  `GOODSIG`/`VALIDSIG` for captured output, `/dev/null`, and no explicit output;
  Carrick reported `BADSIG` for all three.
- Detached verification passed under Carrick when the clearsigned message was
  split into a Docker-valid detached signature fixture. That moved the failure
  out of RSA/signature verification and into clearsigned-message parsing and
  canonicalization.
- Host-generated clearsigned fixtures reproduced the threshold. Carrick passed
  small payloads (`32768`, `49152`, `57344`) with byte-identical output. Around
  `61440`-`64000`, Carrick could emit byte-identical cleartext but report
  `NODATA`. At `65000` and above, Carrick produced the same near-64 KiB zero
  window family; the controlled first window was `(61663, 3824)`, then every
  `65536` bytes. Docker reported `GOODSIG`/`VALIDSIG` throughout.
- Verbose gpgv on those controlled fixtures shows Carrick losing clearsigned
  armor/signature state near the threshold (`block_filter: 1st length byte
  missing`, then `unexpected armor: -----END PGP SIGNATURE-----`) before the
  larger fixture becomes a normal `BADSIG`.
- Watching the original InRelease input buffer at the first bad-output offset
  showed the input word stayed nonzero through the bad output writes. That made
  input delivery look unlikely until a narrower read-buffer trace checked the
  tail of the 64 KiB `read(2)` destination.

Corrected root cause: Carrick's syscall guest-memory copy helpers selected one
mapping for an entire buffer. The first 64 KiB InRelease read crossed a live
stage-1 owner boundary: bytes before `0x5555555c3000` belonged to the old
mapping, while the tail beginning at `0x5555555c3000` translated to a newer
alias mapping. Carrick copied correct bytes into the old backing for that tail,
but translated `gpgv` read zeros from the new backing. The helpers now walk
copies in 4 KiB stage-1 chunks and reselect the mapping for each chunk.

Post-fix validation:

- `rosetta-gpgv-aliasfix-1780418798-36608`: direct InRelease `gpgv` returns rc
  0 with `GOODSIG`/`VALIDSIG`, writes 254968 bytes, and matches Docker's
  cleartext SHA256
  `26758a13cecfaff9ff274d31ea9a4633674a999bd130c09f6ecd66a4b8071184`.
- `trace-read-subrange-aliasfix-1780418821-37179`: targeted trace returns rc 0,
  reports `0` `MISMATCH` lines, and shows the old bad tail split at
  `0x5555555c3000` with `map_start=0x5555555c3000`, `MATCH`, and nonzero
  subrange bytes.
- `rosetta-clearsign-aliasfix-1780418876-39855`: the controlled
  `thresh_65536.asc` fixture returns rc 0 with `GOODSIG`/`VALIDSIG` and a
  Docker-matching cleartext hash.
- `rosetta-apt-update-aliasfix-1780418888-40044`: full `apt-get update` fetched
  all four InRelease files and emitted no signature error, but it was stopped
  after a separate hang and exited 137. Track that as a separate apt surface if
  it reproduces.
