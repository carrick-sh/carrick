# ELF exec errno witness

Clean-room fixtures from [elf(5)](https://man7.org/linux/man-pages/man5/elf.5.html)
and the System V ABI. This records numeric errno **and** exit/signal status:
Linux may reject a segment after exec's no-return point. A valid static
AArch64 exit(0) control must execute first. All child waits are bounded.

`oracle.json` is **provisional, pending the director's native arm64 Linux
bless**. Its current assumptions are ENOEXEC (8), no signal, and child exit 0
for main ET_REL, p_filesz > p_memsz, and unterminated PT_INTERP;
ELIBBAD (80) for existing ET_REL/non-ELF interpreters; ENOENT (2) for
a missing interpreter. Valid and embedded-NUL interpreters exit 42. Both
the full and formerly truncated interpreter paths exist, preventing an
accidental missing-file pass. A passing
provisional comparison establishes Carrick's behavior, not Linux parity.
Do not copy these assumptions into the generic blessed oracle cache.

The signed runner builds this fixture automatically (no Docker). For a
standalone build from the repository root:

```sh
source /Volumes/carrick/dev/env.sh
export CARRICK_RUN_ID=elf-fix-probe-build
fixture=crates/carrick-conformance-next/tests/fixtures/elf-exec-errno
export CARRICK_ELF_FIXTURE_SOURCE_SHA256=$(shasum -a 256 "$fixture/src/main.rs" | cut -d ' ' -f 1)
CARGO_TARGET_DIR="$PWD/target/elf-exec-errno" cargo build --manifest-path "$fixture/Cargo.toml" --target aarch64-unknown-linux-musl --release --locked
just test-conformance-next case_elf_exec_errno --exact --nocapture
```

The guest prints the compiled source fingerprint; the embedded runner checks
the current source against the oracle, compares all output, and records the
binary SHA-256. The signed runner records executable identity and cleanup.
Run the **same guest binary** on native arm64 Linux to bless: retain its stdout,
binary hash, image digest and kernel identity, then update `stdout` and change
`status` to `blessed` with that provenance. Do not normalize a death into errno.

Carrick cannot currently represent a non-UTF-8 interpreter pathname in its
string-based filesystem API. The probe explicitly checks ENOEXEC (8) rather
than silently running the main image. Native Linux accepts pathname bytes;
this absent non-UTF-8 pathname is expected to return ENOENT (2). The oracle
stores native output; the host test names and checks this single representation
limit separately. This is a disclosed divergence, not a parity claim.
