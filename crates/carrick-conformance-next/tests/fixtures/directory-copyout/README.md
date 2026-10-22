# Untouched directory destinations (#759 stage 2)

Clean-room getdents(2) fixture. A real lower-layer directory is opened with
openat(O_DIRECTORY), fstat is reported separately, then raw getdents64 drains
into a fresh 32 KiB anonymous-private mmap, a fresh 2 MiB malloc allocation,
and an initialized 1 KiB stack buffer.
The mmap and malloc payloads are untouched before their first syscall. Complete names are
parsed, sorted, checked for duplicates and compared across destinations.
The process reports numeric errno values and exits nonzero on a failure.
Native x86_64 Linux is diagnostic; native ARM64 Docker is the oracle.

From the repo root on the Mac, the signed runner rebuilds the fixture and
compiled source fingerprint:

```sh
CARRICK_RUN_ID=759-directory-copyout env -u RUSTC_WRAPPER CARRICK_SCCACHE=0 just test-conformance-next case_libpython_directory_copyout --nocapture
```

Run the same fixture source at the pre-fix witness commit and the candidate.
The candidate adds the normal-buffer control and enlarges malloc; preserve
those fixture changes when switching the runtime to the pre-fix witness. This test
prints the actual guest output before requiring a blessed exact oracle, so
a missing bless cannot conceal which syscall failed. Keep source hash,
executable SHA-256, image digest, kernel identity and output for both runs.
The oracle is intentionally pending until the director supplies that evidence.

After stopping Carrick, run the exact same static ELF in native ARM64 Docker:

```sh
docker run --rm --platform linux/arm64 --mount "type=bind,src=$PWD/target/directory-copyout/aarch64-unknown-linux-musl/release/directory-copyout,dst=/tmp/directory-copyout,readonly" python:3.12-slim timeout 10 /tmp/directory-copyout /usr/local/lib/python3.12
```

For native diagnostics the first argument may name any real directory. No
waits, guest subprocesses, fake backends, or image mutations are involved.
Output excludes inode values, ordering and syscall batch sizes, which are
not portable directory-stream identities. Timing/work acceptance remains a
separate paired same-image measurement; exact output alone does not prove it.
