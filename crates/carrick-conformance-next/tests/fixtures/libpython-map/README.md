# Private fixed file loader layout (#759)

Clean-room fixture from mmap(2) and the signed syscall shapes in #759.
The native x86_64 Linux diagnostic passes. The oracle is provisional until
blessed on native ARM64 Docker; a provisional pass is not Linux acceptance.
The recorded reservation flags are 0x822 (private anonymous, DENYWRITE),
while the text/data flags are 0x812 (private fixed file, DENYWRITE). The
fixture covers that observed anonymous reservation first, then the file-backed
reservation requested in the brief. Text is aligned to 64 KiB within the
reservation and unused prefix/suffix mappings are trimmed. The trace omits
trim arguments, mprotect arguments and the data file offset; the fixture
protects the data target NONE and exercises offsets 0x47a000 and 0x479000,
respectively congruent and incongruent with its VA modulo a 16 KiB host page.
It does not claim the omitted arguments were recovered.

The signed case opens the real immutable OCI lower file
`/usr/local/lib/libpython3.12.so.1.0` in `python:3.12-slim`. A static probe can
exercise the failing loader pattern without first loading libpython. This
matters: a newly created mutable /tmp file takes a different old lowering
path. With no filename argument, the standalone probe creates a patterned real
file for VM-free native diagnostics. All data bytes, private stores and the
two adjacent bytes are checked. No waits, forks or blocking IPC are used.

The signed runner automatically rebuilds the fixture and its compiled source
fingerprint. From the repository root on the Mac:

```sh
CARRICK_RUN_ID=759-libpython-map env -u RUSTC_WRAPPER CARRICK_SCCACHE=0 just test-conformance-next case_libpython_ --nocapture
```

The test hashes current source and executable and requires the guest to emit
its compiled source fingerprint. Run the same static binary on native ARM64
Docker after stopping Carrick, retain image digest, kernel identity, binary
hash and stdout, and bless `oracle.json` against that evidence.
The startup selector additionally requires `python:3.12-slim python3 -c
'print(1)'` to succeed. The existing deferred-anonymous, signal-mask and
syscall-destination witnesses now have `case_` names so signed selectors
include them. Full signed promotion and the CLI startup demo remain required.

After stopping all Carrick phases, the director can bless the same binary on
native ARM64 Docker (record the resolved image digest and kernel identity):

```sh
docker run --rm --platform linux/arm64 --mount "type=bind,src=$PWD/target/libpython-map/aarch64-unknown-linux-musl/release/libpython-map,dst=/tmp/libpython-map,readonly" python:3.12-slim /tmp/libpython-map /usr/local/lib/libpython3.12.so.1.0
```
