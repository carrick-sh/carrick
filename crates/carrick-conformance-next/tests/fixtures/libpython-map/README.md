# Private fixed file loader layout (#759)

Clean-room fixture from mmap(2) and the signed syscall shapes in #759.
The native x86_64 Linux diagnostic passes. The oracle is provisional until
blessed on native ARM64 Docker; a provisional pass is not Linux acceptance.
The trace supplied to this worker omits the trim addresses and data offset:
the fixture uses two unused suffix pages for trims and exercises offsets
0x47a000 and 0x479000, respectively congruent and incongruent with the data
VA modulo a 16 KiB host page. It does not claim those omitted arguments were
recovered. Both are legal Linux mappings. All data bytes, private stores and
the two adjacent bytes are checked. No waits, forks or blocking IPC are used.

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
