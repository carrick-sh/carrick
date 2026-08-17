# Post-SIGCHLD conformance closure checkpoint

This checkpoint measures the reviewed post-exec child-exit signal-authority
fix across the complete frozen macOS/HVF arm64 conformance surface. The full
Carrick phase completed before the 84 Docker cache-miss rows began. The strict
probe phase then exercised both arm64 libc sets against the same signed Carrick
binary. This is a red discovery checkpoint, not a conformance-complete claim.

## Artifact

- Binary source: `3ef2bf7a8f04dd31ffba54ae4a036ced96e149e2`
- Frozen-scope commit: `abcc3728` (docs-only; binary unchanged)
- Signed Carrick SHA-256:
  `f559bfac450706ea7cac7e0054ed5982e603187dddbb9e6890805f87d88fa95c`
- CDHash: `72d8a02c66e89dc4b7333978e2dff083a74b2da4`
- LC_UUID: `196E6ADB-5BC6-3B46-BFF9-DD78FFD1BDAC`
- Hypervisor entitlement: present/true
- `__TEXT,__dof_carrick`: present
- Manifest SHA-256:
  `36042b91814ca767d61a6615c0023aa07773b7f5649fc65038fae6c34367d282`
- Image identities are unchanged from `scripts/conformance/closure-scope.json`.

`RUST_TEST_THREADS=1 just ci` passed on the binary source tree. Its durable log
is `target/conformance/closure-after-sigchld/just-ci.log` (596,265 bytes,
SHA-256
`a998c51854849da30d91e4dd0703d2186e045415862da78cac5ba5d5d4de8102`).

## Complete results

- Suites: 2,127 unique rows; 1,199 MATCH and 928 INCOMPLETE.
- Semantic assertion gaps: 4,761, down from 7,006.
- Unexercised assertion rows: 7,775, down from 10,037.
- Infrastructure-affected suites: 605, unchanged.
- Blocked timeouts: 6, unchanged in count but not identity.
- Strict probes: 858/858 rows; 844 PASS and 14 FAIL, unchanged in count.
- Valid completing `>=10x` pathologies: 6, down from 7.

The suite headline moves by only one because closure rejects any remaining
failed or skipped assertion, but the executed assertion surface moved
substantially:

- `node-app-smoke` is exact TAP MATCH at 2,405 ms / 406 ms = 5.92x.
- `node-v8-smoke` is exact TAP MATCH at 975 ms / 404 ms = 2.41x.
- `node-libuv` no longer reaches its 180-second wrapper deadline. It emits all
  507 planned TAP positions in 58,299 ms: 498 exercised assertions (490 pass
  and 8 fail) plus 9 skipped assertions.
  Its Docker row remains an invalid one-assertion setup failure because the
  manifest launches the root-dropping wrapper as uid 65534; its 145.02x ratio
  is therefore not valid performance evidence.
- `cpython-asyncio` advances from 64 observed passing assertions to 2,521
  passing assertions and completes in 110,951 ms. It remains INCOMPLETE because
  closure rejects its 18 skipped assertions.
- `cpython-multiprocessing_main_handling` and `go-runtime_pprof` become MATCH.
  The former is now a valid 11.01x pathology and remains correctness-blocking.

Four rows changed to MATCH (`node-app-smoke`, `node-v8-smoke`,
`cpython-multiprocessing_main_handling`, and `go-runtime_pprof`). Three
previous MATCH rows changed to INCOMPLETE (`ltp-kill10`, `ltp-shmctl05`, and
`ltp-waitpid13`). The timeout roster also rotated: `cpython-compileall`,
`cpython-concurrent_futures`, and `cpython-multiprocessing_main_handling`
cleared their prior timeouts, while `cpython-multiprocessing_fork`,
`ltp-kill10`, and `ltp-shmctl05` timed out in this eight-worker discovery run.
Those three regressions require isolated repeated attribution before being
assigned to this change; no waiver or retry-recovered acceptance was added.

The six currently valid `>=10x` rows are:

- `cpython-multiprocessing_main_handling` 11.01x
- `go-crypto` 32.39x
- `go-crypto_internal_fips140deps` 15.45x
- `go-go_build` 32.28x
- `go-go_doc_comment` 24.05x
- `ltp-timerfd_settime02` 32.50x

## Probe closure

The strict build produced exactly 430 selected musl binaries and 430 selected
GNU binaries. The 818 generic rows and 40 dedicated rows were all emitted;
there were no missing, skipped, infrastructure, or unexercised probe rows.
Fourteen semantic failures remain: ten generic and four dedicated. Although
the total is unchanged, the exact set changed: `childsubreaper` moved from a
musl failure/GNU pass to a musl pass/GNU failure. The generated ledger names
every current source/libc/runner tuple.

The aggregate probe log SHA-256 is
`743ed399a669bb5bf42662e3741b0cc3627f8367133aea4106003cc6fdb162cc`.
The component log SHA-256 values are:

- build: `2e477f0946d99242ca0add614b1218674c321b10fc4ca02287c35e7204bfcd02`
- generic: `541e6b608bd595a36b342fdbe21ba63e5c24c75a54b9c0597d5f87463e1a5287`
- dedicated: `f1ce12628ba6de5555eaba50fa27d0d286b4620ff69792c232552d01b4270848`

The build exited 0. The generic and dedicated executions exited nonzero because
the 14 real conformance gaps remain; those red exits are the intended fail-closed
result.

## Raw evidence and cleanup

- Results JSONL:
  `target/conformance/closure-after-sigchld/results.jsonl` (2,127 lines,
  SHA-256
  `023879245685a900891eebf6bf9ce7a2b78b3c145d93bf7b0dbb95da1763f499`)
- Suite log: `target/conformance/closure-after-sigchld/suites.log`
  (SHA-256
  `f1aa80aa7c0569a6dc94fd84087d5138e445be886cd5a16a91e5799e7a0accd1`)
- Probe log: `target/conformance/closure-after-sigchld/probes.log`
- Generated controller: `docs/conformance-closure-ledger.md`
- Suite closure exit: 1, caused by the 928 explicit INCOMPLETE rows.
- Scoped Carrick cleanup: zero processes for the suite, generic-probe, and
  dedicated-probe run IDs.
- Docker cleanup: zero `conf-*` containers.

No baseline was blessed, no known gap or retry was accepted, and the signed
binary hash remained unchanged through the suite and probe phases.
