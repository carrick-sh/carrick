# CI input caches and fetch failures

Hosted CI prepares external inputs before compiling or testing. The setup and
fetch composite actions restore exact `actions/cache` keys, invoke `justfile`
recipes, and save successful inputs immediately, even if a later code check
fails. Workflow step deadlines additionally cap multi-input preparation,
leaving time for failure reporting within the job deadline. There are no
fallback restore keys. Changing an input pin invalidates
its cache. Compiled artifacts still use the separate `Swatinem/rust-cache`.

| Input / consumer | Cache identity and verification | Miss policy |
| --- | --- | --- |
| Rust, all compiling jobs | OS, architecture, entire `rust-toolchain.toml` (version, components, targets); rustup verifies distribution checksums | `RUSTUP_MAX_RETRIES=5`, 600-second process-group deadline |
| Bootstrap just | OS, architecture, `inputs/tools.json`; just 1.58.0, checksums from the SHA-pinned install-action manifest, no installer fallback | Pinned action's finite retries; curl connect 15 s, transfer 180 s, retry window 240 s; enclosing setup step 12 min |
| sccache, cargo-deny | OS, architecture, tool list and `inputs/tools.json` (versions, URLs, SHA-256); verify cached archives on every use | curl: 5 retries including transport errors, connect 15 s, attempt 180 s, retry window 1,100 s |
| actionlint | OS, architecture, justfile containing 1.7.12 and SHA-256; verify archive on every use | Same bounded curl policy |
| Semgrep | OS, architecture, Python ABI and `inputs/semgrep.txt`; fully pinned transitive dependencies and wheel hashes | pip: 5 retries, 30-second socket timeout, 600-second download deadline; wheel-only, hashed offline install on every run |
| FreeBSD sysroot | Release and justfile hash (the #637 mirror URLs and pinned SHA-256); verify cached archive before extracting | Preserve #637's ordered archive and release mirrors (including the project release copy); each mirror connect 20 s, attempt 600 s, 2 retries; workflow step cap 8 min |
| NetBSD sysroot | `inputs/sysroots.json`: permanent archive URLs, release and SHA-512; verify cached archives before extracting | Same bounded curl policy; step cap 8 min for both archives |
| Linux / BSD C tools from apt | Runner image OS/version, architecture, package group, recipe hash; authenticated apt indexes and version-named debs cached together | 5 retries, HTTP(S) timeout 30 s, each command 600 s; warm installs use `--no-download` |
| Cargo registries and git sources | OS, architecture, committed lockfiles/manifests and Cargo configuration; Cargo checks registry checksums and locked git revisions | Try locked offline fetch first; otherwise 5 transport retries, HTTP timeout 30 s, 600-second deadline per manifest; builds then use `CARGO_NET_OFFLINE=true` |
| Event base git commits (`ci-probe-coverage-base`, `ci-changes`) | Full checkout/object database, commit SHA; never contact origin for an existing commit | At most 6 attempts, each 30 s, HTTP low-speed bound 15 s |
| gcloud SDK (hosted GCP controller) | `inputs/gcloud.json`: 589.0.0 archive URL and SHA-256; verify on every use | Same bounded curl policy |

Paths under `inputs/` above are relative to `scripts/ci/`. Local recipe runs can
set `CARRICK_CI_CACHE` to an isolated directory. Semgrep also needs
`RUNNER_TEMP`; sysroot recipes retain their `FBSD_*` / `NBSD_*` arguments.
Rustup and Cargo retain their normal homes. The offline Cargo population covers
the workspace, conformance probes, fixture workspaces, fuzzing, crate test
fixtures, and script tools used by the gates; historical experiments and
archived evidence are not CI build inputs. The fuzz lockfile's workspace edges
were refreshed so dependency preparation can remain `--locked`.

The two receipt-gate jobs execute only the merge-group **base** tree. Their
thin bootstrap steps use official cache actions, the base toolchain/lockfile,
`RUSTUP_MAX_RETRIES=5`, Cargo's transport bounds, and a 15-minute step deadline.
They cannot use a candidate's new recipe or local action before it has landed.
The signed HVF job retains its administrator-provisioned read-only Rust tree;
setup never attempts to cache, install or update that toolchain.

Fetch steps write `ci-fetch-status` under `RUNNER_TEMP` **before** attempting a
restore/download. Success restores the previous status; a later successful
fetch cannot erase an earlier failure. Timeout or failure leaves the input
name behind. Always-run reporters expose it as a job output and step summary;
`ci-results` explicitly names infrastructure fetch failures and still fails
closed. Other checks skip after infrastructure preparation fails, leaving time
for the reporter. Tests and conformance verdicts are never retried.

## Other workflow network operations and boundaries

GitHub checkout/action distribution, artifact upload/download, issue/PR API
queries, WIF authentication, fixture relay publication, and receipt polling are
run-specific service operations. Caching their responses could substitute the
wrong commit, authorization or receipt. They retain their existing action/job
bounds and transport integrity. The fixture relay already verifies the
publisher's SHA-256, bounds the whole download to 300 s (maximum 600 s), allows
one transport retry per part, and falls back to the run's GitHub artifact.
Fixture dependency fetches use the prepared Cargo cache offline first.

Not covered: provisioning **inside** the optional GCP fallback VM
(`scripts/ci/gcp-kvm-run.sh`), and owner-run Willow/cloudmac template
provisioning. A fresh GCP VM has only an objectCreator receipt-bucket account;
sharing an input cache there needs a separate transport/IAM or image-owner
change. The director explicitly excluded that fallback bootstrap from #615.
The hosted controller's SDK is covered above.

Pin provenance: binary tool hashes come from install-action commit
`e407f7bafb71fd004bc5c2da3032e5470cbb6ef0`; the FreeBSD base hash comes from
[the release team's ports manifest](https://github.com/freebsd/freebsd-ports/blob/26b1960fce527352233bdd7da0e293b881e719e1/misc/freebsd-release-manifests/files/MANIFESTS/amd64-amd64-14.3-RELEASE),
#637 owns the FreeBSD mirror list and digest; this layer preserves both.
NetBSD hashes from [the release SHA512 file](https://archive.netbsd.org/pub/NetBSD-archive/NetBSD-10.1/amd64/binary/sets/SHA512).
The gcloud SHA-256 was computed from the versioned official archive and checked
against its public Cloud Storage object's MD5 metadata. Refresh the Semgrep
lock with `uv pip compile --universal --generate-hashes --python-version 3.12`
from `semgrep==1.179.0` (or the deliberately updated pin), then verify cold and
warm wheel installs on the affected Python ABIs.
