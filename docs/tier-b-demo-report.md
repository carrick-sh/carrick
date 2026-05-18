# Tier B demo report — `busybox echo hello` against Alpine

## Environment

- Date: 2026-05-18
- macOS: `Darwin Timothys-MacBook-Air-2.local 25.5.0 Darwin Kernel Version 25.5.0: Mon Apr 27 20:41:26 PDT 2026; root:xnu-12377.121.6~2/RELEASE_ARM64_T8132 arm64` (macOS 26 / Tahoe, Apple Silicon)
- Carrick worktree: `/Volumes/CaseSensitive/carrick/.claude/worktrees/agent-ab27f527132522b0f`, branch `main` @ `02eddd3` (clean before this report)
- Release build: `cargo build --release --bin carrick` succeeded in 25.8s, no warnings of note.
- HVF capabilities (`./target/release/carrick trap-capabilities`):

```json
{
  "backend": "hypervisor_framework",
  "available_on_this_host": true,
  "implemented": true
}
```

## Pull attempt

### First attempt — tag reference

Command:

```
./target/release/carrick pull docker.io/library/alpine:latest
```

Outcome: **Registry rejected by client-side platform resolver.** Exact error:

```
Error: OCI registry operation failed: Image manifest not found:
  no entry found in image index manifest matching client's default platform
```

Root cause: `src/oci.rs::pull_image` constructs `oci_distribution::Client::default()`. The default `ClientConfig` ships `platform_resolver = Some(current_platform_resolver)`, which matches manifests where `os == go_os()` AND `architecture == go_arch()`. On this host that evaluates to `os == "darwin" && architecture == "arm64"`, but `docker.io/library/alpine`'s OCI image index advertises only `linux/{amd64,arm/v6,arm/v7,arm64,386,ppc64le,s390x,riscv64}`. No entry matches `darwin/arm64`, so the resolver returns `None` and `oci-distribution` bails with the error above. The registry itself was reachable (HTTPS token endpoint and `/v2/library/alpine/manifests/latest` responded with the full index when probed directly via `curl`).

### Workaround — digest-pinned pull

Bypassed the resolver by fetching the `linux/arm64` manifest digest out-of-band and pulling it directly. The bootstrap accepts `@sha256:...` references and short-circuits the index-resolution path (digest references are fetched as concrete manifests).

```
TOKEN=$(curl -s "https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/alpine:pull" \
  | python3 -c "import json,sys;print(json.load(sys.stdin)['token'])")
curl -s -H "Authorization: Bearer $TOKEN" \
  -H "Accept: application/vnd.docker.distribution.manifest.list.v2+json,application/vnd.oci.image.index.v1+json" \
  "https://registry-1.docker.io/v2/library/alpine/manifests/latest" \
  | python3 -c "import json,sys
m=json.load(sys.stdin)
for x in m['manifests']:
    p=x.get('platform',{})
    if p.get('architecture')=='arm64' and p.get('os')=='linux':
        print(x['digest'])"
# -> sha256:378c4c5418f7493bd500ad21ffb43818d0689daaad43e3261859fb417d1481a0

./target/release/carrick pull \
  docker.io/library/alpine@sha256:378c4c5418f7493bd500ad21ffb43818d0689daaad43e3261859fb417d1481a0
```

Outcome: **success.** Result:

- Manifest digest: `sha256:378c4c5418f7493bd500ad21ffb43818d0689daaad43e3261859fb417d1481a0`
- Image dir: `/Users/tjfontaine/.carrick/images/docker.io/library/alpine/sha256/378c4c5418f7493bd500ad21ffb43818d0689daaad43e3261859fb417d1481a0`
- Config size: 627 bytes
- Layers: 1
  - Layer digest: `sha256:d17f077ada118cc762df373ff803592abf2dfa3ddafaa7381e364dd27a88fca7`
  - Media type: `application/vnd.oci.image.layer.v1.tar+gzip`
  - Size: 4,199,870 bytes (~4.0 MiB)
  - Path: `/Users/tjfontaine/.carrick/blobs/sha256/d17f077ada118cc762df373ff803592abf2dfa3ddafaa7381e364dd27a88fca7`

## Run attempt

Command (using the digest-pinned reference from the successful pull):

```
./target/release/carrick run \
  docker.io/library/alpine@sha256:378c4c5418f7493bd500ad21ffb43818d0689daaad43e3261859fb417d1481a0 \
  /bin/busybox echo hello
```

(Note: `Commands::Run` in `src/main.rs` does not expose `--max-traps` or `--compat-report`; it always uses `DEFAULT_MAX_TRAPS = 1_000_000` and prints the report inline. So `--max-traps 4096` from the brief is not accepted here.)

Outcome: **Failed before HVF was even constructed.** Exit code 1. No traps executed (the run never reached the dispatcher / HVF loop). Stderr (122 bytes, full):

```
Error: failed to compose image rootfs layers

Caused by:
    layer contains a path outside the rootfs: etc/../proc/mounts
```

Stdout was empty.

- Trap count reached: 0 (rootfs composition failed before any guest code was loaded; `LinuxAbi`, the dispatcher, `AddressSpace`, and HVF were never instantiated).
- First three unhandled syscalls: **N/A** — never started executing the guest.
- First three unhandled ioctls: **N/A**.
- First three unimplemented `/proc` reads: **N/A**.
- First three unimplemented `/sys` reads: **N/A**.
- Exit code (Linux guest sense): **N/A** — host process exited 1 with the error above.
- Captured stdout/stderr: see above (stdout empty, stderr 122 bytes shown verbatim).

### Why the rootfs composer rejected the layer

`src/rootfs.rs::normalize_path` flatly rejects any `Component::ParentDir` (`..`), and `normalize_symlink_target` reaches it via:

```rust
fn normalize_symlink_target(link_path: &Path, target: &Path) -> Result<PathBuf, RootFsError> {
    if target.is_absolute() {
        return normalize_rootfs_path(target);
    }
    let parent = link_path.parent().unwrap_or_else(|| Path::new(""));
    normalize_path(&parent.join(target), false)   // <- contains ".."
}
```

The Alpine layer carries perfectly ordinary POSIX relative symlinks whose textual targets contain `..`. Confirmed via `tar -tzvf` on the cached layer:

```
lrwxrwxrwx 0 0 0 0 Apr 14 21:51 etc/mtab -> ../proc/mounts
lrwxrwxrwx 0 0 0 0 Apr 14 21:51 etc/os-release -> ../usr/lib/os-release
lrwxrwxrwx 0 0 0 0 Apr 14 21:51 usr/share/apk/keys/aarch64/alpine-devel@lists.alpinelinux.org-58199dcc.rsa.pub -> ../alpine-devel@lists.alpinelinux.org-58199dcc.rsa.pub
...
```

`/etc/mtab -> ../proc/mounts` is well-formed: `etc/` + `../proc/mounts` reduces to `proc/mounts`, which is in-rootfs. The composer is throwing on a legitimate symlink layout that any container runtime accepts. The first failing entry happens to be `etc/mtab` (the first symlink-with-`..`-target in the tar order); subsequent ones (`etc/os-release`, the many `usr/share/apk/keys/<arch>/...` entries) would also trip the same path.

`normalize_path` should reduce `..` components against the accumulated path (popping the previous `Normal` component) and only reject when the path would escape *above* the rootfs root (i.e., the stack would underflow). That's what `path-clean`-style canonicalization does, and it's what `tar`/OCI extractors do.

## Diagnosis

The Tier B demo is currently blocked on two cliffs *before* any guest instruction executes. Both are squarely in host-side bootstrap code; neither requires touching the HVF trap loop or syscall dispatch surface.

1. **Symlink-target path normalization in `RootFs` (`src/rootfs.rs`).** Blocking. Classification: **bootstrap-stub-extension** (small, well-scoped change to existing host code).
   - `normalize_path` (called from `normalize_symlink_target` and `normalize_layer_path` with `allow_absolute=false`) rejects every `Component::ParentDir`. Replace the blanket `Err(UnsafePath)` for `ParentDir` with: pop the last `Normal` component from `out`; if `out` is empty (would escape root), *then* return `UnsafePath`. Apply only to relative-target reduction; the absolute-target path (`normalize_rootfs_path(target)`) is already independently safe since it walks from the synthetic root.
   - This alone unblocks layer composition for Alpine. No new dependencies. ~10 lines of code plus tests covering `etc/mtab -> ../proc/mounts`, `a/b/c -> ../../x`, and an actual escape (`a -> ../../../etc/passwd` must still error).

2. **Pull-by-tag for Linux images on a macOS host (`src/oci.rs::pull_image`).** Blocking only if you want a friendlier UX than the digest workaround; *not* blocking Tier B itself once you accept the digest pin. Classification: **bootstrap-stub-extension**.
   - The `oci-distribution` client defaults to host-OS resolution, so on macOS it asks for `darwin/arm64` and finds nothing in a `linux/*` index. Build a `ClientConfig` with `platform_resolver: Some(Box::new(|m| /* pick linux/arm64, then linux/amd64 as a deliberate fallback or just linux/arm64 */))`. Equivalently, the Tier B demo can be reproduced today by pre-resolving the digest as shown above.

There is no evidence of any missing-syscall or missing-`/proc` work being required for Tier B — that question is unanswerable from this run because we never reached the dispatcher. Once issue (1) is fixed, the next failure mode to expect (from reading `dispatch.rs`, `linux_abi.rs`, the existing fixture suite under `fixtures/linux-aarch64-hello/src/`, and the v0.1 plan in `plan.md`) is dynamic-loader-driven syscalls in `/bin/busybox` (musl ldso-bootstrap: `mmap`, `mprotect`, `read`, `pread64`, `openat`, `readlinkat`, `set_tid_address`, `set_robust_list`, `rseq`, `prlimit64`, `getrandom`, `brk`, `arch_specific_register_setup`). That follow-on investigation is out of scope for this report; this report's job was to find the first wall, and the first wall is rootfs composition.

### Smallest path forward

- Patch `normalize_path` to collapse `..` rather than reject. **Required.**
- (Optional, quality-of-life) Add a Linux/arm64 platform resolver to `pull_image` so `carrick pull docker.io/library/alpine:latest` works without an external digest lookup.
- Re-run `./target/release/carrick run docker.io/library/alpine@sha256:378c4...d1481a0 /bin/busybox echo hello`, capture the embedded `report` field from the JSON output, and iterate on whatever the first unhandled syscall / ioctl / proc-read is.

## Reproduction

A future engineer can replay this exact investigation against the same Alpine bits as follows. (The digest is pinned, so the demo is stable against future Alpine pushes.)

```bash
# From the repo root.
cargo build --release --bin carrick

./target/release/carrick trap-capabilities

# Tag pull (fails today on this host platform).
./target/release/carrick pull docker.io/library/alpine:latest

# Digest pull (works).
./target/release/carrick pull \
  docker.io/library/alpine@sha256:378c4c5418f7493bd500ad21ffb43818d0689daaad43e3261859fb417d1481a0

# Run (fails today during rootfs composition).
./target/release/carrick run \
  docker.io/library/alpine@sha256:378c4c5418f7493bd500ad21ffb43818d0689daaad43e3261859fb417d1481a0 \
  /bin/busybox echo hello

# Confirm the offending symlinks in the cached layer.
tar -tzvf ~/.carrick/blobs/sha256/d17f077ada118cc762df373ff803592abf2dfa3ddafaa7381e364dd27a88fca7 \
  | awk '$NF ~ /\.\./ || $(NF-1) ~ /\.\./' | head
```

The cached image lives under `$HOME/.carrick/` by default (or `$CARRICK_HOME` if set). Removing that directory between runs forces a fresh pull.
