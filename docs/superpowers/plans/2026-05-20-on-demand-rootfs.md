# On-Demand Rootfs (`--fs host` streaming) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Under `--fs host`, stream OCI layers directly to the cap-std scratch Dir without ever building the in-memory `RootFs`, eliminating both the ~244 MB steady-state and the ~600 MB load-time peak. Spec: `docs/superpowers/specs/2026-05-20-on-demand-rootfs-design.md`.

**Architecture:** A streaming extractor reads each layer blob as a file stream (gzip-decoded on the fly) and applies tar entries — files/dirs/symlinks (+ mode), OCI whiteouts/opaque dirs — directly to a `cap_std::fs::Dir`. The `--fs host` run path uses it and constructs the dispatcher with NO in-memory rootfs (the `HostFsBackend` Dir is already disk-authoritative; `drop_rootfs_layer`/`rootfs = None` is already supported by every read path). `--fs memory` is unchanged.

**Tech Stack:** Rust, `flate2` (streaming `GzDecoder`), `tar`, `cap-std`.

---

## Background (verified facts)

- `src/rootfs.rs::apply_layer` (line 266) is the reference: it fully decompresses gz into a `Vec`, then `tar::Archive` over a `Cursor`, handling `OPAQUE_WHITEOUT` (`.wh..wh..opq`), `WHITEOUT_PREFIX` (`.wh.`), dirs, symlinks (`normalize_symlink_target`), files. Path safety via `normalize_layer_path`. These free helpers + consts are reusable (same module).
- `src/rootfs.rs::extract_to_disk` (line 144) already writes a built `RootFs` to disk preserving mode (`set_permissions`) + symlinks; drops uid/gid/mtime/special-files. The streaming path keeps this same fidelity envelope.
- `src/dispatch/mod.rs`: `drop_rootfs_layer()` (line 835) sets `rootfs = None`; comment + read paths confirm "all layered VFS reads and read_exec_file fall back gracefully to overlay-only when rootfs is None." `rootfs()` returns `Option<&RootFs>`.
- `src/main.rs`: `--fs host` today does `RootFs::from_layer_paths(&layers)` (line 561, builds full tree = the peak) → `host.seed_from_rootfs(rootfs)` (775) → `set_fs_backend` (798) → `drop_rootfs_layer()` (803). We replace the build+seed with streaming extraction and skip building the tree.
- `src/fs_backend.rs::HostFsBackend` holds `dir: cap_std::fs::Dir` (private). Needs a method to extract into it.
- OCI layer blobs live on disk in the store (`src/oci.rs`, `fs::write` to `blobs/sha256/...`); the run path has their paths.

## File Structure

- **`src/rootfs.rs`** — add `pub fn extract_layer_paths_to_dir(paths: &[PathBuf], dir: &cap_std::fs::Dir) -> Result<ExtractStats, RootFsError>` (streaming). Reuse `normalize_layer_path`, `normalize_symlink_target`, `OPAQUE_WHITEOUT`, `WHITEOUT_PREFIX`. One responsibility: layer-blob → disk Dir with overlay/whiteout semantics. `ExtractStats { files, dirs, symlinks, skipped_special }` for logging/tests.
- **`src/fs_backend.rs`** — `HostFsBackend::extract_layers(&mut self, paths: &[PathBuf]) -> io::Result<ExtractStats>` calling the extractor against `self.dir`.
- **`src/main.rs`** — `--fs host` run/run-elf path: stream into the backend, construct dispatcher WITHOUT `with_rootfs` (no in-memory base). `--fs memory` keeps `from_layer_paths`.
- **`tests/rootfs_streaming.rs`** (new) — unit tests for the extractor against a `tempfile` + `cap_std::fs::Dir`.

---

## Task 1: Streaming extractor core

**Files:**
- Modify: `src/rootfs.rs`
- Test: `tests/rootfs_streaming.rs` (create)

- [ ] **Step 1: Write failing tests** in `tests/rootfs_streaming.rs`. Build small in-memory tar (and tar.gz) layers with the `tar`/`flate2` crates, write them to temp files, run `extract_layer_paths_to_dir` into a `cap_std::fs::Dir` over a `tempfile::TempDir`, assert disk state:

```rust
use std::io::Write;
use std::path::PathBuf;

fn write_tar(dir: &std::path::Path, name: &str, build: impl FnOnce(&mut tar::Builder<Vec<u8>>)) -> PathBuf {
    let mut b = tar::Builder::new(Vec::new());
    build(&mut b);
    let bytes = b.into_inner().unwrap();
    let p = dir.join(name);
    std::fs::File::create(&p).unwrap().write_all(&bytes).unwrap();
    p
}

#[test]
fn extracts_file_dir_symlink_with_mode() {
    let tmp = tempfile::TempDir::new().unwrap();
    let scratch = tempfile::TempDir::new().unwrap();
    let layer = write_tar(tmp.path(), "l0.tar", |b| {
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Directory); h.set_mode(0o755); h.set_size(0);
        b.append_data(&mut h, "etc/", std::io::empty()).unwrap();
        let data = b"hello\n";
        let mut h2 = tar::Header::new_gnu();
        h2.set_entry_type(tar::EntryType::Regular); h2.set_mode(0o600); h2.set_size(data.len() as u64);
        b.append_data(&mut h2, "etc/motd", &data[..]).unwrap();
        let mut h3 = tar::Header::new_gnu();
        h3.set_entry_type(tar::EntryType::Symlink); h3.set_size(0);
        h3.set_link_name("motd").unwrap();
        b.append_link(&mut h3, "etc/motd.link", "motd").unwrap();
    });
    let dir = cap_std::fs::Dir::open_ambient_dir(scratch.path(), cap_std::ambient_authority()).unwrap();
    let stats = carrick::rootfs::extract_layer_paths_to_dir(&[layer], &dir).unwrap();
    assert_eq!(stats.files, 1);
    assert!(scratch.path().join("etc/motd").is_file());
    assert_eq!(std::fs::read(scratch.path().join("etc/motd")).unwrap(), b"hello\n");
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(std::fs::metadata(scratch.path().join("etc/motd")).unwrap().permissions().mode() & 0o777, 0o600);
    assert_eq!(std::fs::read_link(scratch.path().join("etc/motd.link")).unwrap().to_str().unwrap(), "motd");
}

#[test]
fn later_layer_overrides_and_whiteout_deletes() {
    let tmp = tempfile::TempDir::new().unwrap();
    let scratch = tempfile::TempDir::new().unwrap();
    let l0 = write_tar(tmp.path(), "l0.tar", |b| {
        let d = b"v0"; let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Regular); h.set_mode(0o644); h.set_size(d.len() as u64);
        b.append_data(&mut h, "a.txt", &d[..]).unwrap();
        let d2 = b"keep"; let mut h2 = tar::Header::new_gnu();
        h2.set_entry_type(tar::EntryType::Regular); h2.set_mode(0o644); h2.set_size(d2.len() as u64);
        b.append_data(&mut h2, "b.txt", &d2[..]).unwrap();
    });
    let l1 = write_tar(tmp.path(), "l1.tar", |b| {
        let d = b"v1"; let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Regular); h.set_mode(0o644); h.set_size(d.len() as u64);
        b.append_data(&mut h, "a.txt", &d[..]).unwrap();        // override
        let mut hw = tar::Header::new_gnu();                     // whiteout b.txt
        hw.set_entry_type(tar::EntryType::Regular); hw.set_mode(0o644); hw.set_size(0);
        b.append_data(&mut hw, ".wh.b.txt", std::io::empty()).unwrap();
    });
    let dir = cap_std::fs::Dir::open_ambient_dir(scratch.path(), cap_std::ambient_authority()).unwrap();
    carrick::rootfs::extract_layer_paths_to_dir(&[l0, l1], &dir).unwrap();
    assert_eq!(std::fs::read(scratch.path().join("a.txt")).unwrap(), b"v1");
    assert!(!scratch.path().join("b.txt").exists());
}

#[test]
fn opaque_whiteout_clears_dir() {
    let tmp = tempfile::TempDir::new().unwrap();
    let scratch = tempfile::TempDir::new().unwrap();
    let l0 = write_tar(tmp.path(), "l0.tar", |b| {
        let d = b"x"; let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Regular); h.set_mode(0o644); h.set_size(d.len() as u64);
        b.append_data(&mut h, "d/old.txt", &d[..]).unwrap();
    });
    let l1 = write_tar(tmp.path(), "l1.tar", |b| {
        let mut hq = tar::Header::new_gnu();
        hq.set_entry_type(tar::EntryType::Regular); hq.set_mode(0o644); hq.set_size(0);
        b.append_data(&mut hq, "d/.wh..wh..opq", std::io::empty()).unwrap();
        let d = b"new"; let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Regular); h.set_mode(0o644); h.set_size(d.len() as u64);
        b.append_data(&mut h, "d/new.txt", &d[..]).unwrap();
    });
    let dir = cap_std::fs::Dir::open_ambient_dir(scratch.path(), cap_std::ambient_authority()).unwrap();
    carrick::rootfs::extract_layer_paths_to_dir(&[l0, l1], &dir).unwrap();
    assert!(!scratch.path().join("d/old.txt").exists());
    assert!(scratch.path().join("d/new.txt").is_file());
}
```

- [ ] **Step 2: Run, verify fail** — `cargo test --test rootfs_streaming` → FAIL (`extract_layer_paths_to_dir` undefined). Add `tempfile` to `[dev-dependencies]` if absent (it's already used by fs_backend tests).

- [ ] **Step 3: Implement** `extract_layer_paths_to_dir` in `src/rootfs.rs`:
  - `pub struct ExtractStats { pub files: u64, pub dirs: u64, pub symlinks: u64, pub skipped_special: u64 }`.
  - For each path: open the blob as `std::fs::File`; sniff the first 2 bytes for gzip magic `0x1f 0x8b` (then re-open / `BufReader` + `GzDecoder`, else raw `BufReader`); `tar::Archive::new(reader)` over the **streaming** reader (no full decompress Vec). Call a private `apply_tar_to_dir(&mut archive, dir, &mut stats)`.
  - `apply_tar_to_dir`: iterate `archive.entries()?`. For each: `normalize_layer_path` (reuse). Detect opaque/whiteout by filename exactly as `apply_layer` (lines 283-297) but acting on the Dir:
    - opaque → `dir.remove_dir_all(parent)?` (ignore NotFound) then `dir.create_dir_all(parent)?`.
    - whiteout → remove `parent/hidden_name` from the Dir: try `remove_file`, then `remove_dir_all`, ignore NotFound.
  - Else by `entry.header().entry_type()`:
    - dir → `dir.create_dir_all(path)`; set mode via `dir.set_permissions(path, Permissions::from_mode(mode))` (cap-std `set_permissions`); `stats.dirs += 1`.
    - symlink → ensure parent dir; remove any existing at path; `dir.symlink(link_name, path)` (cap-std `Dir::symlink(original, link)`); `stats.symlinks += 1`.
    - file → ensure parent dir; `let mut f = dir.create(path)?; std::io::copy(&mut entry, &mut f)?;` then `dir.set_permissions(path, Permissions::from_mode(mode))`; `stats.files += 1`. (Streaming copy — never buffers the whole file.)
    - hard_link → `dir.hard_link(link_name, dir, path)`; on error fall back to copying the target file's bytes; `stats.files += 1`.
    - char/block/fifo/other special → skip; `stats.skipped_special += 1`; `crate::probes::…` partial probe if cheap (else just count).
  - "ensure parent dir" = `if let Some(p) = path.parent() { dir.create_dir_all(p)?; }`. Use cap-std relative paths (strip leading `/`; `normalize_layer_path` already yields relative).
  - Path-escape: cap-std rejects `..`/absolute automatically; `normalize_layer_path` already guards. Propagate errors as `RootFsError`.

- [ ] **Step 4: Run, verify pass** — `cargo test --test rootfs_streaming`. Add a `skips_special_file` test (append a char-device header) and a `rejects_path_escape` test (entry path `../evil`) and make them pass.

- [ ] **Step 5: Commit** — `git add src/rootfs.rs tests/rootfs_streaming.rs Cargo.toml && git commit -m "rootfs: streaming layer extraction to a cap-std Dir"` + `Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>`.

---

## Task 2: HostFsBackend streaming entry point

**Files:**
- Modify: `src/fs_backend.rs`
- Test: extend `tests/rootfs_streaming.rs` or fs_backend's inline tests

- [ ] **Step 1: Write failing test** — construct a `HostFsBackend` over a temp scratch (use the existing test ctor pattern, e.g. `HostFsBackend::new_in(tmp)` then locate its Dir, OR a test-only `from_dir`), call `backend.extract_layers(&[layer_path])`, assert `backend.lookup("/etc/motd")` returns `OverlayEntry::File(b"hello\n")` and `metadata("/etc/motd")` reports a file. (Mirror an existing HostFsBackend test for setup.)

- [ ] **Step 2: Run, verify fail.**

- [ ] **Step 3: Implement** `HostFsBackend::extract_layers(&mut self, paths: &[std::path::PathBuf]) -> std::io::Result<crate::rootfs::ExtractStats>` → `crate::rootfs::extract_layer_paths_to_dir(paths, &self.dir).map_err(|e| std::io::Error::other(e.to_string()))`. (Keep `seed_from_rootfs(&RootFs)` as-is for now — see the spec's open question; remove only if no caller remains after Task 3.)

- [ ] **Step 4: Run, verify pass** — `cargo test --test rootfs_streaming` (+ `cargo test --lib fs_backend`).

- [ ] **Step 5: Commit** — `"fs_backend: HostFsBackend::extract_layers streams layers into the scratch Dir"`.

---

## Task 3: Wire `--fs host` run path to stream (no in-memory rootfs)

**Files:**
- Modify: `src/main.rs` (the `FsBackendKind::Host` arm ~760-803 and the `Run` handler ~561)
- Test: covered by Task 4's integration run (no clean unit harness for the CLI wiring)

- [ ] **Step 1:** Read the current `Run` + `FsBackendKind::Host` flow (main.rs ~540-805). Today: build `RootFs::from_layer_paths(&layers)`, `with_rootfs`/`with_rootfs_and_executable`, then for Host: `host.seed_from_rootfs(&rootfs)` + `set_fs_backend` + `drop_rootfs_layer`.

- [ ] **Step 2: Implement** — for `--fs host`: do NOT call `RootFs::from_layer_paths`. Instead create the `HostFsBackend`, call `host.extract_layers(&layer_paths)`, build the dispatcher via `SyscallDispatcher::new()` (+ set executable_path) — i.e. NO `with_rootfs` (rootfs stays `None`) — then `set_fs_backend(Box::new(host))`. For `--fs memory`: unchanged (`from_layer_paths` + `with_rootfs` + memory backend). Keep the executable-path plumbing identical for both. Ensure the `--raw`/report and `run-elf --rootfs-layer` host paths get the same treatment (factor a helper if the two call sites diverge). Verify the execve path: with `rootfs = None`, `read_exec_file`/`load_elf_from_rootfs` must resolve the binary from the overlay Dir — confirmed supported by `drop_rootfs_layer`'s contract; test in Task 4.

- [ ] **Step 3: Build** — `cargo build` clean; `./scripts/build-signed.sh`.

- [ ] **Step 4: Smoke** — `./target/release/carrick run --raw --fs host docker.io/library/debian:stable /bin/true` exits 0; `... /bin/sh -c 'ls /etc >/dev/null && cat /etc/os-release | head -1'` prints the Debian line. (If the binary won't load with `rootfs=None`, fix the execve/exec-load path to read from the overlay before proceeding.)

- [ ] **Step 5: Commit** — `"run: stream OCI layers to disk for --fs host; no in-memory rootfs"`.

---

## Task 4: Verify — conformance, apt gate, and RSS win

**Files:** none (verification); record numbers in the commit message + memory.

- [ ] **Step 1:** `cargo test` — full suite green (lib + integration + both Docker conformance suites). `cargo clippy --all-targets` → 0.
- [ ] **Step 2: v1.0 gate** — `./target/release/carrick run --raw --fs host docker.io/library/debian:stable /bin/sh -c "apt-get update >/dev/null 2>&1 && apt-get install -y hello && /usr/bin/hello"` → `Hello, world!`.
- [ ] **Step 3: RSS win (record before/after):**
  - Peak: `/usr/bin/time -l ./target/release/carrick run --raw --fs host docker.io/library/debian:stable /bin/true 2>&1 | grep 'maximum resident'`.
  - Steady-state: launch `... /bin/sleep 60 &`, `vmmap -summary <pid> | grep 'Physical footprint:'`.
  - Expect: peak ~600 MB → well under 150 MB; steady-state → tens of MB. Note any fork+exec latency change (`time` a 100x `/bin/true` loop). If RSS did NOT drop, STOP and investigate (the in-memory tree is still being built somewhere) before claiming success.
- [ ] **Step 4: Commit** — `"test: on-demand rootfs conformance + record RSS before/after"`; update the [[process-overhead]] memory note with the achieved numbers.

---

## Risks (from spec; watch during impl)

1. Whiteout/opaque parity with `apply_layer` — share helpers, the Task 1 tests cover each case.
2. Metadata reconstruction with `rootfs=None` — `backend.metadata()` is the sole source; conformance + smoke (`ls -l`, `stat`) covers it. If a tool needs uid/gid fidelity beyond uid=0, note it (out of scope).
3. Per-entry disk-write cost for thousands of small files — measure in Task 4; should match today's `extract_to_disk`.
4. `--fs memory` divergence — shared tar/whiteout helpers; both paths run under conformance.
5. execve with `rootfs=None` — explicitly smoke-tested in Task 3 Step 4.
