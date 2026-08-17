# Phase report — repair the `node-libuv` Docker oracle

**Date:** 2026-08-17
**Lane:** canonical macOS / Apple Silicon / HVF / HVPatch, Linux arm64 guest
**Phase:** step 1 of the handoff's Node libuv sequence (oracle repair only).
No Carrick guest ran in this phase; it is a Docker-only measurement.

## Why

`node-libuv`'s docker row never reached libuv. The suite declared
`docker_flags = ["--user", "65534"]`, but the image's
`/usr/local/bin/nodejs-conformance` wrapper builds its own fixture and drops
privilege itself:

```sh
cp -R /opt/libuv-src/test "$tmp/test"
chown -R 1000:1000 "$tmp"
...
os.setgid(1000)
os.setuid(1000)
os.execv(binary, ...)
```

Starting the container as uid 65534 makes that `chown -R` fail `EPERM`, so the
wrapper died during setup. The cached oracle therefore recorded a **setup
failure**, not Linux libuv behaviour — and every one of the 507 libuv assertion
positions was ledgered as `docker = absent` (unexercised), not compared.

This also invalidates the previously recorded `node-libuv` 145.02x ratio as
performance evidence: it was measured against a container that never ran the
suite.

## What changed

- `scripts/conformance/suites.toml`: dropped `docker_flags` from `[[suite]]`
  `node-libuv`.
- `crates/carrick-conformance/src/generate.rs`: dropped the hardcoded
  `libuv.docker_flags = vec![s("--user"), s("65534")]` in `build()`.
- Two red-first regression tests so regeneration cannot restore the flag:
  - `manifest::tests::node_libuv_manifest_does_not_pin_docker_user` asserts on
    the **committed** manifest;
  - `generate::tests::node_libuv_regen_does_not_pin_docker_user` asserts the
    regen override tables never hand `node-libuv` a `--user`.
  Both were proven RED by temporarily restoring the flag in both places, then
  GREEN after restoring the fix. Neither test can silently skip: the manifest
  test panics if it cannot read or parse the committed manifest, and panics if
  `node-libuv` is absent from it.
- `crates/carrick-conformance/src/main.rs`: new `--oracle-fill` /
  `--oracle-fill-profile` docker-only repair path (below).

### Why a new `--oracle-fill` mode was required

A suite's docker oracle is keyed by its **declaration**, so repairing the
declaration mints a new determinant key whose row does not exist. There was no
way to fill exactly that one row:

- the closure gate (`--closure`) correctly **rejects suite filters** — it is the
  gate, and must run the whole frozen surface;
- `--refresh-oracle` on a closure run would re-run all 2,127 docker oracles to
  capture one.

`--oracle-fill` runs **docker only** for an explicitly named selection: no
carrick runs, no classification, no gate verdict, no baseline. It always runs
the container fresh, and invalidates the row *before* running so a failed
refresh leaves a **miss** rather than silently reverting to the superseded
oracle. It refuses an empty/unfiltered selection and refuses `--closure`.

**The profile is load-bearing.** `ParserProfile::Regression` and
`ParserProfile::ClosureV1` are *different cache keys*
(`oracle.rs:oracle_key_for_profile`). Filling `regression` while the closure
gate is the consumer writes a row the gate never reads and leaves the gate's own
row missing. That exact mistake was made once already in this campaign — a
repaired `node-libuv` row was captured under the regression profile and recorded
as "oracle refreshed" while the closure gate still had no oracle for it.
`--oracle-fill-profile` therefore **defaults to `closure`**, and
`tests::oracle_fill_profile_defaults_to_closure_and_rejects_unknown` pins that.

## Result — the repaired oracle

```
cargo run -q -p carrick-conformance -- \
  --oracle-fill --oracle-fill-profile closure --suite node-libuv

oracle-fill: 1 suite(s), profile=closure, platform=LinuxArm64
  [docker] node-libuv -> Success n=499 pass=499 fail=0 broken=0 skip=8 (45493 ms)
```

**507 TAP positions: 499 pass, 0 fail, 8 skip.** The plan line `1..507` is the
first line of output, and `platform_output` reports
`uv_cwd: /tmp/nodejs-libuv.EdAunU` — the wrapper's chowned fixture root — which
is the proof that the `chown` succeeded and TAP begins *after* the
`setgid(1000)`/`setuid(1000)` drop. stderr was empty (sha256
`e3b0c442…b7852b855`, the empty-string digest).

### Serialization and provenance

- No Carrick process was running (`ps` checked before the run); this was a
  Docker-only phase, per the never-concurrent rule.
- **No image rebuild.** Image id at run time was
  `sha256:1ed49af83bd30401e1b275957b99a1c28f6c582ab3d987997afb5888fa302718`,
  identical to the frozen Node digest in `scripts/conformance/closure-scope.json`.
- Docker container cleanup: `run_docker` removes its named container before and
  after; `docker ps` showed only the two long-lived registries.

| artifact | sha256 |
|---|---|
| `docker-oracle-libuv.tap` (preserved raw stdout) | `91edc8bfb6a2c46f83c4ecb11e6b91e9b58448385e1ef4a987e499260b95a477` |
| docker stderr (empty) | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `scripts/conformance/oracle-cache.jsonl` (after fill) | `f8340ff30f9c1937eef1832997014672fa5e5348ba0849e769895a88fada951f` |
| `scripts/conformance/suites.toml` (after repair) | `cc487b0c000a121456c62d713101267239f22efaf9260c4330f534293b79010d` |

The raw TAP is committed here as `docker-oracle-libuv.tap` deliberately: the
previous checkpoint's evidence lived only in `target/` inside a worktree that no
longer exists, so every raw artifact it cited is gone. This one is 17 KB and is
the ground truth for 507 assertion positions — it is worth carrying.

## Linux ground truth this establishes

The oracle skips exactly 8 positions, each with an explicit reason:

| # | test | Linux skip reason |
|---|---|---|
| 70 | `fs_event_watch_dir_recursive` | recursive directory watching unsupported on this platform |
| 273 | `poll_close_doesnt_corrupt_stack` | Windows-only |
| 274 | `poll_closesocket` | Windows-only |
| 321 | `spawn_quoted_path` | Windows-only |
| 327 | `spawn_setuid_setgid` | must run as root (the wrapper is uid 1000) |
| 370 | `tcp_connect6_link_local` | IPv6 link-local traffic unsupported here |
| 453 | `tty` | cannot open `/dev/tty` (no controlling terminal) |
| 472 | `udp_multicast_join6` | no external IPv6 interface |

This resolves two of the handoff's open questions directly, without needing a
privilege-correct sublane:

- **`spawn_quoted_path` and `spawn_setuid_setgid` skipping is correct parity**,
  provided Carrick skips them for the same reason. They are not Carrick
  coverage gaps.
- **`udp_multicast_join6` skipping is correct parity** for the same reason.

Conversely, anything Carrick skips that does **not** appear in this table is a
real gap, because Linux ran and passed it. `pipe_set_chmod` is not in this
table.

## Status / what this phase does NOT claim

- This is step 1 only. No Carrick side was measured in this phase, so **no
  assertion-level libuv verdict is claimed here.**
- The stale `--user 65534` rows remain in `oracle-cache.jsonl`. They are inert:
  no suite declaration can produce their determinant key any more. They were
  left rather than hand-edited out of an 8,000-line committed cache.
- The closure scope check reports `scope drift in binary_sha256` because
  `target/release/carrick` has been rebuilt since the frozen checkpoint. That is
  expected mid-campaign and must be re-frozen before the next authoritative
  closure run.
