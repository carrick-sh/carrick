# In-progress allocator screen — not terminal candidate acceptance

Read-only snapshot of `el1-memory-corrections` during worker
`el1-elastic-metadata` first turn. The worker remains active and owns its tree;
these findings must be rechecked on its terminal revision before review.
Source SHA-256 and extraction boundaries are in `snapshot.json`.

The screen retains the unchanged allocator core and supplies aligned, owned
backing. No worker files were edited. Both programs compile with rustc and
exit 101 on behavioral assertions:

- `screen.rs.txt`: a 64-byte request with alignment 64 returns remainder 32.
  The payload starts after a 32-byte header; rounding block size does not align
  the payload address.
- `grant-size.rs.txt`: a 65536-byte grant cannot supply the 65536-byte payload
  requested by the growth wrapper, because headers need additional space.
  The wrapper currently computes grants from payload size alone. This is a
  wrapper sizing obligation, not a claim that a core allocator should omit
  its header.

Reproduce from repository root:

```sh
rustc --edition=2024 --crate-name alignment_screen docs/perf-results/2026-09-26-el1-elastic-metadata-director/in-progress-screen/screen.rs.txt -o /tmp/el1-alignment-screen
/tmp/el1-alignment-screen
rustc --edition=2024 --crate-name grant_size_screen docs/perf-results/2026-09-26-el1-elastic-metadata-director/in-progress-screen/grant-size.rs.txt -o /tmp/el1-grant-size-screen
/tmp/el1-grant-size-screen
```

Review must also establish actual guest stage-1 mapping and exact owner lifetime,
reusable dynamic aperture space, bounded free-list search, an installed global
allocator, and a fixture that really exceeds the 9 MiB bootstrap. The current
four 64 KiB requests do not establish growth. These are source-review questions,
not new signed execution results. The production syscall table assigns 448 to
`process_mrelease`; a test entry may not commandeer that Linux syscall.

No allocator implementation is integrated or accepted by this screen.
