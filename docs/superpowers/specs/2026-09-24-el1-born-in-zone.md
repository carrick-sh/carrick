# EL1 in-zone objects: born in the zone, one owner, one implementation

Status: design, 2026-09-24. Supersedes the delegate/recall ownership model of
`2026-09-22-el1-kernel-design.md` section 4 for regular files and inotify.

## Why

The EL1 vertical proved its ceiling and then stalled on coordination, not on
the in-guest code:

| Measurement (signed, HVF) | Result |
|---|---|
| Single-thread add_watch+write+lseek+rm_watch loop, all served in-guest | 503-527 ns/iter vs 9,258-9,755 ns with `CARRICK_EL1=0` (17-19x) |
| LTP inotify09, best mode (file and instance both resident) | 4.5 s vs ~33 s with `CARRICK_EL1=0` |
| LTP inotify09, same binary, six consecutive runs | 4.6 s, 14 s, 31 s, 34 s: ownership decided by startup races |

Every defect of the last five review rounds had one shape: two owners of one
object and a protocol to move it between them. Eligibility, delegate, recall,
backoff, "inspection recalls", "forward recalls", instance-recalled-before-its-
marks and host-model watches that stop receiving in-guest events are all
consequences of that protocol. The fast mode shows what removes them: when the
host ran the same operation code against the in-zone object instead of
recalling it, six million forwarded operations cost no ownership change.

Linux has no such protocol because the page cache and the inotify instance are
the authoritative objects and every CPU runs the same code against them. This
design gives Carrick the same shape for the objects that never leave the
compat zone.

## Model

1. **Born in the zone.** An in-zone object is created in the EL1 aperture when
   the guest creates it, never promoted later:
   - an inotify instance at `inotify_init1`;
   - a regular file on the private host-passthrough rootfs at `open`, when it
     fits the zone (size cap, slot available; see Capacity).
   There is no eligibility decision at first I/O, no delegation transaction and
   no backoff.

2. **One implementation, two executors.** The operation code in
   `carrick-el1` (`serve_locked_file_op`, the inotify ring/watch code in
   `carrick-inotify-core`) is the only implementation. EL1 runs it when the
   guest traps into it and never waits (a busy lock forwards). The host runs
   the same code, waiting on the lock, for every forwarded operation and for
   operations EL1 does not implement (fstat's size, FIONREAD, readiness, close).
   A forwarded operation is never an ownership change.

3. **Split inode and open file.** Files get two in-zone records, as in Linux:
   `ZoneInode` (size, pages, dirty and zero-filled masks, marks, host identity,
   lock) shared by every open description of the inode, and `ZoneOpenFile`
   (offset, status flags, inode handle) per description. The fd map points at
   the open-file record. Multiple descriptions of one inode are then ordinary,
   not a reason to leave the zone.

4. **The host fd is backing, not an owner.** Write-back happens at `fsync`,
   `fdatasync`, `syncfs`, last close of the inode, exec (close-on-exec), carrier
   teardown and eviction, and before a host operation reads the backing
   (`fstat`, via `el1_delegation::sync_to_host`). Write-back never changes where
   the object lives. The host mtime is the write-back time, not the time of
   each in-zone write; exact times need the inode to carry them.

5. **Demotion is the only exit, and it is one-way per inode lifetime.** An
   operation the zone cannot model exactly demotes the inode to the host path:
   `mmap` of the file (until the cache can be mapped), a write past the size
   cap, `O_APPEND` on a new description, `fallocate`/`FICLONE`/`copy_file_range`
   into it, a watch from a host-model watcher (fanotify), a seccomp filter or
   interceptor that observes the served syscalls, record locks. Demotion writes
   back, detaches every open-file record and never re-promotes the inode while
   it has open descriptions. A demoted inode is a host file, exactly as today
   without EL1.

6. **Inotify instances leave the zone only by outgrowing it.** Their ring, wd
   allocator and watch table are authoritative. Watches on host-path (demoted
   or non-zone) files are served by the host enqueueing into the same in-zone
   ring, so an event always lands in the one queue the guest reads. An
   instance that reaches the zone's watch capacity demotes to the host inotify
   model, terminally: its in-zone files with marks are recalled first, then
   its watches, wd allocator and pending events move to the host state. An
   instance the zone cannot hold at `inotify_init1` (no slot) is a host
   instance for its whole life.

## Invariants (each gets a type or a test, not a comment)

- One owner per object for its whole lifetime; no API moves ownership except
  demotion, which is terminal.
- One implementation per operation; the host calls `carrick-el1`, never a
  parallel host version.
- Every IN_MODIFY for a watched in-zone file is enqueued by the code path that
  performed the write, into the instance's in-zone ring.
- Lock order: inode, then instance; open-file state is under the inode lock.
  No dentry, namespace or description guard is held while taking either.
- The EL1 image carries an ABI layout hash in its header; the host refuses to
  boot EL1 with a mismatched image (the stale-image failure served zero file
  operations silently).

## Capacity

The first cut keeps the fixed aperture: `MAX_ZONE_INODES` inodes of at most
`DELEGATED_FILE_MAX_SIZE` bytes each. A file that does not fit at open is a
host file for that open (not an error). When the inode table is full, the least
recently used inode with no open descriptions is written back and freed; an
inode with open descriptions is never evicted. A later step replaces the fixed
slot with a paged cache.

## Contracts

- `kernel.el1.inotify` binds LTP inotify09, five runs, every run: TPASS, at
  least 90% of add_watch, rm_watch, write and lseek served in-guest, a startup
  bound on object creation, runtime ratio <= 2.0 against native Docker.
- A new semantic contract binds the inotify event stream under the race
  (every IN_MODIFY of a served write reaches the watching instance; IN_IGNORED
  is the last event of its wd), against the Docker oracle.
- `kernel.el1.files` keeps its loop contract and adds two descriptions of one
  inode (different offsets, shared bytes) and fstat after in-zone writes.

## Status (2026-09-23)

Phase 1 is implemented on `director/el1-inotify-r5`: instances are born in
the zone and the host serves forwarded file operations against the in-zone
object (`carrick_el1::serve_locked_file_op`). Kind probes and fstat no longer
recall (`inspect_kind`, `sync_to_host`). About 80 accessor sites that match
only kinds that can never be in the zone still recall if reached. Phase 2
removes recall-on-access rather than migrating them one by one.

| inotify09, signed CLI, serial phases | Wall |
|---|---|
| Carrick, EL1 on | 2.64-2.95 s |
| Carrick, `CARRICK_EL1=0` | 37.2-37.8 s |
| Docker (native arm64) | 5.67-6.03 s |

## Phases

1. Inotify instances born in the zone; host serves inotify read, FIONREAD,
   readiness and close against the in-zone instance; host-path writes to
   watched files enqueue into the zone ring. Removes instance recall.
2. Files born in the zone at open with the inode/open-file split; host serves
   fstat's size and times from the inode; write-back points above. Removes
   delegate-at-first-write, backoff, `ever_shared`, eligibility.
3. Demotion as the single exit, with each trigger listed above and a test per
   trigger. Delete `recall` as an API.
4. ABI layout hash in the image header, checked at boot.
5. Signed gates: the contracts above, `just conformance-probes`, LTP inotify
   and file suites, `just ci`; land.
