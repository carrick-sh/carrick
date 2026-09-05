#!/usr/sbin/dtrace -qs
/*
 * Stage-1 table arena source lifecycle: where a process's page-table manager
 * is bound and whether it carries an arena source (the thing that lets the
 * process grow past one 440-table arena).
 *
 * What it measures: every `carrick*:::stage1-arena-bind` (authority pointer,
 * manager present, has_source, arena count) and every
 * `carrick*:::stage1-arena-install` (site: 1 manager present, 2 eager build,
 * 3 deferred, 4 applied by lazy edit build, 5 applied by exec rebuild;
 * applied; deferred; authority pointer), with host pid/tid and a monotonic
 * timestamp so cross-thread ordering can be reconstructed.
 *
 * Provider ABI qualified live on macOS 26 arm64 against carrick-observability:
 * stage1-arena-bind carries (uint64_t authority, uint32_t present,
 * uint32_t has_source, uint32_t arenas); stage1-arena-install carries
 * (uint32_t site, uint32_t applied, uint32_t deferred, uint64_t authority).
 *
 * Perturbation: none on the edit or syscall path — both probes fire only at
 * bind/install events (a handful per process). Written for the CPython
 * test_compile `-v` case whose arena source vanished when `RUST_LOG=debug`
 * was NOT set (the eprintln-class instrument perturbed the race away).
 *
 * Usage: carrick trace -s scripts/dtrace/hvpatch-stage1-arena.d run ...
 */

carrick*:::stage1-arena-bind
{
    printf("STAGE1ARENA|bind|ns=%d|pid=%d|tid=%d|authority=0x%x|present=%d|has_source=%d|arenas=%d\n",
        timestamp, pid, tid, arg0, arg1, arg2, arg3);
}

carrick*:::stage1-arena-install
{
    printf("STAGE1ARENA|install|ns=%d|pid=%d|tid=%d|site=%d|applied=%d|deferred=%d|authority=0x%x\n",
        timestamp, pid, tid, arg0, arg1, arg2, arg3);
}

carrick*:::stage1-arena-replace
{
    printf("STAGE1ARENA|replace|ns=%d|pid=%d|tid=%d|site=%d|source_before=%d|source_after=%d|authority=0x%x\n",
        timestamp, pid, tid, arg0, arg1, arg2, arg3);
}

carrick*:::stage1-arena-absent
{
    printf("STAGE1ARENA|absent|ns=%d|pid=%d|tid=%d|site=%d|authority=0x%x\n",
        timestamp, pid, tid, arg0, arg1);
}
