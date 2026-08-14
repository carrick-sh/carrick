#!/usr/sbin/dtrace -qs
/*
 * Prove that one HVPatch crash capture has a complete, fail-closed lifecycle
 * from the fatal task's request through the wait-status commit. The output
 * binds the task-local generation to exact PID/TID, snapshot populations,
 * serialized length, and SHA-256 words for the bytes offered to publication.
 *
 * Provider ABI qualified from carrick-observability on macOS 26.0.1 arm64:
 * carrick*:::hvpatch-core-lifecycle carries
 * (uint32_t phase, int32_t Linux PID, int32_t Linux TID,
 * uint64_t generation, uint32_t outcome). Phases are 0=request,
 * 1=all-vCPU quiesce, 2=snapshot complete, 3=serialized, 4=atomic rename,
 * 5=wait-status commit, and 6=failed/declined. Outcome zero is success;
 * phase 6 uses 1 for error and 2 for a bounded no-publication decision.
 * carrick*:::hvpatch-core-context carries
 * (generation, mm, ASID, required threads, collected threads).
 * carrick*:::hvpatch-core-census carries
 * (generation, NT_FILE mappings, ELF notes, PT_LOADs, serialized bytes).
 * carrick*:::hvpatch-core-hash carries generation followed by the exact
 * SHA-256 digest as four big-endian uint64_t words.
 *
 * This script fails closed: zero events, a missing/duplicate phase, generation
 * drift, absent census/hash, any failure edge, timeout, DTrace error/drop, or
 * a nonzero Carrick exit produces status=error and a nonzero DTrace exit.
 *
 * Perturbation: six lifecycle events plus one context, one census, and one hash
 * event per crash. No syscall, trap, memory-read, or instruction hot path is
 * instrumented.
 */

#pragma D option quiet

dtrace:::BEGIN
{
    started = timestamp;
    lifecycle = 0;
    requests = 0;
    quiesced = 0;
    snapshots = 0;
    serialized = 0;
    published = 0;
    committed = 0;
    failed = 0;
    contexts = 0;
    censuses = 0;
    hashes = 0;
    generation = (uint64_t)0;
    linux_pid = 0;
    linux_tid = 0;
    mm = (uint64_t)0;
    asid = 0;
    required_threads = (uint64_t)0;
    collected_threads = (uint64_t)0;
    mappings = (uint64_t)0;
    notes = (uint64_t)0;
    loads = (uint64_t)0;
    core_bytes = (uint64_t)0;
    hash0 = (uint64_t)0;
    hash1 = (uint64_t)0;
    hash2 = (uint64_t)0;
    hash3 = (uint64_t)0;
    identity_drift = 0;
    join_drift = 0;
    bounded = 0;
    errors = 0;
    drops = 0;
    target_exit_seen = 0;
    target_exit_code = -1;
    target_exit_reason = 0;
    valid = 0;
    printf("HVPATCHCORE1|header|version=1\n");
}

carrick*:::hvpatch-core-lifecycle
/pid == $target || progenyof($target)/
{
    lifecycle++;
    requests += arg0 == 0;
    quiesced += arg0 == 1;
    snapshots += arg0 == 2;
    serialized += arg0 == 3;
    published += arg0 == 4;
    committed += arg0 == 5;
    failed += arg0 == 6 || arg4 != 0;
    generation = arg0 == 0 ? (uint64_t)arg3 : generation;
    linux_pid = arg0 == 0 ? (int32_t)arg1 : linux_pid;
    linux_tid = arg0 == 0 ? (int32_t)arg2 : linux_tid;
    identity_drift += arg0 != 0 &&
        ((uint64_t)arg3 != generation || (int32_t)arg1 != linux_pid ||
        (int32_t)arg2 != linux_tid);
    printf("HVPATCHCORE1|lifecycle|phase=%u|pid=%d|tid=%d|generation=%llu|outcome=%u\n",
        (uint32_t)arg0, (int32_t)arg1, (int32_t)arg2,
        (uint64_t)arg3, (uint32_t)arg4);
}

carrick*:::hvpatch-core-census
/pid == $target || progenyof($target)/
{
    censuses++;
    join_drift += (uint64_t)arg0 != generation;
    mappings = (uint64_t)arg1;
    notes = (uint64_t)arg2;
    loads = (uint64_t)arg3;
    core_bytes = (uint64_t)arg4;
    printf("HVPATCHCORE1|census|generation=%llu|mappings=%llu|notes=%llu|loads=%llu|bytes=%llu\n",
        (uint64_t)arg0, mappings, notes, loads, core_bytes);
}

carrick*:::hvpatch-core-context
/pid == $target || progenyof($target)/
{
    contexts++;
    join_drift += (uint64_t)arg0 != generation;
    mm = (uint64_t)arg1;
    asid = (uint32_t)arg2;
    required_threads = (uint64_t)arg3;
    collected_threads = (uint64_t)arg4;
    printf("HVPATCHCORE1|context|generation=%llu|mm=%llu|asid=%u|required_threads=%llu|collected_threads=%llu\n",
        (uint64_t)arg0, mm, asid, required_threads, collected_threads);
}

carrick*:::hvpatch-core-hash
/pid == $target || progenyof($target)/
{
    hashes++;
    join_drift += (uint64_t)arg0 != generation;
    hash0 = (uint64_t)arg1;
    hash1 = (uint64_t)arg2;
    hash2 = (uint64_t)arg3;
    hash3 = (uint64_t)arg4;
    printf("HVPATCHCORE1|hash|generation=%llu|sha256=%016llx%016llx%016llx%016llx\n",
        (uint64_t)arg0, hash0, hash1, hash2, hash3);
}

dtrace:::DROP
{
    drops++;
}

dtrace:::ERROR
{
    errors++;
}

syscall::exit:entry
/pid == $target/
{
    target_exit_seen = 1;
    target_exit_code = (int)arg0;
}

proc:::exit
/pid == $target/
{
    target_exit_reason = arg0;
    valid = lifecycle == 6 && requests == 1 && quiesced == 1 &&
        snapshots == 1 && serialized == 1 && published == 1 &&
        committed == 1 && failed == 0 && contexts == 1 && censuses == 1 && hashes == 1 &&
        generation != 0 && identity_drift == 0 && join_drift == 0 &&
        mm > 0 && asid > 0 && required_threads >= 3 &&
        collected_threads == required_threads && mappings > 0 &&
        notes == 4 + 3 * collected_threads && loads > 0 && core_bytes > 0 &&
        (hash0 != 0 || hash1 != 0 || hash2 != 0 || hash3 != 0) &&
        bounded == 0 && errors == 0 && drops == 0 &&
        target_exit_seen == 1 && target_exit_code == 0;
    exit(valid ? 0 : 2);
}

profile:::tick-1sec
/timestamp - started > 120 * 1000000000/
{
    bounded = 1;
    exit(3);
}

dtrace:::END
{
    valid = lifecycle == 6 && requests == 1 && quiesced == 1 &&
        snapshots == 1 && serialized == 1 && published == 1 &&
        committed == 1 && failed == 0 && contexts == 1 && censuses == 1 && hashes == 1 &&
        generation != 0 && identity_drift == 0 && join_drift == 0 &&
        mm > 0 && asid > 0 && required_threads >= 3 &&
        collected_threads == required_threads && mappings > 0 &&
        notes == 4 + 3 * collected_threads && loads > 0 && core_bytes > 0 &&
        (hash0 != 0 || hash1 != 0 || hash2 != 0 || hash3 != 0) &&
        bounded == 0 && errors == 0 && drops == 0 &&
        target_exit_seen == 1 && target_exit_code == 0;
    printf("HVPATCHCORE1|summary|status=%s|lifecycle=%d|requests=%d|quiesced=%d|snapshots=%d|serialized=%d|published=%d|committed=%d|failed=%d|contexts=%d|censuses=%d|hashes=%d|generation=%llu|pid=%d|tid=%d|mm=%llu|asid=%u|required_threads=%llu|collected_threads=%llu|mappings=%llu|notes=%llu|loads=%llu|bytes=%llu|identity_drift=%d|join_drift=%d|bounded=%d|errors=%d|drops=%d|target_exit_seen=%d|target_exit_code=%d|target_exit_reason=%d\n",
        valid ? "ok" : "error", lifecycle, requests, quiesced,
        snapshots, serialized, published, committed, failed, contexts,
        censuses, hashes, generation, linux_pid, linux_tid, mm, asid,
        required_threads, collected_threads, mappings, notes, loads,
        core_bytes, identity_drift, join_drift, bounded, errors,
        drops, target_exit_seen, target_exit_code, target_exit_reason);
}
