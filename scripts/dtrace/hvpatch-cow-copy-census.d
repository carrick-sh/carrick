#!/usr/sbin/dtrace -qs
/*
 * Validate bytes copied by fresh-owner and unpublished-lane COW paths.
 * Darwin arm64 scalar ABI: (old_frame, source_ipa, source_hash, dest_hash,
 * length). Length is 16 KiB for fresh owners or 4 KiB for reused lanes.
 * Perturbation is high: hashing scans every copied byte. Content/count
 * evidence only, never use this capture for wall-time or CPU attribution.
 */
#pragma D option quiet
#pragma D option bufsize=32m

dtrace:::BEGIN
{ started = timestamp; events = 0; errors = 0; seen = 0; code = -1; bounded = 0; pages = 0; compounds = 0; bytes = 0; }

carrick*:::hvpatch-frame-cow-copy
/pid == $target || progenyof($target)/
{
    events++;
    errors += arg2 != arg3 || (arg4 != 4096 && arg4 != 16384);
    pages += arg4 == 4096;
    compounds += arg4 == 16384;
    bytes += arg4;
}

syscall::exit:entry
/pid == $target/
{ seen = 1; code = (int)arg0; }

proc:::exit
/pid == $target/
{ exit(seen && code == 0 && events > 0 && errors == 0 ? 0 : 2); }

dtrace:::ERROR
{ errors++; exit(3); }

tick-1s
/timestamp - started > 45 * 1000000000/
{ bounded = 1; exit(4); }

dtrace:::END
{ printf("COWCOPY|summary|events=%d|errors=%d|seen=%d|code=%d|bounded=%d|pages=%d|compounds=%d|bytes=%llu\n", events, errors, seen, code, bounded, pages, compounds, (uint64_t)bytes); }
