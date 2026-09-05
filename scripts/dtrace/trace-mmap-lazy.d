#pragma D option quiet

/*
 * TRACE MMAP LAZY FILE BACKING AND SPARSE MATERIALIZATION
 *
 * (a) Measures: calls and returns for materialize_private_file_backing,
 *     ensure_sparse_mmap_backing, overlay_shared_file_view, and zero_backing.
 * (b) Provider facts: pid provider on the carrick binary.
 * (c) Perturbation: minimal (fires only on mmap lifecycle functions).
 */

pid$target::*materialize_private_file_backing*:entry
{
    printf("[%d] materialize_private_file_backing: entry\n", pid);
}

pid$target::*materialize_private_file_backing*:return
{
    printf("[%d] materialize_private_file_backing: return %d\n", pid, (int)arg1);
}

pid$target::*overlay_shared_file_view*:entry
{
    printf("[%d] overlay_shared_file_view: entry\n", pid);
}

pid$target::*ensure_sparse_mmap_backing*:entry
{
    @sparse[probefunc] = count();
}

pid$target::*zero_guest_backing*:entry
{
    @zero[probefunc] = count();
}

tick-1s { secs++; }
tick-1s /secs >= 10/ { exit(0); }
