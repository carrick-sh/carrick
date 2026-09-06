#pragma D option quiet

/*
 * TRACE MMAP BACKING REFUSAL REASON
 *
 * (a) Measures: entry/return of materialize_private_file_backing,
 *     whether materialize_sparse_mmap_extent is reached,
 *     and whether mapping_for_range found any mapping.
 * (b) Provider facts: pid provider on carrick binary.
 * (c) Perturbation: minimal.
 */

pid$target::*materialize_private_file_backing*:entry
{
    self->in_backing = 1;
    self->va = arg1;
    self->len = arg2;
    printf("BACKING ENTRY: va=0x%llx len=0x%llx\n", (unsigned long long)arg1, (unsigned long long)arg2);
}

pid$target::*materialize_sparse_mmap_extent*:entry
/self->in_backing/
{
    printf("  EXTENT ENTRY: start=0x%llx end=0x%llx\n", (unsigned long long)arg1, (unsigned long long)arg2);
}

pid$target::*materialize_sparse_mmap_extent*:return
/self->in_backing/
{
    printf("  EXTENT RETURN: arg1=0x%llx\n", (unsigned long long)arg1);
}

pid$target::*materialize_private_file_backing*:return
{
    printf("BACKING RETURN: va=0x%llx ret=%d\n", (unsigned long long)self->va, (int)arg1);
    self->in_backing = 0;
}

