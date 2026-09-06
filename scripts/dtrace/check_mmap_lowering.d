#pragma D option quiet

pid$target::*map_private_file_backed*:entry
{
    printf("map_private_file_backed ENTRY va=0x%llx len=0x%llx\n", (unsigned long long)arg1, (unsigned long long)arg2);
}

pid$target::*snapshot_private_host_file*:entry
{
    printf("snapshot_private_host_file ENTRY fd=%d len=0x%llx\n", (int)arg0, (unsigned long long)arg2);
}

pid$target::*write_bytes_unchecked*:entry
{
    printf("write_bytes_unchecked ENTRY va=0x%llx\n", (unsigned long long)arg1);
}

pid$target::*protect_range*:entry
{
    printf("protect_range ENTRY va=0x%llx len=0x%llx prot=0x%llx\n", (unsigned long long)arg1, (unsigned long long)arg2, (unsigned long long)arg3);
}
