#pragma D option quiet

pid$target::*map_private_file_backed*:entry
{
    self->va = arg1;
    self->len = arg2;
    self->sret = arg0;
}

pid$target::*map_private_file_backed*:return
{
    this->disc = *(uint8_t *)arg1;
    this->val = *(uint8_t *)(arg1 + 1);
    printf("map_private_file_backed RETURN va=0x%llx len=0x%llx: sret=%p disc=%d val=%d\n",
        (unsigned long long)self->va, (unsigned long long)self->len, (void *)arg1, this->disc, this->val);
}
