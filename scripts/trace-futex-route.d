#pragma D option quiet
#pragma D option strsize=256

carrick*:::futex-route
/pid == $target || progenyof($target)/
{
    printf("[%d] futex-route addr=0x%llx op=%d shared=%d host=0x%llx\n",
        pid, (uint64_t)arg1, (int)arg2, (int)arg3, (uint64_t)arg4);
}

tick-1s { secs++; }
tick-1s /secs >= 8/ { exit(0); }
