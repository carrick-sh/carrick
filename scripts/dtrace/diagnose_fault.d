carrick*:::vcpu-fault
{
    printf("VCPU FAULT: esr=0x%llx elr=0x%llx far=0x%llx x30=0x%llx sp=0x%llx tid=%d\n",
        arg0, arg1, arg2, arg3, arg4, arg5);
}
