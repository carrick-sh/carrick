#pragma D option quiet
#pragma D option strsize=256
carrick*:::hv-vm-map-alias
{
    printf("HVMAP va=0x%llx ipa=0x%llx size=0x%llx rc=%d forked=%d\n",
        (unsigned long long)arg0,(unsigned long long)arg1,(unsigned long long)arg2,(int)arg3,(int)arg4);
}
carrick*:::pt-alias-walk
{
    printf("PTWALK rc=%d\n", (int)arg5);
}
