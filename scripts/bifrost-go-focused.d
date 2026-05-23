#!/usr/bin/env bifrost
#pragma D option quiet

tracepoint:guest:syscalls:sys_enter_rt_sigaction
{
    printf("rt_sigaction pid=%d sig=%d new=%#x old=%#x size=%d\n",
        pid, arg0, arg1, arg2, arg3);
}

tracepoint:guest:syscalls:sys_enter_tgkill
{
    printf("tgkill pid=%d tgid=%d tid=%d sig=%d\n",
        pid, arg0, arg1, arg2);
}

tracepoint:guest:syscalls:sys_enter_epoll_pwait
{
    printf("epoll_pwait enter pid=%d epfd=%d events=%#x max=%d timeout=%d\n",
        pid, arg0, arg1, arg2, arg3);
}

tracepoint:guest:syscalls:sys_exit_epoll_pwait
{
    printf("epoll_pwait exit pid=%d ret=%d\n", pid, arg0);
}

tracepoint:guest:signal:signal_generate
{
    printf("signal_generate pid=%d sig=%d errno=%d code=%d\n",
        pid, arg0, arg1, arg2);
}
