#!/usr/bin/env python3
"""What interfaces does the guest see, and which IPv6 addresses are 'external'?

libuv's can_ipv6_external() skips udp_multicast_join6 unless some AF_INET6
address is non-internal. The Docker container has only ::1 and skips; carrick
surfaces the Mac's en0 link-local and does not.
"""
import socket, sys
print("if_nameindex:", socket.if_nameindex(), flush=True)
try:
    with open("/proc/net/if_inet6") as f:
        for line in f:
            parts = line.split()
            if len(parts) >= 6:
                addr = ":".join(parts[0][i:i+4] for i in range(0, 32, 4))
                print("  if_inet6 %-8s scope=%s addr=%s" % (parts[5], parts[3], addr), flush=True)
except OSError as e:
    print("  /proc/net/if_inet6:", e, flush=True)
sys.stdout.flush()
