// The local socket families glibc's resolver opens, on x86_64 (#1906): a
// netlink route socket (`getifaddrs`, `getaddrinfo`'s AI_ADDRCONFIG) and
// AF_UNIX sockets (the nscd probe, a local listener), made by the run root
// and then by a fork child. Every line is `who.name result`, where an fd
// prints as `fd` and a failure as `-errno`; the native run is the oracle.
// Only facts both worlds share are printed: the loopback interface and its
// address, never an interface count or a port id.
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

static const char *who;

static long call(long ret) { return ret < 0 ? -errno : ret; }

static void value(const char *name, long ret) { printf("%s.%s %ld\n", who, name, call(ret)); }

static int fd(const char *name, long ret) {
    ret = call(ret);
    if (ret >= 0) {
        printf("%s.%s fd\n", who, name);
    } else {
        printf("%s.%s %ld\n", who, name, ret);
    }
    return (int)ret;
}

// One route dump: whether the reply named `lo` (links) or 127.0.0.1
// (addresses), and whether it ended with NLMSG_DONE.
static void dump(int nl, int type, const char *name) {
    struct {
        struct nlmsghdr header;
        struct rtgenmsg family;
        char pad[3];
    } request;
    memset(&request, 0, sizeof request);
    request.header.nlmsg_len = sizeof request;
    request.header.nlmsg_type = type;
    request.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    request.header.nlmsg_seq = type;
    request.family.rtgen_family = AF_UNSPEC;
    struct sockaddr_nl kernel;
    memset(&kernel, 0, sizeof kernel);
    kernel.nl_family = AF_NETLINK;
    char label[64];
    snprintf(label, sizeof label, "%s.sendto", name);
    value(label, syscall(SYS_sendto, nl, &request, sizeof request, 0, &kernel, sizeof kernel));

    static char reply[16384];
    int done = 0, loopback = 0, error = 0;
    for (int round = 0; round < 64 && !done && !error; round++) {
        struct iovec iov = {reply, sizeof reply};
        struct sockaddr_nl from;
        struct msghdr message;
        memset(&message, 0, sizeof message);
        message.msg_name = &from;
        message.msg_namelen = sizeof from;
        message.msg_iov = &iov;
        message.msg_iovlen = 1;
        long got = syscall(SYS_recvmsg, nl, &message, 0);
        if (got <= 0) {
            snprintf(label, sizeof label, "%s.recvmsg", name);
            value(label, got);
            return;
        }
        for (struct nlmsghdr *header = (struct nlmsghdr *)reply; NLMSG_OK(header, got);
             header = NLMSG_NEXT(header, got)) {
            if (header->nlmsg_type == NLMSG_DONE) {
                done = 1;
            } else if (header->nlmsg_type == NLMSG_ERROR) {
                error = 1;
            } else if (header->nlmsg_type == RTM_NEWLINK) {
                struct ifinfomsg *link = NLMSG_DATA(header);
                int left = IFLA_PAYLOAD(header);
                for (struct rtattr *attr = IFLA_RTA(link); RTA_OK(attr, left);
                     attr = RTA_NEXT(attr, left)) {
                    if (attr->rta_type == IFLA_IFNAME && strcmp(RTA_DATA(attr), "lo") == 0) {
                        loopback = 1;
                    }
                }
            } else if (header->nlmsg_type == RTM_NEWADDR) {
                struct ifaddrmsg *address = NLMSG_DATA(header);
                int left = IFA_PAYLOAD(header);
                for (struct rtattr *attr = IFA_RTA(address); RTA_OK(attr, left);
                     attr = RTA_NEXT(attr, left)) {
                    if (address->ifa_family == AF_INET && attr->rta_type == IFA_ADDRESS &&
                        memcmp(RTA_DATA(attr), "\x7f\0\0\1", 4) == 0) {
                        loopback = 1;
                    }
                }
            }
        }
    }
    printf("%s.%s.loopback %d\n", who, name, loopback);
    printf("%s.%s.done %d\n", who, name, done);
    printf("%s.%s.error %d\n", who, name, error);
}

static void netlink(void) {
    int nl = fd("netlink.socket", syscall(SYS_socket, AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE));
    struct sockaddr_nl self;
    memset(&self, 0, sizeof self);
    self.nl_family = AF_NETLINK;
    value("netlink.bind", syscall(SYS_bind, nl, &self, sizeof self));
    socklen_t len = sizeof self;
    value("netlink.getsockname", syscall(SYS_getsockname, nl, &self, &len));
    printf("%s.netlink.getsockname.family %d len %d\n", who, self.nl_family, (int)len);
    dump(nl, RTM_GETLINK, "netlink.links");
    dump(nl, RTM_GETADDR, "netlink.addresses");
    value("netlink.close", syscall(SYS_close, nl));
}

static void local(void) {
    // glibc's nscd probe: a stream socket whose connect finds no daemon.
    int probe = fd("unix.socket", syscall(SYS_socket, AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0));
    struct sockaddr_un name;
    memset(&name, 0, sizeof name);
    name.sun_family = AF_UNIX;
    strcpy(name.sun_path, "/nonexistent-carrick-c3/socket");
    value("unix.connect.absent", syscall(SYS_connect, probe, &name, sizeof name));
    value("unix.close", syscall(SYS_close, probe));

    // A listener on an abstract name, a client, and one exchange.
    memset(&name, 0, sizeof name);
    name.sun_family = AF_UNIX;
    int length = snprintf(name.sun_path + 1, sizeof name.sun_path - 1, "carrick-c3-%s-%d", who,
                          (int)getpid());
    socklen_t size = (socklen_t)(sizeof(sa_family_t) + 1 + length);
    int listener = fd("unix.listener", syscall(SYS_socket, AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0));
    value("unix.bind", syscall(SYS_bind, listener, &name, size));
    value("unix.listen", syscall(SYS_listen, listener, 4));
    int client = fd("unix.client", syscall(SYS_socket, AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0));
    value("unix.connect", syscall(SYS_connect, client, &name, size));
    int peer = fd("unix.accept", syscall(SYS_accept4, listener, NULL, NULL, SOCK_CLOEXEC));
    value("unix.sendto", syscall(SYS_sendto, client, "hi", 2, 0, NULL, 0));
    char got[3] = {0};
    value("unix.recvfrom", syscall(SYS_recvfrom, peer, got, 2, 0, NULL, NULL));
    printf("%s.unix.recvfrom.data %s\n", who, got);
    struct sockaddr_un bound;
    memset(&bound, 0, sizeof bound);
    socklen_t bound_size = sizeof bound;
    value("unix.getsockname", syscall(SYS_getsockname, listener, &bound, &bound_size));
    printf("%s.unix.getsockname.family %d same %d\n", who, bound.sun_family,
           bound_size == size && memcmp(&bound, &name, size) == 0);
    value("unix.close.peer", syscall(SYS_close, peer));
    value("unix.close.client", syscall(SYS_close, client));
    value("unix.close.listener", syscall(SYS_close, listener));
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    who = "root";
    netlink();
    local();
    pid_t child = fork();
    if (child == 0) {
        who = "child";
        netlink();
        local();
        _exit(0);
    }
    int status = 0;
    who = "root";
    value("waitpid", waitpid(child, &status, 0) == child ? 0 : -1);
    printf("root.child.status %d\n", status);
    return 0;
}
