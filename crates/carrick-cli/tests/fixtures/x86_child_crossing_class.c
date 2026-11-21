/* Exhaustive allowlisted-crossing witness for an exec'd native child on x86_64.
 *
 * Compiled freestanding (-nostdlib -static -no-pie -fno-stack-protector) so no
 * libc startup runs before _start. Invoked with argc == 1, the root process
 * forks a child that execve()s argv[0] with argv = [argv[0], "child", NULL],
 * waits for that exec'd child to exit 0, and exits 7.
 *
 * Invoked as the exec'd child (argc == 2), it creates an isolated "cc_work"
 * scratch directory in its working directory, prepares valid targets and
 * ring/host descriptors, invokes every allowlisted crossing from
 * crates/carrick-personality-linux/src/crossing.rs and
 * docs/design/arm-ring-first-flip.tsv, cleans up "cc_work", and prints one
 * line per crossing:
 *   <canonical_nr> <x86_nr> <name> <ret>\n
 */

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long u64;
typedef long i64;

__asm__(
    ".global _start\n"
    ".text\n"
    "_start:\n"
    "    mov %rsp, %rdi\n"
    "    and $-16, %rsp\n"
    "    call entry\n"
    "    ud2\n"
);

static i64 sc6(i64 nr, i64 a0, i64 a1, i64 a2, i64 a3, i64 a4, i64 a5) {
    i64 ret;
    register i64 r10 __asm__("r10") = a3;
    register i64 r8 __asm__("r8") = a4;
    register i64 r9 __asm__("r9") = a5;
    __asm__ volatile(
        "syscall"
        : "=a"(ret)
        : "a"(nr), "D"(a0), "S"(a1), "d"(a2), "r"(r10), "r"(r8), "r"(r9)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static i64 sc0(i64 nr) { return sc6(nr, 0, 0, 0, 0, 0, 0); }
static i64 sc1(i64 nr, i64 a0) { return sc6(nr, a0, 0, 0, 0, 0, 0); }
static i64 sc2(i64 nr, i64 a0, i64 a1) { return sc6(nr, a0, a1, 0, 0, 0, 0); }
static i64 sc3(i64 nr, i64 a0, i64 a1, i64 a2) { return sc6(nr, a0, a1, a2, 0, 0, 0); }
static i64 sc4(i64 nr, i64 a0, i64 a1, i64 a2, i64 a3) { return sc6(nr, a0, a1, a2, a3, 0, 0); }
static i64 sc5(i64 nr, i64 a0, i64 a1, i64 a2, i64 a3, i64 a4) {
    return sc6(nr, a0, a1, a2, a3, a4, 0);
}

__attribute__((noreturn)) static void die(int code) {
    sc1(231, code);
    __builtin_unreachable();
}

static char out_buf[16384];
static u64 out_len = 0;

static void put_ch(char c) {
    if (out_len < sizeof(out_buf)) {
        out_buf[out_len++] = c;
    }
}

static void put_str(const char *s) {
    while (*s) {
        put_ch(*s++);
    }
}

static void put_u64(u64 v) {
    char tmp[24];
    int n = 0;
    if (v == 0) {
        put_ch('0');
        return;
    }
    while (v > 0) {
        tmp[n++] = (char)('0' + (v % 10));
        v /= 10;
    }
    while (n > 0) {
        put_ch(tmp[--n]);
    }
}

static void put_i64(i64 v) {
    if (v < 0) {
        put_ch('-');
        put_u64((u64)(-(v + 1)) + 1);
    } else {
        put_u64((u64)v);
    }
}

static void record(u64 canonical, u64 x86_nr, const char *name, i64 ret) {
    put_u64(canonical);
    put_ch(' ');
    put_u64(x86_nr);
    put_ch(' ');
    put_str(name);
    put_ch(' ');
    put_i64(ret);
    put_ch('\n');
}

static void flush_out(void) {
    u64 off = 0;
    while (off < out_len) {
        i64 w = sc3(1, 1, (i64)(out_buf + off), (i64)(out_len - off));
        if (w <= 0) {
            die(95);
        }
        off += (u64)w;
    }
    out_len = 0;
}

struct timespec_abi {
    i64 tv_sec;
    i64 tv_nsec;
};

struct itimerspec_abi {
    struct timespec_abi it_interval;
    struct timespec_abi it_value;
};

struct iovec_abi {
    void *iov_base;
    u64 iov_len;
};

struct epoll_event_abi {
    u32 events;
    u64 data;
} __attribute__((packed));

struct sockaddr_in_abi {
    u16 sin_family;
    u16 sin_port;
    u32 sin_addr;
    u8 sin_zero[8];
};

struct msghdr_abi {
    void *msg_name;
    u32 msg_namelen;
    u32 _pad0;
    struct iovec_abi *msg_iov;
    u64 msg_iovlen;
    void *msg_control;
    u64 msg_controllen;
    int msg_flags;
    int _pad1;
};

struct mmsghdr_abi {
    struct msghdr_abi msg_hdr;
    u32 msg_len;
    u32 _pad;
};

struct open_how_abi {
    u64 flags;
    u64 mode;
    u64 resolve;
};

enum {
    AT_FDCWD = -100,
    O_RDWR_CREAT_TRUNC = 0x242,
    X86_O_DIRECTORY = 0x10000,
    AT_REMOVEDIR = 0x200,
    NONBLOCK_FLAG = 0x800,
};

static int run_exit_in_grandchild(i64 x86_exit_nr) {
    int status = -1;
    i64 pid = sc0(57);
    if (pid < 0) {
        return (int)pid;
    }
    if (pid == 0) {
        sc1(x86_exit_nr, 0);
        die(96);
    }
    i64 w = sc4(61, pid, (i64)&status, 0, 0);
    if (w < 0) {
        return (int)w;
    }
    return status == 0 ? 0 : -1;
}

static void run_child_crossings(const char *self_path) {
    static const char p_dot[] = ".";
    static const char p_parent[] = "..";
    static const char p_work[] = "cc_work";
    static const char p_sub[] = "cc_sub";
    static const char p_file[] = "cc_file";
    static const char p_file2[] = "cc_file2";
    static const char p_mkdir[] = "cc_mkdir";
    static const char p_fifo[] = "cc_fifo";
    static const char p_sym[] = "cc_sym";
    static const char p_hard[] = "cc_hard";
    static const char p_ren[] = "cc_ren";
    static const char p_ren2[] = "cc_ren2";
    static const char p_missing[] = "cc_missing_1795";
    static const char p_proc_exe[] = "/proc/self/exe";
    static const char xattr_k[] = "user.k";
    static const char xattr_missing[] = "user.missing";
    static const char data4[] = "abcd";
    const char *child_argv[3] = { self_path, "noop", 0 };

    u8 scratch[512];
    u8 stat_buf[256];
    u8 statx_buf[256];
    u8 statfs_buf[128];
    u8 tms_buf[64];
    u8 tv_buf[32];
    u8 vec_byte[8];
    for (u64 i = 0; i < sizeof(scratch); ++i) scratch[i] = 0;

    if (sc3(258, AT_FDCWD, (i64)p_work, 0755) < 0) die(79);
    if (sc1(80, (i64)p_work) < 0) die(78);
    if (sc3(258, AT_FDCWD, (i64)p_sub, 0755) < 0) die(77);

    i64 fd = sc4(257, AT_FDCWD, (i64)p_file, O_RDWR_CREAT_TRUNC, 0644);
    if (fd < 0) die(80);
    if (sc3(1, fd, (i64)data4, 4) != 4) die(81);

    i64 fd2 = sc4(257, AT_FDCWD, (i64)p_file2, O_RDWR_CREAT_TRUNC, 0644);
    if (fd2 < 0) die(82);

    i64 work_dir_fd = sc4(257, AT_FDCWD, (i64)p_dot, X86_O_DIRECTORY, 0);
    if (work_dir_fd < 0) die(83);

    int pfd[2] = { -1, -1 };
    int pfd2[2] = { -1, -1 };
    if (sc2(293, (i64)pfd, NONBLOCK_FLAG) != 0) die(84);
    if (sc2(293, (i64)pfd2, NONBLOCK_FLAG) != 0) die(85);
    if (sc3(1, pfd[1], (i64)data4, 2) != 2) die(86);

    i64 epfd = sc1(291, 0);
    if (epfd < 0) die(87);

    i64 anon = sc6(9, 0, 4096, 3, 0x22, -1, 0);
    if (anon < 0 && (u64)anon > (u64)-4096L) die(88);
    *(volatile u8 *)anon = 0x5a;

    struct timespec_abi zero_ts = { 0, 0 };
    struct timespec_abi ts_out = { 0, 0 };
    struct itimerspec_abi zero_its = { { 0, 0 }, { 0, 0 } };
    struct itimerspec_abi its_out = { { 0, 0 }, { 0, 0 } };
    struct iovec_abi iov_in = { scratch, 4 };
    struct iovec_abi iov_out = { (void *)data4, 4 };
    struct epoll_event_abi ev = { 1, 0x1234 };
    struct epoll_event_abi ev_out = { 0, 0 };
    u64 sigmask = 0;
    int int_val = 0;
    i64 off0 = 0;
    i64 off0_out = 0;

    /* 5..16: xattr family */
    record(5, 188, "setxattr", sc5(188, (i64)p_file, (i64)xattr_k, (i64)data4, 1, 0));
    record(6, 189, "lsetxattr", sc5(189, (i64)p_file, (i64)xattr_k, (i64)data4, 1, 0));
    record(7, 190, "fsetxattr", sc5(190, fd, (i64)xattr_k, (i64)data4, 1, 0));
    record(8, 191, "getxattr", sc4(191, (i64)p_file, (i64)xattr_k, (i64)scratch, 64));
    record(9, 192, "lgetxattr", sc4(192, (i64)p_file, (i64)xattr_k, (i64)scratch, 64));
    record(10, 193, "fgetxattr", sc4(193, fd, (i64)xattr_k, (i64)scratch, 64));
    record(11, 194, "listxattr", sc3(194, (i64)p_file, (i64)scratch, 64));
    record(12, 195, "llistxattr", sc3(195, (i64)p_file, (i64)scratch, 64));
    record(13, 196, "flistxattr", sc3(196, fd, (i64)scratch, 64));
    record(14, 197, "removexattr", sc2(197, (i64)p_file, (i64)xattr_missing));
    record(15, 198, "lremovexattr", sc2(198, (i64)p_file, (i64)xattr_missing));
    record(16, 199, "fremovexattr", sc2(199, fd, (i64)xattr_missing));

    /* 17..38: cwd, epoll, dup, fcntl, inotify, ioctl, flock, namespace creation */
    record(17, 79, "getcwd", sc2(79, (i64)scratch, 256));
    record(21, 233, "epoll_ctl", sc4(233, epfd, 1, pfd[0], (i64)&ev));
    record(22, 281, "epoll_pwait", sc6(281, epfd, (i64)&ev_out, 1, 0, 0, 8));
    i64 dupfd = sc1(32, fd);
    record(23, 32, "dup", dupfd);
    i64 dup3fd = sc3(292, fd, 30, 0);
    record(24, 292, "dup3", dup3fd);
    record(25, 72, "fcntl", sc3(72, fd, 3, 0));
    i64 ifd = sc1(294, NONBLOCK_FLAG);
    record(26, 294, "inotify_init1", ifd);
    if (ifd >= 0) sc1(3, ifd);
    record(29, 16, "ioctl", sc3(16, pfd[0], 0x541b, (i64)&int_val));
    record(32, 73, "flock", sc2(73, fd, 5));
    i64 mk_fifo = sc4(259, AT_FDCWD, (i64)p_fifo, 010600, 0);
    record(33, 259, "mknodat", mk_fifo);
    if (mk_fifo == 0) sc3(263, AT_FDCWD, (i64)p_fifo, 0);
    record(34, 258, "mkdirat", sc3(258, AT_FDCWD, (i64)p_mkdir, 0755));
    record(35, 263, "unlinkat", sc3(263, AT_FDCWD, (i64)p_mkdir, AT_REMOVEDIR));
    record(36, 266, "symlinkat", sc3(266, (i64)p_file, AT_FDCWD, (i64)p_sym));
    record(37, 265, "linkat", sc5(265, AT_FDCWD, (i64)p_file, AT_FDCWD, (i64)p_hard, 0));
    record(38, 264, "renameat", sc4(264, AT_FDCWD, (i64)p_hard, AT_FDCWD, (i64)p_ren));

    /* 43..57: statfs, sizing, access, cwd, mode/owner, open/close */
    record(43, 137, "statfs", sc2(137, (i64)p_dot, (i64)statfs_buf));
    record(44, 138, "fstatfs", sc2(138, fd, (i64)statfs_buf));
    record(45, 76, "truncate", sc2(76, (i64)p_file, 8));
    record(46, 77, "ftruncate", sc2(77, fd, 4));
    record(47, 285, "fallocate", sc4(285, fd, 0, 0, 8));
    record(48, 269, "faccessat", sc4(269, AT_FDCWD, (i64)p_file, 0, 0));
    record(49, 80, "chdir", sc1(80, (i64)p_sub));
    record(50, 81, "fchdir", sc1(81, work_dir_fd));
    record(51, 161, "chroot", sc1(161, (i64)p_missing));
    record(52, 91, "fchmod", sc2(91, fd, 0644));
    record(53, 268, "fchmodat", sc4(268, AT_FDCWD, (i64)p_file, 0644, 0));
    record(54, 260, "fchownat", sc5(260, AT_FDCWD, (i64)p_file, -1, -1, 0));
    record(55, 93, "fchown", sc3(93, fd, -1, -1));
    i64 opened = sc4(257, AT_FDCWD, (i64)p_file, 0, 0);
    record(56, 257, "openat", opened);
    if (opened >= 0) sc1(3, opened);
    record(57, 3, "close", sc1(3, dupfd >= 0 ? dupfd : -1));

    /* 61..88: directory, positioned/vectored I/O, splice, stat, sync, timerfd, utimensat */
    record(61, 217, "getdents64", sc3(217, work_dir_fd, (i64)scratch, 512));
    record(62, 8, "lseek", sc3(8, fd, 0, 0));
    record(63, 0, "read", sc3(0, fd, (i64)scratch, 4));
    record(64, 1, "write", sc3(1, fd, (i64)data4, 4));
    sc3(8, fd, 0, 0);
    record(65, 19, "readv", sc3(19, fd, (i64)&iov_in, 1));
    record(66, 20, "writev", sc3(20, fd, (i64)&iov_out, 1));
    record(67, 17, "pread64", sc4(17, fd, (i64)scratch, 4, 0));
    record(68, 18, "pwrite64", sc4(18, fd, (i64)data4, 4, 0));
    record(69, 295, "preadv", sc5(295, fd, (i64)&iov_in, 1, 0, 0));
    record(70, 296, "pwritev", sc5(296, fd, (i64)&iov_out, 1, 0, 0));
    off0 = 0;
    record(71, 40, "sendfile", sc4(40, fd2, fd, (i64)&off0, 4));
    u64 rdset = 1UL << pfd[0];
    record(72, 270, "pselect6", sc6(270, pfd[0] + 1, (i64)&rdset, 0, 0, (i64)&zero_ts, 0));
    i64 sfd = sc4(289, -1, (i64)&sigmask, 8, NONBLOCK_FLAG);
    record(74, 289, "signalfd4", sfd);
    if (sfd >= 0) sc1(3, sfd);
    record(75, 278, "vmsplice", sc4(278, pfd[1], (i64)&iov_out, 1, 2));
    record(76, 275, "splice", sc6(275, pfd[0], 0, pfd2[1], 0, 1, 2));
    record(77, 276, "tee", sc4(276, pfd2[0], pfd[1], 1, 2));
    record(78, 267, "readlinkat", sc4(267, AT_FDCWD, (i64)p_proc_exe, (i64)scratch, 256));
    record(79, 262, "newfstatat", sc4(262, AT_FDCWD, (i64)p_file, (i64)stat_buf, 0));
    record(80, 5, "fstat", sc2(5, fd, (i64)stat_buf));
    record(81, 162, "sync", sc0(162));
    record(82, 74, "fsync", sc1(74, fd));
    record(83, 75, "fdatasync", sc1(75, fd));
    record(84, 277, "sync_file_range", sc4(277, fd, 0, 4, 0));
    i64 tfd = sc2(283, 1, NONBLOCK_FLAG);
    record(85, 283, "timerfd_create", tfd);
    record(86, 286, "timerfd_settime", sc4(286, tfd >= 0 ? tfd : fd, 0, (i64)&zero_its, 0));
    record(87, 287, "timerfd_gettime", sc2(287, tfd >= 0 ? tfd : fd, (i64)&its_out));
    if (tfd >= 0) sc1(3, tfd);
    record(88, 280, "utimensat", sc4(280, AT_FDCWD, (i64)p_file, 0, 0));

    /* 93..94: terminal crossings in grandchildren */
    record(93, 60, "exit", run_exit_in_grandchild(60));
    record(94, 231, "exit_group", run_exit_in_grandchild(231));

    /* 101..169: sleep and clock crossings */
    record(101, 35, "nanosleep", sc2(35, (i64)&zero_ts, 0));
    record(113, 228, "clock_gettime", sc2(228, 0, (i64)&ts_out));
    record(114, 229, "clock_getres", sc2(229, 0, (i64)&ts_out));
    record(115, 230, "clock_nanosleep", sc4(230, 0, 0, (i64)&zero_ts, 0));
    record(153, 100, "times", sc1(100, (i64)tms_buf));
    record(169, 96, "gettimeofday", sc2(96, (i64)tv_buf, 0));

    /* 198..212, 242, 243, 269: socket crossings */
    i64 tcp_sock = sc3(41, 2, 1 | NONBLOCK_FLAG, 0);
    record(198, 41, "socket", tcp_sock);
    int sv[2] = { -1, -1 };
    i64 sp_ret = sc4(53, 1, 1 | NONBLOCK_FLAG, 0, (i64)sv);
    record(199, 53, "socketpair", sp_ret);
    if (sp_ret == 0) {
        sc1(3, sv[0]);
        sc1(3, sv[1]);
    }

    struct sockaddr_in_abi loopback = { 2, 0, 0x0100007fU, { 0 } };
    struct sockaddr_in_abi bound_addr = { 0, 0, 0, { 0 } };
    u32 addrlen = sizeof(bound_addr);
    int one = 1;
    int opt_out = 0;
    u32 optlen = 4;

    i64 udp_sock = sc3(41, 2, 2 | NONBLOCK_FLAG, 0);
    if (udp_sock >= 0) {
        sc3(49, udp_sock, (i64)&loopback, sizeof(loopback));
        addrlen = sizeof(bound_addr);
        sc3(51, udp_sock, (i64)&bound_addr, (i64)&addrlen);
    }

    i64 s_target = tcp_sock >= 0 ? tcp_sock : fd;
    i64 u_target = udp_sock >= 0 ? udp_sock : fd;
    record(200, 49, "bind", sc3(49, s_target, (i64)&loopback, sizeof(loopback)));
    record(201, 50, "listen", sc2(50, s_target, 1));
    record(202, 43, "accept", sc3(43, s_target, 0, 0));
    record(203, 42, "connect", sc3(42, u_target, (i64)&bound_addr, sizeof(bound_addr)));
    addrlen = sizeof(bound_addr);
    record(204, 51, "getsockname", sc3(51, s_target, (i64)&bound_addr, (i64)&addrlen));
    addrlen = sizeof(bound_addr);
    record(205, 52, "getpeername", sc3(52, u_target, (i64)&bound_addr, (i64)&addrlen));
    record(206, 44, "sendto", sc6(44, u_target, (i64)data4, 1, 0x40, 0, 0));
    record(207, 45, "recvfrom", sc6(45, u_target, (i64)scratch, 16, 0x40, 0, 0));
    record(208, 54, "setsockopt", sc5(54, s_target, 1, 2, (i64)&one, 4));
    record(209, 55, "getsockopt", sc5(55, s_target, 1, 2, (i64)&opt_out, (i64)&optlen));

    struct iovec_abi msg_iov = { (void *)data4, 1 };
    struct iovec_abi rmsg_iov = { scratch, 16 };
    struct msghdr_abi msg = { 0, 0, 0, &msg_iov, 1, 0, 0, 0, 0 };
    struct msghdr_abi rmsg = { 0, 0, 0, &rmsg_iov, 1, 0, 0, 0, 0 };
    struct mmsghdr_abi mmsg = { msg, 0, 0 };
    struct mmsghdr_abi rmmsg = { rmsg, 0, 0 };
    record(211, 46, "sendmsg", sc3(46, u_target, (i64)&msg, 0x40));
    record(212, 47, "recvmsg", sc3(47, u_target, (i64)&rmsg, 0x40));
    record(242, 288, "accept4", sc4(288, s_target, 0, 0, NONBLOCK_FLAG));
    record(269, 307, "sendmmsg", sc4(307, u_target, (i64)&mmsg, 1, 0x40));
    record(243, 299, "recvmmsg", sc5(299, u_target, (i64)&rmmsg, 1, 0x40, 0));
    record(210, 48, "shutdown", sc2(48, s_target, 2));
    if (tcp_sock >= 0) sc1(3, tcp_sock);
    if (udp_sock >= 0) sc1(3, udp_sock);

    /* 213..452: readahead, execve/at, mm hints/locks, syncfs, renameat2, getrandom, copy_file_range, preadv2/pwritev2, statx, close_range, openat2, faccessat2, epoll_pwait2, fchmodat2 */
    record(213, 187, "readahead", sc3(187, fd, 0, 4));
    record(221, 59, "execve", sc3(59, (i64)p_missing, (i64)child_argv, 0));
    record(223, 221, "fadvise64", sc4(221, fd, 0, 4, 0));
    record(227, 26, "msync", sc3(26, anon, 4096, 4));
    record(228, 149, "mlock", sc2(149, anon, 4096));
    record(229, 150, "munlock", sc2(150, anon, 4096));
    record(230, 151, "mlockall", sc1(151, 1));
    record(231, 152, "munlockall", sc0(152));
    record(232, 27, "mincore", sc3(27, anon, 4096, (i64)vec_byte));
    record(233, 28, "madvise", sc3(28, anon, 4096, 0));
    record(267, 306, "syncfs", sc1(306, fd));
    record(276, 316, "renameat2", sc5(316, AT_FDCWD, (i64)p_ren, AT_FDCWD, (i64)p_ren2, 0));
    record(278, 318, "getrandom", sc3(318, (i64)scratch, 16, 0));
    record(281, 322, "execveat", sc5(322, AT_FDCWD, (i64)p_missing, (i64)child_argv, 0, 0));
    record(284, 325, "mlock2", sc3(325, anon, 4096, 0));
    off0 = 0;
    off0_out = 0;
    record(285, 326, "copy_file_range", sc6(326, fd, (i64)&off0, fd2, (i64)&off0_out, 4, 0));
    record(286, 327, "preadv2", sc6(327, fd, (i64)&iov_in, 1, 0, 0, 0));
    record(287, 328, "pwritev2", sc6(328, fd, (i64)&iov_out, 1, 0, 0, 0));
    record(291, 332, "statx", sc5(332, AT_FDCWD, (i64)p_file, 0, 0x7ff, (i64)statx_buf));
    record(436, 436, "close_range", sc3(436, 30, 30, 0));
    if (dup3fd >= 0 && dup3fd != 30) sc1(3, dup3fd);
    struct open_how_abi how = { 0, 0, 0 };
    i64 opened2 = sc4(437, AT_FDCWD, (i64)p_file, (i64)&how, sizeof(how));
    record(437, 437, "openat2", opened2);
    if (opened2 >= 0) sc1(3, opened2);
    record(439, 439, "faccessat2", sc4(439, AT_FDCWD, (i64)p_file, 0, 0));
    record(441, 441, "epoll_pwait2", sc6(441, epfd, (i64)&ev_out, 1, (i64)&zero_ts, 0, 8));
    record(452, 452, "fchmodat2", sc4(452, AT_FDCWD, (i64)p_file, 0644, 0));

    /* Cleanup */
    sc2(11, anon, 4096);
    sc1(3, epfd);
    sc1(3, pfd[0]);
    sc1(3, pfd[1]);
    sc1(3, pfd2[0]);
    sc1(3, pfd2[1]);
    sc1(3, work_dir_fd);
    sc1(3, fd2);
    sc1(3, fd);
    sc3(263, AT_FDCWD, (i64)p_sym, 0);
    sc3(263, AT_FDCWD, (i64)p_hard, 0);
    sc3(263, AT_FDCWD, (i64)p_ren, 0);
    sc3(263, AT_FDCWD, (i64)p_ren2, 0);
    sc3(263, AT_FDCWD, (i64)p_file2, 0);
    sc3(263, AT_FDCWD, (i64)p_file, 0);
    sc3(263, AT_FDCWD, (i64)p_sub, AT_REMOVEDIR);
    sc1(80, (i64)p_parent);
    sc3(263, AT_FDCWD, (i64)p_work, AT_REMOVEDIR);

    flush_out();
    die(0);
}

void entry(u64 *sp) {
    u64 argc = sp[0];
    const char *self_path = (const char *)sp[1];
    if (argc >= 2) {
        run_child_crossings(self_path);
    }
    i64 pid = sc0(57);
    if (pid < 0) {
        die(90);
    }
    if (pid == 0) {
        const char *argv[3] = { self_path, "child", 0 };
        sc3(59, (i64)self_path, (i64)argv, 0);
        die(92);
    }
    int status = -1;
    if (sc4(61, pid, (i64)&status, 0, 0) < 0 || status != 0) {
        die(91);
    }
    die(7);
}
