/* goetexec_pagezero_probe.c — SIGSEGV-net premise probe for the Go ET_EXEC
 * value-range-scan verdict (docs/superpowers/specs/
 * 2026-08-07-goetexec-value-range-scan-verdict.md).
 *
 * What it measures: in a default-linked Darwin/arm64 host process (same
 * __PAGEZERO shape as carrick's Direct-mode loader: vmaddr 0, vmsize 4 GiB —
 * verify with `otool -l target/release/carrick | grep -A4 __PAGEZERO`), is
 * the OLD Go ET_EXEC base range [0x10000, image_end ~0x121b1a8] really a
 * guaranteed fault net?  Three facts, each printed with its receipt:
 *   1. a read of any address in that range raises a catchable
 *      SIGSEGV/SIGBUS with si_addr equal to the stale address;
 *   2. MAP_FIXED mmap inside the range FAILS — __PAGEZERO is reserved, so
 *      nothing can accidentally map over the net during the guest's life;
 *   3. MAP_FIXED mmap at the relocated base (old VA + 4 GiB) succeeds.
 * Perturbation: none — standalone probe, no carrick involvement.
 * Qualified live on Darwin 27.0.0 arm64 (this host); the __PAGEZERO default
 * is a Mach-O linker property, not a kernel tunable.
 *
 * Build/run: cc -o /tmp/pagezero_probe scripts/perf/goetexec_pagezero_probe.c
 *            /tmp/pagezero_probe
 */
#include <errno.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <mach-o/dyld.h>

static sigjmp_buf jb;
static volatile uint64_t fault_addr;
static volatile int fault_sig;

static void on_fault(int sig, siginfo_t *si, void *uap) {
    (void)uap;
    fault_sig = sig;
    fault_addr = (uint64_t)si->si_addr;
    siglongjmp(jb, 1);
}

static void probe_read(uint64_t va) {
    fault_sig = 0;
    if (sigsetjmp(jb, 1) == 0) {
        volatile uint64_t v = *(volatile uint64_t *)va;
        printf("read  0x%09llx: NO FAULT (value 0x%llx) — NET BROKEN\n",
               (unsigned long long)va, (unsigned long long)v);
    } else {
        printf("read  0x%09llx: %s si_addr=0x%llx — faults, catchable\n",
               (unsigned long long)va, fault_sig == SIGSEGV ? "SIGSEGV" : "SIGBUS",
               (unsigned long long)fault_addr);
    }
}

static void probe_map(uint64_t va) {
    void *p = mmap((void *)va, 0x10000, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANON | MAP_FIXED, -1, 0);
    if (p == MAP_FAILED)
        printf("mmap  0x%09llx MAP_FIXED: FAIL errno=%d (%s) — range reserved\n",
               (unsigned long long)va, errno, strerror(errno));
    else
        printf("mmap  0x%09llx MAP_FIXED: OK -> %p\n", (unsigned long long)va, p);
}

int main(void) {
    setbuf(stdout, NULL);
    struct sigaction sa = {0};
    sa.sa_sigaction = on_fault;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);

    /* the go1.24.13 cmd/compile ET_EXEC image span is [0x10000, 0x121b1a8] */
    probe_read(0x10000);    /* first PT_LOAD base            */
    probe_read(0x117ac08);  /* ssa.opcodeTable FP site VA    */
    probe_read(0x121b1a0);  /* last mapped word of the image */
    probe_map(0x10000);     /* net cannot be mapped over ... */
    probe_map(0x1000000);   /* ... anywhere in the old range */
    /* Relocated first PT_LOAD base. Darwin/arm64 mmap requires 16 KiB
     * alignment, so the mappable unit is the segment base — the 4 KiB-aligned
     * .text VA rides inside it, as the direct-tier loaders already handle for
     * 4K-in-16K images. 0x10000 + exactly 4 GiB collides with the host
     * executable's own default __TEXT vmaddr (0x100000000 + slide), so a
     * relocating loader picks any free high delta; +8 GiB shown here. */
    printf("host image base: 0x%llx (slide 0x%llx)\n",
           (unsigned long long)((uint64_t)_dyld_get_image_vmaddr_slide(0) + 0x100000000ull),
           (unsigned long long)_dyld_get_image_vmaddr_slide(0));
    probe_map(0x100010000); /* old+4GiB: expected to collide with host image */
    probe_map(0x200010000); /* old+8GiB: a free high delta                   */
    return 0;
}
