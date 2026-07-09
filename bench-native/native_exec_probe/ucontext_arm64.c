#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif

#include <stdint.h>
#include <libkern/OSCacheControl.h>
#include <string.h>
#include <ucontext.h>

struct carrick_uc_snapshot {
    uint64_t x[9];
    uint64_t sp;
    uint64_t pc;
};

int carrick_snapshot_ucontext(void *uap, struct carrick_uc_snapshot *out) {
#if defined(__aarch64__)
    if (uap == 0 || out == 0) {
        return -1;
    }

    ucontext_t *uc = (ucontext_t *)uap;
    if (uc->uc_mcontext == 0) {
        return -2;
    }

    memset(out, 0, sizeof(*out));
    out->x[0] = uc->uc_mcontext->__ss.__x[0];
    out->x[1] = uc->uc_mcontext->__ss.__x[1];
    out->x[2] = uc->uc_mcontext->__ss.__x[2];
    out->x[3] = uc->uc_mcontext->__ss.__x[3];
    out->x[4] = uc->uc_mcontext->__ss.__x[4];
    out->x[5] = uc->uc_mcontext->__ss.__x[5];
    out->x[6] = uc->uc_mcontext->__ss.__x[6];
    out->x[7] = uc->uc_mcontext->__ss.__x[7];
    out->x[8] = uc->uc_mcontext->__ss.__x[8];
    out->sp = uc->uc_mcontext->__ss.__sp;
    out->pc = uc->uc_mcontext->__ss.__pc;
    return 0;
#else
    (void)uap;
    (void)out;
    return -3;
#endif
}

void carrick_probe_clear_icache(void *start, size_t len) {
    sys_icache_invalidate(start, len);
}
