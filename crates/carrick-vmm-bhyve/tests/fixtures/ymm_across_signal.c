/* Regression test: AVX YMM upper halves must survive a signal save/restore.
 *
 * Loads YMM0 with a known 32-byte pattern, then kill(self, SIGUSR1) via a raw
 * syscall in the SAME inline-asm block so YMM0 stays live in the register (not
 * spilled). The pending signal is delivered at the syscall return: carrick saves
 * the guest FP into the sigframe, runs the handler (which CLOBBERS YMM0's upper
 * half), and restores the FP on rt_sigreturn. If the save/restore is FXSAVE-only
 * it loses the YMM upper 128 bits, so YMM0[128:256] comes back as the handler's
 * zeroed garbage -> "YMM_BAD". A correct XSAVE path preserves all 256 bits.
 *
 * Build (linux/amd64, static):
 *   docker run --rm -v "$PWD":/w --platform linux/amd64 gcc:13 \
 *     gcc -O2 -mavx2 -static /w/ymm_across_signal.c -o /w/ymm_across_signal
 * Oracle (real Linux): `docker run ... gcc:13 /w/ymm_across_signal` -> YMM_OK.
 * Under carrick on bhyve: `carrick run -v ...:/t <image> /t` -> must be YMM_OK
 * (was YMM_BAD before the bhyve get_xsave/set_xsave override landed).
 */
#include <signal.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

static void handler(int sig) {
    (void)sig;
    /* Clobber YMM0's upper half so the guest value MUST be restored from the
     * sigframe on rt_sigreturn. */
    __asm__ volatile("vxorps %%ymm0, %%ymm0, %%ymm0\n\t" ::: "ymm0");
}

int main(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handler;
    sigaction(SIGUSR1, &sa, NULL);

    unsigned char pat[32], out[32];
    for (int i = 0; i < 32; i++) pat[i] = (unsigned char)(i + 1);
    long pid = (long)getpid();

    __asm__ volatile(
        "vmovdqu (%1), %%ymm0\n\t"   /* ymm0 = pat (all 256 bits live)        */
        "mov %2, %%rdi\n\t"          /* rdi = pid                              */
        "mov $10, %%esi\n\t"         /* esi = SIGUSR1 (10 on Linux)            */
        "mov $62, %%eax\n\t"         /* rax = __NR_kill (62)                   */
        "syscall\n\t"                /* signal delivered here, ymm0 still live */
        "vmovdqu %%ymm0, (%0)\n\t"   /* out = ymm0 after the signal            */
        :
        : "r"(out), "r"(pat), "r"(pid)
        : "ymm0", "rax", "rdi", "rsi", "rcx", "r11", "memory");

    if (memcmp(pat, out, 32) == 0) {
        printf("YMM_OK\n");
        return 0;
    }
    printf("YMM_BAD lo=%d hi-zeroed=%d\n", memcmp(pat, out, 16) == 0,
           out[16] == 0 && out[31] == 0);
    return 1;
}
