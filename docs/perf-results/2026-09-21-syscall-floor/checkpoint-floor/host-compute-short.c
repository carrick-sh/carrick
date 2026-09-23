// Independently authored macOS/AArch64 compute attribution, MIT OR Apache-2.0.
// Host-only control: no guest, translator, carrier, syscall or acceptance claim.
// Mirrors the timed arithmetic and scalar load/increment/store loop shapes.
// It cannot isolate CPU placement/frequency differences across host and Linux VM.
#include <inttypes.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

static uint64_t now(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t) != 0) __builtin_trap();
    return (uint64_t)t.tv_sec * 1000000000 + (uint64_t)t.tv_nsec;
}

static void *measure(void *ignored) {
    (void)ignored;
    const uint64_t n = 65536;
    for (unsigned sample = 0; sample < 10; ++sample) {
        for (unsigned order = 0; order < 2; ++order) {
            const unsigned memory = order ^ (sample & 1);
            uint64_t count = n, value = 0, data = 0;
            const uint64_t start = now();
            if (!memory) {
                __asm__ volatile(
                    "2: add %x[value], %x[value], #7\n"
                    "sub %x[value], %x[value], #6\n"
                    "sub %x[count], %x[count], #1\n"
                    "cbnz %x[count], 2b\n"
                    : [value] "+&r"(value), [count] "+&r"(count)
                    : : "cc", "memory");
            } else {
                uintptr_t base;
                __asm__ volatile(
                    // One address-producing instruction per iteration, like ADR
                    // in the ELF. This is a register copy of a host stack address.
                    "2: mov %x[base], %x[data]\n"
                    "ldr %x[value], [%x[base]]\n"
                    "add %x[value], %x[value], #1\n"
                    "str %x[value], [%x[base]]\n"
                    "sub %x[count], %x[count], #1\n"
                    "cbnz %x[count], 2b\n"
                    : [value] "=&r"(value), [count] "+&r"(count), [base] "=&r"(base)
                    : [data] "r"(&data) : "cc", "memory");
            }
            const uint64_t elapsed = now() - start;
            if (count != 0 || value != n || (memory && data != n)) __builtin_trap();
            printf("{\"phase\":%u,\"sample\":%u,\"iterations\":%" PRIu64
                   ",\"elapsed_ns\":%" PRIu64 ",\"verified\":true}\n",
                   memory ? 4 : 3, sample, n, elapsed);
        }
    }
    return NULL;
}

int main(void) {
    pthread_t worker;
    if (pthread_create(&worker, NULL, measure, NULL) != 0) return 1;
    if (pthread_join(worker, NULL) != 0) return 2;
    return 0;
}
