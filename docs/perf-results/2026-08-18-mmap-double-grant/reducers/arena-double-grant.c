/* arena-double-grant.c — does carrick's mmap arena hand out one VA twice?
 *
 * Carrick's anonymous-arena allocator has two independent hand-out paths
 * (`crates/carrick-runtime/src/dispatch/mem.rs`, `next_mmap_address_inner`):
 *
 *   - a free-list FIRST FIT over `free_regions` (`mem.rs:2307`), and
 *   - a BUMP cursor `mmap_next` (`mem.rs:2316`).
 *
 * They are reconciled only by the invariant stated at `mem.rs:485` —
 * "everything at/above `mmap_next` is unallocated" — and NOTHING enforces its
 * second half: no code path clamps a `free_regions` entry to lie below
 * `mmap_next`. Two guest sequences that are ordinary on Linux put a free region
 * strictly ABOVE the cursor, after which the free list hands that VA out and
 * the bump cursor later climbs over it and hands out the SAME VA a second time.
 * The second hand-out is flagged `stale` (it is below `mmap_writable_high`), so
 * carrick memsets it to zero — through the first grant's live mapping.
 *
 * Case B is the cheap one: `MAP_FIXED` returns early at `mem.rs:2276` WITHOUT
 * advancing `mmap_next`, so munmapping that mapping inserts a free region above
 * the cursor with no other setup.
 * Case A needs a superset munmap: the absorb loop at `mem.rs:4295` only takes
 * free regions CONTIGUOUS BELOW the lowered cursor, so an interior hole that
 * the lowering jumps past survives above it.
 *
 * RED (carrick): `alias=1`, and/or the first grant's bytes read back as 00.
 * GREEN (Linux): `alias=0` and the bytes are intact — Linux never returns a
 * live VA from `mmap(NULL, ...)`.
 *
 * Run identically under carrick and under the native-arm64 Docker oracle, one
 * at a time, never concurrently.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static size_t PAGE;
/* Big enough that an incidental libc/ld.so hole is never the first fit. */
#define NPAGES 32

static char *anon(size_t n) {
    void *p = mmap(NULL, n, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    return p == MAP_FAILED ? NULL : (char *)p;
}

/* How many of `n` bytes are zero — the first grant was filled with 0x5A, so a
 * nonzero count is carrick's reuse scrub writing through a live mapping. */
static size_t zeros(const char *p, size_t n) {
    size_t z = 0;
    for (size_t i = 0; i < n; i++) if (p[i] == 0) z++;
    return z;
}

/* Case B — MAP_FIXED above the cursor, then munmap it. */
static int case_fixed(void) {
    char *probe = anon(PAGE);
    if (!probe) return fprintf(stderr, "B: probe mmap failed\n"), 2;
    /* Ends exactly at the cursor, so carrick lowers the cursor back to here. */
    munmap(probe, PAGE);

    char *fixed_at = probe + 512 * PAGE;          /* free by the invariant */
    char *f = mmap(fixed_at, NPAGES * PAGE, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (f == MAP_FAILED) return fprintf(stderr, "B: MAP_FIXED failed\n"), 2;
    memset(f, 0x5A, NPAGES * PAGE);                   /* raise the dirty watermark */
    munmap(f, NPAGES * PAGE);                         /* free region above cursor */

    char *first = anon(NPAGES * PAGE);                /* expect the free-list fit */
    if (!first) return fprintf(stderr, "B: first mmap failed\n"), 2;
    memset(first, 0x5A, NPAGES * PAGE);

    /* Now walk the bump cursor upward and see whether it re-issues `first`. */
    int alias = 0;
    for (int i = 0; i < 96 && !alias; i++) {
        char *g = anon(NPAGES * PAGE);
        if (!g) break;
        if (g == first) alias = 1;
    }
    size_t z = zeros(first, NPAGES * PAGE);
    printf("B fixed_at=%p first=%p alias=%d zeroed_bytes_of_first=%zu\n",
           (void *)fixed_at, (void *)first, alias, z);
    return alias || z ? 1 : 0;
}

/* Case A — an interior hole that a superset munmap's cursor lowering jumps. */
static int case_superset(void) {
    char *a = anon(4 * NPAGES * PAGE);
    if (!a) return fprintf(stderr, "A: mmap failed\n"), 2;
    memset(a, 0xAA, 4 * NPAGES * PAGE);
    munmap(a + NPAGES * PAGE, NPAGES * PAGE);   /* interior hole, cursor unchanged */
    munmap(a, 4 * NPAGES * PAGE);             /* superset: ends at cursor, lowers it */

    char *first = anon(NPAGES * PAGE);     /* expect the surviving hole */
    if (!first) return fprintf(stderr, "A: reuse mmap failed\n"), 2;
    memset(first, 0x5A, NPAGES * PAGE);

    int alias = 0;
    for (int i = 0; i < 96 && !alias; i++) {
        char *g = anon(NPAGES * PAGE);
        if (!g) break;
        if (g == first) alias = 1;
    }
    size_t z = zeros(first, NPAGES * PAGE);
    printf("A base=%p first=%p alias=%d zeroed_bytes_of_first=%zu\n",
           (void *)a, (void *)first, alias, z);
    return alias || z ? 1 : 0;
}

int main(void) {
    PAGE = (size_t)sysconf(_SC_PAGESIZE);
    printf("page=%zu\n", PAGE);
    int rc = 0;
    rc |= case_fixed();
    rc |= case_superset();
    printf("verdict=%s\n", rc ? "DOUBLE-GRANT-OBSERVED" : "clean");
    return rc;
}
