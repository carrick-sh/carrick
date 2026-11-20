// Self-authored root-MM table-stock regression: one touched page in each of
// sixteen 2 MiB regions of a 32 MiB anonymous mapping.
#include <sys/mman.h>
#include <unistd.h>

int main(void) {
    const size_t stride = 2U * 1024U * 1024U;
    volatile unsigned char *memory = mmap(0, 16U * stride,
                                          PROT_READ | PROT_WRITE,
                                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (memory == MAP_FAILED) return 2;
    for (unsigned i = 0; i < 16; ++i) memory[i * stride] = (unsigned char)(i + 1);
    for (unsigned i = 0; i < 16; ++i)
        if (memory[i * stride] != i + 1) return 3;
    static const char success[] = "ROOT_TABLES_OK\n";
    return write(STDOUT_FILENO, success, sizeof(success) - 1) == sizeof(success) - 1 ? 0 : 4;
}
