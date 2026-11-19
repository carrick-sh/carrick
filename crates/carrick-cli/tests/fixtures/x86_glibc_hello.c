#include <stdio.h>

#ifndef __GLIBC__
#error "This fixture requires glibc startup and exit code"
#endif

int main(void)
{
    puts("hello, x86_64 world");
    return 0;
}
