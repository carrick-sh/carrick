#include <string.h>
#include <unistd.h>

int main(void)
{
    static const char message[] = "dynamic glibc hello\n";
    char buffer[32];
    memset(buffer, 0, sizeof buffer);
    memcpy(buffer, message, strlen(message));
    return write(STDOUT_FILENO, buffer, strlen(buffer)) == sizeof message - 1 ? 0 : 1;
}
