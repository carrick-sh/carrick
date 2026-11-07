/* Host preflight only: prove this user can create a VM on real /dev/kvm. */
#include <fcntl.h>
#include <linux/kvm.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <unistd.h>
int main(void) {
    int kvm = open("/dev/kvm", O_RDWR | O_CLOEXEC);
    if (kvm < 0) { perror("open /dev/kvm"); return 1; }
    int api = ioctl(kvm, KVM_GET_API_VERSION, 0);
    if (api != 12) { fprintf(stderr, "unexpected KVM API: %d\n", api); close(kvm); return 1; }
    int vm = ioctl(kvm, KVM_CREATE_VM, 0);
    if (vm < 0) { perror("KVM_CREATE_VM"); close(kvm); return 1; }
    printf("KVM_GET_API_VERSION=%d KVM_CREATE_VM=success\n", api);
    close(vm);
    close(kvm);
    return 0;
}
