# followup-3: chroot has no hermetic witness

Part of #2157. chroot needs CAP_SYS_CHROOT natively, so a native oracle run of a fixture cannot
pass unprivileged, and the x86 root's chroot would change the kernel graph's root for later
staged opens. Left unflipped until a privileged oracle lane or a typed witness exists.
