# x86 native exec transport (#1093 S4c)

Guest surface: `execve` from a native fork child. Linux authority: `execve(2)`;
a successful replacement never returns, while preparation failures preserve
the predecessor. The existing `process.exec.custody` contract owns this surface.

`carrick-vmm-kvm::cpl0_initial_mm::native_fork_child_execs_static_successor`
uses the production CPL0 image and executor pool. The parent remains alive in
`wait4` while the child execs a separate static ELF. The successor prints `X`
and exits zero; if exec returns, the child exits with the returned errno and
the parent propagates it. The initial witness fails with ENOSYS (38), rather
than hanging. Both fixture binaries also pass a native Linux sanity run;
this is not an arm64 Docker oracle or a signed acceptance result.

The existing VM-free `carrick-x86-cpl0::exec_successor::tests` cover closed-slot
adoption, cancellation and predecessor preservation. They already pass on main;
they do not prove the missing stopped-host transport.

The image-region import is moved from KVM boot to the shared CPL0 host
coordinator as `import_x86_image_regions`. The boot caller still owns its
root-release lease, space publication and gate opening. The helper imports
exactly the existing ELF and stack reservation rows and does not open a space.
This extraction adds no exec caller yet and changes no work budget.

Outstanding implementation: service dispatch for a child Exec request, retained
preparation custody and successor construction, stopped-vCPU adopt/cancel/settle
crossings, and exact physical predecessor retirement. These must reuse
`X86ExecSuccessor`, the neutral closed-successor protocol and shared fork stock.
Root exec and the crossing allowlist remain separate slices. The production KVM
witness is intentionally red until this work lands; it is not a known gap or
an ignored test. No runtime-ratio or signed-promotion claim is made.
