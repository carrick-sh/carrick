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

## Round 2: guest builder boundary and terminal refusal

The production fork-child witness still returns errno 38 on branch head
`578a9a15b`. The new VM-free production-runtime binding
`native_process_runtime::host_test_support::post_arm_exec_adoption_failure_is_sigsegv`
publishes a valid sealed preparation, installs a conflicting physical root,
and resumes the real exec continuation. It reaches the adopter after the exec
gate arms, cancels the preparation exactly once, and currently terminates with
SIGKILL (9), rather than the required SIGSEGV (11). The companion malformed
manifest case retains its existing assertions. This is a red witness, not a
claimed semantic fix; the shared ARM mapping is unchanged.

The remaining builder work cannot be replaced with host descriptor writes.
`carrick-x86-carrier/src/initial_boot.rs::load` binds staging to the original
boot extent, authenticates only bootstrap CR3 `0x600000`, and calls the one-shot
`table_span::admit_tables`. `entry::InitialWords` and
`carrick-el1-abi::x86_cpl0_table_alias` likewise license the bootstrap/initial
physical windows. Re-entering boot would overwrite live initial-image custody
and repeat global table admission. The host service currently has no retained
reply phase that lets a guest build a successor before sealing/adoption.

Proposed integration: retain a typed guest-build input with the exec
preparation, including disjoint physical grants and immutable image records.
An owned CPL0 continuation executes the existing `install_initial_image`
editor against that unopened successor, preserving the predecessor and its
execution context. A stopped completion authenticates its publication receipts
and imports image regions through `import_x86_image_regions`; only then does
preparation seal its manifest and advance to adoption. Boot and exec share the
editor and record validation, while boot alone admits the global working-table
span. Guest table aliases must authenticate the new grant extent rather than
reuse the live boot extent. Cancellation retains predecessor custody, and any
Busy/owner release retains the exact build continuation before rerun. The
existing fork-stock replacement and predecessor receipt remain the authority
for adoption and settlement.

The director confirmed this slice owns that guest entry and forbade moving
stack or descriptor authority to the host. No builder, preparation directory,
service routing, or consuming transport has been implemented in round 2.
