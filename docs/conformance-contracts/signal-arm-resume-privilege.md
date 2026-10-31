# ARM signal return privilege boundary

`signal.arm.resume-privilege` owns ARM `rt_sigreturn` routing and the
supervisor resume-state publication boundary. Linux authority is
`sigreturn(2)`: return restores a userspace context, never a supervisor
execution context. Until ARM delivery moves in-ring, syscall 139 forwards
to the carrier that owns the delivered frame ABI.

VM-free bindings are `arm_sigreturn_stays_with_host_frame_owner` in
`carrick-personality-linux` and
`forged_supervisor_or_masked_pstate_is_refused` in `carrick-el1`. The latter
rejects EL1 and each DAIF masking bit, while accepting EL0 with NZCV.
The structural budget is one constant-time PSTATE check before any register
publication, with no additional copies, waits, or allocations. Both tests
were red before the routing and validation corrections.

Signed ARM execution and same-image oracle bindings remain outstanding;
VM-free evidence does not establish full signal frame compatibility. The
in-ring ARM restore path remains unrouted until Linux ucontext and FPSIMD
restore and forced SIGSEGV on invalid frames are implemented together.

The public ARM frame codec is shared by the carrier and dormant EL1 backend
in `carrick-personality-linux::signal::arm`, under
`kernel.el1.signal-delivery-owner`. `arm_public_signal_frame_roundtrip_has_no_private_magic`
restores the public prefix without a private trailer. The extension witnesses
cover reordered FPSIMD, duplicate FPSIMD/ESR, malformed lengths, missing or
half terminators, truncated extents, and refusal before GPR/SIMD publication.
The parser walks the entire admitted 4 KiB reserved area through the null
record, advancing by at least 16 bytes per nonterminal record with checked
bounds, no allocation and no guest-pointer chasing. The admitted lane carries
FPSIMD and optional ESR; SVE/SME and out-of-line extra context are refused.
Authority for this record format is the [public arm64 SVE signal ABI
documentation](https://www.kernel.org/doc/html/latest/arch/arm64/sve.html#signal-handling)
and [Arm's Linux Plumbers 2017 signal-frame diagrams](https://blog.linuxplumbersconf.org/2017/ocw/system/presentations/4671/original/plumbers-dm-2017.pdf),
alongside [sigreturn(2)](https://man7.org/linux/man-pages/man2/sigreturn.2.html)
and the Arm Architecture Reference Manual for A-profile (`SPSR_EL1` / `PSTATE`
EL0 condition and execution-state fields `NZCV[31:28]`, `DIT[24]`, `SSBS[12]`
versus privileged `M[4:0]` and `DAIF[9:6]`). On signal delivery, `arm_signal::build`
masks internal EL1/EL0 execution-control bits (`0x3c0` in masked mode or `0x340`
in GIC mode) out of `uc_mcontext.pstate` via `AARCH64_EL0_USER_PSTATE_MASK`
while preserving legal guest EL0 flags, and `SignalFrameParams` carries
`interrupted_sp` separately from the selected placement `sp` so `uc_mcontext.sp`
records the interrupted user SP even when `SA_ONSTACK` places the handler frame
on the alternate stack (matching native arm64 Linux oracle
`sha256:5e927c284bf55a7dc796262e311a0703344f62f41f5621eb56843111b1d37e15`:
`sa_onstack frame_on_alt=1 saved_sp_on_alt=0 pstate=0x60000000`). On `rt_sigreturn`,
`arm::decode` rejects any non-EL0-user `pstate` bit before register or FPSIMD
publication, and `arm_signal::restore` / `apply_restored_context` re-apply the
canonical internal EL0 DAIF mask (`0x3c0` on bits `[9:6]`, `AARCH64_EL0_VISIBLE_DAIF`;
cleared of `PSTATE.I` at the `write_el1_hook` `eret` boundary when `El1IrqMode::Gic`
is active so `(spsr & 0x3c0) | PSTATE_I == 0x3c0` holds across both modes) while
preserving legal guest EL0 flags in `AARCH64_EL0_USER_PSTATE_MASK`
(`arm_signal_delivery_masks_internal_daif_and_preserves_el0_user_pstate_flags`,
`arm_public_return_restores_internal_daif_and_preserves_el0_user_flags`,
`arm_signal_delivery_separates_interrupted_sp_from_altstack_placement`, and
`production_deliver_signal_on_syscall_return_preserves_interrupted_sp_and_masks_daif`).

The ARM `sigaltstack` setup case of `kernel.el1.signal-delivery-owner`
uses the VM-free `sigaltstack_serves_off_the_alternate_stack` witness. Native
arm64 Docker oracle confirmation is still required at the atomic cutover.
The arm64 minimum is 5120 bytes (5119 returns ENOMEM); x86_64 retains its
separate 2048-byte minimum. Linux treats input SS_ONSTACK as a no-op and
ignores SS_AUTODISARM when SS_DISABLE is set. For the downward-growing stack,
the base SP is off-stack and the initial top SP is on-stack. The setup witnesses
also require a new rt_sigprocmask mask to remain committed when writing oldset
returns EFAULT, with any newly owed signal work preserved. These VM-free
checks do not establish signed ARM delivery.
Bad flags plus undersized
storage return EINVAL (-22); undersized storage alone returns ENOMEM (-12);
SS_DISABLE ignores size. Input and output may alias: the entire new stack is
read before the old stack is written, and the old value is returned while the
new value is installed. Bad input and output pointers return EFAULT (-14).
A valid replacement (including SS_DISABLE) is committed before writing old_ss,
so an old_ss fault returns EFAULT with the new stack state retained.
Bad flags beat a bad output pointer with EINVAL, and output remains untouched
on validation errors. While executing on the alternate stack, input copy-in
runs first (so an invalid ss pointer returns EFAULT (-14)), and any readable
change (valid, bad flags, undersized, or disable) returns EPERM (-1), even with
a bad output pointer; no output is written. An on-stack query reports
SS_ONSTACK. SS_AUTODISARM is accepted and is returned in the old flags at bit
31. The structural budget is one fixed-size input read, one fixed-size output
write, and one slot publication after validation, with no carrier handback,
task scan, allocation, or wait.
