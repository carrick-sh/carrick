# Signal return result ownership

`signal.return.no-result` owns successful in-ring `rt_sigreturn` completion.
Authority is [sigreturn(2)](https://man7.org/linux/man-pages/man2/sigreturn.2.html):
the operation restores the interrupted context and never returns a syscall
result. Its completion settles the same entry without a scheduler handoff or
result installation, including when carrier return work is pending.

VM-free binding: `signal_return_contract` in `carrick-personality-linux`.
Native x86/KVM binding: `x86_signal_handler.S` compares a nonzero restored
accumulator against native execution. The VM-free result-ownership assertion
failed before correction. Completion adds no memory copies, allocation, or
waits; result publication count is zero. Signed ARM binding is unavailable on
Linux and ARM still uses its host frame owner.
