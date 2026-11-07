# File transfer copy refusals (slice 5a)

`kernel.copyout.owner-refusal` covers the host dispatcher's explicit sendfile
offset. Linux sendfile(2) advances that pointer by bytes transferred and leaves
the input description offset unchanged. Internal owner contention must not
become errno 14 or replay the transfer. The VM-free production dispatcher
witness refuses input and output admission separately, then requires one
three-byte transfer and an offset change from 1 to 4.

`kernel.native.host-file-venue` covers native getdents64 completion. The
carrier has already consumed the directory entries before acknowledging its
reply. A memory wait must retain that reply, result and byte cursor; a retry
must not issue a second getdents request. The native-process witness drives
production ARM staging and service completion, injects one copy refusal and
requires the same 24-byte entry once, with only CarrierWork during the wait.
It supplies a carrier reply under a real claimed ticket; it does not exercise
a host directory backend or prove physical backing supply.

Signed HVF, native ARM64 Docker, x86 guest execution, runtime ratios and
exact-artifact promotion remain higher-layer gates.
