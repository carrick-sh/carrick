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

Independent review also identified repeatable synthetic and retained-executable
fd reads whose cursor moved before output admission. The production read,
pread, readv and preadv witness covers those descriptions and proc-self memory.
Source callbacks now preserve a typed owner refusal, and the existing bounded
copy helper advances the cursor only after committing its prepared output.
Vectors keep the same description guard and return only the delivered prefix
if a later piece refuses. The source is never consumed on a zero-byte refusal.
The scalar witness was red at EFAULT (14); after that repair the vector witness
was red at a false zero-byte read. Proc-self memory retains Linux's EIO (5)
for genuinely inaccessible source memory rather than classifying contention
as that error. Native directory controls additionally require errno 14 for a
true output fault and a true preparation fault; internal refusal never earns
that verdict.

Synthetic-device output uses that same admission loop with a temporary
cursor rather than a description offset. Zero/full and random devices fill
the admitted page-sized scratch; the CSPRNG accepts the existing borrowed
buffer without allocating a new source Vec per piece. The same CSPRNG
function retains its existing fatal authority. Null-device EOF performs no
output preparation, even when the fixture has a pending owner refusal.
