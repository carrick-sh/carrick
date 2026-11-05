# Sparse host-served mmap publication (#1670)

`kernel.el1.anonymous-retirement` and `kernel.mm.shared-file-reuse` cover
production mmap dispatch for a 4096-byte MAP_ANONYMOUS|MAP_DROPPABLE (0x28)
request and a 0x6994-byte read-only MAP_SHARED snapshot respectively.

These mappings retain host-served attributes in an admitted reservation root.
The private sparse classification introduced for #1663 still prevents eager
anonymous scrubbing. It does not supply physical backing for an attributed
anonymous mapping or a shared file snapshot. Ordinary protection publication
can try to allocate backing independently of the admitted owner; copying a
snapshot through guest UserWrite also uses the wrong initialization authority.

Use the existing transactional host alias publisher for these host-served
shapes on sparse admitted MMs, including when placement is in the low arena.
The guest VA stays unchanged. Anonymous publication supplies zero backing;
file publication receives the complete rounded snapshot and zero final-page
tail. The publisher owns backing installation, stage-1 publication and VMA
commit. The existing alias retirement path then owns its eventual cleanup.

The VM-free bindings require one transactional publication, zero ordinary
protection calls, zero guest writes and zero anonymous scrubs. They check the
exact file bytes and tail and require no committed VMA before installation or
after abandoning it. Backend protection refusal is injected at the existing
GuestMemory boundary to expose the two old errno 12 paths. This proves dispatch
selection and payload custody, not live HVF installation or terminal retirement.

The director must rerun the signed CPython version/thread/fork/subprocess/Pool
table. In particular, the reported multiprocessing structural-retirement fatal
has not been reproduced by these VM-free tests; a passing dispatch witness is
not evidence that that fatal is repaired. Native ARM64 Docker comparison,
signed smoke and exact-artifact acceptance remain required.
