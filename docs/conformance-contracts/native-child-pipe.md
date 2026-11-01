# Native child pipe creation

Issue #1346 extends `kernel.native.host-file-venue` to `pipe2`.
Linux `pipe(2)` requires a reader/writer pair in the calling process's table,
with independent access modes and the requested O_NONBLOCK and O_CLOEXEC bits.
A failed pair allocation must publish neither descriptor.

The carrier uses the same pipe factory as the root dispatcher. Existing IPC
endpoint OFDs enter the child's table in one fd-core transaction, including
capacity growth outside that transaction. No root host-table slot or host
resource token is allocated. Dropping the factory's preparation descriptions
leaves only the child's ring references. Reads, writes and final close then
use the ordinary shared IPC cores. If output becomes unwritable after staging,
completion withdraws the created pair in ring. The carrier stamps the exact
endpoint backing identities into the reply. Withdrawal authenticates those
identities under the table mutation lock, so closing and reusing a numeric fd
before completion cannot make rollback close a different resource.

The VM-free bindings cover production syscall decoding/staging, publication
into a forked table with its parent still alive, independent endpoint flags,
byte round-trip, final-writer EOF, final-reader object retirement, and atomic
EMFILE (24) and EINVAL (22) refusal. A completion-copy EFAULT (14) must
withdraw the pair; conditional-withdrawal tests preserve reused slots and a
live peer table. They assert zero additional host-resource
tokens and no root host descriptor publication. Existing pipe lifecycle and
linear create/close bindings retain their work budgets.

These bindings do not prove guest execution. Acceptance still requires the
production `carrick run IMAGE /bin/sh -c '(echo a | cat); :'` to print `a` on a
signed HVF artifact, red on admitted main and green on the candidate. The
native-crossing-refused DTrace profile must confirm the live route. The final
`:` keeps the parent shell live rather than allowing subshell elision. The Linux
worker cannot supply that ARM/HVF evidence or the Docker differential; the
director owns those gates and artifact provenance.
