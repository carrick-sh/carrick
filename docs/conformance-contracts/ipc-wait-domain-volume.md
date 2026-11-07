# Pipe volume and readiness identity (#1669)

Contract: `kernel.el1.ipc-two-process`. Linux `pipe(2)` requires EMFILE
(errno 24) at the process descriptor limit; closing the descriptors permits
new pipes. Each live pipe remains a distinct object.

The VM-free binding
`serial_host_pipemass_fd_limit_preserves_wait_domains_and_incarnations`
uses production syscall dispatch for prlimit64, pipe2 and close. It fills an
8193-descriptor table twice, checks EMFILE, closes every pair, and checks
that only the initial descriptors remain. A bound carrier metadata queue
must retain its identity throughout. The two rounds exercise both many live
objects and generation advancement on recycled slots.

IPC readiness indices are `1 + 2 * object.index + lane`. The scheduler
owns the shared `IPC_OBJECT_CAPACITY` ceiling (262144 objects), and the IPC
object store derives `IPC_MAX_OBJECTS` from it. Its readiness domain therefore
contains `1 + 2 * IPC_OBJECT_CAPACITY` queues, including reserved index zero.
Metadata begins after that whole domain, followed by MM queues. Thread-record
capacity does not bound object capacity: one thread can own many pipes.

Every object admitted by the elastic store has both readiness lanes, including
objects above index 2046. An unrepresentable key is an authority invariant and
fails closed, never a capacity errno. Each admitted IPC lane retains object
generation + 1, so slot reuse advances its exact incarnation without entering
another owner's domain. Queue storage is provisioned with the carrier; no
per-transfer queue allocation or object-population scan is introduced.
The scheduler reservation is page-rounded from `size_of::<ZoneTables>()`;
the carrier region is rounded to its 64 MiB mapping granule after all fixed
tables and the scheduler. It now occupies 128 MiB. Dynamic metadata follows
that region, so it cannot alias the larger scheduler. The shared ARM/CPL0
layout checks and ABI fingerprint cover this geometry; signed execution of
this larger artifact remains required.

The CPL0 interrupt/lifecycle fixture derives its sidecars from the complete
scheduler size and places that backing above the bootstrap allocator in a
separate physical window. Bootstrap allocator backing follows the reserved
maximum initial-image extent, keeping it disjoint from the larger production
metadata. Those address-space gaps allocate no host RAM. Its second page-table
root retains a disjoint low
RAM reservation accepted by the shared table-alias authority. The fixture's
supervisor and direct aliases both name the new scheduler backing; production
initial-extent boot keeps its separate allocation path.

Restoring admitted main's shared constructor while retaining the production
dispatcher witness reproduces `ipc::admission: object wait generation
collision` and SIGABRT. This is a queue-domain collision, rather than a missing
object-generation increment: the generic scheduler constructor accepts indices
reserved for metadata and MM owners. The ABI stale-object witness additionally
checks that both lane keys keep their indices and strictly advance their
generations when the production object allocator reuses a slot.

The director retains signed PID-1 pipemass and Linux output comparison on
macOS. This VM-free witness proves admission, close and identity isolation,
not guest instruction execution or end-to-end runtime ratios.
