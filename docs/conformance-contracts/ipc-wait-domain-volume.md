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

IPC readiness indices are `1 + 2 * object.index + lane`, strictly below
ZONE_RECORDS. Index ZONE_RECORDS belongs to metadata, followed by MM queues.
The shared object-key constructor must reject indices outside IPC's domain,
matching the existing in-ring eligibility rule. Objects outside this domain
remain host-served, as before; no new queue allocation or population scan is
introduced. Each admitted IPC lane retains object generation + 1, so slot
reuse advances its exact incarnation without entering another owner's domain.

The director retains signed PID-1 pipemass and Linux output comparison on
macOS. This VM-free witness proves admission, close and identity isolation,
not guest instruction execution or end-to-end runtime ratios.
