# Filesystem cache cohort

`kernel.fs.cache-cohort` covers cached path, directory topology, root-marker,
and guest-metadata observations. Independent backing namespaces must not
invalidate each other; observers admitted to the same backing cohort, including
host-fork descendants, must observe its publications. The structural budget is
zero additional dentry host opens in kernel B after kernel A mutates its own
namespace. VM-free bindings are
`independent_kernels_keep_all_fs_generations_and_cached_names_isolated`,
`independent_backing_namespace_mutation_keeps_other_cache_generation`, and
`cohort_generation_words_survive_host_fork`.

Host self-reexec preserves the historical anonymous-mapping boundary: reopening
the durable root establishes a fresh coherence cohort. The binding
`host_backend_reexec_authority_reattaches_exact_root` pins this distinction.
Pre-admission layer-cache extraction publishes no coherence generations;
backend-owned extraction publishes to its observing cohort. Signed file probes
provide integration evidence; full oracle and promotion remain director-owned.

External binds have no dentry/stat or capacity cache: `BindVfs::lookup`,
`lookup_nofollow`, and `real_stat` read host metadata per call. The rootfs
dentry cache is bypassed by mount routing. Ordinary host rename/unlink/create
visibility already passes on `4a2307912`, pinned by
`independent_bind_cohorts_observe_shared_host_namespace`.

The resolve cache does retain intermediate-symlink rewrites and formerly
trusted only the rootfs generation. On `4a2307912`,
`independent_bind_cohorts_observe_replaced_intermediate_symlink` fails:
after replacing `link -> old` with `link -> new`, B keeps `/bind/old/file`.
A carrier-owned `BindCacheCohorts` registry admits each bind source by the
host root's `(st_dev, st_ino)` identity, pinning that inode while observers
remain. Prepared rootfs cohorts in that carrier join the same source cohort;
fork descendants retain it. Resolve entries stamp only the bind authorities
actually read, before their component reads, including nested resolutions.
Bind namespace publications invalidate those dependent entries while unrelated
rootfs generations and cache work remain independent.

The historical external-writer boundary remains explicit: host mutations that
do not publish through an admitted cohort can still leave a cached symlink
rewrite stale. There is no process registry or cross-carrier authority, and
self-reexec starts fresh admission. Failed source admission leaves ordinary
host lookup errors intact rather than manufacturing a shared authority.
