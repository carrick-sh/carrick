# Native pipe preparation checkpoint (#1346)

`kernel.el1.ipc-fd-authority` now binds the unpublished-description owner.
Linux pipe2 requires either two new descriptors or no new descriptors on
failure (pipe(2)). Reader and writer own distinct open descriptions; a failure
allocating the writer must release both the admitted reader and the writer's
unwrapped endpoint.

`PreparedDescriptions` owns the whole input array before admission. A refused
admission keeps the admitted prefix and the raw suffix, so the canonical venue
can grow the description store without allocating a second reader. Abort
returns each final backing exactly once, outside descriptor locks. Pair
publication uses the existing `SlotTableTransaction::install_pair`; neither a
one-slot table nor a backing-growth refusal publishes a half pair. Its search
and publication work remains the existing two bitmap searches and two retains.
Admission and settlement visit each input once per attempt; pipe2 has exactly
two inputs. No new scanning allocator or guest-memory work runs under the
transaction.

`HostIpc::prepare_pipe` supplies the existing canonical object creation,
retired-ring reclamation, ring stock and description growth policy. The
production host pipe now uses this preparation instead of separate manual
rollback branches. Tests force second-description refusal at the configured
ceiling, then repeat it beyond the object population to detect endpoint leaks.
The pair publication fixture tests a one-slot table, canonical slot growth,
independent close-on-exec flags and nonblocking status, and 256 create/close
cycles without description or object growth. The fd-core fixture separately
forces a partial admission, provisions one more OFD and resumes the same owner.

This is a checkpoint, not native-child acceptance. The native operation still
needs to retain this owner through service growth/preparation and cancellation,
secure the whole eight-byte output for the final commit, and route pipe2 only
once that protocol is implemented. No descriptor rollback by numeric close is
introduced. Both native-child production-dispatch witnesses remain red. The
signed `carrick run` witness, tracing, signed promotion and Docker differential
remain unrun on this Linux worker. #1506 can instantiate the same neutral owner
with one input and add single-description publication; no eventfd, epoll or
timerfd object types are added here.

## Whole-output fence continuation

The next checkpoint adds `MmPortal::fence_word_write`: a bounded eight-byte
output can span two noncontiguous physical pages. Both translations and user
write permissions are checked under one exact-MM editor before any output
capability escapes. A missing, read-only or COW tail refuses the entire word.
No supply, growth or suspension runs under that editor. A Busy refusal drops
all temporary custody and preserves the existing owner-wait result.

The output venue binds both retained physical mappings before descriptor
publication. `WordWriteOutput::write` then consumes that authority with no
fallible copy; the editor stays live until both pieces are written. The unsafe
binding requires exact physical custody and any executable-cache maintenance.
The VM-free binding uses separate byte arrays for physical mappings and does
not claim a production physical-map venue exists.

Native operation retention, canonical service growth, owner-wait/cancellation
integration, production physical output binding and shared native pipe2
routing are still required. The two native-child witnesses are still expected
to fail; this checkpoint does not satisfy the signed CLI acceptance criterion.
