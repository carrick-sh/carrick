# IPC output owner waits (#1780)

The `kernel.memory.owner-wait` contract covers completed SysV message and
semaphore answers in both guest ISAs. An invalid buffer returns errno 14;
a buffer waiting for its memory owner retains the completed answer and parks
on that owner's notification. Linux IPC metadata and received payloads are
not queried or dequeued again after output begins.

The personality entry's output state owns the bytes, original result and next
unwritten byte. A received message also retains its queue identity, original
position and type, so a genuine output fault can restore the message as before.
The native service takes the same state on refusal, using its existing exact-MM
page copy and owner wait. The receiver waking from an empty queue uses this
same owner. No lock, permit or execution lease is retained while parked.

The deterministic bound is one successful write per page-contained piece, with
no replay of a committed prefix. The production `ipc::invoke` witness injects
a typed refusal, then crosses the real native service and scheduler Gate wait:
4096 bytes commit, the second page waits, and release commits only the remaining
4096 bytes with the original 8184-byte receive result. Metadata witnesses cover
both wire layouts, Done, Fault, and NotYet once followed by success.
The unaligned record binding starts six bytes before a page boundary on both
ISAs, refuses the second page once, then changes the committed prefix before
resuming. The changed prefix must survive while only the suffix is copied.

These VM-free witnesses do not prove signed guest execution or an end-to-end
runtime ratio. HVF and Docker promotion remain separate acceptance evidence.
Existing IPC input-copy consumers are outside this output-custody slice.

The guest-copy debt gate now counts direct `.is_done()` consumers as a
source-derived monotone total. Its first comparison measures base source with
the same scanner; subsequent comparisons use the committed ceiling. Existing
per-file error and bool-interface ceilings retain their previous limits. A
new typed consumer cannot borrow unmeasured headroom from this introduction.
