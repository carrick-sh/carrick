# Futex immediate completion (#2288)

Contract: `kernel.el1.futex-handoff`, Linux futex(2) EFAULT for an unreadable
word. A completed call must install its result in the calling frame; a
scheduler switch must preserve the successor frame and never install the
departing call's result there. No extra guest copy, retry, or queue operation
is needed to publish the result.

The production ARM copy path can return NotYet before the owner refuses
preparation with EFAULT. The two-live-thread VM-free owner-wait fixture covers
that refusal through production dispatch. The x86 production fixture covers
a genuine atomic word-copy fault through the native futex owner. Existing
owner-wait tests retain suspension and synchronous redispatch coverage.

Reuse main's #2272 bounded sampler and Node fixtures unchanged. This PR does
not add scheduler, native-service, carrier, or handback capture coverage.
A zero sample count cannot establish absence of invalid returns. Node abort
acceptance requires the director's paired signed population.

Red-first proof after rebasing on GitHub main:

- The ARM owner-fault witness returned x0 = 1073741824 (the input address),
  expected -14. The fixed entry publishes -14 and its diagnostic retains the
  original address, with two live threads, one word read and no scheduler park.
- The successor control's pre-fix diagnostic falsely attributed result 28 to
  the departing task's op 393. With the fix it records no successor row, and
  retains the real caller's later EINVAL with its original address.
- The production x86 copy-fault control passes both before and after moving
  immediate publication from the adapter into authenticated shared completion.

The inherited sampler still suppresses positive non-wait results broadly;
requeue count validation and waitv sampling are outside this immediate-return
claim. No carrier completion instrumentation is added. Signed Node acceptance
and paired population evidence remain outstanding.

Result publication and host-return checkpoints are separate decisions. Futex
completions are marked with an in-zone return venue in the shared owner, so
installing their result does not add a native host checkpoint. Explicit owed
work is still honored. The existing mapping-owner and fork-child EINVAL
witnesses exposed an unintended Served-to-WithWork change during verification;
they retain their exact Served assertions after the venue distinction.
