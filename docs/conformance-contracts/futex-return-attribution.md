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
