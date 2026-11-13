# x86 CPL0 host never releases an MM's COW pool records or supplied COW custody at MM retirement

Labels: follow-up, x86, kvm, mm

**What happens.** The x86 host publishes COW grants in `supply_cow_grant`,
but it never calls `CowGrantPool::release_mm`. When an MM retires, its READY
or USED records stay in the pool. The host's supplied-COW custody
(`cow_pending` since #2263) also stays until carrier teardown. That covers
an MM that exits with a supplied COW it never consumed.

#2263 bounds the live-MM part. A supply is reserved for its exact page and
source frame. Under the MM's next supply exclusion, the host revokes and
returns any supply whose source no longer exists. A *retired* MM gets no
next supply, so its records are only reclaimed when the carrier ends.

**What it means.** Each such record holds one of the 64 probe slots of its
MM key until carrier teardown. MM keys are never reused, so no live MM
loses capacity, but the physical extent is retained.

Acceptance: MM retirement on x86 releases that MM's pool records and
cancels its unclaimed COW supplies under the retirement exclusion. Show it
with a fork child that exits while its COW supply is unconsumed, then
census the pool and the inventory.
