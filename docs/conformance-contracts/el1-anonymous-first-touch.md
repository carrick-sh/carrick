# Partial retirement during anonymous grant settlement

`kernel.el1.anonymous-first-touch` requires a verified bulk grant's surviving
pages to keep their exact physical owner when EL1 retires a neighboring page
before the host settles the receipt. The retired page must never reappear in
the residency index; the authenticated fault page must retain its committed
bit and host residency. Settlement partitions only the bounded deferred-return
journal, publishes at most one more fragment than overlapping returns, and
performs no carrier-wide residency scan. An untouched surviving fragment stays
prepared rather than becoming resident. The VM-free bindings are
`delegated_partial_retirement_settlement_preserves_the_unretired_fault` and the
published-grant settlement cases in `mem/delegated_tests.rs`. Signed binding:
`el1_anonymous_reservations_stay_in_guest`; copyout also exercises the peer
resident selection that consumes this committed evidence.
