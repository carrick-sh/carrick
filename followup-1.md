# go-version on x86 KVM exits 125: `idle peer forward binding mismatch: TaskIdMismatch`

Labels: main-defect, x86, kvm

**What happens.** On x86 KVM, the scoreboard row `go-version` exits 125 on GitHub
main (03055d691) and on the #2263 head alike. The carrier stops with
`idle peer forward binding mismatch: TaskIdMismatch`, raised from the idle-peer
forward binding check (`crates/carrick-x86-cpl0-host/src/cpl0_boot.rs:1217`
and `:1475` on main). This is a separate stop. #2263 removes the earlier
`kernel fault policy refused: reason 9` that #2141 reported. With that fixed,
Go gets further and then hits this stop.

**What it means.** #2263 cannot claim `go-version` as a pass. The scoreboard
stays red for x86 Go until this binding mismatch is understood.

**Not done in #2263.** Recorded only, as the director asked. It is not
trivially separable from the forward-binding authentication.

Acceptance: `go version` exits 0 on x86 KVM against the Docker oracle, with
the forward-binding mismatch explained by a witness that fails on main.
