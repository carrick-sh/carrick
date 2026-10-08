# Native signal startup milestone

Contract: `kernel.signal.native-startup`. Signal calls use the authenticated
process venue and existing `NativeProcessSignals`, never the carrier's signal
state. No launch, boot-export, loan or aperture code is changed.

| Call | Required-KVM result | ARM impact |
|---|---|---|
| rt_sigaction | SIGPIPE ignore; SIGSEGV/SIGBUS handler installation/query; known flags, restorer and mask retained; SIGKILL installation returns EINVAL | Shared wire/routing and action-owner policy; SA_ONSTACK retained as typed metadata. ARM lanes without this native process venue keep their existing fallback. No ARM handler-frame change. |
| rt_sigprocmask | Query/update and blocked SIGABRT delivery on mask restoration pass | Existing shared mask algorithm unchanged; admitted native process venues now select their retained inbox after mask changes. Legacy ARM venues keep existing pending-work handling. |
| sigaltstack | Query disabled stack, install and query pointer/size pass | Existing shared algorithm unchanged; no ISA stack-layout change. |
| tkill/tgkill | Signal-zero identity probe, ignored self-signal, foreign target ESRCH, invalid signal EINVAL, direct/blocked SIGABRT termination pass | Shared request validation, exact-task inbox and retirement; no host PID lookup. Native caught-handler/job-control delivery remains unsupported. |
| Root command completion | SIGABRT produces CLI exit code 134; guest retirement retains signal wait encoding | ISA-neutral command-code conversion; only x86 guest completion uses it here. Existing physical record remains unchanged. |

Owner identity is supplied by cherry-picking `01e86b399d43440ecdd24d8f7808a2dcbef1d5f2`
with `-x`, preserving its author. It provides the shared PID/TID projection and
its VM-free red-first evidence; this lane adds no second identity implementation.

Red-first evidence:

- Static action/tkill/tgkill dependencies returned exact -38 before routing;
  shared routing assertion failed at canonical 134. Mask/altstack dependencies
  were already green and were preserved.
- Direct self-abort reached fatal port 0xcc (CLI 125) before root command-code
  lowering, then passed with 134.
- Masked self-abort returned -95 (fixture exit 96) before guest inbox delivery,
  then passed with 134 after mask restoration.
- Installing ignore left pending count 1 instead of 0. The two-owner VM-free
  test now proves discard is local to the exact owner.
- The initial new selector removed only one ignored RT instance, leaving seven
  at scale eight. The corrected selector discards the key's whole population;
  scales 1/8/32 pass. Standard signals coalesce to one at those same scales.

Native Linux additionally confirms blocked ignored signals become pending,
while reinstalling explicit ignore or default-ignore discards them. This was
measured in a separate native process using sigprocmask, tkill, sigpending and
sigaction; both SIGPIPE explicit ignore and SIGCHLD default ignore gave pending
1 before reinstall and 0 after it. Pending selection is serialized with action
installation, examines at most 64 keys, and retains entries whose native
handler/job-control delivery is unsupported. Failed retirement restores its
admitted signal rather than consuming it.

Reproducer:

```sh
CARRICK_REQUIRE_KVM=1 cargo test -p carrick-cli --no-default-features --features platform-linux --test x86_kvm_run mounted_static_x86_signal_ -- --nocapture --test-threads=1
cargo test -p carrick-el1 --lib native_process_ -- --nocapture
cargo test -p carrick-personality-linux --test x86_wave2 -- --nocapture
```

This milestone covers the startup shapes, not complete signal emulation. It
does not create native caught-handler frames, implement stopped-task job control,
or emit a core file. Signed ARM/HVF verification and full acceptance are deferred
to the director. Poll readiness remains the separate fd-authority work described
in [the stdio/poll design](x86-native-stdio-poll-design.md).

## Final startup dependency results

N1's MAP_STACK admission fix was cherry-picked with `-x` from
`853534225f01643dcfddc831a37f3f4588028005` as `fded82e7b`, preserving its author.
The added static stack-mapping dependency was red with exact -38 before the
pick. It now passes on required KVM, including the guard-page protection,
both usable stack-end touches and alternate-stack installation/query. Its
shared `admitted_anonymous_stack_mapping_stays_with_el1_root` test also passes.
This correction admits Linux's advisory flag for both ISAs; GROWSDOWN and
HUGETLB remain on their existing paths. No launch or aperture change is involved.

All eight `mounted_static_x86_signal_` dependencies pass native Linux and
required KVM in 4.20 seconds of test execution. The independent poll witness
still returns exact -38. All eight unchanged same-source lifecycle/IPC workloads
pass natively; KVM now exits with command code 134 and no scenario output,
before main, instead of the old fatal hlt/125. Native poll ENOSYS fault injection
and the masked-abort dependency identify this as poll -> guest-owned SIGABRT.
Poll is the remaining blocker in the established pre-main startup set. The
active workload tests remain red; no shared scenario failure is attributed.

The tested debug CLI SHA-256 is
`cc1eb3cf3bbe0a2c3d616bc3839d2913bdfcc9bf416cd00edb621313cb3f9505`.
Focused VM-free results: 18 native owner tests, 36 shared entry tests,
25 lifecycle tests and the N1 mapping test pass. Inventory reconciliation on
the clean merged code snapshot produced no changes and left the original
compiler capture untouched because its recorded host slice differs.
