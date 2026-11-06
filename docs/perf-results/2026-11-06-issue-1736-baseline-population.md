# Issue #1736 baseline signed population

Source revision: `0d5dfaa508e5b92edbe2b18404cd2c7d4230f719`

Fixture bundle:
`de1c1bd060c311e46d9afd37adf53f835ac7bd5697d994e1ae6feda937d2aa9f.tar.gz`
(input identity
`1e769b2a8667733a568d456e233f99ea3369f46da83f8a036d78a86a6ffe16b1`).

The signed test executable was
`target/release/deps/el1_sched-24da1b99c955c4f7`, SHA-256
`085ff7de9ed8304b321282bf210c7a51c3b1055205b4868eb4e3b6167e70ca76`,
CDHash `5a558aee661a67f99856b62707353051eff3b3fb`, LC_UUID
`334C96A5-0A95-3968-9D8D-F2E5B97222F0`. It carried the hypervisor
entitlement and `__TEXT,__dof_carrick`.

Each invocation used an exact libtest filter under `just lease carrick`.
Every run completed its unentitled negative control and run-ID-scoped cleanup.
Raw logs are under `target/issue1736/population-before/`.

| Signed test | Pass | Fail | Failure mode |
|---|---:|---:|---|
| `el1_tlb_cross_vcpu_mm_edits_leave_no_stale_translation` | 20 | 0 | none observed |
| `el1_tlb_fork_and_exec_leave_no_stale_translation` | 19 | 1 | stale writable parent translation on run 16 |

The failing fork fixture completed normally: no alarm, command timeout, signal,
or Carrick panic fired. It reported `child_failures=1`,
`parent_failures=0`, `errors=0`, and `timeouts=0`. The child waits until the
parent's CPU-1 worker performs its post-fork write. A child failure therefore
means that write used a stale writable translation and modified the frame that
the child inherited, instead of faulting through the fork's COW-armed parent
descriptor. The enclosing Rust test then panicked only because the fixture
returned exit status 1.
