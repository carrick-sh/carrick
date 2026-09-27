# EL1 metadata host-wait red witness

Source `7f40c2ad09f39ee27de8376dec5e0a0c4763a8e0` executes the real signed
allocator growth/return path and fails the no-host-wait-while-masked contract.
The fixture returned `rc=4`: two extent grants and two returns reached the
synchronous `HVC #6` boundary with `DAIF.I` set. The entitlement negative
control passed and both run-scoped cleanup checks reported zero processes.

The exact signed test executable is frozen at
`target/el1-completion/allocator-irq-red/frozen/el1_sched-f0f1569da0c4c729`:

- SHA-256: `a6d303d0834eb31de7aba02084582d7e299f95102ddd7347d11e7797b54caeac`
- CDHash: `1e2abc471afadb1c6ba462d4bc22c3abb3d47751`
- LC_UUID: `79403D9E-B923-302F-83AB-955FCCC79A0D`
- hypervisor entitlement: present
- `__dof_carrick`: present

The frozen CLI SHA-256 is
`7e3e129f7768fc38d756f4f8390feee449d4c92d163db84952cdd0a3d5cae72e`; the
Linux fixture SHA-256 is
`4556a00caa4bc910cb99826251c224aaaffa73f4d5cd1486c0ce7f473c27235b`.
`signed-red.log` is the complete signed run. `disk-guard.log` preserves the
earlier pre-execution disk refusal and confers no runtime evidence.

This is red evidence only. It does not accept the mailbox correction, the
allocator, first-touch handling, or memory checkpoint 2.
