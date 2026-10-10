# ARM fork root-registry refusal (incomplete)

Source: `4b62f3a6ab981de754567ea326be3e9a238ac8df`.
Published bundle transport SHA-256:
`98586dfb8d6f0dd3b0999bcfb8e1930d722198aeabc5b55bb86b803a9e2464a7`.
Restore verified 1,135 executables; input identity:
`0196f252b697e4870b2d7296ae90df34823e2fac1ecac06b659a245545b543b1`.

Both foreground commands failed the warm-up assertion:

```sh
CARRICK_RUN_ID=arm-step5-sol2-4b62-fork-a CARRICK_ARM_RING_FIRST=0 scripts/test-signed.sh carrick-embed el1_fork_cow_resolves_in_guest --exact --nocapture
CARRICK_RUN_ID=arm-step5-sol2-4b62-fork-b CARRICK_ARM_RING_FIRST=0 scripts/test-signed.sh carrick-embed el1_fork_cow_resolves_in_guest --exact --nocapture
```

Each reported first admission stage 6 (RootRegistry), live TTBR0
`282136401674241` (presence bit included), process refusals
`[0, 2, 0, 0, 0, 0]`, `refused[134]=0`, and fork progress
`[1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0]`. No native fork failure;
zero surviving run-scoped processes. Both unentitled controls passed.
The logs are adjacent. Neither run proves child entry or fork acceptance.

The executable was `el1_sched-3c5925ab20bafee2`. Identity sampled during
run b's build, before its signing output (the preceding signed artifact):
SHA-256 `2d54c9f8d1298db2f2677c6e554e5040f96d3e069ea4f9b112a6ff26cea73df4`,
CDHash `5af6ec90e4f230cac2e72d069f914fbe2d97b6d4`.
After run b: SHA-256
`9ce955d15ec2336c23bcb85a50c0f407a058d73e79eaef73c597879f398ab933`,
CDHash `85a776c3e2bd836b0aad6a3c0477d7a29da39f6d`.
Run b's bytes are retained in ignored
`target/arm-step5-sol2/4b62-b/el1_sched-3c5925ab20bafee2`.
Run a's bytes were not copied before the next runner re-signed them; its
identity attribution is based on sampling timing, not a retained artifact.

The next diagnostic captures both observed and registered identity tuples:
(task, execution generation, MM key, thread generation, AddressContext
generation, scheduler record id, scheduler record incarnation). A tag of 1
means the complete first tuple is published; MAX means publication remains
in progress. An absent registered group is all zeros. This is failure-only
instrumentation; the successful fork path does not call its no-inline scratch
helper. Stack peak still requires exact guest-image verification.

The snapshot test was red with the new snapshot copy loop removed: all zeros
instead of both retained identities. It passes with the loop restored.

Still required: exact-input bundle for this diagnostic, two focused signed
runs, cause-directed fix with fork/migration and wrong-PID VM-free controls,
two green fork witnesses, then `just test-embed el1_` compared against the
34 explicit baseline failures plus six `el1_files` failures. The director has
also been asked for origin/main's two Linux KVM wait4 controls; no reply yet.
