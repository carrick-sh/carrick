# Signed concurrent allocator witness

Source 8fc9c913a (full revision in identity.json). Both allocator tests pass
on one exact signed executable. Negative entitlement control passes; original
and CLI run scopes both have zero remaining processes. Artifacts are frozen
at the paths in identity.json, including the exact Linux fixture.

Concurrent case: four guest allocator users, sixteen synchronized rounds,
10 MiB growth/free per worker per round, and 1,024 successful uname calls.
The assertion on EL1 forwarded[160] proves those calls reached host service.
The test requires dynamic grants, no denial, exact grant/return count equality
and byte equality, and completion within the unchanged 30-second watchdog.
This proves concurrent invocation/completion and host-service progress; it
does not measure interrupt latency or prove a particular overlap timeline.
The sequential growth/denial case also passes with 5,767,168 bytes returned.

This is not complete allocator acceptance. EL1 IRQ masking/host-wait protocol,
private control gating and deterministic work/retention budgets remain open.
The currently synchronous metadata HVC executes from masked EL1; restoring
entry DAIF does not prove the no-host-wait-while-masked requirement.
The <0.125 first-touch exit slope and per-workload 2x target remain unproven.
