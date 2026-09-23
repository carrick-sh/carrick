# Session handoff checkpoint

The authoritative continuation is [the root handoff](../../../../handoff-inotify09-2026-09-22.md).
Local main received the campaign checkpoint and seven position-only lock-inventory
updates. This is not release acceptance or a new performance result.

Fresh post-merge checks pass: kernel recipe 2,377 tests with one existing ignore,
content 22, syscall cost 1, runtime contract 1, lifetime compile-fail 2, contract
registry, scoped Clippy and formatting. Full commands and source identity are in
[verification.json](verification.json). The source-input manifest differs from
the latest drain-step snapshot only by formatting three older tests.

Reconciliation and domain lint remain red. The host-authority snapshot omits the
new experiment dependency; a madvise abort site and changed K1 categories require
review; six inline-assembly sites lack reviewed authority coverage. Their exact
errors are retained. Later lint-domain steps did not execute. No gate was disabled.

The initial formatting check and formatting-only patch are retained. Historical
raw logs and unified patches have whitespace findings and remain byte-identical;
source outside that evidence archive passes diff-check. The original three
SHA256SUMS manifests verified all 150 listed files. The frozen performance
baseline and the three unrelated main plans were separately hash-checked.

All previously open signed semantic failures remain open. No new signed guest,
original-workload timing, full CI, probe/smoke/full promotion or push was performed.

Concurrent AArch64 source edits appeared after the checks. They remain outside
this handoff and its test receipt; see verification.json and current git status.
