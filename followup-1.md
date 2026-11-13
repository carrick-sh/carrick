# Follow-up: scoreboard process-group cleanup failed during #2274 verification

On this Debian 13 worker, run `2274-full-1` (`cargo test -p carrick-xtask`,
concurrent with the requested gates) failed `scoreboard::tests::timeout_kills_the_whole_row`:
`row's process group 17911 still has members`, at `scoreboard.rs:675`.
409 tests passed, 2 failed, 4 ignored. The other failure was the scaler fixture
missing the newly required running-workflow response; that fixture is corrected
in this PR. Both new #2274 witnesses passed.

The scoreboard failure has not been reproduced on current GitHub main and is
not claimed to be pre-existing or flaky. Do not retry until green. Preserve this
run's evidence in the PR. The director should investigate the surviving process
state and compare current main under the same load before assigning a cause.
If another scheduled verification changes the verdict, track it as flaky with
both run IDs; a subsequent pass does not retire this observation.

The required full verification after correcting the scaler fixture (`2274-full-2`)
passed all 411 unit tests, including the scoreboard timeout test. This is a
changed verdict: treat the scoreboard case as **flaky**, not cleared. No
scoreboard code changed between these runs. Per the task instruction, no issue
was created; the director should publish a `flaky` issue with both run IDs.
That run subsequently exposed an integration expectation that still permitted
draining a pending request; the test now requires Busy and checks idle draining
using a separate runner state.
