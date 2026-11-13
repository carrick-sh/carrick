# Follow-up: futex invalid operands beyond op 393 (P1)

Source: independent review of #2272, issue #1671.

The alignment repair deliberately admits only misaligned untimed op 393.
Audit other futex operations' invalid-operand admission and errno precedence
against Linux man pages and a bounded Docker oracle (never copyleft source).
Do not expand this PR's production policy without red production-entry witnesses.

Acceptance: enumerate supported operations and prove numeric errno precedence
for invalid alignment/bitsets through ARM and x86 production dispatch, with
zero operand loads and no queue enrollment when operands are invalid.
