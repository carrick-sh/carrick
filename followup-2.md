# Follow-up: x86 futex diagnostic PC and slot provenance (P2)

Source: independent review of #2272, issue #1671.

The futex diagnostic currently derives PC from an ARM frame (zero on x86)
and slot from task_index. Audit whether the shared frame interface should
supply the actual guest PC and execution slot for x86 samples.

Acceptance: define available/unavailable provenance explicitly and add
production-frame known-answer witnesses for PC and slot on both ISAs.
Do not fabricate identity when the execution binding is unavailable.
