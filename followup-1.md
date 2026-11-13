# flaky: x86 group retirement may cross from an already unregistered CR3

Run IDs: 2282-fix-1 (two witnesses pass), 2282-fix-irq (futex and computing pass; runnable fails at WORK_PORT with unregistered CR3 0x480c000). The fix-irq artifact includes terminal IRQ-return handling, so this is a failure observed during a changed schedule, not a same-artifact rate estimate. Do not retry until green. Tracking the retirement/installed-root ordering in #2282; no known-gap admission.
