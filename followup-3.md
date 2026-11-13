title: investigate x86 Python thread and subprocess SIGSEGVs
parent: #2271

Evidence from the prior-round PR receipts (not rerun in round 2):
py-thread and py-subproc exit 139 with empty stderr on both GitHub main e2e10d32a and round-1 head 905ed7c95. py-version and py-fork pass. Empty stderr does not identify a memory or lifecycle cause.

Acceptance:
Reproduce once on current main and candidate using exact artifact receipts and bounded carrick trace/debug or carrier core inspection. Record actual fault values; reduce into a production-entry red witness before changing the shared owner. Require both ecosystem rows to pass without retries, polling or budget changes.

Clean room: consult specifications and man pages; do not read copyleft source.
