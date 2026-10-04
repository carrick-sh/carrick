# Landing impact

Median wall seconds [min–max]; one excluded warm-up. Fixed samples, no retries. Child CPU is host child-process CPU (Docker client CPU, not container CPU). Performance is report-only. A controlled single-variable campaign on a quiet host is required for claims; this report does not prove host quietness.

| workload | base | candidate | Docker | base/Docker | candidate/Docker | per-op seconds base / candidate / Docker | per-op ratios base / candidate | 2x objective |
|---|---|---|---|---|---|---|---|---|
| true | INCOMPLETE: missing, failed, stale or mismatched evidence | — | — | — | — | — | — | INCOMPLETE |
| node-startup | INCOMPLETE: missing, failed, stale or mismatched evidence | — | — | — | — | — | — | INCOMPLETE |
| node-core-worker-message-port | INCOMPLETE: missing, failed, stale or mismatched evidence | — | — | — | — | — | — | INCOMPLETE |
| spawn-loop | 1.263128 [1.227987–1.488882] | 1.361767 [1.326386–1.386555] | 0.440216 [0.341092–0.619972] | 2.869x | 3.093x | 0.001205918 / 0.001302915 / 0.000245332 | 4.915x / 5.311x | over |
| thread-spawn | 17.964329 [17.048192–37.672976] | 17.002158 [16.770881–17.622891] | 31.128944 [13.808773–33.684038] | 0.577x | 0.546x | 0.017841884 / 0.016881540 / 0.030434177 | 0.586x / 0.555x | met |
| fork-exec | 0.723144 [0.701474–1.069127] | 0.715576 [0.685398–0.863839] | 0.231827 [0.226090–0.250293] | 3.119x | 3.087x | 0.002961188 / 0.002977291 / 0.000438581 | 6.752x / 6.788x | over |

base: HEAD `097559be9f98ca0767a0517f744b4408b701ce89`, run `impact-45710-1791123813152193000`, samples 10.

candidate: HEAD `097559be9f98ca0767a0517f744b4408b701ce89`, run `impact-56442-1791124487710807000`, samples 10.

Docker: HEAD `097559be9f98ca0767a0517f744b4408b701ce89`, run `impact-36510-1791123173213353000`, samples 10.
