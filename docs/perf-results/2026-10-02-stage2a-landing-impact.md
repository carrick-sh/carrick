# Stage 2a landing impact (2026-10-02)

First per-operation receipt from `just xtask impact` (base = landing K artifact `carrick-cand-landk`, product-equivalent to main before stage 2a; candidate = the exact `just el1-gate`-accepted stage 2a artifact, SHA-256 `77246aeb343b...`, CDHash `414dd3db6d06...`). Quiet window: no other guest runs; Docker phase only after both carrick phases completed. Stage 2a changes namespace host-op cost only, so these workloads are expected to be neutral; the value of this receipt is the per-operation baseline against native arm64 Docker.

Before measuring, `conformance-probes/target/aarch64-unknown-linux-musl/release/perf_fork_exec` had to be rebuilt: the checked-in source emits `impact_window_ns`, the previously built executable did not.


Median wall seconds [min–max]; one excluded warm-up. Fixed samples, no retries. Child CPU is host child-process CPU (Docker client CPU, not container CPU). Performance is report-only. A controlled single-variable campaign on a quiet host is required for claims; this report does not prove host quietness.

| workload | base | candidate | Docker | base/Docker | candidate/Docker | per-op seconds base / candidate / Docker | per-op ratios base / candidate | 2x objective |
|---|---|---|---|---|---|---|---|---|
| true | 0.043504 [0.043026–0.045325] | 0.043730 [0.041795–0.044541] | 0.129492 [0.113293–0.139697] | 0.336x | 0.338x | — | — | met |
| node-startup | 0.115023 [0.112776–0.116744] | 0.115926 [0.113886–0.121938] | 0.136163 [0.127861–0.204539] | 0.845x | 0.851x | — | — | met |
| node-core-worker-message-port | 1.579613 [1.500509–1.671470] | 1.643714 [1.555165–1.715701] | 1.069252 [0.968934–1.079560] | 1.477x | 1.537x | — | — | met |
| spawn-loop | 1.279058 [1.267322–1.293438] | 1.264828 [1.250843–1.335068] | 0.265306 [0.255595–0.280365] | 4.821x | 4.767x | 0.001225777 / 0.001208430 / 0.000143046 | 8.569x / 8.448x | over |
| thread-spawn | 17.251608 [16.799464–35.525191] | 17.120068 [16.875353–35.599332] | 11.142637 [11.067678–11.223580] | 1.548x | 1.536x | 0.017128291 / 0.016993822 / 0.010989744 | 1.559x / 1.546x | met |
| fork-exec | 0.714882 [0.708817–0.748243] | 0.721862 [0.680774–0.752303] | 0.233367 [0.221496–0.249579] | 3.063x | 3.093x | 0.002929213 / 0.002949629 / 0.000440263 | 6.653x / 6.700x | over |

base: HEAD `d7ecaffd31d5163dbe5067ec1adbc290491920c9`, run `impact-57072-1790997642567205000`, samples 10.

candidate: HEAD `d7ecaffd31d5163dbe5067ec1adbc290491920c9`, run `impact-62025-1790997915661614000`, samples 10.

Docker: HEAD `d7ecaffd31d5163dbe5067ec1adbc290491920c9`, run `impact-66666-1790998207063058000`, samples 10.
