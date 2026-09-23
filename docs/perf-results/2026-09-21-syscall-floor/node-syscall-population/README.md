# Node fixed syscall-cost sensitivity

Fresh diagnostic capture on frozen signed candidate
fd96c7d450060e04ec7cc28933d82843c28521ecf80875567bd17dbdb5cec27f.
Five app-smoke iterations completed; all five success markers and the terminal
marker are present. The trace exited successfully with no errors, observed root
exit, and closes 10,916 begins, argument events and service completions, including
per-number begin/argument equality and no unmatched completions. Scoped cleanup
reports zero remaining processes. No build or Docker workload ran concurrently.
The already-running registry services were not workload timing competitors.

The per-iteration population is 2,183.2 including shell overhead. Under the
hypothetical assumption that every counted call saves the same fixed amount,
0.5/1/2 microseconds per call gives 1.092/2.183/4.366 milliseconds of aggregate
service work saved. These are arithmetic sensitivity values, NOT predicted wall
speedups, causal upper bounds, additive component measurements or fresh timing.
Scheduling, overlap, trace perturbation and second-order effects remain relevant.
No claim is made that EL1-resolved calls appear in this host-service population.

Prior untraced measurements on this artifact were 245.5 ms Node versus 56 ms
native ARM64 Docker. Closing that 189.5 ms gap through a uniform per-call saving
alone would require about 86.8 microseconds per counted call, far larger than
the measured low-work syscall baseline. This comparison does not attribute the
gap to macOS I/O; it is intentionally raw, and the earlier matched host-I/O
controls remain separately reported. The existing controls are not rerun here.

Decision: stop expanding DSR prerequisites as the sole near-parity strategy.
Retain the unpublished adapter and explicit incomplete contract for the common
syscall-floor objective, but prioritize a controlled intervention in Node's
memory-management work for Node impact. Profile recurrence only nominates the
candidate: require reduced untraced completion time against the frozen corrected
control. The approximately 2,183-call population does not itself rank madvise,
munmap, synchronization or guest compute as the longest pole.

Existing native-I/O controls already isolate substantial valid-fstat overhead
(about 2,034 ns Carrick versus 241 ns macOS in the earlier control), while Carrick
beats Docker host bind in the tested buffered writes. Preserve those comparisons;
do not replace the project goal with raw Linux I/O parity or subtract unrelated
microbenchmark medians from whole-workload timing.
