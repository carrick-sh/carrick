# Fixed workload acceptance on the e8db2fd51 artifact

Python: two fixed rounds of eight suites passed, 16 unique round/suite rows.
Every Carrick result is successful and its passed/failed/broken/skipped totals
match the fresh Linux reference. No known or new differences, serial
confirmation, or retry was used. Normal workers=8 and Python workers=4 were
retained, with existing oracle-derived budgets. The first cold-cache discovery
attempt is preserved separately: it hit five-second discovery deadlines and
was stopped during serial confirmation (exit143); it is not acceptance.

The native ARM64 oracle-fill completed all eight Python suites and go-build
successfully before Carrick started. The private cache contains 13 rows across
parser profiles covering nine selected suites. Python image digest remained
3126629643b4adcf57ba5cecdb7f9ed257e733b56cd81da70fd5fdbdc1745b30;
Go remained357a08793e683c6a174d3955c704a5194e825f38fcdcb91d1d4ee2bccd6b188b.
No fill Docker container or Carrick guest remained after the Python rounds.
CLI SHA was unchanged from the signed EL1 gate.

Multiprocessing_fork passed 344 assertions with51 skips each round (395 tests
including skips), matching Linux. These runs do not attribute the historical
Parked/SnapshotRestoreFailed crash. The other prior lifecycle proofs remain
separate requirements.

Concurrent Python timings are not controlled performance acceptance. In
particular mmap's observed0.878/0.885s against Linux0.403s exceeds2x and
requires a quiet matched comparison before any overhead claim. No cost gate
is declared closed here. Fixed Go20 finished and failed; details below.

## Blocking Go retirement failure

The fixed20 Go population completed with19 MATCH and one REGRESSION,
round2/run conf-20571-c00. Overall harness status is1; later passes do not
clear the failure. It aborted after473ms, before BUILD_OK, with:

> publish detached terminal inventory retirement receipt: frame FrameId(2697) still has live mappings

The later MM-authority drop abort names kernel_mm14 and is explicitly a
consequence. Native Go succeeded; no new native run overlapped Carrick.
The release CLI SHA still matches the candidate. This is an observed Carrick
failure, not yet attribution to the batch3 source changes or the historical
Python crash. Promotion stops here.

Bounded next hypothesis: detached retirement plans a final RetireFrame from
a mapping-count snapshot, then a sibling publication wins before the commit
is applied. Inspect the existing mutation authority spanning preparation and
publication and reduce the interleaving with two live MMs before changing
code. The current frame-inventory guard correctly refuses live-frame retirement;
do not remove that check, retry it, or treat the19 passes as closure.
