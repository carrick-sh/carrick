# EL1 resident anonymous munmap acceptance

This directory binds `kernel.el1.anonymous-munmap` to implementation commit
`73dfedec1a12554790c6fef86375e9fe26733c54`. A fully resident tagged private
anonymous range is now retired by guest EL1 under the exact-MM editor before
the syscall crosses one host boundary for authenticated physical return and
VMA bookkeeping.

## Impact

The previous retirement checkpoint proved that the host path could return and
reuse EL1 frame grants, but `munmap` itself still left stage-1 ownership on the
host. This increment moves the guest-visible terminal retirement and TLB
invalidation into EL1. The host boundary remains deliberately present for
stage-2/frame-inventory return and policy metadata; deleting its duplicate
idempotent stage-1 edit and page-table pause belongs to the final checkpoint-2
writer removal after anonymous `mmap`/`brk` and fork COW have moved.

The exact signed scale run completed every same-VA zero-fill/write/unmap cycle:

| Pages | Rounds | Host exits | EL1-served munmap | Host fallback | Grants / returns | Reused | Bytes granted / returned |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 256 | 4 | 44 | 5 | 1 | 6 / 6 | 3 | 4,308,992 / 4,308,992 |
| 1,024 | 4 | 56 | 5 | 1 | 14 / 14 | 9 | 16,891,904 / 16,891,904 |
| 4,096 | 4 | 80 | 5 | 1 | 38 / 38 | 27 | 67,223,552 / 67,223,552 |

Each process performs four target-range unmaps. Its static runtime adds one
eligible private-anonymous cleanup served by EL1 and one fixed untagged cleanup
that remains on the host fallback; the signed test asserts both populations
separately. Incremental exit slopes are 0.0039 and 0.0020 exits per added page
per round against the 0.125 limit.

## Contract evidence

The red-first MMU tests initially failed to compile because no guest retirement
operation existed. They now prove that one allocation-free editor retires
complete L2 blocks and L3 leaves, retains their exact output address, marks
them invalid and retired, and changes nothing for partial coarse blocks or
untagged terminals. The EL1 policy tests prove page rounding, Linux malformed
argument results, exact-MM editor release, and host fallback for unproved
mapping shapes.

`signed-scale-green.log` is a direct run of the exact signed test executable.
`signed-artifacts.jsonl` records the preceding full signed harness gate: the
requested test passed, the unentitled negative control classified `HV_DENIED`
correctly, and scoped cleanup reported zero processes. The signed harness run
recorded 47/56/80 exits and slopes 0.0029/0.0020; the direct retained transcript
recorded 44/56/80 and 0.0039/0.0020. Both are below the same deterministic
structural ceiling and have identical semantic, service, return and reuse
counters.

The exact fixture was then run serially at 256, 1,024 and 4,096 pages on native
arm64 Docker using
`ubuntu@sha256:33ceb71981b602c1a7443a53469e4dba065f7503eab3078a2d7a57a2ab987517`.
All three rows report `zero=true writes=true unmaps=true`; their separate stderr
files are empty and no scoped containers remain.

Source validation also passed 109 MMU tests, 68 EL1 tests, warning-denied Clippy
for the touched MMU/EL1/runtime/embed crates, the macOS runtime compile check,
format/diff checks, and the contract registry at 65 contracts, 15 claims and
144 surfaces.

## Exact artifacts

- CLI SHA-256: `bdadb731fd0747be6534fc0b39c4ae14e3a668302713b7c16ec38a5e831ded15`
- CLI CDHash: `4f1341e5d4f6f18c1f8c9b374869424e564bcb85`
- CLI LC_UUID: `6FA9960B-F474-3230-ADEA-355765072E9C`
- CLI entitlement: `com.apple.security.hypervisor=true`
- CLI `__TEXT,__dof_carrick`: present
- signed test SHA-256: `89e986cc10b2a477971bb87c5bc6bd318fcc8316dbc922f4689d7779234ce64f`
- signed test CDHash: `ac9eba06f5f5cbfb1c95ec2e6bea10ef6f25dddb`
- signed test LC_UUID: `95024D30-8476-3AE8-94C4-B64748BD1AFD`
- fixture SHA-256: `53a5a4d3f340f24af67ca91526a2ba612552d6f8aac7cbb8768665c1459dca4e`
