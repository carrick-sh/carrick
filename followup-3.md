# followup-3: slice d must wire routing, the doorbell arm and staging of file bytes

Slice c's host service is reachable only from the carrier entry points and
tests. Slice d owns: the ring routing x86 fork-child exec to the native
exec service (today `settle_unwired_native_service` answers staged ENOSYS),
the `ServiceOperation::Exec` arm in `cpl0_native_service.rs` (today a fatal
"unsupported" refusal) that calls `prepare_native_x86_exec_image` +
`stage_native_exec`, retains a `ParkedX86Exec` per ticket and probes it
after fork-stock settlements, seals the manifest from
`X86ExecPreparation::seal`, and stages the image's file bytes where the
CPL0 build (`build_x86_successor`) can copy them. The build must take the
reserved tables in order (first = sealed root) and produce the sealed rsp.
Also: the built stack row is imported as PRIVATE|GROWSDOWN before admission,
where boot inserts it opaque after admission; confirm the adopter treats
both the same.
Found in #1093 S4c slice c (PR #2205).
