# Integrated metadata CI: contract inventory correction

Full CI on bc5500391 passed workspace Clippy and reached contract-inventory
validation, then exited 1 because the generated inventory lacked the new
kernel.mm.metadata-refusal claim on mmap, munmap and mprotect. The generated
correction adds exactly those three associations; no syscall support status
or existing claim is changed. Raw failing output is inventory-drift.log.
A complete CI rerun is required after committing this correction.
