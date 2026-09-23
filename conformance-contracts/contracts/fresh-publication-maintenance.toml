schema_version = 1
id = "kernel.mm.fresh-publication-maintenance"
title = "Fresh inaccessible local backing avoids redundant stage-1 maintenance"
guest_surfaces = ["memory:first-touch"]
semantic_authority = ["Private anonymous mappings preserve zero-fill, protection and isolation; no accessible translation is published before fault permission commit"]
fixture = "unit:fresh-sparse-maintenance"
scale_points = [1, 8, 32, 128]
rationale = "Fresh local holes with unchanged live valid descriptors need publication ordering, not a guest maintenance transition. Replacement, structural valid-descriptor edits and rollback remain conservative."
[bindings]
vm_free = "carrick-vmm-hvf::trap::foreign_mm::tests::fresh_sparse_publication_avoids_stage1_maintenance"
[bindings.unresolved]
embed_structural = "Registered signed production counter binding pending"
embed = "Signed first-touch, fork, protection, residency and foreign-copyout proof pending"
docker = "Same-source Linux differential pending"
production = "VM-free real publication uses stage-2 stub and test authority; signed concurrency and actual maintenance census pending"
[[structural_budgets]]
kind = "affine"
metric = "page_table_invalidations"
base = 0
per_unit = 0
layers = ["vm-free"]
rationale = "Count actual supplied stage-1 maintenance callback invocations for a fresh inaccessible local extent; no elapsed-time inference."
