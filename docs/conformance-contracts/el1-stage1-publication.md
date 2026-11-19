# EL1 stage-1 publication


## Private-file first-touch residency (#2420)

Linux private file mappings may keep more than 4,096 independently faulted
pages live in one address space. Each 4 KiB file grant keeps its authenticated
mapping and frame generations, resident-page bits and transfer pins until
retirement. A wider grant cannot supersede those identities.

The shared carrier region reserves space for address-stable residency segments.
Publication searches the active segments and activates the next one when its
bounded probes find no reusable row. The initial region allocation backs the
reservation for both ISAs. Unused extension records are zero-filled and require
no per-record boot initialization. A lookup performs bounded probes per
published segment. A growth operation never rehashes existing rows or moves
their pins, and broad retirement visits only activated segments.

The VM-free private-file witnesses drive portal selection and descriptor
execution on ARM and x86. Each crosses the initial segment, retains a transfer
pin across growth, reconciles dirty slots and retires the mapped span. Signed
pip download and install evidence is collected separately on the m4 lane.
