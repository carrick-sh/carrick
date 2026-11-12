# followup-2: x86 exec successor data frames are eager and one memslot each

The host Exec service reserves every image and stack page as a private data
frame before the arm (the design's choice, mirroring boot), in one fresh
private extent (one carrier memslot) per exec. Large images (Node, ~100 MB)
cost their whole size in guest RAM per exec, and memslot capacity bounds
concurrent prepared execs. ARM maps ELF pages lazily from file sources
(`prepare_native_successor`). Consider lazy file-backed image rows for x86,
and a typed "not now" for memslot exhaustion (today a carrier TrapError).
Found in #1093 S4c slice c (PR #2205).
