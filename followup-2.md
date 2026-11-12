# Follow-up: x86 CPL0 fork-child readlink after #2084

#2084 routes ordinal 78 to the native file family, but x86 CPL0 still answers it as a
counted refusal. Executable custody is #1903, and no x86 type implements `NativeExecHostService`.
- A plain symlink (`readlink lnk`) needs no executable custody. The x86 lane could serve
  it once #2084's `HostFileOp::Readlinkat` exists, leaving only `/proc/self/exe` behind #1903.
- Plain `readlink` (x86 native 89) isn't recognized on the CPL0 lane, which refuses it in
  overflow bucket 512. musl x86_64 and busybox issue it. (Noted in #2084's follow-ups.)
Owner: whoever takes #1903 or the x86 native-file seam, stacked on #2084.
