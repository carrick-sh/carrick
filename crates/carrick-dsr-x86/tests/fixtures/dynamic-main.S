.global _start
.type _start,@function
_start:
  # The native loader must enter PT_INTERP, never this main-image sentinel.
  ud2
