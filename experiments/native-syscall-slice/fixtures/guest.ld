ENTRY(_start)
PHDRS { code PT_LOAD FLAGS(5); data PT_LOAD FLAGS(6); }
SECTIONS {
  . = 0x400000;
  .text : { *(.text*) } :code
  . = ALIGN(0x1000);
  .data : { *(.data*) *(.bss*) } :data
  /DISCARD/ : { *(.comment) *(.note*) }
}
