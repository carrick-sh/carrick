/* Thin CPL0 entry image; common personality stays in carrick-el1. */
ENTRY(carrick_x86_syscall)
SECTIONS {
    . = 0x100000;
    .text : ALIGN(4096) { *(.text .text.*) }
    .rodata : ALIGN(4096) { *(.rodata .rodata.*) }
    .data : ALIGN(4096) { *(.data .data.*) *(.got .got.*) }
    .bss : ALIGN(4096) { *(.bss .bss.*) *(COMMON) }
    /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) }
}
