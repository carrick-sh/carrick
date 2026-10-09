/* Thin CPL0 entry image; common personality stays in carrick-el1. */
ENTRY(carrick_x86_syscall)
SECTIONS {
    . = 0xffffffff80000000;
    /* Keep fixed boot records ahead of variable code/data growth. */
    .irq_header : { KEEP(*(.irq_header)) }
    .initial_boot_header 0xffffffff80001000 : { KEEP(*(.initial_boot_header)) }
    .progress_header 0xffffffff80002000 : { KEEP(*(.progress_header)) }
    . = 0xffffffff80003000;
    .text : ALIGN(4096) { *(.text .text.*) }
    .rodata : ALIGN(4096) { *(.rodata .rodata.*) }
    .data : ALIGN(4096) { *(.data .data.*) *(.got .got.*) }
    .bss : ALIGN(4096) { *(.bss .bss.*) *(COMMON) }
    ASSERT(. <= CARRICK_X86_CPL0_IMAGE_END, "CPL0 image exceeds supervisor extent")
    /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) }
}
