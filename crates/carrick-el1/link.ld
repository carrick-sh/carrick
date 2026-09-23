/* Linker script for carrick-el1 in-guest kernel image */
ENTRY(carrick_el1_syscall)

SECTIONS
{
    . = 0x2D04000000;
    _image_start = .;

    .header : ALIGN(8) {
        BYTE(0x43) BYTE(0x45) BYTE(0x4c) BYTE(0x31) /* "CEL1" */
        LONG(1)                                       /* version 1 */
        QUAD(carrick_el1_syscall - _image_start)      /* entry_offset */
        QUAD(_image_end - _image_start)               /* image_size */
    }

    .text : ALIGN(16) {
        *(.text .text.*)
    }

    .rodata : ALIGN(16) {
        *(.rodata .rodata.*)
    }

    .data : ALIGN(16) {
        *(.data .data.*)
    }

    .bss : ALIGN(16) {
        *(.bss .bss.*)
        *(COMMON)
    }

    . = ALIGN(16);
    _image_end = .;

    /DISCARD/ : {
        *(.comment)
        *(.note*)
        *(.eh_frame*)
    }
}
