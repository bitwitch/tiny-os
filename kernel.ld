/* The entry point of the kernel is the boot function. */
ENTRY(boot)

SECTIONS {
    /* The base address is 0x80200000, this is where OpenSBI jumps.*/
    . = 0x80200000;
	__kernel_base = .;

    .text :{
		/* The .text.boot section is always placed at the beginning. */
        KEEP(*(.text.boot));
        *(.text .text.*);
    }

    .rodata : ALIGN(4) {
        *(.rodata .rodata.*);
    }

    .data : ALIGN(4) {
        *(.data .data.*);
    }

    .bss : ALIGN(4) {
        __bss = .;
        *(.bss .bss.* .sbss .sbss.*);
        __bss_end = .;
    }

    /* Allocate some space for the stack */
    . = ALIGN(4);
    . += 128 * 1024; /* 128KB */
    __stack_top = .;

    /* Allocate some space for dynamic memory */
    . = ALIGN(4096);
	__free_ram = .;
    . += 64 * 1024 * 1024; /* 64MB */
    __free_ram_end = .;
}
