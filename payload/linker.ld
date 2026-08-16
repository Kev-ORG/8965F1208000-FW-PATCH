ENTRY(_exploit)

SECTIONS
{
  . = 0xFEBF0000;
  .text.entry : ALIGN(2) { KEEP(*(.text.entry)) }
  .text : ALIGN(2) { *(.text .text.*) }
  .rodata : ALIGN(4) { *(.rodata .rodata.*) }
  /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) *(.debug*) *(.data*) *(.bss*) }
}
