ENTRY(_exploit)
SECTIONS
{
  . = 0xFEBF0000;
  .text.entry : ALIGN(2) { KEEP(*(.text.entry)) }
  .text.before_intent : ALIGN(2) { *(.text.before_intent) }
  ASSERT(
    ADDR(.text.before_intent) + SIZEOF(.text.before_intent) <= 0xFEBF0600,
    "before-intent helpers exceed 0x600"
  )
  . = 0xFEBF0600;
  .intent : ALIGN(4) { KEEP(*(.intent)) }
  ASSERT(SIZEOF(.intent) == 0x80, "restore intent is not exactly 0x80 bytes")
  . = 0xFEBF0680;
  .text : ALIGN(2) { *(.text .text.*) }
  .rodata : ALIGN(4) { *(.rodata .rodata.*) }
  /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) *(.debug*) *(.data*) *(.bss*) }
}
