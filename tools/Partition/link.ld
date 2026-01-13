ENTRY(_start)

PHDRS {
  text PT_LOAD FILEHDR PHDRS FLAGS(5); /* R|X */
  data PT_LOAD            FLAGS(6);    /* R|W */
}

SECTIONS {
  /* Virtual load address of the enclave */
  . = 0x410000;

  /* RX segment: also carries ELF file header and PHDR table */
  .text : {
    *(.text.start)
    *(.text .text.*)
    *(.srodata .srodata.*)   /* small rodata with text if you like */
    *(.rodata .rodata.*)
  } :text

  /* RW segment */
  .data : {
    *(.data .data.*)
  } :data

  .bss : {
    __bss_start = .;
    *(.bss .bss.* COMMON)
    __bss_end = .;
  } :data

  /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) *(.eh_frame_hdr*) }
}

