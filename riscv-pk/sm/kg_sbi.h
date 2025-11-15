#pragma once
#include <stdint.h>

#define KG_EID 0x09000000UL  /* vendor/experimental range */

enum kg_fid {
  KG_ECREATE    = 0,
  KG_ESET_SHBUF = 1,
  KG_ELOAD      = 2,
  KG_EENTER     = 3,
  KG_EEXIT      = 4,
  KG_EDESTROY   = 5,
};

/* Example structs you’ll use as args/returns */
struct kg_create {
  uint64_t base_phys;   /* enclave DRAM base (power-of-two aligned) */
  uint64_t size;        /* size (power-of-two) */
  uint64_t entry_uva;   /* enclave entry VA (U-mode) */
  uint64_t satp;        /* enclave root page table (Sv39) */
};

long kg_ecall_dispatch(unsigned long fid,
                          unsigned long a0, unsigned long a1,
                          unsigned long a2, unsigned long a3,
                          unsigned long a4, unsigned long a5,
                          unsigned long *ret_lo, unsigned long *ret_hi)