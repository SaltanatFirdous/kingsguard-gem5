#include "kg_sbi.h"

/* Forward decls for your handlers (you’ll add them shortly) */
long kg_do_ecreate(uint64_t base, uint64_t size, uint64_t entry, uint64_t satp, uint64_t *out_id);
long kg_do_set_shbuf(uint64_t id, uint64_t sh_pa, uint64_t sh_sz);
long kg_do_eload(uint64_t id, uint64_t src_pa, uint64_t dst_off, uint64_t len, uint64_t *bytes);
long kg_do_eenter(uint64_t id, uint64_t *reason, uint64_t *opaque);
long kg_do_eexit(uint64_t id);
long kg_do_edestroy(uint64_t id);

/* This is called from the ECALL trap path with regs/args already unpacked */

{
  switch (fid) {
    case KG_ECREATE: {
      uint64_t id = 0; long err = kg_do_ecreate(a0,a1,a2,a3,&id);
      *ret_lo = err; *ret_hi = id; return 0;
    }
    case KG_ESET_SHBUF: {
      long err = kg_do_set_shbuf(a0,a1,a2);
      *ret_lo = err; *ret_hi = 0; return 0;
    }
    case KG_ELOAD: {
      uint64_t bytes=0; long err = kg_do_eload(a0,a1,a2,a3,&bytes);
      *ret_lo = err; *ret_hi = bytes; return 0;
    }
    case KG_EENTER: {
      uint64_t reason=0, opaque=0; long err = kg_do_eenter(a0,&reason,&opaque);
      *ret_lo = err ? err : reason; *ret_hi = opaque; return 0;
    }
    case KG_EEXIT:    *ret_lo = kg_do_eexit(a0);    *ret_hi = 0; return 0;
    case KG_EDESTROY: *ret_lo = kg_do_edestroy(a0); *ret_hi = 0; return 0;
  }
  *ret_lo = -2 /* SBI_ERR_NOT_SUPPORTED */; *ret_hi = 0; return 0;
}
