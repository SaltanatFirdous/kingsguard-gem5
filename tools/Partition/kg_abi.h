// include/kg_abi.h
#pragma once
#include <stdint.h>

// ---------- Kingsguard ECALL command numbers ----------
enum {
  KG_ECREATE = 0x100,  // host -> SM: create enclave
  KG_EENTER  = 0x101,  // host -> SM: enter enclave
  KG_EEXIT   = 0x102,  // enclave -> SM: exit to host
  KG_OCALL   = 0x103,  // enclave -> SM: request host service
};

// Example OCALL service IDs
enum {
  KG_OCALL_PUTS = 1,
};

// Shared buffer for host<->enclave arguments (lives in non-enclave mem)
typedef struct {
  volatile uint64_t reason;   // 0=none, 1=ocall, 2=return
  volatile uint64_t svc_id;   // for OCALL: service kind
  volatile uint64_t arg0;     // opaque (e.g., pointer/length pairs)
  volatile uint64_t arg1;
  volatile uint64_t arg2;
  volatile uint8_t  buf[256]; // small message area
  volatile uint64_t len;      // bytes valid in buf
} kg_shared_t;

// EID type
typedef uint64_t kg_eid_t;

// Low-level user-mode ECALL helper (U -> S trap)
static inline long kg_ecall(long cmd, long a0, long a1, long a2, long a3) {
  //printf("kg_ecall\n");
  register long ra0 asm("a0") = a0;
  register long ra1 asm("a1") = a1;
  register long ra2 asm("a2") = a2;
  register long ra3 asm("a3") = a3;
  register long ra7 asm("a7") = cmd;
  asm volatile("ecall"
               : "+r"(ra0)
               : "r"(ra1), "r"(ra2), "r"(ra3), "r"(ra7)
               : "memory");
  return ra0; // SM/OS returns status in a0
}

// ---------- Host-side wrappers ----------

static inline long kg_ECREATE(int fd, kg_shared_t *shared,
                                 uint64_t flags, kg_eid_t *out_eid) {
  //printf("kg_ecreate\n");
  long ret = kg_ecall(KG_ECREATE,
                      (long)fd,               // a0
                      (long)shared,           // a1
                      (long)(flags), // a2
                      0L);                    // a3
  if (ret >= 0 && out_eid) *out_eid = (kg_eid_t)ret;
  return ret < 0 ? ret : 0;
}


/* static inline long kg_ECREATE(const void *img, uint64_t img_sz,
                              uint64_t entry_offset, // entry within img
                              kg_shared_t *shared,
                              kg_eid_t *out_eid) {
  // a0=img_ptr, a1=img_size, a2=entry_off, a3=shared_ptr
  long ret = kg_ecall(KG_ECREATE, (long)img, (long)img_sz,
                      (long)entry_offset, (long)shared);
  if (ret >= 0) *out_eid = (kg_eid_t)ret;
  return ret < 0 ? ret : 0;
}*/

static inline long kg_EENTER(kg_eid_t eid, kg_shared_t *shared) {
  // a0=eid, a1=shared_ptr
  return kg_ecall(KG_EENTER, (long)eid, (long)shared, 0, 0);
}

// ---------- Enclave-side wrappers ----------
static inline long kg_EEXIT(void) {
  return kg_ecall(KG_EEXIT, 0, 0, 0, 0);
}

//static inline long kg_OCALL(uint64_t svc_id, uint64_t arg0,
  //                          uint64_t arg1, uint64_t arg2) {
  // a0=svc_id, a1=arg0, a2=arg1, a3=arg2
static inline long kg_OCALL(kg_eid_t eid, kg_shared_t *shared) {
  return kg_ecall(KG_OCALL, (long)eid, (long)shared, 0, 0);
}

