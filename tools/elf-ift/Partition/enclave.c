// host/host.c
#include <stdint.h>
#include "kg_abi.h"

static void *kg_memcpy(volatile void *dst, const void *src, unsigned long n) {
  unsigned char *d = (unsigned char*)dst;
  const unsigned char *s = (const unsigned char*)src;
  while (n--) *d++ = *s++;
}

void _start(uint64_t a0, uint64_t a1) {
  kg_shared_t* shared = (kg_shared_t*)(uintptr_t)a1;  //read shared_buf from the host
  
  // ---- 1) Make an OCALL to print "hello" ----
  static const char msg[] = "hello";
  int n = sizeof(msg) - 1;
  if (n > sizeof shared->buf) n = sizeof shared->buf;

  // Fill the mailbox the way the host expects
  shared->svc_id = KG_OCALL_PUTS;  // host-side will match on this
  shared->len    = (uint64_t)n;    // host reads shared.len
  kg_memcpy(shared->buf, msg, n);
  kg_eid_t eid;
  kg_OCALL(eid, shared); // make an ocall
  
  kg_EEXIT(); //exit the enclave
}

