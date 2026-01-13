// host/host.c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>   // open, close (POSIX)
#include <fcntl.h>    // O_RDONLY, O_RDWR, etc.
#include <errno.h>    
#include "kg_abi.h"

static int read_file(const char *path, uint8_t **out, size_t *out_sz) {
  FILE *f = fopen(path, "rb");
  if (!f) return -1;
  fseek(f, 0, SEEK_END);
  long sz = ftell(f);
  fseek(f, 0, SEEK_SET);
  if (sz <= 0) { fclose(f); return -1; }
  uint8_t *buf = (uint8_t*)malloc(sz);
  if (!buf) { fclose(f); return -1; }
  if (fread(buf, 1, sz, f) != (size_t)sz) { free(buf); fclose(f); return -1; }
  fclose(f);
  *out = buf; *out_sz = (size_t)sz;
  return 0;
}

int main(int argc, char **argv) {
  
  int efd = open("./enclave", O_RDONLY);
  static kg_shared_t shared = {0};
  kg_eid_t eid;

  long rc = kg_ECREATE(efd, &shared, /*flags=*/0, &eid);
  if (rc != 0) { perror("ECREATE_FD"); exit(1); }

  rc = kg_EENTER(eid, &shared);
  if (rc != 0) { perror("EENTER"); exit(1); }

  

  // After return, SM should have copied the OCALL payload into shared.
  if (shared.svc_id == KG_OCALL_PUTS) {
    // Host handles the OCALL: print the string the enclave requested.
    uint64_t n = shared.len; if (n > sizeof(shared.buf)) n = sizeof(shared.buf);
    fwrite((const void*)shared.buf, 1, (size_t)n, stdout);
    fputc('\n', stdout);

    // Optionally, write results back (none needed for puts).
    shared.reason = 0;

    // Re-enter so the enclave can continue (and likely EEXIT).
    if (kg_EENTER(eid, &shared) != 0) {
      fprintf(stderr, "EENTER (resume) failed\n");
     
      return 1;
    }
  }

  printf("end of host\n");
  return 0;
}

