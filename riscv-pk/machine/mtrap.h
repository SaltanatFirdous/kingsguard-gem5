// See LICENSE for license details.

#ifndef _RISCV_MTRAP_H
#define _RISCV_MTRAP_H

#include "encoding.h"

#ifdef __riscv_atomic
# define MAX_HARTS 8 // arbitrary
#else
# define MAX_HARTS 1
#endif

#ifndef __ASSEMBLER__

#include <stdint.h>
#include <stddef.h>
#include <stdarg.h>

#define read_const_csr(reg) ({ unsigned long __tmp; \
  asm ("csrr %0, " #reg : "=r"(__tmp)); \
  __tmp; })

#define MAX_MEMREFS 3
#define MAX_TASK 10
#define MAX_ENCL_THREADS 1

typedef struct
{
  char* vaddr;
  size_t n;
} mem_ref_t;

struct ctx
{
  uintptr_t slot;
  uintptr_t ra;
  uintptr_t sp;
  uintptr_t gp;
  uintptr_t tp;
  uintptr_t t0;
  uintptr_t t1;
  uintptr_t t2;
  uintptr_t s0;
  uintptr_t s1;
  uintptr_t a0;
  uintptr_t a1;
  uintptr_t a2;
  uintptr_t a3;
  uintptr_t a4;
  uintptr_t a5;
  uintptr_t a6;
  uintptr_t a7;
  uintptr_t s2;
  uintptr_t s3;
  uintptr_t s4;
  uintptr_t s5;
  uintptr_t s6;
  uintptr_t s7;
  uintptr_t s8;
  uintptr_t s9;
  uintptr_t s10;
  uintptr_t s11;
  uintptr_t t3;
  uintptr_t t4;
  uintptr_t t5;
  uintptr_t t6;
};

struct csrs
{
  uintptr_t sstatus;    //Supervisor status register.
  uintptr_t sedeleg;    //Supervisor exception delegation register.
  uintptr_t sideleg;    //Supervisor interrupt delegation register.
  uintptr_t sie;        //Supervisor interrupt-enable register.
  uintptr_t stvec;      //Supervisor trap handler base address.
  uintptr_t scounteren; //Supervisor counter enable

  /*  Supervisor Trap Handling */
  uintptr_t sscratch;   //Scratch register for supervisor trap handlers.
  uintptr_t sepc;       //Supervisor exception program counter.
  uintptr_t scause;     //Supervisor trap cause.
  //NOTE: This should be stval, toolchain issue?
  uintptr_t sbadaddr;   //Supervisor bad address.
  uintptr_t sip;        //Supervisor interrupt pending.

  /*  Supervisor Protection and Translation */
  uintptr_t satp;     //Page-table base register.

};

/* enclave thread state */
struct thread_state
{
  int prev_mpp;
  uintptr_t prev_mepc;
  uintptr_t prev_mstatus;
  struct csrs prev_csrs;
  struct ctx prev_state;
};

typedef struct {
  uint64_t id, base, size, entry, satp;
  uint64_t sh_pa, sh_sz;
  int state;   // 0=NEW, 1=READY, 2=RUNNING
  uint32_t inuse:1;
  mem_ref_t mem_ref[MAX_MEMREFS];
  uint64_t data_vma_start;
  uint64_t data_memsz;
  uint64_t ustack;
  uint64_t return_pc;
  uint64_t pgd;
  uint64_t host_pc;
  struct thread_state threads[MAX_ENCL_THREADS];
} encl;

#define MAX_ENCL 10
static inline int supports_extension(char ext)
{
  return read_const_csr(misa) & (1 << (ext - 'A'));
}

static inline int xlen()
{
  return read_const_csr(misa) < 0 ? 64 : 32;
}

extern uintptr_t mem_size;
extern volatile uint64_t* mtime;
extern volatile uint32_t* plic_priorities;
extern size_t plic_ndevs;
extern uint64_t misa_image;

typedef struct {
  volatile uint32_t* ipi;
  volatile int mipi_pending;

  volatile uint64_t* timecmp;

  volatile uint32_t* plic_m_thresh;
  volatile uint32_t* plic_m_ie;
  volatile uint32_t* plic_s_thresh;
  volatile uint32_t* plic_s_ie;
} hls_t;

#define MACHINE_STACK_TOP() ({ \
  uintptr_t sp = (uintptr_t)__builtin_frame_address(0) ; \
  (char *)((sp + RISCV_PGSIZE) & -RISCV_PGSIZE); })

// hart-local storage, at top of stack
#define HLS() ((hls_t*)(MACHINE_STACK_TOP() - HLS_SIZE))
#define OTHER_HLS(id) ((hls_t*)((char*)HLS() + RISCV_PGSIZE * ((id) - read_const_csr(mhartid))))

hls_t* hls_init(uintptr_t hart_id);
void parse_config_string();
void poweroff(uint16_t code) __attribute((noreturn));
void printm(const char* s, ...);
void vprintm(const char *s, va_list args);
void putstring(const char* s);
#define assert(x) ({ if (!(x)) die("assertion failed: %s", #x); })
#define die(str, ...) ({ printm("%s:%d: " str "\n", __FILE__, __LINE__, ##__VA_ARGS__); poweroff(-1); })

void swap_prev_state(struct thread_state* state, uintptr_t* regs, int return_on_resume);
void swap_prev_mepc(struct thread_state* state, uintptr_t* regs, uintptr_t mepc);
void swap_prev_mstatus(struct thread_state* state, uintptr_t* regs, uintptr_t mstatus);
void swap_prev_smode_csrs(struct thread_state* thread);

void setup_pmp();
void enter_supervisor_mode(void (*fn)(uintptr_t), uintptr_t arg0, uintptr_t arg1)
  __attribute__((noreturn));
void enter_machine_mode(void (*fn)(uintptr_t, uintptr_t), uintptr_t arg0, uintptr_t arg1)
  __attribute__((noreturn));
void boot_loader(uintptr_t dtb);
void boot_other_hart(uintptr_t dtb);

static inline void wfi()
{
  asm volatile ("wfi" ::: "memory");
}

#endif // !__ASSEMBLER__

#define IPI_SOFT       0x1
#define IPI_FENCE_I    0x2
#define IPI_SFENCE_VMA 0x4
#define IPI_HALT       0x8

#define MACHINE_STACK_SIZE RISCV_PGSIZE
#define MENTRY_HLS_OFFSET (INTEGER_CONTEXT_SIZE + SOFT_FLOAT_CONTEXT_SIZE)
#define MENTRY_FRAME_SIZE (MENTRY_HLS_OFFSET + HLS_SIZE)
#define MENTRY_IPI_OFFSET (MENTRY_HLS_OFFSET)
#define MENTRY_IPI_PENDING_OFFSET (MENTRY_HLS_OFFSET + REGBYTES)

#ifdef __riscv_flen
# define SOFT_FLOAT_CONTEXT_SIZE 0
#else
# define SOFT_FLOAT_CONTEXT_SIZE (8 * 32)
#endif
#define HLS_SIZE 64
#define INTEGER_CONTEXT_SIZE (32 * REGBYTES)
#define RISCV_PGLEVELS ((VA_BITS - RISCV_PGSHIFT) / RISCV_PGLEVEL_BITS)
#endif
