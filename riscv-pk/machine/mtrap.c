// See LICENSE for license details.

#include "mtrap.h"
#include "mcall.h"
#include "htif.h"
#include "atomic.h"
#include "bits.h"
#include "vm.h"
#include "uart.h"
#include "uart16550.h"
#include "uart_litex.h"
#include "finisher.h"
#include "fdt.h"
#include "unprivileged_memory.h"
#include "disabled_hart_mask.h"
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <inttypes.h>
#include <string.h>


#define mem_base 0x80200000
#define ENCLAVE_SUCCESS 0

static encl encl_arr[MAX_ENCL];
static struct ctx host_ctx;
static int curr_task = 0;
#define SHARED_BUF_SIZE 4096   // one page
#define CHARPTR (char *)

// Force page alignment
__attribute__((aligned(4096)))
static uint8_t shared_syscall_buf[SHARED_BUF_SIZE];

int user_app = 0;

int total_machine_cycles;
int cycles1, cycles2;
static void dump_regs(uintptr_t* regs) {
   for(int i=0;i<32;++i){
     printm("x%d : 0x%" PRIx64 "\n",i, *(regs+i));
   }
}

static const char* regname[32] = {
  "x0/zero","x1/ra","x2/sp","x3/gp","x4/tp","x5/t0","x6/t1","x7/t2",
  "x8/s0","x9/s1","x10/a0","x11/a1","x12/a2","x13/a3","x14/a4","x15/a5",
  "x16/a6","x17/a7","x18/s2","x19/s3","x20/s4","x21/s5","x22/s6","x23/s7",
  "x24/s8","x25/s9","x26/s10","x27/s11","x28/t3","x29/t4","x30/t5","x31/t6"
};

void store_host_context(uintptr_t * host_regs){
  int i;
  for(i=0; i<32; i++)
  {
    uintptr_t *host_ctx_regs = (uintptr_t *)&host_ctx;
    host_ctx_regs[i] = ((unsigned long *)host_regs)[i];
  }
}

void restore_host_context(uintptr_t * encl_regs){
  int i;
  for(i=0; i<32; i++)
  {
    uintptr_t *host_ctx_regs = (uintptr_t *)&host_ctx;
    encl_regs[i] = ((unsigned long *)host_ctx_regs)[i];
  }
}

/* Swaps the entire s-mode visible state, general registers and then csrs */
void swap_prev_state(struct thread_state* thread, uintptr_t* regs, int return_on_resume)
{
  printm("swap prev state\n");
  int i;
  uintptr_t* prev = (uintptr_t*) &thread->prev_state;

  for(i=0; i<32; i++)
  {
    /* swap state */
    // printm("prev[i]: %x  regs[i]: %x\n", prev[i], regs[i]);
    uintptr_t tmp = prev[i];
    prev[i] = ((unsigned long *)regs)[i];
    ((unsigned long *)regs)[i] = tmp;
  }

  prev[0] = !return_on_resume;

  // swap_prev_smode_csrs(thread);

  return;
}

/* Swaps all s-mode csrs defined in 1.10 standard */

void swap_prev_smode_csrs(struct thread_state*
thread){

  uintptr_t tmp;

#define LOCAL_SWAP_CSR(csrname) \
  tmp = thread->prev_csrs.csrname;                 \
  thread->prev_csrs.csrname = read_csr(csrname);   \
  write_csr(csrname, tmp);

  // LOCAL_SWAP_CSR(sstatus);
  // These only exist with N extension.
  //LOCAL_SWAP_CSR(sedeleg);
  //LOCAL_SWAP_CSR(sideleg);
  LOCAL_SWAP_CSR(sie);
  // LOCAL_SWAP_CSR(stvec);
  LOCAL_SWAP_CSR(scounteren);
  LOCAL_SWAP_CSR(sscratch);
  LOCAL_SWAP_CSR(sepc);
  LOCAL_SWAP_CSR(scause);
  LOCAL_SWAP_CSR(sbadaddr);
  // LOCAL_SWAP_CSR(sip);
  // LOCAL_SWAP_CSR(satp);

#undef LOCAL_SWAP_CSR
}

void swap_prev_mepc(struct thread_state* thread, uintptr_t* regs, uintptr_t current_mepc)
{
  uintptr_t tmp = thread->prev_mepc;
  thread->prev_mepc = current_mepc;
  write_csr(mepc, tmp);
}

static inline uintptr_t context_switch_to_enclave(uintptr_t* k_regs, uint64_t eid, uint8_t *shared_buf, uintptr_t * host_regs){

  printm("context switch to enclave\n");
  
  store_host_context(host_regs);
  swap_prev_state(&encl_arr[curr_task].threads[0], k_regs, 1);

  uintptr_t interrupts = 0;
  write_csr(mideleg, interrupts);


    if(encl_arr[curr_task].state == 0){  //if new enclave
          write_csr(mepc, (uintptr_t) encl_arr[curr_task].entry); //go to start address
          encl_arr[curr_task].state = 1; //ready
    }
    if(encl_arr[curr_task].state == 2){ //return after ocall
          write_csr(mepc,encl_arr[curr_task].return_pc + 4);
          encl_arr[curr_task].state = 1; //ready
    }

    printm("mepc before return: %x\n", read_csr(mepc));
    printm("sepc before return: %x\n", read_csr(sepc));
     uintptr_t mstatus = read_csr(mstatus);
    uintptr_t mpie_from_mie = (mstatus & MSTATUS_MIE) ? MSTATUS_MPIE : 0;
    uintptr_t new_mstatus = (mstatus & ~(MSTATUS_MPP | MSTATUS_MPIE | MSTATUS_MIE)) | mpie_from_mie;
    write_csr(mstatus, new_mstatus);
    write_csr(0x30a, 1);  //enable TEE
    write_csr(0x00b, 1);  //enable DIFT
    write_csr(0x30b, 1);  //enable CFA
    
    k_regs[11] = (uintptr_t)shared_buf;
  return ENCLAVE_SUCCESS;
}

static inline void context_switch_to_host(uintptr_t* encl_regs){


  uintptr_t interrupts = MIP_SSIP | MIP_STIP | MIP_SEIP;
  write_csr(mideleg, interrupts);

  /* restore host context */
  swap_prev_state(&encl_arr[curr_task].threads[0], encl_regs, 1); //probably not needed
  restore_host_context(encl_regs);
  write_csr(mepc, encl_arr[curr_task].host_pc);

  uintptr_t pending = read_csr(mip);

  if (pending & MIP_MTIP) {
    clear_csr(mip, MIP_MTIP);
    set_csr(mip, MIP_STIP);
  }
  if (pending & MIP_MSIP) {
    clear_csr(mip, MIP_MSIP);
    set_csr(mip, MIP_SSIP);
  }
  if (pending & MIP_MEIP) {
    clear_csr(mip, MIP_MEIP);
    set_csr(mip, MIP_SEIP);
  }

  return;
}


static uintptr_t uva2pa(uintptr_t vaddr, uintptr_t scause);
void __attribute__((noreturn)) bad_trap(uintptr_t* regs, uintptr_t dummy, uintptr_t mepc)
{
  die("machine mode: unhandlable trap %d @ %p", read_csr(mcause), mepc);
}



int get_available_idx() {
  for(int i = 0; i < MAX_ENCL; i++) {
    if (!encl_arr[i].inuse)
        return i;
  }
  return -1;
}
#if 1
  int get_current_task_idx(uint64_t satp) {
    for(int i = 0; i < MAX_TASK; i++) {
      if (encl_arr[i].inuse) {
  #ifdef DEBUG_2
          uint64_t satp_enc = encl_arr[i].satp;  // store as 64-bit too
            printm("satp enc=0x%016lx idx=%d satp read=0x%016lx\n",
                   (unsigned long)satp_enc, i, (unsigned long)satp);
  #endif
          if (encl_arr[i].satp == satp) {
              return i;
          }
      }
    }
    return -1;
  }
#endif

void map_tags(uint64_t fa, uint64_t *phy_fa, uintptr_t idx){
   uint64_t page_off_in_data = (fa - encl_arr[curr_task].data_vma_start) & ~(uint64_t)0xFFF; // page offset in data
   uintptr_t tag_src_pa = 0x80D00000ULL + (page_off_in_data >> 6); // 1B per 64B
    uintptr_t tag_dst_pa = 0x80D00000ULL + (idx * 64ULL);           // 64B per page

    // treat PAs as pointers (PA==VA assumption); otherwise use pa2kva(tag_*_pa)
    volatile uint8_t *src = (volatile uint8_t *)(uintptr_t)tag_src_pa;
    volatile uint8_t *dst = (volatile uint8_t *)(uintptr_t)tag_dst_pa;

    // copy exactly 64 bytes
    for (size_t i = 0; i < 64; ++i)
        dst[i] = src[i];
}
        

static uintptr_t mcall_load_tags(uint8_t* buf, size_t size){
  uint64_t *elf_tags_in_shadow_mem = (uint64_t *)0x80d00000;
  uint64_t *src = (uint64_t *)buf;

  // Copy `size` bytes from buf to shadow memory
  size_t num_tags = size / sizeof(uint64_t);
  for (size_t i = 0; i < num_tags; ++i) {
    elf_tags_in_shadow_mem[i] = src[i];
  }
  return 1;
  }


static uintptr_t mcall_load_hash(uint64_t* buf){
  uint64_t *hash_in_sm_mem = (uint64_t *)0x80e00000;

  for (size_t i = 0; i < 4; ++i) {  //64*4=256
    hash_in_sm_mem[i] = buf[i];
  }

  write_csr(0x30c, buf[0]);  // bits [63:0]
  write_csr(0x30d, buf[1]);  // bits [127:64]
  write_csr(0x30d, buf[2]);  // bits [191:128]
  write_csr(0x30f, buf[3]);  // bits [255:192]
  return 0;
  }


  static uintptr_t mcall_register_base(){
       write_csr(0x308, 1);
      return 0;
  }

  static uintptr_t mcall_create_enclave(uint8_t* buf, size_t size, uint64_t data_vma_start, uint64_t data_memsz, uintptr_t entry_pc, uint64_t ustack_top){
    int idx = get_available_idx();
    // if entry not available then let the user know and return
    if (-1 == idx) {
      return 1;
    }

     encl_arr[idx].id = (uint64_t)(idx+1);
     encl_arr[idx].entry = entry_pc;
     encl_arr[idx].inuse = 1;
     encl_arr[idx].ustack = ustack_top;
     encl_arr[idx].satp = read_csr(satp),  //null pointer dereference if sent from kernel
     printm("entry pc = 0x%x\n", entry_pc);
     encl_arr[idx].state = 0; //new enclave
     encl_arr[idx].data_vma_start = data_vma_start;
     encl_arr[idx].data_memsz = data_memsz;
     encl_arr[idx].threads[0].prev_state.sp = ustack_top;  //setting enclave stack pointer
     encl_arr[idx].threads[0].prev_csrs.satp = read_csr(satp);  //setting enclave satp
     
      uintptr_t ret = mcall_load_tags(buf, size);
  
     return idx;
  
  }

  static uintptr_t mcall_eenter(uintptr_t* k_regs, uint64_t eid, uint8_t* shared_buf, uintptr_t * host_regs){
     write_csr(sscratch, k_regs[4]);
   
      encl_arr[curr_task].host_pc = read_csr(sepc);
    if ( -1 == curr_task) {
       printm("invalid enclave\n");
       return -1;
    }

    printm("entry pc = 0x%x\n", encl_arr[curr_task].entry);
    printm("host pc = 0x%x\n", encl_arr[curr_task].host_pc);
    
    return context_switch_to_enclave(k_regs, eid, shared_buf, host_regs);

  }
  
  static void mcall_eexit(uintptr_t * encl_regs){
      write_csr(0x30a, 0);  //disable TEE
      write_csr(0x00b, 0);  //disable DIFT
      write_csr(0x30b, 0);  //disable CFA
      encl_arr[curr_task].state = 0; //stop the enclave
      //no need to save return pc
      context_switch_to_host(encl_regs);
      uintptr_t mstatus = read_csr(mstatus);
      uintptr_t mpie_from_mie = (mstatus & MSTATUS_MIE) ? MSTATUS_MPIE : 0;
      uintptr_t new_mstatus = (mstatus & ~(MSTATUS_MPP | MSTATUS_MPIE | MSTATUS_MIE)) | mpie_from_mie;
      write_csr(mstatus, new_mstatus);
      write_csr(mepc, encl_arr[0].host_pc + 4);
      extern void __redirect_trap();
     __redirect_trap();
  }

  static void mcall_ocall(uintptr_t * encl_regs){
      write_csr(0x30a, 0);  //disable TEE
      write_csr(0x00b, 0);  //disable DIFT
      write_csr(0x30b, 0);  //disable CFA
      // set mpp to U -- return to host user process
      encl_arr[curr_task].state = 2; //running : to indicate eenter should return to last pc
      encl_arr[curr_task].return_pc = read_csr(sepc);
      context_switch_to_host(encl_regs);
      uintptr_t mstatus = read_csr(mstatus);
      uintptr_t mpie_from_mie = (mstatus & MSTATUS_MIE) ? MSTATUS_MPIE : 0;
      uintptr_t new_mstatus = (mstatus & ~(MSTATUS_MPP | MSTATUS_MPIE | MSTATUS_MIE)) | mpie_from_mie;
      write_csr(mstatus, new_mstatus);
      write_csr(mepc, encl_arr[0].host_pc + 4);
      extern void __redirect_trap();
     __redirect_trap();
  }


  void redirect_trap(uintptr_t epc, uintptr_t mstatus, uintptr_t badaddr)
  {
    write_csr(sbadaddr, badaddr);
    write_csr(sepc, epc);
    write_csr(scause, read_csr(mcause));
    write_csr(mepc, read_csr(stvec));

    uintptr_t new_mstatus = mstatus & ~(MSTATUS_SPP | MSTATUS_SPIE | MSTATUS_SIE);
    uintptr_t mpp_s = MSTATUS_MPP & (MSTATUS_MPP >> 1);
    new_mstatus |= (mstatus * (MSTATUS_SPIE / MSTATUS_SIE)) & MSTATUS_SPIE;
    new_mstatus |= (mstatus / (mpp_s / MSTATUS_SPP)) & MSTATUS_SPP;
    new_mstatus |= mpp_s;
    write_csr(mstatus, new_mstatus);

    extern void __redirect_trap();
    return __redirect_trap();
  }



  void redirect_page_fault(uintptr_t vaddr, uintptr_t scause){
  
    //printm("Raising %x page fault in S layer at %lx sepc: 0x%x\n",scause, vaddr, read_csr(sepc));
  
  uintptr_t mstatus = read_csr(mstatus);

  write_csr(stval, vaddr);
  write_csr(scause, scause);

  // if(scause >=13) {
  //   write_csr(sepc, read_csr(sepc) - 0x4);
  // }

  write_csr(mepc, read_csr(stvec));

  uintptr_t new_mstatus = mstatus & ~(MSTATUS_SPP | MSTATUS_SPIE | MSTATUS_SIE);
  uintptr_t mpp_s = MSTATUS_MPP & (MSTATUS_MPP >> 1);
  new_mstatus |= (mstatus * (MSTATUS_SPIE / MSTATUS_SIE)) & MSTATUS_SPIE;
  //new_mstatus |= (mstatus / (mpp_s / MSTATUS_SPP)) & MSTATUS_SPP;
  new_mstatus |= mpp_s;
  write_csr(mstatus, new_mstatus);
  
  extern void __redirect_trap();
  return __redirect_trap();
}


static size_t pte_ppn(pte_t pte)
{
  return pte >> PTE_PPN_SHIFT;
}

static uintptr_t ppn(uintptr_t addr)
{
  return addr >> RISCV_PGSHIFT;
}

static size_t pt_idx(uintptr_t addr, int level)
{
  size_t idx = addr >> (RISCV_PGLEVEL_BITS*level + RISCV_PGSHIFT);
  //printm("idx: 0x%" PRIx64 "\n", idx);
  return idx & ((1 << RISCV_PGLEVEL_BITS) - 1);
}

static inline pte_t* walk(pte_t* t, uintptr_t addr, int level)
{
  for (int i = RISCV_PGLEVELS - 1; i > level; i--) {
    size_t idx = pt_idx(addr, i);
   // printm("idx2: 0x%" PRIx64 "\n", idx);
   // printm("t[idx]:0x%x\n", t[idx]);
    if(!(t[idx] & PTE_V)){
   // printm("return 0\n");
      return 0;
    }
   // printm("****0x%x\n", t[idx]);
    t = (pte_t*)(pte_ppn(t[idx]) << RISCV_PGSHIFT);
  }
  return &t[pt_idx(addr, level)];
}

// user virtual address to physical address
static uintptr_t uva2pa(uintptr_t vaddr, uintptr_t scause){
  //printm("uva2pa\n");
  uintptr_t satp = read_csr(satp) << RISCV_PGSHIFT;
  uintptr_t* p_entry = (uintptr_t*)walk((pte_t*)satp, vaddr, 0);
  //printm("walk done\n");
  if(!p_entry)
	  redirect_page_fault(vaddr, scause);
  //printm("redirect page fault done\n");
  uintptr_t last_level_pte = *(uintptr_t*)walk((pte_t*)satp, vaddr, 0);
  //printm("walk done again"); 

  if(last_level_pte == 0){
      //printm("zero\n");
      redirect_page_fault(vaddr, scause);

  }
  //printm("uva2pa done\n");
  return ((uintptr_t)pte_ppn(last_level_pte) << RISCV_PGSHIFT) | (vaddr & ((1 << RISCV_PGSHIFT) -1 ));
}

  static void copy_params(uintptr_t* regs){

  uintptr_t syscall = *(regs+17);
  uintptr_t vaddr;
  char* paddr;
  int n;

  mem_ref_t *mem_ref = (mem_ref_t *)(&encl_arr[curr_task].mem_ref[0]);
  // printm("Syscall %d\n", syscall);

    switch(syscall)
    {
      case SYS_uname:
        mem_ref[0].vaddr = CHARPTR *(regs+10); //this is where the kernel will write
        mem_ref[0].n = 336;
        // mem_ref[0].n = 0;
        // give kernel the shared buffer instead
       // *(regs+10) = (uintptr_t) shared_syscall_buf;
      break;

    case SYS_readlinkat:
      vaddr = *(regs+11);
      for(int i=0; i<15; i+=8){
        //char * paddr = CHARPTR uva2pa(vaddr+i ,13);
        uint64_t * paddr = (uint64_t *)uva2pa(vaddr+i ,13);
        memcpy((char *)shared_syscall_buf + i, paddr, 1);
        
      }
      
      // mem_ref[0].n= 16;
      // mem_ref[0].vaddr = CHARPTR *(regs+11);
      mem_ref[1].vaddr = CHARPTR *(regs+12);
      n = *(regs+13);
      mem_ref[1].n = n + (8-(n%8));
    break;

    case SYS_brk:
    #if 0
       
      if(*(regs+10) != 0){
       
        mem_ref[0].n = 0;
        mem_ref[0].vaddr = CHARPTR(*(regs+10) - *(regs+11));
        
        if(mem_ref[0].n < 0)
          mem_ref[0].n = 0;
        
      }
      #endif
      //printm("sys_brk\n");
    break;

    case SYS_read:
      n = *(regs+12);
      vaddr = *(regs+11);
      // give kernel the shared buffer instead
      *(regs+11) = (uintptr_t) shared_syscall_buf;
      mem_ref[0].n= n;
      mem_ref[0].vaddr = CHARPTR vaddr;
    break;

    case SYS_write:
      vaddr = *(regs+11);
      n = *(regs+12);
      paddr = (char *)uva2pa(vaddr ,13);
      //printm("write arg: %s\n", paddr);
      memcpy((char *)shared_syscall_buf, paddr, n);
      shared_syscall_buf[16] = '\0';
      //*(regs+11) = (uintptr_t) shared_syscall_buf;
     
     
     
    break;

    case SYS_openat:
      vaddr = *(regs+11);
      paddr = (char *)uva2pa(vaddr ,13);
      //copy pathname to shared buffer for OS access
      // strncpy((char *)shared_syscall_buf, paddr, 16);
      memcpy((char *)shared_syscall_buf, paddr, 16);
      shared_syscall_buf[16] = '\0';
      // give kernel the shared buffer instead
      *(regs+11) = (uintptr_t) shared_syscall_buf;
      //no need to copy on return
    
      
      
      
    break;
    
    case SYS_open:
      vaddr = *(regs+10);
     
      for(int i=0; i<16; i+=8){
        uint64_t * paddr = (uint64_t *)(uva2pa(vaddr+i ,13) & 0xfffffff8);
       
      
      }
      
      
      mem_ref[0].n= 16;
      //mem_ref[0].n= 0;
      mem_ref[0].vaddr = CHARPTR vaddr;
    break;

    case SYS_newfstatat:
      //printm("newfstatat\n");
      vaddr = *(regs+11); //pathname
      paddr = (char *)uva2pa(vaddr ,13);
      
      //copy pathname to shared buffer for OS access
      // strncpy((char *)shared_syscall_buf, paddr, 16);
      memcpy((char *)shared_syscall_buf, paddr, 16);
      shared_syscall_buf[16] = '\0';
      *(regs+11) = (uintptr_t) shared_syscall_buf;

      
      //no need to copy on return

      vaddr = *(regs+12);  //stat struct: no need to copy, os will write into it
      paddr = (char *)uva2pa(vaddr ,13);
      *(regs+12) = (uintptr_t) (shared_syscall_buf + 16);
      //do this if we need to copy on return
      mem_ref[0].n= 50;
      mem_ref[0].vaddr = CHARPTR vaddr;

    break;
    
    case SYS_newfstat:
      vaddr = *(regs+11);        //this is where the kernel will write
      // give kernel the shared buffer instead
      *(regs+11) = (uintptr_t) shared_syscall_buf;
      //copy back the results on return
      mem_ref[0].n= 16;
      mem_ref[0].vaddr = CHARPTR vaddr;


    break;

    /* Special handling required when exit is called.
     * this system call doesn't return to the calling
     * process and OS will endup cleaning the process
     * context. Therefore we need to clean up the process
     * data maintained by the shim.
     */
    case SYS_exit_group:
      /* decrypt the program header again. This was
       * identified by purely intuition of what steps
       * were executed during program loading.
       * Sans this, program would crash when exit is called.
       * What for is it used by OS for an exiting process?
       * Yet to be understood.
       */
       //printm("exit\n");
      printm("cycles in SM %lld\n", total_machine_cycles);
      // we are exiting the process and will
      // never return to user mode for this call
      // clear satp register and free up task reference entry.
      write_csr(0x00b, 0);
      write_csr(0x30a, 0);
      write_csr(0x30b, 0);  
      encl_arr[curr_task].satp = 0;
      encl_arr[curr_task].inuse = 0;
     break;
     
     case SYS_exit:
      
      // we are exiting the process and will
      // never return to user mode for this call
      // clear satp register and free up task reference entry.
      printm("cycles in SM %lld\n", total_machine_cycles);
      write_csr(0x00b, 0);
      write_csr(0x30a, 0);
      write_csr(0x30b, 0); 
      encl_arr[curr_task].satp = 0;
      encl_arr[curr_task].inuse = 0;
     break;
     
     case SYS_execve:
     //printm("execve\n");   //not an ecall
     vaddr = *(regs +15);
     //printm("vaddr:0x%x\n", vaddr);
     dump_regs(regs);
     for(int i=0; i<15; i+=8){
        uint64_t * paddr = (uint64_t *)uva2pa(vaddr+i ,13);
        }
      
     break;
   }
}

static void copy_ret(uintptr_t* regs){

  uintptr_t syscall = *(regs+17);
  // if(syscall == 214)
  //   printm("sys_brk return\n");
  //printm("Encrypt Syscall: %d\n", syscall);
  //dump_regs(regs);
  // printm("Encrypt Syscall: %d\n", syscall);
  //printm("encrypt memory\n");
  //printm("task_Ref= %0x\n", &task_ref[curr_task].mem_ref[0]);
  uint8_t a;
  mem_ref_t *mem_ref = &encl_arr[curr_task].mem_ref[0];
  uint8_t *temp_dst = &a;
  // if(syscall == 214){
  //     printm("mem_ref.vaddr= %0lx\n", mem_ref[0].vaddr);
  //     printm("mem_ref.n= %0x\n", mem_ref[0].n);
  // }
  for (int i = 0; i < 2; ++i) {
        if (mem_ref[i].n == 0)
            continue;

        // Convert enclave virtual to physical address
        uint8_t *dst = (uint8_t *) uva2pa((uintptr_t) mem_ref[i].vaddr, 15);
        uint8_t *src = shared_syscall_buf;  // start of shared buffer

        // Copy n bytes from shared buffer into enclave memory
        for (int j = 0; j < mem_ref[i].n; j++)
          memcpy(temp_dst, &src[j], 1);

        // Reset bookkeeping
        mem_ref[i].n = 0;
    }
}


  // Going towards the application
  void supervisor_to_user_trap(uintptr_t* regs, uintptr_t mcause, uintptr_t mepc){
    cycles1 = read_csr(0xb00);
    uintptr_t satp = read_csr(satp);
    uintptr_t scause = read_csr(scause);
    curr_task = get_current_task_idx(satp);
    if ( -1 != curr_task) {
    if(scause == 8){
      copy_ret(regs);
    }

    if(scause == 13 || scause == 15){  //if page fault (scause 12 is for instruction page fault)
        
         uintptr_t fa = read_csr(stval);              //faulting address
         uint64_t * phy_fa;
         uintptr_t idx = 0;
        //  printm("--------------------Faulting address: 0x%x----------------\n", fa);
        if(fa < 0x80000000){  //only for virtual addresses from user space
          phy_fa = (uint64_t *)uva2pa(fa,12);    //physical address
        //  printm("------------------Physical faulting address: %p----------------\n", phy_fa);
          uintptr_t offset = (uintptr_t)phy_fa - (uintptr_t)mem_base;  
          idx = offset >> 12;                     //page number = phy add/4kb (starting from 0x80000000
        //  printm("------------------Page index: %x----------------\n", idx);
         write_csr(0x7cc, satp); //write owner into hardware reg: this should be based on page idx, for overhead purpose its okay
        }

        //check if the fault is from data section; to load its tags
        if (fa >= encl_arr[curr_task].data_vma_start || fa < encl_arr[curr_task].data_vma_start + encl_arr[curr_task].data_memsz){
                     map_tags(fa, phy_fa, idx);
        }
   }
        cycles2 = read_csr(0xb00);
        total_machine_cycles += cycles2 - cycles1;
        // printm("s_to_u cycles: %d\n", cycles2-cycles1);

    }

    else{

         user_app = read_csr(0x310);
         if(user_app == 1){
          printm("increasing the time\n");
         uintptr_t mtimecmp_address = 0x2004000; 
         volatile uint64_t *mtimecmp;
         mtimecmp = (volatile uint64_t *)mtimecmp_address;
         *mtimecmp+=200000000;
    }
     
  }
    extern void __redirect_trap();
    return __redirect_trap();

  }

  // Going towards OS
  void user_to_supervisor_trap(uintptr_t* regs, uintptr_t mcause, uintptr_t mepc){
     cycles1 = read_csr(0xb00);
    uintptr_t satp = read_csr(satp);
    curr_task = get_current_task_idx(satp);
    uintptr_t scause = read_csr(scause);
    if(scause == 8){
      if(*(regs + 17) == 0x103){
         mcall_ocall(regs);
      }
      else if(*(regs + 17) == 0x102){
         mcall_eexit(regs);
      }
      copy_params(regs);
    }

     cycles2 = read_csr(0xb00);
     total_machine_cycles += cycles2 - cycles1;
    extern void __redirect_trap();
    return __redirect_trap();
  }

static uintptr_t mcall_console_putchar(uint8_t ch)
{
  if (uart) {
    uart_putchar(ch);
  } else if (uart16550) {
    uart16550_putchar(ch);
  } else if (uart_litex) {
    uart_litex_putchar(ch);
  } else if (htif) {
    htif_console_putchar(ch);
  }
  return 0;
}

void putstring(const char* s)
{
  while (*s)
    mcall_console_putchar(*s++);
}

void vprintm(const char* s, va_list vl)
{
  char buf[256];
  vsnprintf(buf, sizeof buf, s, vl);
  putstring(buf);
}

void printm(const char* s, ...)
{
  va_list vl;

  va_start(vl, s);
  vprintm(s, vl);
  va_end(vl);
}

static void send_ipi(uintptr_t recipient, int event)
{
  if (((disabled_hart_mask >> recipient) & 1)) return;
  atomic_or(&OTHER_HLS(recipient)->mipi_pending, event);
  mb();
  *OTHER_HLS(recipient)->ipi = 1;
}

static uintptr_t mcall_console_getchar()
{
  if (uart) {
    return uart_getchar();
  } else if (uart16550) {
    return uart16550_getchar();
  } else if (uart_litex) {
    return uart_litex_getchar();
  } else if (htif) {
    return htif_console_getchar();
  } else {
    return (uintptr_t)-1;
  }
}

static uintptr_t mcall_clear_ipi()
{
  return clear_csr(mip, MIP_SSIP) & MIP_SSIP;
}

static uintptr_t mcall_shutdown()
{
  poweroff(0);
}

static uintptr_t mcall_set_timer(uint64_t when)
{
  *HLS()->timecmp = when;
  clear_csr(mip, MIP_STIP);
  set_csr(mie, MIP_MTIP);
  return 0;
}

static void send_ipi_many(uintptr_t* pmask, int event)
{
  _Static_assert(MAX_HARTS <= 8 * sizeof(*pmask), "# harts > uintptr_t bits");
  uintptr_t mask = hart_mask;
  if (pmask)
    mask &= load_uintptr_t(pmask, read_csr(mepc));

  // send IPIs to everyone
  for (uintptr_t i = 0, m = mask; m; i++, m >>= 1)
    if (m & 1)
      send_ipi(i, event);

  if (event == IPI_SOFT)
    return;

  // wait until all events have been handled.
  // prevent deadlock by consuming incoming IPIs.
  uint32_t incoming_ipi = 0;
  for (uintptr_t i = 0, m = mask; m; i++, m >>= 1)
    if (m & 1)
      while (*OTHER_HLS(i)->ipi)
        incoming_ipi |= atomic_swap(HLS()->ipi, 0);

  // if we got an IPI, restore it; it will be taken after returning
  if (incoming_ipi) {
    *HLS()->ipi = incoming_ipi;
    mb();
  }
}

void mcall_trap(uintptr_t* regs, uintptr_t mcause, uintptr_t mepc)
{
  write_csr(mepc, mepc + 4);

  uintptr_t n = regs[17], arg0 = regs[10], arg1 = regs[11], arg2 = regs[12], arg3 = regs[13], arg4 = regs[14], arg5 = regs[15], arg6 = regs[16], retval, ipi_type;
     

  switch (n)
  {
    case SBI_CONSOLE_PUTCHAR:
      retval = mcall_console_putchar(arg0);
      break;
    case SBI_CONSOLE_GETCHAR:
      retval = mcall_console_getchar();
      break;
    case SBI_SEND_IPI:
      ipi_type = IPI_SOFT;
      goto send_ipi;
    case SBI_REMOTE_SFENCE_VMA:
    case SBI_REMOTE_SFENCE_VMA_ASID:
      ipi_type = IPI_SFENCE_VMA;
      goto send_ipi;
    case SBI_REMOTE_FENCE_I:
      ipi_type = IPI_FENCE_I;
send_ipi:
      send_ipi_many((uintptr_t*)arg0, ipi_type);
      retval = 0;
      break;
    case SBI_CLEAR_IPI:
      retval = mcall_clear_ipi();
      break;
    case SBI_SHUTDOWN:
      retval = mcall_shutdown();
      break;
    case SBI_SET_TIMER:
#if __riscv_xlen == 32
      retval = mcall_set_timer(arg0 + ((uint64_t)arg1 << 32));
#else
      retval = mcall_set_timer(arg0);
#endif
      break;
    case SBI_LOAD_TAGS:
      retval = mcall_load_tags((uint8_t *)arg0, arg1);
      break;

    case SBI_LOAD_HASH:
      retval = mcall_load_hash((uint64_t *)arg0);
      break;

    case SBI_CREATE_ENCLAVE:
      retval = mcall_create_enclave((uint8_t *)arg0, arg1, arg2, arg3, arg4, arg5);
      break;

    case SBI_REGISTER_BASE:
      retval = mcall_register_base();
      break;

    case SBI_EENTER:
      retval = mcall_eenter(regs, arg0, (uint8_t *)arg1, (uintptr_t *) arg2);
      break;

    case SBI_EEXIT:
      mcall_eexit(regs);
      retval = 0;
      break;

    case SBI_OCALL:
      mcall_ocall(regs);
      retval = 0;
      break;


    default:
      retval = -ENOSYS;
      break;
  }
  regs[10] = retval;
}

void pmp_trap(uintptr_t* regs, uintptr_t mcause, uintptr_t mepc)
{
  redirect_trap(mepc, read_csr(mstatus), read_csr(mtval));
}

static void machine_page_fault(uintptr_t* regs, uintptr_t mcause, uintptr_t mepc)
{
  // MPRV=1 iff this trap occurred while emulating an instruction on behalf
  // of a lower privilege level. In that case, a2=epc and a3=mstatus.
  // a1 holds MPRV if emulating a load or store, or MPRV | MXR if loading
  // an instruction from memory.  In the latter case, we should report an
  // instruction fault instead of a load fault.
  if (read_csr(mstatus) & MSTATUS_MPRV) {
    if (regs[11] == (MSTATUS_MPRV | MSTATUS_MXR)) {
      if (mcause == CAUSE_LOAD_PAGE_FAULT)
        write_csr(mcause, CAUSE_FETCH_PAGE_FAULT);
      else if (mcause == CAUSE_LOAD_ACCESS)
        write_csr(mcause, CAUSE_FETCH_ACCESS);
      else
        goto fail;
    } else if (regs[11] != MSTATUS_MPRV) {
      goto fail;
    }

    return redirect_trap(regs[12], regs[13], read_csr(mtval));
  }

fail:
  bad_trap(regs, mcause, mepc);
}

void trap_from_machine_mode(uintptr_t* regs, uintptr_t dummy, uintptr_t mepc)
{
  uintptr_t mcause = read_csr(mcause);

  switch (mcause)
  {
    case CAUSE_LOAD_PAGE_FAULT:
    case CAUSE_STORE_PAGE_FAULT:
    case CAUSE_FETCH_ACCESS:
    case CAUSE_LOAD_ACCESS:
    case CAUSE_STORE_ACCESS:
      return machine_page_fault(regs, mcause, mepc);
    default:
      bad_trap(regs, dummy, mepc);
  }
}

void poweroff(uint16_t code)
{
  printm("Power off\r\n");
  finisher_exit(code);
  if (htif) {
    htif_poweroff();
  } else {
    send_ipi_many(0, IPI_HALT);
    while (1) { asm volatile ("wfi\n"); }
  }
}
