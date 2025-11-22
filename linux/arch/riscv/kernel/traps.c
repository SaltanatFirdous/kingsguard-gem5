// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2012 Regents of the University of California
 */

#include <linux/cpu.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/sched/debug.h>
#include <linux/sched/signal.h>
#include <linux/signal.h>
#include <linux/kdebug.h>
#include <linux/uaccess.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/irq.h>
#include <linux/file.h>
#include <linux/sched/task_stack.h> 
#include <asm/processor.h>
#include <asm/ptrace.h>
#include <asm/csr.h>

/* --- Kingsguard opcodes & flags (kernel-visible) --- */
enum {
    KG_ECREATE = 0x100,
    KG_EENTER  = 0x101,
    KG_EEXIT   = 0x102,
    KG_OCALL   = 0x103,
};

int show_unhandled_signals = 1;

extern asmlinkage void handle_exception(void);
extern int kgs_binfmt_load_from_filp(struct file *filp, u64 *out_eid);

static DEFINE_SPINLOCK(die_lock);

void die(struct pt_regs *regs, const char *str)
{
	static int die_counter;
	int ret;

	oops_enter();

	spin_lock_irq(&die_lock);
	console_verbose();
	bust_spinlocks(1);

	pr_emerg("%s [#%d]\n", str, ++die_counter);
	print_modules();
	show_regs(regs);

	ret = notify_die(DIE_OOPS, str, regs, 0, regs->cause, SIGSEGV);

	bust_spinlocks(0);
	add_taint(TAINT_DIE, LOCKDEP_NOW_UNRELIABLE);
	spin_unlock_irq(&die_lock);
	oops_exit();

	if (in_interrupt())
		panic("Fatal exception in interrupt");
	if (panic_on_oops)
		panic("Fatal exception");
	if (ret != NOTIFY_STOP)
		do_exit(SIGSEGV);
}

void do_trap(struct pt_regs *regs, int signo, int code, unsigned long addr)
{
	struct task_struct *tsk = current;

	if (show_unhandled_signals && unhandled_signal(tsk, signo)
	    && printk_ratelimit()) {
		pr_info("%s[%d]: unhandled signal %d code 0x%x at 0x" REG_FMT,
			tsk->comm, task_pid_nr(tsk), signo, code, addr);
		print_vma_addr(KERN_CONT " in ", instruction_pointer(regs));
		pr_cont("\n");
		show_regs(regs);
	}

	force_sig_fault(signo, code, (void __user *)addr);
}

static void do_trap_error(struct pt_regs *regs, int signo, int code,
	unsigned long addr, const char *str)
{
	if (user_mode(regs)) {
		do_trap(regs, signo, code, addr);
	} else {
		if (!fixup_exception(regs))
			die(regs, str);
	}
}

#define DO_ERROR_INFO(name, signo, code, str)				\
asmlinkage __visible void name(struct pt_regs *regs)			\
{									\
	do_trap_error(regs, signo, code, regs->epc, "Oops - " str);	\
}

DO_ERROR_INFO(do_trap_unknown,
	SIGILL, ILL_ILLTRP, "unknown exception");
DO_ERROR_INFO(do_trap_insn_misaligned,
	SIGBUS, BUS_ADRALN, "instruction address misaligned");
DO_ERROR_INFO(do_trap_insn_fault,
	SIGSEGV, SEGV_ACCERR, "instruction access fault");
DO_ERROR_INFO(do_trap_insn_illegal,
	SIGILL, ILL_ILLOPC, "illegal instruction");
DO_ERROR_INFO(do_trap_load_fault,
	SIGSEGV, SEGV_ACCERR, "load access fault");
#ifndef CONFIG_RISCV_M_MODE
DO_ERROR_INFO(do_trap_load_misaligned,
	SIGBUS, BUS_ADRALN, "Oops - load address misaligned");
DO_ERROR_INFO(do_trap_store_misaligned,
	SIGBUS, BUS_ADRALN, "Oops - store (or AMO) address misaligned");
#else
int handle_misaligned_load(struct pt_regs *regs);
int handle_misaligned_store(struct pt_regs *regs);

asmlinkage void do_trap_load_misaligned(struct pt_regs *regs)
{
	if (!handle_misaligned_load(regs))
		return;
	do_trap_error(regs, SIGBUS, BUS_ADRALN, regs->epc,
		      "Oops - load address misaligned");
}

asmlinkage void do_trap_store_misaligned(struct pt_regs *regs)
{
	if (!handle_misaligned_store(regs))
		return;
	do_trap_error(regs, SIGBUS, BUS_ADRALN, regs->epc,
		      "Oops - store (or AMO) address misaligned");
}
#endif
DO_ERROR_INFO(do_trap_store_fault,
	SIGSEGV, SEGV_ACCERR, "store (or AMO) access fault");
// DO_ERROR_INFO(do_trap_ecall_u,
	// SIGILL, ILL_ILLTRP, "environment call from U-mode");

static inline void pt_regs_to_xarray(const struct pt_regs *r, u64 x[32])
{
    x[0]  = 0;          x[1]  = r->ra;   x[2]  = r->sp;   x[3]  = r->gp;
    x[4]  = r->tp;      x[5]  = r->t0;   x[6]  = r->t1;   x[7]  = r->t2;
    x[8]  = r->s0;      x[9]  = r->s1;   x[10] = r->a0;   x[11] = r->a1;
    x[12] = r->a2;      x[13] = r->a3;   x[14] = r->a4;   x[15] = r->a5;
    x[16] = r->a6;      x[17] = r->a7;   x[18] = r->s2;   x[19] = r->s3;
    x[20] = r->s4;      x[21] = r->s5;   x[22] = r->s6;   x[23] = r->s7;
    x[24] = r->s8;      x[25] = r->s9;   x[26] = r->s10;  x[27] = r->s11;
    x[28] = r->t3;      x[29] = r->t4;   x[30] = r->t5;   x[31] = r->t6;
}

asmlinkage __visible void do_trap_ecall_u(struct pt_regs *regs)
{
    /* Fast path for Kingsguard ECALLs coming from U-mode. */
    switch (regs->a7) {

    case KG_ECREATE: {
        long ret;
        u64 eid = 0;

        
            int fd = (int)regs->a0;
            struct fd f = fdget(fd);
            if (!f.file) {
				pr_crit("skip ecall\n");
                regs->a0 = -EBADF;
                regs->epc += 4;   /* skip ECALL */
                return;
            }

            ret = kgs_binfmt_load_from_filp(f.file, &eid);
            fdput(f);

            regs->a0 = (ret < 0) ? ret : (long)eid;
            regs->epc += 4;
            return;
    }

    case KG_EENTER: {
        /* a0 = eid, a1 = shared_user pointer (userspace VA) */
		uint64_t host_epc   = regs->epc; 
		uint64_t eid = regs->a0;
		uint64_t shared_buf = regs->a1;
		struct pt_regs *uregs = task_pt_regs(current);
		uint64_t x[32];
    	pt_regs_to_xarray(uregs, x);
		u64 x_pa = __pa(x);
		 asm volatile("li a7, 12\n"
											"move a0, %0\n"
											"move a1, %1\n"
											"move a2, %2\n"
											"ecall\n"
											:
											: "r" (eid), "r" (shared_buf), "r" (x_pa)
											: "cc");
		
		regs->a0 = 0;
        regs->epc += 4;

        return;
    }

    case KG_EEXIT:
        // enclave traps directly to SM, does not come here
		pr_crit("EEXIT\n");
		asm volatile("li a7, 13\n"
					"ecall\n");
        regs->a0 = 0;
        regs->epc += 4;
        return;

    case KG_OCALL:
        // enclave traps directly to SM
		pr_crit("OCALL\n");
		asm volatile("li a7, 14\n"
					"ecall\n");
        regs->a0 = 0;
        regs->epc += 4;
        return;

    default:
        /* Not ours: fall through to legacy behavior (send SIGILL) */
		 do_trap_error(regs, SIGILL, ILL_ILLTRP, regs->epc,
                  "environment call from U-mode");
        break;
    }

    /* Old behavior (what the macro did): raise SIGILL for unknown ecall */
   
}
DO_ERROR_INFO(do_trap_ecall_s,
	SIGILL, ILL_ILLTRP, "environment call from S-mode");
DO_ERROR_INFO(do_trap_ecall_m,
	SIGILL, ILL_ILLTRP, "environment call from M-mode");

static inline unsigned long get_break_insn_length(unsigned long pc)
{
	bug_insn_t insn;

	if (get_kernel_nofault(insn, (bug_insn_t *)pc))
		return 0;

	return GET_INSN_LENGTH(insn);
}

asmlinkage __visible void do_trap_break(struct pt_regs *regs)
{
	if (user_mode(regs))
		force_sig_fault(SIGTRAP, TRAP_BRKPT, (void __user *)regs->epc);
#ifdef CONFIG_KGDB
	else if (notify_die(DIE_TRAP, "EBREAK", regs, 0, regs->cause, SIGTRAP)
								== NOTIFY_STOP)
		return;
#endif
	else if (report_bug(regs->epc, regs) == BUG_TRAP_TYPE_WARN)
		regs->epc += get_break_insn_length(regs->epc);
	else
		die(regs, "Kernel BUG");
}

#ifdef CONFIG_GENERIC_BUG
int is_valid_bugaddr(unsigned long pc)
{
	bug_insn_t insn;

	if (pc < VMALLOC_START)
		return 0;
	if (get_kernel_nofault(insn, (bug_insn_t *)pc))
		return 0;
	if ((insn & __INSN_LENGTH_MASK) == __INSN_LENGTH_32)
		return (insn == __BUG_INSN_32);
	else
		return ((insn & __COMPRESSED_INSN_MASK) == __BUG_INSN_16);
}
#endif /* CONFIG_GENERIC_BUG */

/* stvec & scratch is already set from head.S */
void trap_init(void)
{
}
