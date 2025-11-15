// See LICENSE for license details.

#ifndef _RISCV_SBI_H
#define _RISCV_SBI_H

#define SBI_SET_TIMER 0
#define SBI_CONSOLE_PUTCHAR 1
#define SBI_CONSOLE_GETCHAR 2
#define SBI_CLEAR_IPI 3
#define SBI_SEND_IPI 4
#define SBI_REMOTE_FENCE_I 5
#define SBI_REMOTE_SFENCE_VMA 6
#define SBI_REMOTE_SFENCE_VMA_ASID 7
#define SBI_SHUTDOWN 8
#define SBI_LOAD_TAGS 9
#define SBI_CREATE_ENCLAVE 10
#define SBI_REGISTER_BASE 11
#define SBI_EENTER 12
#define SBI_EEXIT 13
#define SBI_OCALL 14
#define SBI_LOAD_HASH 15

//syscalls
#define SYS_brk 214
#define SYS_uname 160
#define SYS_readlinkat 78
#define SYS_read 63
#define SYS_write 64
#define SYS_openat 56
#define SYS_open 1024
#define SYS_newfstatat 79
#define SYS_pselect6 72
#define SYS_exit_group 94
#define SYS_exit 93
#define SYS_futex 98
#define SYS_clock_nanosleep 115
#define SYS_rt_sigaction 134
#define SYS_rt_sigprocmask 135
#define SYS_clone 220
#define SYS_execve 221
#define SYS_mmap 222
#define SYS_unmap 215
#define SYS_mprotect 226
#define SYS_socket 198
#define SYS_bind 200
#define SYS_listen 201
#define SYS_accept 202
#define SYS_connect 203
#define SYS_recvfrom 207
#define SYS_recvmmsg 243
#define SYS_recvmsg 212
#define SYS_sendmmsg 269
#define SYS_sendmsg 211
#define SYS_sendto 206
#define SYS_setsockopt 208
#define SYS_getsockopt 209
#define SYS_getsockname 204
#define SYS_shmat 196
#define SYS_shmctl 195
#define SYS_shmdt 197
#define SYS_shmget 194
#define SYS_ioctl 29
#define SYS_pselect6 72
#define SYS_newfstat 80

#endif
