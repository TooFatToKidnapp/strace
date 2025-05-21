#ifndef STRACE_H
#define STRACE_H

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <paths.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/syscall.h>

#include "lookup_table_32.h"
#include "lookup_table_64.h"

#define DBG(fmt, ...)  fprintf(stderr, "DEBUG: %s:%d: " fmt, __FILE__, __LINE__, ##__VA_ARGS__);
#define LOG(fmt, ...)  fprintf(stderr, fmt, ##__VA_ARGS__)

typedef enum sys_param_types {
  NONE,
  INT,
  UINT,
  LONG,
  LONG_LONG,
  ULONG,
  ULONG_LONG,

  UNDEFINED_PTR,
  CHAR_PTR,
  STRUCT_PTR,
  INT_PTR,
  UINT_PTR,

  STRUCT
} e_sys_param_types;

typedef struct s_command {
  char* command_path;
  char** command_args;
  pid_t pid;
  bool is_summery_enabled;
} t_command;

typedef enum cpu_arch {
  ARCH_32,
  ARCH_64,
} e_cpu_arch;

typedef enum process_status {
  RUN,
  EXIT,
  SIGNAL,
} e_process_status;

typedef struct s_syscall_info {
  char *name;
  e_sys_param_types args[6];
  e_sys_param_types ret;
} t_syscall_signature_info;


// https://wiki.osdev.org/CPU_Registers_x86-64
// https://sites.uclouvain.be/SystInfo/usr/include/sys/user.h.html
typedef struct proc_reg_64 {
  uint64_t r15;
  uint64_t r14;
  uint64_t r13;
  uint64_t r12;
  uint64_t rbp;
  uint64_t rbx;
  uint64_t r11;
  uint64_t r10;
  uint64_t r9;
  uint64_t r8;
  uint64_t rax;
  uint64_t rcx;
  uint64_t rdx;
  uint64_t rsi;
  uint64_t rdi;
  uint64_t orig_rax;
  uint64_t rip;
  uint64_t cs;
  uint64_t eflags;
  uint64_t rsp;
  uint64_t ss;
  uint64_t fs_base;
  uint64_t gs_base;
  uint64_t ds;
  uint64_t es;
  uint64_t fs;
  uint64_t gs;
} t_proc_reg_64;


typedef struct proc_reg_32 {
  uint32_t ebx;
  uint32_t ecx;
  uint32_t edx;
  uint32_t esi;
  uint32_t edi;
  uint32_t ebp;
  uint32_t eax;
  uint32_t xds;
  uint32_t xes;
  uint32_t xfs;
  uint32_t xgs;
  uint32_t orig_eax;
  uint32_t eip;
  uint32_t xcs;
  uint32_t eflags;
  uint32_t esp;
  uint32_t xss;
} t_proc_reg_32;



typedef struct s_sys_cycle {
  e_cpu_arch arch;
  e_process_status status;
  t_syscall_signature_info syscall;
  int64_t args[6];
  int64_t ret;
} t_sys_cycle;


void init_command(t_command *command, char *argv[]);
void drop_command(t_command *command, char * reason);
void strace(t_command* command);

#endif
