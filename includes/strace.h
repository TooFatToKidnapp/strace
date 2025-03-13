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

#define DBG(fmt, ...)  fprintf(stderr, "DEBUG: %s:%d: " fmt, __FILE__, __LINE__, ##__VA_ARGS__);
#define LOG(fmt, ...)  fprintf(stderr, fmt, ##__VA_ARGS__)

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
  int64_t args[6];
  int64_t ret;
} t_syscall_info;


// https://wiki.osdev.org/CPU_Registers_x86-64
typedef struct user_regs_64 {
  int64_t r15;
  int64_t r14;
  int64_t r13;
  int64_t r12;
  int64_t rbp;
  int64_t rbx;
  int64_t r11;
  int64_t r10;
  int64_t r9;
  int64_t r8;
  int64_t rax;
  int64_t rcx;
  int64_t rdx;
  int64_t rsi;
  int64_t rdi;
  int64_t orig_rax;
  int64_t rip;
  int64_t cs;
  int64_t eflags;
  int64_t rsp;
  int64_t ss;
  int64_t fs_base;
  int64_t gs_base;
  int64_t ds;
  int64_t es;
  int64_t fs;
  int64_t gs;
} t_user_regs_64;

typedef struct s_sys_cycle {
  e_cpu_arch arch;
  e_process_status status;
  t_syscall_info syscall;
  int64_t args[6];
  int64_t ret;
} t_sys_cycle;


void init_command(t_command *command, char *argv[]);
void drop_command(t_command *command, char * reason);
void strace(t_command* command);

#endif
