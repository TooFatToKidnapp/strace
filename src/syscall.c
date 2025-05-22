#include "../includes/strace.h"

static void get_registers_info(t_sys_cycle * cycle, t_command* command) {
  t_proc_reg_64 regs = {0};
  struct iovec io = {
    .iov_base = &regs,
    .iov_len = sizeof(regs)
  };

  if (0 > ptrace(PTRACE_GETREGSET, command->pid, NT_PRSTATUS, &io)) {
    drop_command(command, "ptrace PTRACE_GETREGSET failed\n");
    exit(1);
  }

  if (io.iov_len == sizeof(t_proc_reg_64)) {
    cycle->arch = ARCH_64;
    cycle->syscall = *(sys_table_64 + regs.orig_rax);
    uint64_t sys_args[6] = {regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9 };
    memcpy(cycle->args, sys_args, sizeof(sys_args));
    cycle->ret = regs.rax;
  } else {
    t_proc_reg_32 regs_32 = {0};
    memcpy(&regs_32, &regs, sizeof(regs_32));
    cycle->arch = ARCH_32;
    cycle->syscall = *(sys_table_32 + regs_32.orig_eax);
    uint64_t sys_args[6] = {regs_32.ebx, regs_32.ecx, regs_32.edx, regs_32.esi, regs_32.edi, regs_32.ebp };
    memcpy(cycle->args, sys_args, sizeof(sys_args));
    cycle->ret = regs_32.eax;
  }
  return;
}

t_sys_cycle get_syscall_info(t_command* command) {
  t_sys_cycle sys_cycle = {0};
  int32_t status;
  siginfo_t info;
  if ( 0 > ptrace(PTRACE_SYSCALL, command->pid, NULL, NULL)) {
    drop_command(command, "ptrace PTRACE_SYSCALL failed\n");
    exit(1);
  }
  waitpid(command->pid, &status, 0);
  ptrace(PTRACE_GETSIGINFO, command->pid, NULL, &info);
  if (WIFEXITED(status)) { // the child process has exited
    sys_cycle.status = EXITED;
    sys_cycle.ret = WEXITSTATUS(status);
  } else if (WIFSIGNALED(status)) { // the child process has been killed
    sys_cycle.status = SIGNAL;
    sys_cycle.ret = WTERMSIG(status);
  } else if (info.si_signo != SIGTRAP) { // the child process has been interrupted by a signal
    sys_cycle.status = SIGNAL;
    sys_cycle.ret = info.si_signo;
    kill(command->pid, SIGKILL);
  } else {
    sys_cycle.status = RUNNING;
    get_registers_info(&sys_cycle, command);
  }
  return sys_cycle;
}
