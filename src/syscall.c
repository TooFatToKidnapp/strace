#include "../includes/strace.h"

// static void get_registers_info(t_sys_cycle * cycle) {

// }


t_sys_cycle get_syscall_info(pid_t child_pid) {
  t_sys_cycle sys_cycle = {0};
  int32_t status;
  siginfo_t info;
  ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL);
  waitpid(child_pid, &status, 0);
  ptrace(PTRACE_GETSIGINFO, child_pid, NULL, &info);
  if (WIFEXITED(status)) { // the child process has exited
    sys_cycle.status = EXIT;
    sys_cycle.ret = WEXITSTATUS(status);
  } else if (WIFSIGNALED(status)) { // the child process has been killed
    sys_cycle.status = SIGNAL;
    sys_cycle.ret = WTERMSIG(status);
  } else if (info.si_signo != SIGTRAP) { // the child process has been interrupted by a signal
    sys_cycle.status = SIGNAL;
    sys_cycle.ret = info.si_signo;
    kill(child_pid, SIGKILL);
  } else {
    sys_cycle.status = RUN;

  }
  return sys_cycle;
}
