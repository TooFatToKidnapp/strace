#include "../includes/strace.h"

static void do_child(t_command* command) {
  ptrace(PTRACE_TRACEME);
  raise(SIGSTOP);
  execvp(command->command_path, command->command_args);
  drop_command(command, "ptrace failed\n");
  LOG("execvp failed\n");
  exit(1);
}

static void do_parent(t_command* command) {
  ptrace(PTRACE_SEIZE, command->pid, 0, PTRACE_O_TRACESYSGOOD); // TRACE THE CHILD
  waitpid(command->pid, 0, 0); // WAIT FOR THE CHILD TO STOP
  sigset_t mask = {0};
  sigfillset(&mask);
  sigprocmask(SIG_SETMASK, &mask, 0); // parent will not receive any non interupt signals
  bool is_sys_exit = false;

  // t_sys_cycle sys_enter = {0};
  // t_sys_cycle sys_exit = {0};

  while (true) {
    // if (!is_sys_exit) {
    //   sys_enter =
    // }
    is_sys_exit = !is_sys_exit;
  }
}


void strace(t_command* command) {
  pid_t pid = fork();
  if (pid == -1) {
    drop_command(command, "fork failed\n");
    exit(1);
  }
  if (pid == 0) {
    return do_child(command);
  }
  else {
    command->pid = pid;
    return do_parent(command);
  }
}
