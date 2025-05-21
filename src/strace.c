#include "../includes/strace.h"

static void do_child(t_command* command) {
  if (0 != raise(SIGSTOP)) {
    // the child processes must wait for the parent
    // so that tha parent can have a chance to start tracking the syscalles in time
    // this might be a recoverable error, but for now just drop the progarm
    drop_command(command, "raise failed\n");
    exit(1);
  }
  execvp(command->command_path, command->command_args);
  drop_command(command, "execvp failed\n");
  exit(1);
}

static void do_parent(t_command* command) {
  // parent ignores all signals
  sigset_t mask = {0};
  if (0 > sigfillset(&mask)) {
    drop_command(command, "sigfillset failed\n");
    exit(1);
  }
  // why block signals? (except SIGKILL and SIGSTOP)
  // https://www.gnu.org/software/libc/manual/html_node/Why-Block.html
  // parent will not receive any non interupt signals
  if (0 > sigprocmask(SIG_SETMASK, &mask, 0)) {
    drop_command(command, "sigprocmask failed\n");
    exit(1);
  }

  // TRACE THE CHILD
  if (0 > ptrace(PTRACE_SEIZE, command->pid, 0, PTRACE_O_TRACESYSGOOD)) {
    drop_command(command, "ptrace PTRACE_SEIZE failed\n");
    exit(1);
  }

  // WAIT FOR THE CHILD TO STOP
  if (0 > waitpid(command->pid, 0, 0)) {
    drop_command(command, "waitpid failed\n");
    exit(1);
  }


  // bool is_sys_exit = false;
  // t_sys_cycle sys_enter = {0};
  // t_sys_cycle sys_exit = {0};

  // while (true) {
  //   // if (!is_sys_exit) {
  //   //   sys_enter =
  //   // }
  //   is_sys_exit = !is_sys_exit;
  // }
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
