#include "../includes/strace.h"

static void do_child(t_command* command) {
  if (ptrace(PTRACE_TRACEME) == -1) {
    drop_command(command, "ptrace failed\n");
    exit(1);
  }
  raise(SIGSTOP);
  execvp(command->command_path, command->command_args);
  drop_command(command, "ptrace failed\n");
  LOG("execvp failed\n");
  exit(1);
}

static do_parent(t_command* command) {
  int status;
  waitpid(command->pid, &status, 0);
  if (WIFSTOPPED(status)) {
    ptrace(PTRACE_SETOPTIONS, command->pid, 0, PTRACE_O_EXITKILL);
    // ptrace(PTRACE_CONT, command->pid, 0, 0);
    waitpid(command->pid, &status, 0);
    if (WIFEXITED(status)) {
      LOG("child exited with status %d\n", WEXITSTATUS(status));
    }
  }
  else {
    LOG("child stopped with status %d\n", WSTOPSIG(status));
  }
  return 0;
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
