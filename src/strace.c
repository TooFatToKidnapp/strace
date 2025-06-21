#include "../includes/strace.h"


static void do_child(t_command* command) {
  if (0 != raise(SIGSTOP)) {
    // the child processes must wait for the parent
    // so that tha parent can have a chance to start tracking the syscalls in time
    // this might be a recoverable error, but for now just drop the program
    drop_command(command, "raise failed\n");
    exit(1);
  }

  execve(command->command_path, command->command_args, command->env);
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
  // parent will not receive any non interrupt signals
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

  bool is_sys_exit = false;
  t_sys_cycle sys_enter_info = {0};
  t_sys_cycle sys_exit_info = {0};
  struct timeval sys_start_time = {0};
  struct timeval sys_end_time = {0};

  while (true) {
    t_sys_cycle *current_info = is_sys_exit ? &sys_exit_info : &sys_enter_info;
    *current_info = get_syscall_info(command);

    if (is_sys_exit) {
      if (command->is_summery_enabled) {
        if (0 > gettimeofday(&sys_end_time, NULL)) {
          drop_command(command, "gettimeofday failed\n");
          exit(1);
        }
        double sys_duration = GET_SYS_DURATION(sys_start_time, sys_end_time);

        if (sys_enter_info.arch == ARCH_32 && current_info->syscall.name) {
          time_table_32.to_print = true;
          time_table_32.table[sys_enter_info.sys_number].count++;
          time_table_32.table[sys_enter_info.sys_number].time_spent += sys_duration;
          if ((uint32_t)current_info->ret >= (uint32_t)-4095) {
            time_table_32.table[sys_enter_info.sys_number].errors++;
          }
          time_table_32.total_time += sys_duration;
        } else if (sys_enter_info.arch == ARCH_64 && current_info->syscall.name) {
          time_table_64.to_print = true;
          time_table_64.table[sys_enter_info.sys_number].count++;
          time_table_64.table[sys_enter_info.sys_number].time_spent += sys_duration;
          if (current_info->ret >= (uint64_t)-4095) {
            time_table_64.table[sys_enter_info.sys_number].errors++;
          }
          time_table_64.total_time += sys_duration;
        }
      } else {
        format_syscall(&sys_enter_info, &sys_exit_info, command->pid);
      }
    } else if (command->is_summery_enabled) {
      if (0 > gettimeofday(&sys_start_time, NULL)) {
        drop_command(command, "gettimeofday failed\n");
        exit(1);
      }
    }

    if (current_info->status != RUNNING) {
      if (command->is_summery_enabled == false) {
        if (current_info->status == EXITED) {
          LOG("+++ EXITED WITH %ld +++\n", current_info->ret);
        } else {
          LOG("+++ KILLED BY SIG %s +++\n", strsignal((int)current_info->ret));
        }
      }
        break;
    }
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
