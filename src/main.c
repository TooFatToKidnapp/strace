#include "../includes/strace.h"

t_syscall_signature_info sys_table_64[] = LOOKUP_TABLE_64;
t_syscall_signature_info sys_table_32[] = LOOKUP_TABLE_32;
t_total_syscall_stats_32 time_table_32 = {0};
t_total_syscall_stats_64 time_table_64 = {0};
char *errno_table[] = ERRNO_TABLE;

int32_t main(int32_t argc, char *argv[], char** env) {
  if (argc < 2) {
    LOG("ft_strace: must have [OPTION: -c] [PROG ARGS]\n");
    return 1;
  }
  t_command command = {
    .env = env
  };
  init_command(&command, argv);
  strace(&command);
  format_syscall_summary();
  drop_command(&command, NULL);
  return 0;
}
