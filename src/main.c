#include "../includes/strace.h"

t_syscall_signature_info sys_table_64[] = LOOKUP_TABLE_64;
t_syscall_signature_info sys_table_32[] = LOOKUP_TABLE_32;

int32_t main(int32_t argc, char *argv[]) {
  LOG("kill -9 %d\n", getpid());
  if (argc < 2) {
    LOG("ft_strace: must have PROG [ARGS] OPTION [-c] \n");
    return 1;
  }
  t_command command = {0};
  init_command(&command, argv);
  DBG("command_path = [%s]\n", command.command_path);
  for (int32_t i = 0; command.command_args[i]; i++) {
    DBG("command_args[%d] = [%s]\n", i, command.command_args[i]);
  }
  if( command.is_summery_enabled) {
    LOG("Summary enabled\n");
  }
  strace(&command);
  return 0;
}
