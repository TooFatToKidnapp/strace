#include "../includes/strace.h"

int32_t main(int32_t argc, char *argv[]) {

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
  drop_command(&command, NULL);
  return 0;
}
