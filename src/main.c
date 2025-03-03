#include "../includes/strace.h"


static bool is_valid_arg_count(int32_t argc) {
  return argc == 2;
}


int32_t main(int32_t argc, char *argv[]) {
  (void)argv;
  if (!is_valid_arg_count(argc)) {
    fprintf(stderr, "ft_strace: must have PROG [ARGS] or -p PID\n");
    return 1;
  }

  printf("Hello, World!\n");
  return 0;
}
