#include "../includes/strace.h"

void drop_command(t_command *command, char * reason) {
  if (reason) LOG(reason);
  if (command->command_path) {
    free(command->command_path);
  }
  if (command->command_args) {
    for (int32_t i = 0; command->command_args[i]; i++) {
      free(command->command_args[i]);
    }
    free(command->command_args);
  }
}

static bool is_summery_enabled(char *argv[]) {
  if (strncmp(argv[1], "-c", 3) == 0) {
    return true;
  }
  return false;
}

static char **split_by_tokens(char *path, const char *tokens) {
  if (path == NULL) {
    return NULL;
  }
  char **paths = NULL;
  char *token = strtok(path, tokens);
  uint32_t i = 0;
  while (token) {
    paths = realloc(paths, sizeof(char *) * (i + 1));
    if (paths == NULL) {
      LOG("%s\n", "realloc failed");
      exit(1);
    }
    paths[i] = strdup(token);
    if (paths[i] == NULL) {
      LOG("%s\n", "strdup failed");
      exit(1);
    }
    token = strtok(NULL, tokens);
    i++;
  }
  paths = realloc(paths, sizeof(char *) * (i + 1));
  if (paths == NULL) {
    LOG("%s\n", "realloc failed");
    exit(1);
  }
  paths[i] = NULL;
  return paths;
}

static char **get_command_args(char *argv[]) {
  uint32_t args_count_len = 0;
  for (uint32_t i = 0; argv[i]; i++) {
    args_count_len += strlen(argv[i]) + 1;
  }
  if (args_count_len == 0) {
    return NULL;
  }
  char *args_str = calloc(args_count_len, sizeof(char));
  if (args_str == NULL) {
    LOG("%s\n", "malloc failed");
    exit(1);
  }
  for (uint32_t i = 0; argv[i]; i++) {
    strncat(args_str, argv[i], strlen(argv[i]));
    if (argv[i + 1] != NULL) {
      strncat(args_str, " ", 2);
    }
  }
  return split_by_tokens(args_str, " \t\n\r\v\f");
}

void init_command(t_command *command, char *argv[]) {
  command->is_summery_enabled = is_summery_enabled(argv);
  if (command->is_summery_enabled) argv = argv + 2;
  else argv = argv + 1;

  if (access(argv[0], F_OK) == 0) {
    command->command_path = strdup(argv[0]);
    if (command->command_path == NULL) {
      drop_command(command, "strdup failed\n");
      exit(1);
    }
    command->command_args = get_command_args(argv);
    if (command->command_path == NULL) {
      drop_command(command, "get_command_args failed\n");
      exit(1);
    }
  }
  else {
    char *path = getenv("PATH");
    if (path == NULL) {
      path = _PATH_STDPATH;
    }
    char **paths = split_by_tokens(path, ":");
    for (int32_t i = 0; paths[i]; i++) {
      char file_path[strlen(paths[i]) + strlen(argv[0]) + 2];
      snprintf(file_path, sizeof(file_path), "%s/%s", paths[i], argv[0]);
      if (access(file_path, F_OK) == 0) {
        command->command_path = strdup(file_path);
        if (command->command_path == NULL) {
          drop_command(command, "strdup failed\n");
          exit(1);
        }
        command->command_args = get_command_args(argv);
        if (command->command_path == NULL) {
          drop_command(command, "get_command_args failed\n");
          exit(1);
        }
        break;
      }
    }
    for (int32_t i = 0; paths[i]; i++) {
      free(paths[i]);
    }
    free(paths);
    if (command->command_path == NULL) {
      fprintf(stderr, "ft_strace: '%s' is not a valid command\n", argv[0]);
      drop_command(command, NULL);
      exit(1);
    }
  }
}
