#ifndef STRACE_H
#define STRACE_H

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <paths.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <signal.h>

#define DBG(fmt, ...)  fprintf(stderr, "DEBUG: %s:%d: " fmt, __FILE__, __LINE__, ##__VA_ARGS__);
#define LOG(fmt, ...)  fprintf(stderr, fmt, ##__VA_ARGS__)

typedef struct s_command {
  char* command_path;
  char** command_args;
  pid_t pid;
  bool is_summery_enabled;
} t_command;

void init_command(t_command *command, char *argv[]);
void drop_command(t_command *command, char * reason);
void strace(t_command* command);

#endif
