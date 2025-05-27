#include "../includes/strace.h"


static void print_summary_table(t_syscall_stats * syscall_stats, double total_time, bool is_64) {
  LOG("%% time     seconds  usecs/call     calls    errors syscall\n");
  LOG("------ ----------- ----------- --------- --------- ----------------\n");
  uint64_t total_calls = 0;
  uint64_t total_errors = 0;
  for (int i = 0; i < 450; i++) {
    if (syscall_stats[i].count > 0) {
      double percent = (total_time > 0) ? (syscall_stats[i].time_spent * 100 / total_time) : 0;
      double usecs_per_call = (syscall_stats[i].count > 0) ?
        ((syscall_stats[i].time_spent * 1000000) / syscall_stats[i].count) : 0;
      char *name = NULL;
      is_64 == true ? (name = (sys_table_64 + i)->name) : (name = (sys_table_32 + i)->name);
      LOG("%6.2f %11.6f %11.0f %9d %9d %s\n",
             percent,
             syscall_stats[i].time_spent,
             usecs_per_call,
             syscall_stats[i].count,
             syscall_stats[i].errors,
             name);
      total_calls += syscall_stats[i].count;
      total_errors += syscall_stats[i].errors;
    }
  }

    LOG("------ ----------- ----------- --------- --------- ----------------\n");
    LOG("%6.2f %11.6f %11.0f %9lu %9lu total\n",
           100.0, total_time, (total_time / total_calls) * 1000000  , total_calls, total_errors);
}

void format_syscall_summary() {
  if (time_table_64.to_print) {
    print_summary_table(time_table_64.table, time_table_64.total_time, true);
  }

  if (time_table_32.to_print) {
    LOG("System call usage summary for 32 bit mode:\n");
    print_summary_table(time_table_32.table, time_table_32.total_time, false);
  }
}
