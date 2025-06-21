#include "../includes/strace.h"

static uint64_t align_arg_size(uint64_t arg, uint32_t size) {
  if (size <= 0 || size > (uint32_t)sizeof(uint64_t)) return 0;
  if (size == (uint32_t)sizeof(uint64_t)) return arg;

  uint64_t masked = 0;
  memcpy(&masked, &arg, size);
  return masked;
}

static bool is_printable_ascii(const void *data, size_t len) {
  const unsigned char *bytes = (const unsigned char *)data;

  for (uint32_t i = 0; bytes[i] && i < len; i++) {
    if (!(bytes[i] >= 0x20 && bytes[i] <= 0x7E) &&
        !(bytes[i] == '\t' || bytes[i] == '\n' ||
          bytes[i] == '\r' || bytes[i] == '\f' ||
          bytes[i] == '\v')) {
      return false;
    }
  }
  return true;
}

static struct iovec read_child_mem(void *ptr, uint32_t size, pid_t child_pid) {
  struct iovec src = {
    .iov_base = ptr,
    .iov_len = size
  };

  struct iovec dest = {
    .iov_base = calloc(size, 1),
    .iov_len = size
  };
  if (dest.iov_base == NULL) {
    return (struct iovec){ .iov_base = NULL, .iov_len = 0 };
  }

  if (0 > process_vm_readv(child_pid, &dest, 1, &src, 1, 0)) {
    free(dest.iov_base);
    return (struct iovec){ .iov_base = NULL, .iov_len = 0 };
  }

  return dest;
}

static void format_value(e_sys_param_types arg_type, uint64_t arg, e_cpu_arch current_arch, pid_t child_pid) {
  const uint32_t max_ptr_size = current_arch == ARCH_64 ? 8 : 4;
  arg = align_arg_size(arg, max_ptr_size);

  if (arg_type == NONE) {
    LOG("?");
  } else if (arg_type == INT) {
    LOG("%d", (int32_t)arg);
  } else if (arg_type == UINT) {
    LOG("%u", (uint32_t)arg);
  } else if (arg_type == LONG) {
    LOG("%ld", (int64_t)arg);
  } else if (arg_type == ULONG) {
    LOG("%lu", arg);
  } else if (arg_type == STRUCT_PTR
          || arg_type == INT_PTR
          || arg_type == UINT_PTR
          || arg_type == UNDEFINED_PTR) {
      if (arg == 0) {
        LOG("NULL");
      } else {
        LOG("%p", (void*)arg);
      }
  } else if (arg_type == CHAR_PTR) {
    if (arg == 0) {
      LOG("NULL");
    } else {
      struct iovec data = read_child_mem((void*)arg, 4096, child_pid);
      if (data.iov_base == NULL || !is_printable_ascii(data.iov_base, data.iov_len )) {
        LOG("%p", (void*)arg);
      } else {
        LOG("\"%s\"", (char*)data.iov_base);
      }
        free(data.iov_base);
    }
  }
}

static void format_syscall_error(int64_t err, e_cpu_arch arch) {
  if (arch == ARCH_32) {
    err -= 4294967296; // tmejnin
  }
  if (-err > 143 || -err == 41 || -err == 58 || -err == 136 || -err == 137 || -err < 0 || -err > 143) {
    LOG("? UNKNOWN errno %ld", -err);
  } else {
    LOG("-1 %s (%s)", errno_table[-err], strerror(-err));
  }
}

void format_syscall(t_sys_cycle* sys_enter, t_sys_cycle* sys_exit, pid_t child_pid) {
  if (sys_enter->status != RUNNING) return;
  LOG("%s(", sys_enter->syscall.name);
  for (uint32_t i = 0; i < 6 && sys_enter->syscall.args[i] != NONE; ++i) {
    if (i > 0) LOG(", ");
    format_value(sys_enter->syscall.args[i], sys_enter->args[i], sys_enter->arch, child_pid);
  }

  LOG(") = ");
  if (sys_exit->status == RUNNING) {
    if ((uint32_t)sys_exit->ret >= (uint32_t)-4095) {
      format_syscall_error((int64_t)sys_exit->ret, sys_exit->arch);
    } else {
      format_value(sys_exit->syscall.ret, sys_exit->ret, sys_exit->arch, child_pid);
    }
  } else {
    LOG("?");
  }
  LOG("\n");
  if (sys_exit->status == RUNNING && sys_enter->arch != sys_exit->arch) {
    LOG("[ Architecture switched to %s ]\n", sys_exit->arch == ARCH_32 ? "x86" : "x86_64");
  }
}
