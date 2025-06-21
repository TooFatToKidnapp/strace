#include "../includes/strace.h"

static const char* get_signal_name(int signo) {
  switch (signo) {
    case SIGABRT: return "SIGABRT";
    case SIGALRM: return "SIGALRM";
    case SIGBUS: return "SIGBUS";
    case SIGCHLD: return "SIGCHLD";
    case SIGCONT: return "SIGCONT";
    case SIGFPE: return "SIGFPE";
    case SIGHUP: return "SIGHUP";
    case SIGILL: return "SIGILL";
    case SIGINT: return "SIGINT";
    case SIGKILL: return "SIGKILL";
    case SIGPIPE: return "SIGPIPE";
    case SIGQUIT: return "SIGQUIT";
    case SIGSEGV: return "SIGSEGV";
    case SIGSTOP: return "SIGSTOP";
    case SIGTERM: return "SIGTERM";
    case SIGTSTP: return "SIGTSTP";
    case SIGTTIN: return "SIGTTIN";
    case SIGTTOU: return "SIGTTOU";
    case SIGUSR1: return "SIGUSR1";
    case SIGUSR2: return "SIGUSR2";
    case SIGPOLL: return "SIGPOLL";
    case SIGPROF: return "SIGPROF";
    case SIGSYS: return "SIGSYS";
    case SIGURG: return "SIGURG";
    case SIGTRAP: return "SIGTRAP";
    case SIGXCPU: return "SIGXCPU";
    case SIGVTALRM: return "SIGVTALRM";
    case SIGXFSZ: return "SIGXFSZ";
    default: return "UNKNOWN";
  }
}

static const char* get_code_name(int signo, int code) {
  switch (code) {
    case SI_USER: return "SI_USER";
    case SI_KERNEL: return "SI_KERNEL";
    case SI_QUEUE: return "SI_QUEUE";
    case SI_TIMER: return "SI_TIMER";
    case SI_MESGQ: return "SI_MESGQ";
    case SI_ASYNCIO: return "SI_ASYNCIO";
    case SI_SIGIO: return "SI_SIGIO";
    case SI_TKILL: return "SI_TKILL";
  }

  switch (signo) {
    case SIGCHLD:
      switch (code) {
        case CLD_EXITED: return "CLD_EXITED";
        case CLD_KILLED: return "CLD_KILLED";
        case CLD_DUMPED: return "CLD_DUMPED";
        case CLD_TRAPPED: return "CLD_TRAPPED";
        case CLD_STOPPED: return "CLD_STOPPED";
        case CLD_CONTINUED: return "CLD_CONTINUED";
      }
      break;
    case SIGSEGV:
      switch (code) {
        case SEGV_MAPERR: return "SEGV_MAPERR";
        case SEGV_ACCERR: return "SEGV_ACCERR";
      }
      break;
    case SIGFPE:
      switch (code) {
        case FPE_INTDIV: return "FPE_INTDIV";
        case FPE_INTOVF: return "FPE_INTOVF";
        case FPE_FLTDIV: return "FPE_FLTDIV";
        case FPE_FLTOVF: return "FPE_FLTOVF";
        case FPE_FLTUND: return "FPE_FLTUND";
        case FPE_FLTRES: return "FPE_FLTRES";
        case FPE_FLTINV: return "FPE_FLTINV";
        case FPE_FLTSUB: return "FPE_FLTSUB";
      }
      break;
    case SIGILL:
      switch (code) {
        case ILL_ILLOPC: return "ILL_ILLOPC";
        case ILL_ILLOPN: return "ILL_ILLOPN";
        case ILL_ILLADR: return "ILL_ILLADR";
        case ILL_ILLTRP: return "ILL_ILLTRP";
        case ILL_PRVOPC: return "ILL_PRVOPC";
        case ILL_PRVREG: return "ILL_PRVREG";
        case ILL_COPROC: return "ILL_COPROC";
        case ILL_BADSTK: return "ILL_BADSTK";
      }
      break;
    case SIGBUS:
      switch (code) {
        case BUS_ADRALN: return "BUS_ADRALN";
        case BUS_ADRERR: return "BUS_ADRERR";
        case BUS_OBJERR: return "BUS_OBJERR";
      }
      break;
    case SIGTRAP:
      switch (code) {
        case TRAP_BRKPT: return "TRAP_BRKPT";
        case TRAP_TRACE: return "TRAP_TRACE";
      }
      break;
  }

  return "UNKNOWN_CODE";
}

static const char* get_status_name(int status) {
  if (WIFEXITED(status)) {
    static char buf[32];
    snprintf(buf, sizeof(buf), "%d", WEXITSTATUS(status));
    return buf;
  } else if (WIFSIGNALED(status)) {
    return get_signal_name(WTERMSIG(status));
  } else if (WIFSTOPPED(status)) {
    return get_signal_name(WSTOPSIG(status));
  }
  return "UNKNOWN_STATUS";
}

void print_siginfo(const siginfo_t *si) {
  const char * signame = get_signal_name(si->si_signo);
  LOG("--- %s {si_signo=%s, si_code=%s",
    signame,
    signame,
    get_code_name(si->si_signo, si->si_code));

  switch (si->si_signo) {
    case SIGCHLD:
      LOG(", si_pid=%d, si_uid=%d, si_status=%s",
             si->si_pid, si->si_uid, get_status_name(si->si_status));
      LOG(", si_utime=%ld, si_stime=%ld",
             si->si_utime, si->si_stime);
      break;

    case SIGSEGV:
    case SIGBUS:
    case SIGFPE:
    case SIGILL:
      LOG(", si_addr=%p", si->si_addr);
      if (si->si_pid != 0) {
          LOG(", si_pid=%d, si_uid=%d", si->si_pid, si->si_uid);
      }
      break;

    case SIGUSR1:
    case SIGUSR2:
    case SIGTERM:
    case SIGINT:
    case SIGQUIT:
      if (si->si_pid != 0) {
          LOG(", si_pid=%d, si_uid=%d", si->si_pid, si->si_uid);
      }
      if (si->si_code == SI_QUEUE) {
          LOG(", si_value=%d", si->si_value.sival_int);
      }
      break;

    default:
      if (si->si_pid != 0) {
          LOG(", si_pid=%d, si_uid=%d", si->si_pid, si->si_uid);
      }
      break;
  }

  LOG("} ---\n");
}
