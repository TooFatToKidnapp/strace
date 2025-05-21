#ifndef LOOKUP_TABLE_32_H
#define LOOKUP_TABLE_32_H

#include "./strace.h"

#define LOOKUP_TABLE_32 \
{ \
  /* long restart_syscall(void) */ \
  [0] = {"restart_syscall", {NONE}, LONG}, \
  /* void exit(int status) */ \
  [1] = {"exit", {INT}, NONE}, \
  /* int fork(void) */ \
  [2] = {"fork", {NONE}, INT}, \
  /* ssize_t read(int fd, void *buf, size_t count) */ \
  [3] = {"read", {INT, UNDEFINED_PTR, UINT}, UINT}, \
  /* ssize_t write(int fd, const void *buf, size_t count) */ \
  [4] = {"write", {INT, UNDEFINED_PTR, UINT}, UINT}, \
  /* int open(const char *pathname, int flags, mode_t mode) */ \
  [5] = {"open", {CHAR_PTR, INT, UINT}, INT}, \
  /* int close(int fd) */ \
  [6] = {"close", {INT}, INT}, \
  /* pid_t waitpid(pid_t pid, int *status, int options) */ \
  [7] = {"waitpid", {INT, INT_PTR, INT}, INT}, \
  /* int creat(const char *pathname, mode_t mode) */ \
  [8] = {"creat", {CHAR_PTR, UINT}, INT}, \
  /* int link(const char *oldpath, const char *newpath) */ \
  [9] = {"link", {CHAR_PTR, CHAR_PTR}, INT}, \
  /* int unlink(const char *pathname) */ \
  [10] = {"unlink", {CHAR_PTR}, INT}, \
  /* int execve(const char *pathname, char *const argv[], char *const envp[]) */ \
  [11] = {"execve", {CHAR_PTR, UNDEFINED_PTR, UNDEFINED_PTR}, INT}, \
  /* int chdir(const char *path) */ \
  [12] = {"chdir", {CHAR_PTR}, INT}, \
  /* time_t time(time_t *tloc) */ \
  [13] = {"time", {UNDEFINED_PTR}, LONG}, \
  /* int mknod(const char *pathname, mode_t mode, dev_t dev) */ \
  [14] = {"mknod", {CHAR_PTR, UINT, ULONG}, INT}, \
  /* int chmod(const char *pathname, mode_t mode) */ \
  [15] = {"chmod", {CHAR_PTR, UINT}, INT}, \
  /* int lchown(const char *pathname, uid_t owner, gid_t group) */ \
  [16] = {"lchown", {CHAR_PTR, UINT, UINT}, INT}, \
  /* int break(void) - obsolete */ \
  [17] = {"break", {NONE}, INT}, \
  /* int oldstat(const char *pathname, struct stat *buf) - obsolete */ \
  [18] = {"oldstat", {CHAR_PTR, STRUCT_PTR}, INT}, \
  /* off_t lseek(int fd, off_t offset, int whence) */ \
  [19] = {"lseek", {INT, LONG, INT}, LONG}, \
  /* pid_t getpid(void) */ \
  [20] = {"getpid", {NONE}, INT}, \
  /* int mount(const char *source, const char *target, const char *filesystemtype, unsigned long mountflags, const void *data) */ \
  [21] = {"mount", {CHAR_PTR, CHAR_PTR, CHAR_PTR, ULONG, UNDEFINED_PTR}, INT}, \
  /* int umount(const char *target) */ \
  [22] = {"umount", {CHAR_PTR}, INT}, \
  /* int setuid(uid_t uid) */ \
  [23] = {"setuid", {UINT}, INT}, \
  /* uid_t getuid(void) */ \
  [24] = {"getuid", {NONE}, UINT}, \
  /* int stime(time_t *t) - obsolete */ \
  [25] = {"stime", {UNDEFINED_PTR}, INT}, \
  /* long ptrace(enum __ptrace_request request, pid_t pid, void *addr, void *data) */ \
  [26] = {"ptrace", {INT, INT, UNDEFINED_PTR, UNDEFINED_PTR}, LONG}, \
  /* unsigned int alarm(unsigned int seconds) */ \
  [27] = {"alarm", {UINT}, UINT}, \
  /* int oldfstat(int fd, struct stat *buf) - obsolete */ \
  [28] = {"oldfstat", {INT, STRUCT_PTR}, INT}, \
  /* int pause(void) */ \
  [29] = {"pause", {NONE}, INT}, \
  /* int utime(const char *filename, const struct utimbuf *times) */ \
  [30] = {"utime", {CHAR_PTR, STRUCT_PTR}, INT}, \
  /* int stty(int fd, const struct sgttyb *argp) - obsolete */ \
  [31] = {"stty", {INT, STRUCT_PTR}, INT}, \
  /* int gtty(int fd, struct sgttyb *argp) - obsolete */ \
  [32] = {"gtty", {INT, STRUCT_PTR}, INT}, \
  /* int access(const char *pathname, int mode) */ \
  [33] = {"access", {CHAR_PTR, INT}, INT}, \
  /* int nice(int inc) */ \
  [34] = {"nice", {INT}, INT}, \
  /* int ftime(struct timeb *tp) - obsolete */ \
  [35] = {"ftime", {STRUCT_PTR}, INT}, \
  /* void sync(void) */ \
  [36] = {"sync", {NONE}, NONE}, \
  /* int kill(pid_t pid, int sig) */ \
  [37] = {"kill", {INT, INT}, INT}, \
  /* int rename(const char *oldpath, const char *newpath) */ \
  [38] = {"rename", {CHAR_PTR, CHAR_PTR}, INT}, \
  /* int mkdir(const char *pathname, mode_t mode) */ \
  [39] = {"mkdir", {CHAR_PTR, UINT}, INT}, \
  /* int rmdir(const char *pathname) */ \
  [40] = {"rmdir", {CHAR_PTR}, INT}, \
  /* int dup(int oldfd) */ \
  [41] = {"dup", {INT}, INT}, \
  /* int pipe(int pipefd[2]) */ \
  [42] = {"pipe", {INT_PTR}, INT}, \
  /* clock_t times(struct tms *buf) */ \
  [43] = {"times", {STRUCT_PTR}, LONG}, \
  /* int prof(void) - obsolete */ \
  [44] = {"prof", {NONE}, INT}, \
  /* int brk(void *addr) */ \
  [45] = {"brk", {UNDEFINED_PTR}, INT}, \
  /* int setgid(gid_t gid) */ \
  [46] = {"setgid", {UINT}, INT}, \
  /* gid_t getgid(void) */ \
  [47] = {"getgid", {NONE}, UINT}, \
  /* typedef void (*sighandler_t)(int); sighandler_t signal(int signum, sighandler_t handler) */ \
  [48] = {"signal", {INT, UNDEFINED_PTR}, UNDEFINED_PTR}, \
  /* uid_t geteuid(void) */ \
  [49] = {"geteuid", {NONE}, UINT}, \
  /* gid_t getegid(void) */ \
  [50] = {"getegid", {NONE}, UINT}, \
  /* int acct(const char *filename) */ \
  [51] = {"acct", {CHAR_PTR}, INT}, \
  /* int umount2(const char *target, int flags) */ \
  [52] = {"umount2", {CHAR_PTR, INT}, INT}, \
  /* int lock(void) - obsolete */ \
  [53] = {"lock", {NONE}, INT}, \
  /* int ioctl(int fd, unsigned long request, ...) */ \
  [54] = {"ioctl", {INT, ULONG, UNDEFINED_PTR}, INT}, \
  /* int fcntl(int fd, int cmd, ... ) */ \
  [55] = {"fcntl", {INT, INT, LONG}, INT}, \
  /* int mpx(void) - obsolete */ \
  [56] = {"mpx", {NONE}, INT}, \
  /* int setpgid(pid_t pid, pid_t pgid) */ \
  [57] = {"setpgid", {INT, INT}, INT}, \
  /* int ulimit(int cmd, long newlimit) - obsolete */ \
  [58] = {"ulimit", {INT, LONG}, LONG}, \
  /* int oldolduname(struct oldutsname *buf) - obsolete */ \
  [59] = {"oldolduname", {STRUCT_PTR}, INT}, \
  /* int umask(mode_t mask) */ \
  [60] = {"umask", {UINT}, UINT}, \
  /* int chroot(const char *path) */ \
  [61] = {"chroot", {CHAR_PTR}, INT}, \
  /* int ustat(dev_t dev, struct ustat *ubuf) - obsolete */ \
  [62] = {"ustat", {UINT, STRUCT_PTR}, INT}, \
  /* int dup2(int oldfd, int newfd) */ \
  [63] = {"dup2", {INT, INT}, INT}, \
  /* pid_t getppid(void) */ \
  [64] = {"getppid", {NONE}, INT}, \
  /* pid_t getpgrp(void) */ \
  [65] = {"getpgrp", {NONE}, INT}, \
  /* pid_t setsid(void) */ \
  [66] = {"setsid", {NONE}, INT}, \
  /* int sigaction(int signum, const struct sigaction *act, struct sigaction *oldact) */ \
  [67] = {"sigaction", {INT, STRUCT_PTR, STRUCT_PTR}, INT}, \
  /* int sgetmask(void) - obsolete */ \
  [68] = {"sgetmask", {NONE}, LONG}, \
  /* int ssetmask(long newmask) - obsolete */ \
  [69] = {"ssetmask", {LONG}, LONG}, \
  /* int setreuid(uid_t ruid, uid_t euid) */ \
  [70] = {"setreuid", {UINT, UINT}, INT}, \
  /* int setregid(gid_t rgid, gid_t egid) */ \
  [71] = {"setregid", {UINT, UINT}, INT}, \
  /* int sigsuspend(const sigset_t *mask) */ \
  [72] = {"sigsuspend", {STRUCT_PTR}, INT}, \
  /* int sigpending(sigset_t *set) */ \
  [73] = {"sigpending", {STRUCT_PTR}, INT}, \
  /* int sethostname(const char *name, size_t len) */ \
  [74] = {"sethostname", {CHAR_PTR, UINT}, INT}, \
  /* int setrlimit(int resource, const struct rlimit *rlim) */ \
  [75] = {"setrlimit", {INT, STRUCT_PTR}, INT}, \
  /* int getrlimit(int resource, struct rlimit *rlim) */ \
  [76] = {"getrlimit", {INT, STRUCT_PTR}, INT}, \
  /* int getrusage(int who, struct rusage *usage) */ \
  [77] = {"getrusage", {INT, STRUCT_PTR}, INT}, \
  /* int gettimeofday(struct timeval *tv, struct timezone *tz) */ \
  [78] = {"gettimeofday", {STRUCT_PTR, STRUCT_PTR}, INT}, \
  /* int settimeofday(const struct timeval *tv, const struct timezone *tz) */ \
  [79] = {"settimeofday", {STRUCT_PTR, STRUCT_PTR}, INT}, \
  /* int getgroups(int size, gid_t list[]) */ \
  [80] = {"getgroups", {INT, UNDEFINED_PTR}, INT}, \
  /* int setgroups(size_t size, const gid_t *list) */ \
  [81] = {"setgroups", {UINT, UNDEFINED_PTR}, INT}, \
  /* int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout) */ \
  [82] = {"select", {INT, STRUCT_PTR, STRUCT_PTR, STRUCT_PTR, STRUCT_PTR}, INT}, \
  /* int symlink(const char *target, const char *linkpath) */ \
  [83] = {"symlink", {CHAR_PTR, CHAR_PTR}, INT}, \
  /* int oldlstat(const char *pathname, struct stat *buf) - obsolete */ \
  [84] = {"oldlstat", {CHAR_PTR, STRUCT_PTR}, INT}, \
  /* int readlink(const char *pathname, char *buf, size_t bufsiz) */ \
  [85] = {"readlink", {CHAR_PTR, CHAR_PTR, UINT}, INT}, \
  /* int uselib(const char *library) - obsolete */ \
  [86] = {"uselib", {CHAR_PTR}, INT}, \
  /* int swapon(const char *path, int swapflags) */ \
  [87] = {"swapon", {CHAR_PTR, INT}, INT}, \
  /* int reboot(int magic, int magic2, int cmd, void *arg) */ \
  [88] = {"reboot", {INT, INT, INT, UNDEFINED_PTR}, INT}, \
  /* int readdir(unsigned int fd, struct old_linux_dirent *dirp, unsigned int count) - obsolete */ \
  [89] = {"readdir", {UINT, STRUCT_PTR, UINT}, INT}, \
  /* int mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) */ \
  [90] = {"mmap", {UNDEFINED_PTR, UINT, INT, INT, INT, LONG}, UNDEFINED_PTR}, \
  /* int munmap(void *addr, size_t length) */ \
  [91] = {"munmap", {UNDEFINED_PTR, UINT}, INT}, \
  /* int truncate(const char *path, off_t length) */ \
  [92] = {"truncate", {CHAR_PTR, LONG}, INT}, \
  /* int ftruncate(int fd, off_t length) */ \
  [93] = {"ftruncate", {INT, LONG}, INT}, \
  /* int fchmod(int fd, mode_t mode) */ \
  [94] = {"fchmod", {INT, UINT}, INT}, \
  /* int fchown(int fd, uid_t owner, gid_t group) */ \
  [95] = {"fchown", {INT, UINT, UINT}, INT}, \
  /* int getpriority(int which, id_t who) */ \
  [96] = {"getpriority", {INT, INT}, INT}, \
  /* int setpriority(int which, id_t who, int prio) */ \
  [97] = {"setpriority", {INT, INT, INT}, INT}, \
  /* int profil(unsigned short *buf, size_t bufsiz, size_t offset, unsigned int scale) - obsolete */ \
  [98] = {"profil", {UNDEFINED_PTR, UINT, UINT, UINT}, INT}, \
  /* int statfs(const char *path, struct statfs *buf) */ \
  [99] = {"statfs", {CHAR_PTR, STRUCT_PTR}, INT}, \
  /* int fstatfs(int fd, struct statfs *buf) */ \
  [100] = {"fstatfs", {INT, STRUCT_PTR}, INT}, \
  /* int ioperm(unsigned long from, unsigned long num, int turn_on) */ \
  [101] = {"ioperm", {ULONG, ULONG, INT}, INT}, \
  /* int socketcall(int call, unsigned long *args) */ \
  [102] = {"socketcall", {INT, UNDEFINED_PTR}, INT}, \
  /* int syslog(int type, char *bufp, int len) */ \
  [103] = {"syslog", {INT, CHAR_PTR, INT}, INT}, \
  /* int setitimer(int which, const struct itimerval *new_value, struct itimerval *old_value) */ \
  [104] = {"setitimer", {INT, STRUCT_PTR, STRUCT_PTR}, INT}, \
  /* int getitimer(int which, struct itimerval *curr_value) */ \
  [105] = {"getitimer", {INT, STRUCT_PTR}, INT}, \
  /* int stat(const char *pathname, struct stat *statbuf) */ \
  [106] = {"stat", {CHAR_PTR, STRUCT_PTR}, INT}, \
  /* int lstat(const char *pathname, struct stat *statbuf) */ \
  [107] = {"lstat", {CHAR_PTR, STRUCT_PTR}, INT}, \
  /* int fstat(int fd, struct stat *statbuf) */ \
  [108] = {"fstat", {INT, STRUCT_PTR}, INT}, \
  /* int olduname(struct utsname *buf) - obsolete */ \
  [109] = {"olduname", {STRUCT_PTR}, INT}, \
  /* int iopl(int level) */ \
  [110] = {"iopl", {INT}, INT}, \
  /* int vhangup(void) */ \
  [111] = {"vhangup", {NONE}, INT}, \
  /* int idle(void) - obsolete */ \
  [112] = {"idle", {NONE}, INT}, \
  /* int vm86old(struct vm86_struct *info) - obsolete */ \
  [113] = {"vm86old", {STRUCT_PTR}, INT}, \
  /* pid_t wait4(pid_t pid, int *status, int options, struct rusage *rusage) */ \
  [114] = {"wait4", {INT, INT_PTR, INT, STRUCT_PTR}, INT}, \
  /* int swapoff(const char *path) */ \
  [115] = {"swapoff", {CHAR_PTR}, INT}, \
  /* int sysinfo(struct sysinfo *info) */ \
  [116] = {"sysinfo", {STRUCT_PTR}, INT}, \
  /* int ipc(unsigned int call, int first, int second, int third, void *ptr, long fifth) */ \
  [117] = {"ipc", {UINT, INT, INT, INT, UNDEFINED_PTR, LONG}, INT}, \
  /* int fsync(int fd) */ \
  [118] = {"fsync", {INT}, INT}, \
  /* int sigreturn(unsigned long __unused) */ \
  [119] = {"sigreturn", {ULONG}, INT}, \
  /* int clone(int (*fn)(void *), void *stack, int flags, void *arg, ...) */ \
  [120] = {"clone", {UNDEFINED_PTR, UNDEFINED_PTR, INT, UNDEFINED_PTR, INT_PTR, UNDEFINED_PTR}, INT}, \
  /* int setdomainname(const char *name, size_t len) */ \
  [121] = {"setdomainname", {CHAR_PTR, UINT}, INT}, \
  /* int uname(struct utsname *buf) */ \
  [122] = {"uname", {STRUCT_PTR}, INT}, \
  /* int modify_ldt(int func, void *ptr, unsigned long bytecount) */ \
  [123] = {"modify_ldt", {INT, UNDEFINED_PTR, ULONG}, INT}, \
  /* int adjtimex(struct timex *buf) */ \
  [124] = {"adjtimex", {STRUCT_PTR}, INT}, \
  /* int mprotect(void *addr, size_t len, int prot) */ \
  [125] = {"mprotect", {UNDEFINED_PTR, UINT, INT}, INT}, \
  /* int sigprocmask(int how, const sigset_t *set, sigset_t *oldset) */ \
  [126] = {"sigprocmask", {INT, STRUCT_PTR, STRUCT_PTR}, INT}, \
  /* int create_module(const char *name, size_t size) - obsolete */ \
  [127] = {"create_module", {CHAR_PTR, UINT}, UNDEFINED_PTR}, \
  /* int init_module(void *module_image, unsigned long len, const char *param_values) */ \
  [128] = {"init_module", {UNDEFINED_PTR, ULONG, CHAR_PTR}, INT}, \
  /* int delete_module(const char *name, int flags) */ \
  [129] = {"delete_module", {CHAR_PTR, INT}, INT}, \
  /* int get_kernel_syms(struct kernel_sym *table) - obsolete */ \
  [130] = {"get_kernel_syms", {STRUCT_PTR}, INT}, \
  /* int quotactl(int cmd, const char *special, int id, void *addr) */ \
  [131] = {"quotactl", {INT, CHAR_PTR, INT, UNDEFINED_PTR}, INT}, \
  /* pid_t getpgid(pid_t pid) */ \
  [132] = {"getpgid", {INT}, INT}, \
  /* int fchdir(int fd) */ \
  [133] = {"fchdir", {INT}, INT}, \
  /* int bdflush(int func, long data) - obsolete */ \
  [134] = {"bdflush", {INT, LONG}, INT}, \
  /* int sysfs(int option, unsigned long arg1, unsigned long arg2) */ \
  [135] = {"sysfs", {INT, ULONG, ULONG}, INT}, \
  /* int personality(unsigned long persona) */ \
  [136] = {"personality", {ULONG}, INT}, \
  /* int afs_syscall(void) - Not implemented */ \
  [137] = {"afs_syscall", {NONE}, INT}, \
  /* int setfsuid(uid_t fsuid) */ \
  [138] = {"setfsuid", {UINT}, INT}, \
  /* int setfsgid(gid_t fsgid) */ \
  [139] = {"setfsgid", {UINT}, INT}, \
  /* int _llseek(unsigned int fd, unsigned long offset_high, unsigned long offset_low, loff_t *result, unsigned int whence) */ \
  [140] = {"_llseek", {UINT, ULONG, ULONG, UNDEFINED_PTR, UINT}, INT}, \
  /* int getdents(unsigned int fd, struct linux_dirent *dirp, unsigned int count) */ \
  [141] = {"getdents", {UINT, STRUCT_PTR, UINT}, INT}, \
  /* int _newselect(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout) */ \
  [142] = {"_newselect", {INT, STRUCT_PTR, STRUCT_PTR, STRUCT_PTR, STRUCT_PTR}, INT}, \
  /* int flock(int fd, int operation) */ \
  [143] = {"flock", {INT, INT}, INT}, \
  /* int msync(void *addr, size_t length, int flags) */ \
  [144] = {"msync", {UNDEFINED_PTR, UINT, INT}, INT}, \
  /* ssize_t readv(int fd, const struct iovec *iov, int iovcnt) */ \
  [145] = {"readv", {INT, STRUCT_PTR, INT}, LONG}, \
  /* ssize_t writev(int fd, const struct iovec *iov, int iovcnt) */ \
  [146] = {"writev", {INT, STRUCT_PTR, INT}, LONG}, \
  /* pid_t getsid(pid_t pid) */ \
  [147] = {"getsid", {INT}, INT}, \
  /* int fdatasync(int fd) */ \
  [148] = {"fdatasync", {INT}, INT}, \
  /* int _sysctl(struct __sysctl_args *args) */ \
  [149] = {"_sysctl", {STRUCT_PTR}, INT}, \
  /* int mlock(const void *addr, size_t len) */ \
  [150] = {"mlock", {UNDEFINED_PTR, UINT}, INT}, \
  /* int munlock(const void *addr, size_t len) */ \
  [151] = {"munlock", {UNDEFINED_PTR, UINT}, INT}, \
  /* int mlockall(int flags) */ \
  [152] = {"mlockall", {INT}, INT}, \
  /* int munlockall(void) */ \
  [153] = {"munlockall", {NONE}, INT}, \
  /* int sched_setparam(pid_t pid, const struct sched_param *param) */ \
  [154] = {"sched_setparam", {INT, STRUCT_PTR}, INT}, \
  /* int sched_getparam(pid_t pid, struct sched_param *param) */ \
  [155] = {"sched_getparam", {INT, STRUCT_PTR}, INT}, \
  /* int sched_setscheduler(pid_t pid, int policy, const struct sched_param *param) */ \
  [156] = {"sched_setscheduler", {INT, INT, STRUCT_PTR}, INT}, \
  /* int sched_getscheduler(pid_t pid) */ \
  [157] = {"sched_getscheduler", {INT}, INT}, \
  /* int sched_yield(void) */ \
  [158] = {"sched_yield", {NONE}, INT}, \
  /* int sched_get_priority_max(int policy) */ \
  [159] = {"sched_get_priority_max", {INT}, INT}, \
  /* int sched_get_priority_min(int policy) */ \
  [160] = {"sched_get_priority_min", {INT}, INT}, \
  /* int sched_rr_get_interval(pid_t pid, struct timespec *tp) */ \
  [161] = {"sched_rr_get_interval", {INT, STRUCT_PTR}, INT}, \
  /* int nanosleep(const struct timespec *req, struct timespec *rem) */ \
  [162] = {"nanosleep", {STRUCT_PTR, STRUCT_PTR}, INT}, \
  /* void *mremap(void *old_address, size_t old_size, size_t new_size, int flags, ... ) */ \
  [163] = {"mremap", {UNDEFINED_PTR, UINT, UINT, INT, UNDEFINED_PTR}, UNDEFINED_PTR}, \
  /* int setresuid(uid_t ruid, uid_t euid, uid_t suid) */ \
  [164] = {"setresuid", {UINT, UINT, UINT}, INT}, \
  /* int getresuid(uid_t *ruid, uid_t *euid, uid_t *suid) */ \
  [165] = {"getresuid", {INT_PTR, INT_PTR, INT_PTR}, INT}, \
  /* int vm86(struct vm86_struct *info) - obsolete */ \
  [166] = {"vm86", {STRUCT_PTR}, INT}, \
  /* int query_module(const char *name, int which, void *buf, size_t bufsize, size_t *ret) - obsolete */ \
  [167] = {"query_module", {CHAR_PTR, INT, UNDEFINED_PTR, UINT, UNDEFINED_PTR}, INT}, \
  /* int poll(struct pollfd *fds, nfds_t nfds, int timeout) */ \
  [168] = {"poll", {STRUCT_PTR, UINT, INT}, INT}, \
  /* int nfsservctl(int cmd, struct nfsctl_arg *argp, union nfsctl_res *resp) - obsolete */ \
  [169] = {"nfsservctl", {INT, STRUCT_PTR, UNDEFINED_PTR}, INT}, \
  /* int setresgid(gid_t rgid, gid_t egid, gid_t sgid) */ \
  [170] = {"setresgid", {UINT, UINT, UINT}, INT}, \
  /* int getresgid(gid_t *rgid, gid_t *egid, gid_t *sgid) */ \
  [171] = {"getresgid", {INT_PTR, INT_PTR, INT_PTR}, INT}, \
  /* int prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5) */ \
  [172] = {"prctl", {INT, ULONG, ULONG, ULONG, ULONG}, INT}, \
  /* int rt_sigreturn(unsigned long __unused) */ \
  [173] = {"rt_sigreturn", {ULONG}, INT}, \
  /* int rt_sigaction(int signum, const struct sigaction *act, struct sigaction *oldact, size_t sigsetsize) */ \
  [174] = {"rt_sigaction", {INT, STRUCT_PTR, STRUCT_PTR, UINT}, INT}, \
  /* int rt_sigprocmask(int how, const sigset_t *set, sigset_t *oldset, size_t sigsetsize) */ \
  [175] = {"rt_sigprocmask", {INT, STRUCT_PTR, STRUCT_PTR, UINT}, INT}, \
  /* int rt_sigpending(sigset_t *set, size_t sigsetsize) */ \
  [176] = {"rt_sigpending", {STRUCT_PTR, UINT}, INT}, \
  /* int rt_sigtimedwait(const sigset_t *set, siginfo_t *info, const struct timespec *timeout, size_t sigsetsize) */ \
  [177] = {"rt_sigtimedwait", {STRUCT_PTR, STRUCT_PTR, STRUCT_PTR, UINT}, INT}, \
  /* int rt_sigqueueinfo(pid_t tgid, int sig, siginfo_t *info) */ \
  [178] = {"rt_sigqueueinfo", {INT, INT, STRUCT_PTR}, INT}, \
  /* int rt_sigsuspend(const sigset_t *mask, size_t sigsetsize) */ \
  [179] = {"rt_sigsuspend", {STRUCT_PTR, UINT}, INT}, \
  /* ssize_t pread64(int fd, void *buf, size_t count, off_t offset) */ \
  [180] = {"pread64", {INT, UNDEFINED_PTR, UINT, LONG}, LONG}, \
  /* ssize_t pwrite64(int fd, const void *buf, size_t count, off_t offset) */ \
  [181] = {"pwrite64", {INT, UNDEFINED_PTR, UINT, LONG}, LONG}, \
  /* int chown(const char *pathname, uid_t owner, gid_t group) */ \
  [182] = {"chown", {CHAR_PTR, UINT, UINT}, INT}, \
  /* char *getcwd(char *buf, size_t size) */ \
  [183] = {"getcwd", {CHAR_PTR, UINT}, CHAR_PTR}, \
  /* int capget(cap_user_header_t header, cap_user_data_t data) */ \
  [184] = {"capget", {STRUCT_PTR, STRUCT_PTR}, INT}, \
  /* int capset(cap_user_header_t header, const cap_user_data_t data) */ \
  [185] = {"capset", {STRUCT_PTR, STRUCT_PTR}, INT}, \
  /* int sigaltstack(const stack_t *ss, stack_t *old_ss) */ \
  [186] = {"sigaltstack", {STRUCT_PTR, STRUCT_PTR}, INT}, \
  /* ssize_t sendfile(int out_fd, int in_fd, off_t *offset, size_t count) */ \
  [187] = {"sendfile", {INT, INT, INT_PTR, UINT}, LONG}, \
  /* int getpmsg(int fildes, struct strbuf *ctlptr, struct strbuf *dataptr, int *bandp, int *flagsp) - not implemented */ \
  [188] = {"getpmsg", {INT, STRUCT_PTR, STRUCT_PTR, INT_PTR, INT_PTR}, INT}, \
  /* int putpmsg(int fildes, struct strbuf *ctlptr, struct strbuf *dataptr, int band, int flags) - not implemented */ \
  [189] = {"putpmsg", {INT, STRUCT_PTR, STRUCT_PTR, INT, INT}, INT}, \
  /* pid_t vfork(void) */ \
  [190] = {"vfork", {NONE}, INT}, \
  /* int ugetrlimit(int resource, struct rlimit *rlim) - obsolete version of getrlimit */ \
  [191] = {"ugetrlimit", {INT, STRUCT_PTR}, INT}, \
  /* void *mmap2(void *addr, size_t length, int prot, int flags, int fd, off_t pgoffset) */ \
  [192] = {"mmap2", {UNDEFINED_PTR, UINT, INT, INT, INT, LONG}, UNDEFINED_PTR}, \
  /* int truncate64(const char *path, off64_t length) */ \
  [193] = {"truncate64", {CHAR_PTR, LONG_LONG}, INT}, \
  /* int ftruncate64(int fd, off64_t length) */ \
  [194] = {"ftruncate64", {INT, LONG_LONG}, INT}, \
  /* int stat64(const char *pathname, struct stat64 *statbuf) */ \
  [195] = {"stat64", {CHAR_PTR, STRUCT_PTR}, INT}, \
  /* int lstat64(const char *pathname, struct stat64 *statbuf) */ \
  [196] = {"lstat64", {CHAR_PTR, STRUCT_PTR}, INT}, \
  /* int fstat64(int fd, struct stat64 *statbuf) */ \
  [197] = {"fstat64", {INT, STRUCT_PTR}, INT}, \
  /* int lchown32(const char *pathname, uid_t owner, gid_t group) */ \
  [198] = {"lchown32", {CHAR_PTR, UINT, UINT}, INT}, \
  /* uid_t getuid32(void) */ \
  [199] = {"getuid32", {NONE}, UINT}, \
  /* gid_t getgid32(void) */ \
  [200] = {"getgid32", {NONE}, UINT}, \
  /* uid_t geteuid32(void) */ \
  [201] = {"geteuid32", {NONE}, UINT}, \
  /* gid_t getegid32(void) */ \
  [202] = {"getegid32", {NONE}, UINT}, \
  /* int setreuid32(uid_t ruid, uid_t euid) */ \
  [203] = {"setreuid32", {UINT, UINT}, INT}, \
  /* int setregid32(gid_t rgid, gid_t egid) */ \
  [204] = {"setregid32", {UINT, UINT}, INT}, \
  /* int getgroups32(int size, gid_t list[]) */ \
  [205] = {"getgroups32", {INT, UNDEFINED_PTR}, INT}, \
  /* int setgroups32(size_t size, const gid_t *list) */ \
  [206] = {"setgroups32", {UINT, UNDEFINED_PTR}, INT}, \
  /* int fchown32(int fd, uid_t owner, gid_t group) */ \
  [207] = {"fchown32", {INT, UINT, UINT}, INT}, \
  /* int setresuid32(uid_t ruid, uid_t euid, uid_t suid) */ \
  [208] = {"setresuid32", {UINT, UINT, UINT}, INT}, \
  /* int getresuid32(uid_t *ruid, uid_t *euid, uid_t *suid) */ \
  [209] = {"getresuid32", {INT_PTR, INT_PTR, INT_PTR}, INT}, \
  /* int setresgid32(gid_t rgid, gid_t egid, gid_t sgid) */ \
  [210] = {"setresgid32", {UINT, UINT, UINT}, INT}, \
  /* int getresgid32(gid_t *rgid, gid_t *egid, gid_t *sgid) */ \
  [211] = {"getresgid32", {INT_PTR, INT_PTR, INT_PTR}, INT}, \
  /* int chown32(const char *pathname, uid_t owner, gid_t group) */ \
  [212] = {"chown32", {CHAR_PTR, UINT, UINT}, INT}, \
  /* int setuid32(uid_t uid) */ \
  [213] = {"setuid32", {UINT}, INT}, \
  /* int setgid32(gid_t gid) */ \
  [214] = {"setgid32", {UINT}, INT}, \
  /* int setfsuid32(uid_t fsuid) */ \
  [215] = {"setfsuid32", {UINT}, INT}, \
  /* int setfsgid32(gid_t fsgid) */ \
  [216] = {"setfsgid32", {UINT}, INT}, \
  /* int pivot_root(const char *new_root, const char *put_old) */ \
  [217] = {"pivot_root", {CHAR_PTR, CHAR_PTR}, INT}, \
  /* int mincore(void *addr, size_t length, unsigned char *vec) */ \
  [218] = {"mincore", {UNDEFINED_PTR, UINT, CHAR_PTR}, INT}, \
  /* int madvise(void *addr, size_t length, int advice) */ \
  [219] = {"madvise", {UNDEFINED_PTR, UINT, INT}, INT}, \
  /* int getdents64(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count) */ \
  [220] = {"getdents64", {UINT, STRUCT_PTR, UINT}, INT}, \
  /* int fcntl64(int fd, int cmd, ...) */ \
  [221] = {"fcntl64", {INT, INT, LONG}, INT}, \
  /* pid_t gettid(void) */ \
  [224] = {"gettid", {NONE}, INT}, \
  /* ssize_t readahead(int fd, off64_t offset, size_t count) */ \
  [225] = {"readahead", {INT, LONG_LONG, UINT}, LONG}, \
  /* int setxattr(const char *path, const char *name, const void *value, size_t size, int flags) */ \
  [226] = {"setxattr", {CHAR_PTR, CHAR_PTR, UNDEFINED_PTR, UINT, INT}, INT}, \
  /* int lsetxattr(const char *path, const char *name, const void *value, size_t size, int flags) */ \
  [227] = {"lsetxattr", {CHAR_PTR, CHAR_PTR, UNDEFINED_PTR, UINT, INT}, INT}, \
  /* int fsetxattr(int fd, const char *name, const void *value, size_t size, int flags) */ \
  [228] = {"fsetxattr", {INT, CHAR_PTR, UNDEFINED_PTR, UINT, INT}, INT}, \
  /* ssize_t getxattr(const char *path, const char *name, void *value, size_t size) */ \
  [229] = {"getxattr", {CHAR_PTR, CHAR_PTR, UNDEFINED_PTR, UINT}, LONG}, \
  /* ssize_t lgetxattr(const char *path, const char *name, void *value, size_t size) */ \
  [230] = {"lgetxattr", {CHAR_PTR, CHAR_PTR, UNDEFINED_PTR, UINT}, LONG}, \
  /* ssize_t fgetxattr(int fd, const char *name, void *value, size_t size) */ \
  [231] = {"fgetxattr", {INT, CHAR_PTR, UNDEFINED_PTR, UINT}, LONG}, \
  /* ssize_t listxattr(const char *path, char *list, size_t size) */ \
  [232] = {"listxattr", {CHAR_PTR, CHAR_PTR, UINT}, LONG}, \
  /* ssize_t llistxattr(const char *path, char *list, size_t size) */ \
  [233] = {"llistxattr", {CHAR_PTR, CHAR_PTR, UINT}, LONG}, \
  /* ssize_t flistxattr(int fd, char *list, size_t size) */ \
  [234] = {"flistxattr", {INT, CHAR_PTR, UINT}, LONG}, \
  /* int removexattr(const char *path, const char *name) */ \
  [235] = {"removexattr", {CHAR_PTR, CHAR_PTR}, INT}, \
  /* int lremovexattr(const char *path, const char *name) */ \
  [236] = {"lremovexattr", {CHAR_PTR, CHAR_PTR}, INT}, \
  /* int fremovexattr(int fd, const char *name) */ \
  [237] = {"fremovexattr", {INT, CHAR_PTR}, INT}, \
  /* int tkill(int tid, int sig) */ \
  [238] = {"tkill", {INT, INT}, INT}, \
  /* ssize_t sendfile64(int out_fd, int in_fd, off64_t *offset, size_t count) */ \
  [239] = {"sendfile64", {INT, INT, UNDEFINED_PTR, UINT}, LONG}, \
  /* long futex(uint32_t *uaddr, int op, uint32_t val, const struct timespec *timeout, uint32_t *uaddr2, uint32_t val3) */ \
  [240] = {"futex", {UNDEFINED_PTR, INT, UINT, STRUCT_PTR, UNDEFINED_PTR, UINT}, LONG}, \
  /* int sched_setaffinity(pid_t pid, size_t cpusetsize, cpu_set_t *mask) */ \
  [241] = {"sched_setaffinity", {INT, UINT, UNDEFINED_PTR}, INT}, \
  /* int sched_getaffinity(pid_t pid, size_t cpusetsize, cpu_set_t *mask) */ \
  [242] = {"sched_getaffinity", {INT, UINT, UNDEFINED_PTR}, INT}, \
  /* int set_thread_area(struct user_desc *u_info) */ \
  [243] = {"set_thread_area", {STRUCT_PTR}, INT}, \
  /* int get_thread_area(struct user_desc *u_info) */ \
  [244] = {"get_thread_area", {STRUCT_PTR}, INT}, \
  /* int io_setup(unsigned nr_events, aio_context_t *ctx_idp) */ \
  [245] = {"io_setup", {UINT, UNDEFINED_PTR}, INT}, \
  /* int io_destroy(aio_context_t ctx_id) */ \
  [246] = {"io_destroy", {ULONG}, INT}, \
  /* int io_getevents(aio_context_t ctx_id, long min_nr, long nr, struct io_event *events, struct timespec *timeout) */ \
  [247] = {"io_getevents", {ULONG, LONG, LONG, STRUCT_PTR, STRUCT_PTR}, INT}, \
  /* int io_submit(aio_context_t ctx_id, long nr, struct iocb **iocbpp) */ \
  [248] = {"io_submit", {ULONG, LONG, STRUCT_PTR}, INT}, \
  /* int io_cancel(aio_context_t ctx_id, struct iocb *iocb, struct io_event *result) */ \
  [249] = {"io_cancel", {ULONG, STRUCT_PTR, STRUCT_PTR}, INT}, \
  /* int fadvise64(int fd, off_t offset, size_t len, int advice) */ \
  [250] = {"fadvise64", {INT, LONG, UINT, INT}, INT}, \
  /* void exit_group(int status) */ \
  [252] = {"exit_group", {INT}, NONE}, \
  /* int lookup_dcookie(u64 cookie, char *buffer, size_t len) */ \
  [253] = {"lookup_dcookie", {ULONG_LONG, CHAR_PTR, UINT}, INT}, \
  /* int epoll_create(int size) */ \
  [254] = {"epoll_create", {INT}, INT}, \
  /* int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event) */ \
  [255] = {"epoll_ctl", {INT, INT, INT, STRUCT_PTR}, INT}, \
  /* int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout) */ \
  [256] = {"epoll_wait", {INT, STRUCT_PTR, INT, INT}, INT}, \
  /* int remap_file_pages(void *addr, size_t size, int prot, size_t pgoff, int flags) */ \
  [257] = {"remap_file_pages", {UNDEFINED_PTR, UINT, INT, UINT, INT}, INT}, \
  /* int set_tid_address(int *tidptr) */ \
  [258] = {"set_tid_address", {INT_PTR}, INT}, \
  /* int timer_create(clockid_t clockid, struct sigevent *sevp, timer_t *timerid) */ \
  [259] = {"timer_create", {INT, STRUCT_PTR, UNDEFINED_PTR}, INT}, \
  /* int timer_settime(timer_t timerid, int flags, const struct itimerspec *new_value, struct itimerspec *old_value) */ \
  [260] = {"timer_settime", {INT, INT, STRUCT_PTR, STRUCT_PTR}, INT}, \
  /* int timer_gettime(timer_t timerid, struct itimerspec *curr_value) */ \
  [261] = {"timer_gettime", {INT, STRUCT_PTR}, INT}, \
  /* int timer_getoverrun(timer_t timerid) */ \
  [262] = {"timer_getoverrun", {INT}, INT}, \
  /* int timer_delete(timer_t timerid) */ \
  [263] = {"timer_delete", {INT}, INT}, \
  /* int clock_settime(clockid_t clk_id, const struct timespec *tp) */ \
  [264] = {"clock_settime", {INT, STRUCT_PTR}, INT}, \
  /* int clock_gettime(clockid_t clk_id, struct timespec *tp) */ \
  [265] = {"clock_gettime", {INT, STRUCT_PTR}, INT}, \
  /* int clock_getres(clockid_t clk_id, struct timespec *res) */ \
  [266] = {"clock_getres", {INT, STRUCT_PTR}, INT}, \
  /* int clock_nanosleep(clockid_t clockid, int flags, const struct timespec *request, struct timespec *remain) */ \
  [267] = {"clock_nanosleep", {INT, INT, STRUCT_PTR, STRUCT_PTR}, INT}, \
  /* int statfs64(const char *path, size_t sz, struct statfs64 *buf) */ \
  [268] = {"statfs64", {CHAR_PTR, UINT, STRUCT_PTR}, INT}, \
  /* int fstatfs64(int fd, size_t sz, struct statfs64 *buf) */ \
  [269] = {"fstatfs64", {INT, UINT, STRUCT_PTR}, INT}, \
  /* int tgkill(int tgid, int tid, int sig) */ \
  [270] = {"tgkill", {INT, INT, INT}, INT}, \
  /* int utimes(const char *filename, const struct timeval times[2]) */ \
  [271] = {"utimes", {CHAR_PTR, STRUCT_PTR}, INT}, \
  /* int fadvise64_64(int fd, off64_t offset, off64_t len, int advice) */ \
  [272] = {"fadvise64_64", {INT, LONG_LONG, LONG_LONG, INT}, INT}, \
  /* int vserver(int cmd, void *arg) - not implemented */ \
  [273] = {"vserver", {INT, UNDEFINED_PTR}, INT}, \
  /* int mbind(void *addr, unsigned long len, int mode, const unsigned long *nodemask, unsigned long maxnode, unsigned flags) */ \
  [274] = {"mbind", {UNDEFINED_PTR, ULONG, INT, UNDEFINED_PTR, ULONG, UINT}, INT}, \
  /* int get_mempolicy(int *mode, unsigned long *nodemask, unsigned long maxnode, void *addr, unsigned long flags) */ \
  [275] = {"get_mempolicy", {INT_PTR, UNDEFINED_PTR, ULONG, UNDEFINED_PTR, ULONG}, INT}, \
  /* int set_mempolicy(int mode, const unsigned long *nodemask, unsigned long maxnode) */ \
  [276] = {"set_mempolicy", {INT, UNDEFINED_PTR, ULONG}, INT}, \
  /* mqd_t mq_open(const char *name, int oflag, mode_t mode, struct mq_attr *attr) */ \
  [277] = {"mq_open", {CHAR_PTR, INT, UINT, STRUCT_PTR}, INT}, \
  /* int mq_unlink(const char *name) */ \
  [278] = {"mq_unlink", {CHAR_PTR}, INT}, \
  /* int mq_timedsend(mqd_t mqdes, const char *msg_ptr, size_t msg_len, unsigned int msg_prio, const struct timespec *abs_timeout) */ \
  [279] = {"mq_timedsend", {INT, CHAR_PTR, UINT, UINT, STRUCT_PTR}, INT}, \
  /* ssize_t mq_timedreceive(mqd_t mqdes, char *msg_ptr, size_t msg_len, unsigned int *msg_prio, const struct timespec *abs_timeout) */ \
  [280] = {"mq_timedreceive", {INT, CHAR_PTR, UINT, UINT_PTR, STRUCT_PTR}, LONG}, \
  /* int mq_notify(mqd_t mqdes, const struct sigevent *sevp) */ \
  [281] = {"mq_notify", {INT, STRUCT_PTR}, INT}, \
  /* int mq_getsetattr(mqd_t mqdes, const struct mq_attr *newattr, struct mq_attr *oldattr) */ \
  [282] = {"mq_getsetattr", {INT, STRUCT_PTR, STRUCT_PTR}, INT}, \
  /* int kexec_load(unsigned long entry, unsigned long nr_segments, struct kexec_segment *segments, unsigned long flags) */ \
  [283] = {"kexec_load", {ULONG, ULONG, STRUCT_PTR, ULONG}, INT}, \
  /* int waitid(idtype_t idtype, id_t id, siginfo_t *infop, int options) */ \
  [284] = {"waitid", {INT, INT, STRUCT_PTR, INT}, INT}, \
  /* long add_key(const char *type, const char *description, const void *payload, size_t plen, key_serial_t ringid) */ \
  [286] = {"add_key", {CHAR_PTR, CHAR_PTR, UNDEFINED_PTR, UINT, INT}, LONG}, \
  /* key_serial_t request_key(const char *type, const char *description, const char *callout_info, key_serial_t dest_keyring) */ \
  [287] = {"request_key", {CHAR_PTR, CHAR_PTR, CHAR_PTR, INT}, LONG}, \
  /* long keyctl(int operation, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5) */ \
  [288] = {"keyctl", {INT, ULONG, ULONG, ULONG, ULONG}, LONG}, \
  /* int ioprio_set(int which, int who, int ioprio) */ \
  [289] = {"ioprio_set", {INT, INT, INT}, INT}, \
  /* int ioprio_get(int which, int who) */ \
  [290] = {"ioprio_get", {INT, INT}, INT}, \
  /* int inotify_init(void) */ \
  [291] = {"inotify_init", {NONE}, INT}, \
  /* int inotify_add_watch(int fd, const char *pathname, uint32_t mask) */ \
  [292] = {"inotify_add_watch", {INT, CHAR_PTR, UINT}, INT}, \
  /* int inotify_rm_watch(int fd, int wd) */ \
  [293] = {"inotify_rm_watch", {INT, INT}, INT}, \
  /* int migrate_pages(int pid, unsigned long maxnode, const unsigned long *old_nodes, const unsigned long *new_nodes) */ \
  [294] = {"migrate_pages", {INT, ULONG, UNDEFINED_PTR, UNDEFINED_PTR}, INT}, \
  /* int openat(int dirfd, const char *pathname, int flags, mode_t mode) */ \
  [295] = {"openat", {INT, CHAR_PTR, INT, UINT}, INT}, \
  /* int mkdirat(int dirfd, const char *pathname, mode_t mode) */ \
  [296] = {"mkdirat", {INT, CHAR_PTR, UINT}, INT}, \
  /* int mknodat(int dirfd, const char *pathname, mode_t mode, dev_t dev) */ \
  [297] = {"mknodat", {INT, CHAR_PTR, UINT, ULONG}, INT}, \
  /* int fchownat(int dirfd, const char *pathname, uid_t owner, gid_t group, int flags) */ \
  [298] = {"fchownat", {INT, CHAR_PTR, UINT, UINT, INT}, INT}, \
  /* int futimesat(int dirfd, const char *pathname, const struct timeval times[2]) */ \
  [299] = {"futimesat", {INT, CHAR_PTR, STRUCT_PTR}, INT}, \
  /* int fstatat64(int dirfd, const char *pathname, struct stat64 *statbuf, int flags) */ \
  [300] = {"fstatat64", {INT, CHAR_PTR, STRUCT_PTR, INT}, INT}, \
  /* int unlinkat(int dirfd, const char *pathname, int flags) */ \
  [301] = {"unlinkat", {INT, CHAR_PTR, INT}, INT}, \
  /* int renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath) */ \
  [302] = {"renameat", {INT, CHAR_PTR, INT, CHAR_PTR}, INT}, \
  /* int linkat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, int flags) */ \
  [303] = {"linkat", {INT, CHAR_PTR, INT, CHAR_PTR, INT}, INT}, \
  /* int symlinkat(const char *oldpath, int newdirfd, const char *newpath) */ \
  [304] = {"symlinkat", {CHAR_PTR, INT, CHAR_PTR}, INT}, \
  /* ssize_t readlinkat(int dirfd, const char *pathname, char *buf, size_t bufsiz) */ \
  [305] = {"readlinkat", {INT, CHAR_PTR, CHAR_PTR, UINT}, LONG}, \
  /* int fchmodat(int dirfd, const char *pathname, mode_t mode, int flags) */ \
  [306] = {"fchmodat", {INT, CHAR_PTR, UINT, INT}, INT}, \
  /* int faccessat(int dirfd, const char *pathname, int mode, int flags) */ \
  [307] = {"faccessat", {INT, CHAR_PTR, INT, INT}, INT}, \
  /* int pselect6(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, const struct timespec *timeout, const sigset_t *sigmask) */ \
  [308] = {"pselect6", {INT, STRUCT_PTR, STRUCT_PTR, STRUCT_PTR, STRUCT_PTR, STRUCT_PTR}, INT}, \
  /* int ppoll(struct pollfd *fds, unsigned int nfds, const struct timespec *tmo_p, const sigset_t *sigmask) */ \
  [309] = {"ppoll", {STRUCT_PTR, UINT, STRUCT_PTR, STRUCT_PTR}, INT}, \
  /* int unshare(int flags) */ \
  [310] = {"unshare", {INT}, INT}, \
  /* int set_robust_list(struct robust_list_head *head, size_t len) */ \
  [311] = {"set_robust_list", {STRUCT_PTR, UINT}, INT}, \
  /* int get_robust_list(int pid, struct robust_list_head **head_ptr, size_t *len_ptr) */ \
  [312] = {"get_robust_list", {INT, STRUCT_PTR, UNDEFINED_PTR}, INT}, \
  /* ssize_t splice(int fd_in, loff_t *off_in, int fd_out, loff_t *off_out, size_t len, unsigned int flags) */ \
  [313] = {"splice", {INT, UNDEFINED_PTR, INT, UNDEFINED_PTR, UINT, UINT}, LONG}, \
  /* int sync_file_range(int fd, off64_t offset, off64_t nbytes, unsigned int flags) */ \
  [314] = {"sync_file_range", {INT, LONG_LONG, LONG_LONG, UINT}, INT}, \
  /* ssize_t tee(int fd_in, int fd_out, size_t len, unsigned int flags) */ \
  [315] = {"tee", {INT, INT, UINT, UINT}, LONG}, \
  /* ssize_t vmsplice(int fd, const struct iovec *iov, unsigned long nr_segs, unsigned int flags) */ \
  [316] = {"vmsplice", {INT, STRUCT_PTR, ULONG, UINT}, LONG}, \
  /* int move_pages(int pid, unsigned long count, void **pages, const int *nodes, int *status, int flags) */ \
  [317] = {"move_pages", {INT, ULONG, UNDEFINED_PTR, INT_PTR, INT_PTR, INT}, INT}, \
  /* int getcpu(unsigned *cpu, unsigned *node, struct getcpu_cache *tcache) */ \
  [318] = {"getcpu", {UINT_PTR, UINT_PTR, STRUCT_PTR}, INT}, \
  /* int epoll_pwait(int epfd, struct epoll_event *events, int maxevents, int timeout, const sigset_t *sigmask) */ \
  [319] = {"epoll_pwait", {INT, STRUCT_PTR, INT, INT, STRUCT_PTR}, INT}, \
  /* int utimensat(int dirfd, const char *pathname, const struct timespec times[2], int flags) */ \
  [320] = {"utimensat", {INT, CHAR_PTR, STRUCT_PTR, INT}, INT}, \
  /* int signalfd(int fd, const sigset_t *mask, int flags) */ \
  [321] = {"signalfd", {INT, STRUCT_PTR, INT}, INT}, \
  /* int timerfd_create(int clockid, int flags) */ \
  [322] = {"timerfd_create", {INT, INT}, INT}, \
  /* int eventfd(unsigned int initval, int flags) */ \
  [323] = {"eventfd", {UINT, INT}, INT}, \
  /* int fallocate(int fd, int mode, off_t offset, off_t len) */ \
  [324] = { "fallocate", { INT, INT, LONG, LONG }, INT }, \
  /* int timerfd_settime(int fd, int flags, const struct itimerspec *new_value, struct itimerspec *old_value) */ \
  [325] = { "timerfd_settime", { INT, INT, STRUCT_PTR, STRUCT_PTR }, INT }, \
  /* int timerfd_gettime(int fd, struct itimerspec *curr_value) */ \
  [326] = { "timerfd_gettime", { INT, STRUCT_PTR }, INT }, \
  /* int signalfd4(int fd, const sigset_t *mask, size_t sizemask, int flags) */ \
  [327] = { "signalfd4", { INT, STRUCT_PTR, UINT, INT }, INT }, \
  /* int eventfd2(unsigned int initval, int flags) */ \
  [328] = { "eventfd2", { UINT, INT }, INT }, \
  /* int epoll_create1(int flags) */ \
  [329] = { "epoll_create1", { INT }, INT }, \
  /* int dup3(int oldfd, int newfd, int flags) */ \
  [330] = { "dup3", { INT, INT, INT }, INT }, \
  /* int pipe2(int pipefd[2], int flags) */ \
  [331] = { "pipe2", { INT_PTR, INT }, INT }, \
  /* int inotify_init1(int flags) */ \
  [332] = { "inotify_init1", { INT }, INT }, \
  /* ssize_t preadv(int fd, const struct iovec *iov, int iovcnt, off_t offset) */ \
  [333] = { "preadv", { INT, STRUCT_PTR, INT, LONG }, LONG }, \
  /* ssize_t pwritev(int fd, const struct iovec *iov, int iovcnt, off_t offset) */ \
  [334] = { "pwritev", { INT, STRUCT_PTR, INT, LONG }, LONG }, \
  /* int rt_tgsigqueueinfo(pid_t tgid, pid_t tid, int sig, siginfo_t *info) */ \
  [335] = { "rt_tgsigqueueinfo", { INT, INT, INT, STRUCT_PTR }, INT }, \
  /* int perf_event_open(struct perf_event_attr *attr, pid_t pid, int cpu, int group_fd, unsigned long flags) */ \
  [336] = { "perf_event_open", { STRUCT_PTR, INT, INT, INT, ULONG }, INT }, \
  /* int recvmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen, int flags, struct timespec *timeout) */ \
  [337] = { "recvmmsg", { INT, STRUCT_PTR, UINT, INT, STRUCT_PTR }, INT }, \
  /* int fanotify_init(unsigned int flags, unsigned int event_f_flags) */ \
  [338] = { "fanotify_init", { UINT, UINT }, INT }, \
  /* int fanotify_mark(int fanotify_fd, unsigned int flags, uint64_t mask, int dirfd, const char *pathname) */ \
  [339] = { "fanotify_mark", { INT, UINT, ULONG_LONG, INT, CHAR_PTR }, INT }, \
  /* int prlimit64(pid_t pid, int resource, const struct rlimit64 *new_limit, struct rlimit64 *old_limit) */ \
  [340] = { "prlimit64", { INT, INT, STRUCT_PTR, STRUCT_PTR }, INT }, \
  /* int name_to_handle_at(int dirfd, const char *pathname, struct file_handle *handle, int *mount_id, int flags) */ \
  [341] = { "name_to_handle_at", { INT, CHAR_PTR, STRUCT_PTR, INT_PTR, INT }, INT }, \
  /* int open_by_handle_at(int mountdirfd, struct file_handle *handle, int flags) */ \
  [342] = { "open_by_handle_at", { INT, STRUCT_PTR, INT }, INT }, \
  /* int clock_adjtime(clockid_t clk_id, struct timex *tx) */ \
  [343] = { "clock_adjtime", { INT, STRUCT_PTR }, INT }, \
  /* int syncfs(int fd) */ \
  [344] = { "syncfs", { INT }, INT }, \
  /* int sendmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen, int flags) */ \
  [345] = { "sendmmsg", { INT, STRUCT_PTR, UINT, INT }, INT }, \
  /* int setns(int fd, int nstype) */ \
  [346] = { "setns", { INT, INT }, INT }, \
  /* ssize_t process_vm_readv(pid_t pid, const struct iovec *local_iov, unsigned long liovcnt, const struct iovec *remote_iov, unsigned long riovcnt, unsigned long flags) */ \
  [347] = { "process_vm_readv", { INT, STRUCT_PTR, ULONG, STRUCT_PTR, ULONG, ULONG }, LONG }, \
  /* ssize_t process_vm_writev(pid_t pid, const struct iovec *local_iov, unsigned long liovcnt, const struct iovec *remote_iov, unsigned long riovcnt, unsigned long flags) */ \
  [348] = { "process_vm_writev", { INT, STRUCT_PTR, ULONG, STRUCT_PTR, ULONG, ULONG }, LONG }, \
  /* int kcmp(pid_t pid1, pid_t pid2, int type, unsigned long idx1, unsigned long idx2) */ \
  [349] = { "kcmp", { INT, INT, INT, ULONG, ULONG }, INT }, \
  /* int finit_module(int fd, const char *param_values, int flags) */ \
  [350] = { "finit_module", { INT, CHAR_PTR, INT }, INT }, \
  /* int sched_setattr(pid_t pid, struct sched_attr *attr, unsigned int flags) */ \
  [351] = { "sched_setattr", { INT, STRUCT_PTR, UINT }, INT }, \
  /* int sched_getattr(pid_t pid, struct sched_attr *attr, unsigned int size, unsigned int flags) */ \
  [352] = { "sched_getattr", { INT, STRUCT_PTR, UINT, UINT }, INT }, \
  /* int renameat2(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, unsigned int flags) */ \
  [353] = { "renameat2", { INT, CHAR_PTR, INT, CHAR_PTR, UINT }, INT }, \
  /* int seccomp(unsigned int operation, unsigned int flags, void *args) */ \
  [354] = { "seccomp", { UINT, UINT, UNDEFINED_PTR }, INT }, \
  /* ssize_t getrandom(void *buf, size_t buflen, unsigned int flags) */ \
  [355] = { "getrandom", { UNDEFINED_PTR, UINT, UINT }, LONG }, \
  /* int memfd_create(const char *name, unsigned int flags) */ \
  [356] = { "memfd_create", { CHAR_PTR, UINT }, INT }, \
  /* int bpf(int cmd, union bpf_attr *attr, unsigned int size) */ \
  [357] = { "bpf", { INT, STRUCT_PTR, UINT }, INT }, \
  /* int execveat(int dirfd, const char *pathname, char *const argv[], char *const envp[], int flags) */ \
  [358] = { "execveat", { INT, CHAR_PTR, CHAR_PTR, CHAR_PTR, INT }, INT }, \
  /* int socket(int domain, int type, int protocol) */ \
  [359] = { "socket", { INT, INT, INT }, INT }, \
  /* int socketpair(int domain, int type, int protocol, int sv[2]) */ \
  [360] = { "socketpair", { INT, INT, INT, INT_PTR }, INT }, \
  /* int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) */ \
  [361] = { "bind", { INT, STRUCT_PTR, INT }, INT }, \
  /* int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) */ \
  [362] = { "connect", { INT, STRUCT_PTR, INT }, INT }, \
  /* int listen(int sockfd, int backlog) */ \
  [363] = { "listen", { INT, INT }, INT }, \
  /* int accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags) */ \
  [364] = { "accept4", { INT, STRUCT_PTR, INT_PTR, INT }, INT }, \
  /* int getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen) */ \
  [365] = { "getsockopt", { INT, INT, INT, UNDEFINED_PTR, INT_PTR }, INT }, \
  /* int setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen) */ \
  [366] = { "setsockopt", { INT, INT, INT, UNDEFINED_PTR, INT }, INT }, \
  /* int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen) */ \
  [367] = { "getsockname", { INT, STRUCT_PTR, INT_PTR }, INT }, \
  /* int getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen) */ \
  [368] = { "getpeername", { INT, STRUCT_PTR, INT_PTR }, INT }, \
  /* ssize_t sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen) */ \
  [369] = { "sendto", { INT, UNDEFINED_PTR, UINT, INT, STRUCT_PTR, INT }, LONG }, \
  /* ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags) */ \
  [370] = { "sendmsg", { INT, STRUCT_PTR, INT }, LONG }, \
  /* ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen) */ \
  [371] = { "recvfrom", { INT, UNDEFINED_PTR, UINT, INT, STRUCT_PTR, INT_PTR }, LONG }, \
  /* ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags) */ \
  [372] = { "recvmsg", { INT, STRUCT_PTR, INT }, LONG }, \
  /* int shutdown(int sockfd, int how) */ \
  [373] = { "shutdown", { INT, INT }, INT }, \
  /* int userfaultfd(int flags) */ \
  [374] = { "userfaultfd", { INT }, INT }, \
  /* int membarrier(int cmd, int flags) */ \
  [375] = { "membarrier", { INT, INT }, INT }, \
  /* int mlock2(const void *addr, size_t len, int flags) */ \
  [376] = { "mlock2", { UNDEFINED_PTR, UINT, INT }, INT }, \
  /* ssize_t copy_file_range(int fd_in, loff_t *off_in, int fd_out, loff_t *off_out, size_t len, unsigned int flags) */ \
  [377] = { "copy_file_range", { INT, LONG_LONG, INT, LONG_LONG, UINT, UINT }, LONG }, \
  /* ssize_t preadv2(int fd, const struct iovec *iov, int iovcnt, off_t offset, int flags) */ \
  [378] = { "preadv2", { INT, STRUCT_PTR, INT, LONG, INT }, LONG }, \
  /* ssize_t pwritev2(int fd, const struct iovec *iov, int iovcnt, off_t offset, int flags) */ \
  [379] = { "pwritev2", { INT, STRUCT_PTR, INT, LONG, INT }, LONG }, \
  /* int pkey_mprotect(void *addr, size_t len, int prot, int pkey) */ \
  [380] = { "pkey_mprotect", { UNDEFINED_PTR, UINT, INT, INT }, INT }, \
  /* int pkey_alloc(unsigned int flags, unsigned int access_rights) */ \
  [381] = { "pkey_alloc", { UINT, UINT }, INT }, \
  /* int pkey_free(int pkey) */ \
  [382] = { "pkey_free", { INT }, INT }, \
  /* int statx(int dirfd, const char *pathname, int flags, unsigned int mask, struct statx *statxbuf) */ \
  [383] = { "statx", { INT, CHAR_PTR, INT, UINT, STRUCT_PTR }, INT }, \
  /* int arch_prctl(int option, unsigned long arg2) */ \
  [384] = { "arch_prctl", { INT, ULONG }, INT }, \
  /* int io_pgetevents(aio_context_t ctx_id, long min_nr, long nr, struct io_event *events, struct timespec *timeout, const struct __aio_sigset *usig) */ \
  [385] = { "io_pgetevents", { ULONG, LONG, LONG, STRUCT_PTR, STRUCT_PTR, STRUCT_PTR }, INT }, \
  /* int rseq(struct rseq *rseq, uint32_t rseq_len, int flags, uint32_t sig) */ \
  [386] = { "rseq", { STRUCT_PTR, UINT, INT, UINT }, INT }, \
  /* int semget(key_t key, int nsems, int semflg) */ \
  [393] = { "semget", { INT, INT, INT }, INT }, \
  /* int semctl(int semid, int semnum, int cmd, ...) */ \
  [394] = { "semctl", { INT, INT, INT, UNDEFINED_PTR }, INT }, \
  /* int shmget(key_t key, size_t size, int shmflg) */ \
  [395] = { "shmget", { INT, UINT, INT }, INT }, \
  /* int shmctl(int shmid, int cmd, struct shmid_ds *buf) */ \
  [396] = { "shmctl", { INT, INT, STRUCT_PTR }, INT }, \
  /* void *shmat(int shmid, const void *shmaddr, int shmflg) */ \
  [397] = { "shmat", { INT, UNDEFINED_PTR, INT }, UNDEFINED_PTR }, \
  /* int shmdt(const void *shmaddr) */ \
  [398] = { "shmdt", { UNDEFINED_PTR }, INT }, \
  /* int msgget(key_t key, int msgflg) */ \
  [399] = { "msgget", { INT, INT }, INT }, \
  /* int msgsnd(int msqid, const void *msgp, size_t msgsz, int msgflg) */ \
  [400] = { "msgsnd", { INT, UNDEFINED_PTR, UINT, INT }, INT }, \
  /* ssize_t msgrcv(int msqid, void *msgp, size_t msgsz, long msgtyp, int msgflg) */ \
  [401] = { "msgrcv", { INT, UNDEFINED_PTR, UINT, LONG, INT }, LONG }, \
  /* int msgctl(int msqid, int cmd, struct msqid_ds *buf) */ \
  [402] = { "msgctl", { INT, INT, STRUCT_PTR }, INT }, \
  /* int clock_gettime64(clockid_t clockid, struct __kernel_timespec *tp) */ \
  [403] = { "clock_gettime64", { INT, STRUCT_PTR }, INT }, \
  /* int clock_settime64(clockid_t clockid, const struct __kernel_timespec *tp) */ \
  [404] = { "clock_settime64", { INT, STRUCT_PTR }, INT }, \
  /* int clock_adjtime64(clockid_t clockid, struct __kernel_timex *tx) */ \
  [405] = { "clock_adjtime64", { INT, STRUCT_PTR }, INT }, \
  /* int clock_getres_time64(clockid_t clockid, struct __kernel_timespec *res) */ \
  [406] = { "clock_getres_time64", { INT, STRUCT_PTR }, INT }, \
  /* int clock_nanosleep_time64(clockid_t clockid, int flags, const struct __kernel_timespec *rqtp, struct __kernel_timespec *rmtp) */ \
  [407] = { "clock_nanosleep_time64", { INT, INT, STRUCT_PTR, STRUCT_PTR }, INT }, \
  /* int timer_gettime64(timer_t timer_id, struct __kernel_itimerspec *curr_value) */ \
  [408] = { "timer_gettime64", { INT, STRUCT_PTR }, INT }, \
  /* int timer_settime64(timer_t timer_id, int flags, const struct __kernel_itimerspec *new_value, struct __kernel_itimerspec *old_value) */ \
  [409] = { "timer_settime64", { INT, INT, STRUCT_PTR, STRUCT_PTR }, INT }, \
  /* int timerfd_gettime64(int fd, struct __kernel_itimerspec *curr_value) */ \
  [410] = { "timerfd_gettime64", { INT, STRUCT_PTR }, INT }, \
  /* int timerfd_settime64(int fd, int flags, const struct __kernel_itimerspec *new_value, struct __kernel_itimerspec *old_value) */ \
  [411] = { "timerfd_settime64", { INT, INT, STRUCT_PTR, STRUCT_PTR }, INT }, \
  /* int utimensat_time64(int dirfd, const char *pathname, struct __kernel_timespec times[2], int flags) */ \
  [412] = { "utimensat_time64", { INT, CHAR_PTR, STRUCT_PTR, INT }, INT }, \
  /* int pselect6_time64(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct __kernel_timespec *timeout, const sigset_t *sigmask) */ \
  [413] = { "pselect6_time64", { INT, STRUCT_PTR, STRUCT_PTR, STRUCT_PTR, STRUCT_PTR, STRUCT_PTR }, INT }, \
  /* int ppoll_time64(struct pollfd *fds, unsigned int nfds, struct __kernel_timespec *tmo_p, const sigset_t *sigmask, size_t sigsetsize) */ \
  [414] = { "ppoll_time64", { STRUCT_PTR, UINT, STRUCT_PTR, STRUCT_PTR, UINT }, INT }, \
  /* int io_pgetevents_time64(aio_context_t ctx_id, long min_nr, long nr, struct io_event *events, struct __kernel_timespec *timeout, const struct __aio_sigset *usig) */ \
  [416] = { "io_pgetevents_time64", { ULONG, LONG, LONG, STRUCT_PTR, STRUCT_PTR, STRUCT_PTR }, INT }, \
  /* int recvmmsg_time64(int sockfd, struct mmsghdr *msgvec, unsigned int vlen, int flags, struct __kernel_timespec *timeout) */ \
  [417] = { "recvmmsg_time64", { INT, STRUCT_PTR, UINT, INT, STRUCT_PTR }, INT }, \
  /* int mq_timedsend_time64(mqd_t mqdes, const char *msg_ptr, size_t msg_len, unsigned int msg_prio, const struct __kernel_timespec *abs_timeout) */ \
  [418] = { "mq_timedsend_time64", { INT, CHAR_PTR, UINT, UINT, STRUCT_PTR }, INT }, \
  /* ssize_t mq_timedreceive_time64(mqd_t mqdes, char *msg_ptr, size_t msg_len, unsigned int *msg_prio, const struct __kernel_timespec *abs_timeout) */ \
  [419] = { "mq_timedreceive_time64", { INT, CHAR_PTR, UINT, UINT_PTR, STRUCT_PTR }, LONG }, \
  /* int semtimedop_time64(int semid, struct sembuf *sops, size_t nsops, const struct __kernel_timespec *timeout) */ \
  [420] = { "semtimedop_time64", { INT, STRUCT_PTR, UINT, STRUCT_PTR }, INT }, \
  /* int rt_sigtimedwait_time64(const sigset_t *set, siginfo_t *info, const struct __kernel_timespec *timeout, size_t sigsetsize) */ \
  [421] = { "rt_sigtimedwait_time64", { STRUCT_PTR, STRUCT_PTR, STRUCT_PTR, UINT }, INT }, \
  /* int futex_time64(u32 *uaddr, int op, u32 val, struct __kernel_timespec *utime, u32 *uaddr2, u32 val3) */ \
  [422] = { "futex_time64", { INT_PTR, INT, UINT, STRUCT_PTR, INT_PTR, UINT }, INT }, \
  /* int sched_rr_get_interval_time64(pid_t pid, struct __kernel_timespec *tp) */ \
  [423] = { "sched_rr_get_interval_time64", { INT, STRUCT_PTR }, INT }, \
  /* int pidfd_send_signal(int pidfd, int sig, siginfo_t *info, unsigned int flags); */ \
  [424] = {"pidfd_send_signal", {INT, INT, STRUCT_PTR, UINT}, INT}, \
  /* int io_uring_setup(unsigned int entries, struct io_uring_params *params); */ \
  [425] = {"io_uring_setup", {UINT, STRUCT_PTR}, INT}, \
  /* int io_uring_enter(unsigned int fd, unsigned int to_submit, unsigned int min_complete, unsigned int flags, sigset_t *sig, size_t sigsz); */ \
  [426] = {"io_uring_enter", {UINT, UINT, UINT, UINT, STRUCT_PTR, UINT}, INT}, \
  /* int io_uring_register(unsigned int fd, unsigned int opcode, void *arg, unsigned int nr_args); */ \
  [427] = {"io_uring_register", {UINT, UINT, UNDEFINED_PTR, UINT}, INT}, \
  /* int open_tree(int dfd, const char *filename, unsigned int flags); */ \
  [428] = {"open_tree", {INT, CHAR_PTR, UINT}, INT}, \
  /* int move_mount(int from_dfd, const char *from_path, int to_dfd, const char *to_path, unsigned int flags); */ \
  [429] = {"move_mount", {INT, CHAR_PTR, INT, CHAR_PTR, UINT}, INT}, \
  /* int fsopen(const char *fs_name, unsigned int flags); */ \
  [430] = {"fsopen", {CHAR_PTR, UINT}, INT}, \
  /* int fsconfig(int fs_fd, unsigned int cmd, const char *key, const void *value, int aux); */ \
  [431] = {"fsconfig", {INT, UINT, CHAR_PTR, UNDEFINED_PTR, INT}, INT}, \
  /* int fsmount(int fs_fd, unsigned int flags, unsigned int ms_flags); */ \
  [432] = {"fsmount", {INT, UINT, UINT}, INT}, \
  /* int fspick(int dfd, const char *path, unsigned int flags); */ \
  [433] = {"fspick", {INT, CHAR_PTR, UINT}, INT}, \
  /* int pidfd_open(pid_t pid, unsigned int flags); */ \
  [434] = {"pidfd_open", {INT, UINT}, INT}, \
  /* int clone3(struct clone_args *cl_args, size_t size); */ \
  [435] = {"clone3", {STRUCT_PTR, UINT}, LONG}, \
  /* int close_range(unsigned int first, unsigned int last, unsigned int flags); */ \
  [436] = {"close_range", {UINT, UINT, UINT}, INT}, \
  /* int openat2(int dirfd, const char *pathname, struct open_how *how, size_t size); */ \
  [437] = {"openat2", {INT, CHAR_PTR, STRUCT_PTR, UINT}, LONG}, \
  /* int pidfd_getfd(int pidfd, int targetfd, unsigned int flags); */ \
  [438] = {"pidfd_getfd", {INT, INT, UINT}, INT}, \
  /* int faccessat2(int dirfd, const char *pathname, int mode, int flags); */ \
  [439] = {"faccessat2", {INT, CHAR_PTR, INT, INT}, INT}, \
  /* ssize_t process_madvise(int pidfd, const struct iovec *iovec, size_t vlen, int advice, unsigned int flags); */ \
  [440] = {"process_madvise", {INT, STRUCT_PTR, UINT, INT, UINT}, INT}, \
  /* int epoll_pwait2(int epfd, struct epoll_event *events, int maxevents, const struct timespec *timeout, const sigset_t *sigmask); */ \
  [441] = {"epoll_pwait2", {INT, STRUCT_PTR, INT, STRUCT_PTR, STRUCT_PTR}, INT}, \
  /* int mount_setattr(int dirfd, const char *path, unsigned int flags, struct mount_attr *attr, size_t size); */ \
  [442] = {"mount_setattr", {INT, CHAR_PTR, UINT, STRUCT_PTR, UINT}, INT}, \
  /* int quotactl_fd(unsigned int fd, unsigned int cmd, qid_t id, void *addr); */ \
  [443] = {"quotactl_fd", {UINT, UINT, INT, UNDEFINED_PTR}, INT}, \
  /* int landlock_create_ruleset(const struct landlock_ruleset_attr *attr, size_t size, __u32 flags); */ \
  [444] = {"landlock_create_ruleset", {STRUCT_PTR, UINT, UINT}, INT}, \
  /* int landlock_add_rule(int ruleset_fd, enum landlock_rule_type rule_type, const void *rule_attr, __u32 flags); */ \
  [445] = {"landlock_add_rule", {INT, INT, UNDEFINED_PTR, UINT}, INT}, \
  /* int landlock_restrict_self(int ruleset_fd, __u32 flags); */ \
  [446] = {"landlock_restrict_self", {INT, UINT}, INT}, \
  /* int memfd_secret(unsigned int flags); */ \
  [447] = {"memfd_secret", {UINT}, INT}, \
  /* int process_mrelease(int pidfd, unsigned int flags); */ \
  [448] = {"process_mrelease", {INT, UINT}, INT}, \
  /* int futex_waitv(struct futex_waitv *waiters, unsigned int nr_futexes, unsigned int flags, struct timespec *timeout, clockid_t clockid); */ \
  [449] = {"futex_waitv", {STRUCT_PTR, UINT, UINT, STRUCT_PTR, INT}, INT}, \
  /* int set_mempolicy_home_node(unsigned long start, unsigned long len, unsigned long home_node, unsigned long flags); */ \
  [450] = {"set_mempolicy_home_node", {ULONG, ULONG, ULONG, ULONG}, INT} \
}

#endif
