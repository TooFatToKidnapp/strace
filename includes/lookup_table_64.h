#ifndef LOOKUP_TABLE_64_H
#define LOOKUP_TABLE_64_H

#include "./strace.h"

#define LOOKUP_TABLE_64  \
{ \
  /* ssize_t read(int fd, void *buf, size_t count) */ \
  [0] = {"read", {INT, UNDEFINED_PTR, UINT}, UINT}, \
  /* ssize_t write(int fd, const void *buf, size_t count) */ \
  [1] = {"write", {INT, UNDEFINED_PTR, UINT}, UINT}, \
  /* int open(const char *pathname, int flags, mode_t mode) */ \
  [2] = {"open", {CHAR_PTR, INT}, INT}, \
  /* int close(int fd) */ \
  [3] = {"close", {INT}, INT}, \
  /* int stat(const char *path, struct stat *statbuf) */ \
  [4] = {"stat", {CHAR_PTR, STRUCT_PTR}, INT}, \
  /* int fstat(int fd, struct stat *statbuf) */ \
  [5] = {"fstat", {INT, STRUCT_PTR}, INT}, \
  /* int lstat(const char *path, struct stat *statbuf) */ \
  [6] = {"lstat", {CHAR_PTR, STRUCT_PTR}, INT}, \
  /* int poll(struct pollfd *fds, nfds_t nfds, int timeout) */ \
  [7] = {"poll", {STRUCT_PTR, ULONG, INT}, INT}, \
  /* off_t lseek(int fd, off_t offset, int whence) */ \
  [8] = {"lseek", {INT, LONG, INT}, LONG}, \
  /* void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) */ \
  [9] = {"mmap", {UNDEFINED_PTR, UINT, INT, INT, INT, LONG}, UNDEFINED_PTR}, \
  /*  int mprotect(void *addr, size_t len, int prot) */ \
  [10] = {"mprotect", {UNDEFINED_PTR, UINT, INT}, INT}, \
  /*  int munmap(void *addr, size_t length) */ \
  [11] = {"munmap", {UNDEFINED_PTR, UINT}, INT}, \
  /*  int brk(void *addr) */ \
  [12] = {"brk", {UNDEFINED_PTR}, INT}, \
  /*  int rt_sigaction(int signum, const struct sigaction *act, struct sigaction *oldact) */ \
  [13] = {"rt_sigaction", {INT, STRUCT_PTR, STRUCT_PTR}, INT}, \
  /*  int rt_sigprocmask(int how, const sigset_t *set, sigset_t *oldset) */ \
  [14] = {"rt_sigprocmask", {INT, STRUCT_PTR, STRUCT_PTR}, INT}, \
  /*  int rt_sigreturn(void) */ \
  [15] = {"rt_sigreturn", {ULONG}, INT}, \
  /*  int ioctl(int fd, unsigned long request, void *arg) */ \
  [16] = {"ioctl", {INT, ULONG, UNDEFINED_PTR}, INT}, \
  /*  ssize_t pread64(int fd, void *buf, size_t count, off_t offset) */ \
  [17] = {"pread64", {INT, UNDEFINED_PTR, UINT, LONG}, UINT}, \
  /*  ssize_t pwrite64(int fd, const void *buf, size_t count, off_t offset) */ \
  [18] = {"pwrite64", {INT, UNDEFINED_PTR, UINT, LONG}, UINT}, \
  /*  ssize_t readv(int fd, const struct iovec *iov, int iovcnt) */ \
  [19] = {"readv", {INT, STRUCT_PTR, INT}, UINT}, \
  /*  ssize_t writev(int fd, const struct iovec *iov, int iovcnt) */ \
  [20] = {"writev", {INT, STRUCT_PTR, INT}, UINT}, \
  /*  int access(const char *pathname, int mode) */ \
  [21] = {"access", {CHAR_PTR, INT}, INT}, \
  /*  int pipe(int pipefd[2]) */ \
  [22] = {"pipe", {INT_PTR}, INT}, \
  /*  int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout) */ \
  [23] = {"select", {INT, STRUCT_PTR, STRUCT_PTR, STRUCT_PTR, STRUCT_PTR}, INT}, \
  /*  int sched_yield(void) */ \
  [24] = {"sched_yield", {NONE}, INT}, \
  /*  void *mremap(void *old_address, size_t old_size, size_t new_size, int flags, void *new_address) */ \
  [25] = {"mremap", {UNDEFINED_PTR, UINT, UINT, INT, UNDEFINED_PTR}, UNDEFINED_PTR}, \
  /*  int msync(void *addr, size_t length, int flags) */ \
  [26] = {"msync", {UNDEFINED_PTR, UINT, INT}, INT}, \
  /*  int mincore(void *addr, size_t length, unsigned char *vec) */ \
  [27] = {"mincore", {UNDEFINED_PTR, UINT, CHAR_PTR}, INT}, \
  /*  int madvise(void *addr, size_t length, int advice) */ \
  [28] = {"madvise", {UNDEFINED_PTR, UINT, INT}, INT}, \
  /*  int shmget(key_t key, size_t size, int shmflg) */ \
  [29] = {"shmget", {INT, UINT, INT}, INT}, \
  /*  void *shmat(int shmid, const void *shmaddr, int shmflg) */ \
  [30] = {"shmat", {INT, UNDEFINED_PTR, INT}, UNDEFINED_PTR}, \
  /*  int shmctl(int shmid, int cmd, struct shmid_ds *buf) */ \
  [31] = {"shmctl", {INT, INT, STRUCT_PTR}, INT}, \
  /*  int dup(int oldfd) */ \
  [32] = {"dup", {INT}, INT}, \
  /*  int dup2(int oldfd, int newfd) */ \
  [33] = {"dup2", {INT, INT}, INT}, \
  /*  int pause(void) */ \
  [34] = {"pause", {NONE}, INT}, \
  /*  int nanosleep(const struct timespec *req, struct timespec *rem) */ \
  [35] = {"nanosleep", {STRUCT_PTR, STRUCT_PTR}, INT}, \
  /*  int getitimer(int which, struct itimerval *curr_value) */ \
  [36] = {"getitimer", {INT, STRUCT_PTR}, INT}, \
  /*  unsigned int alarm(unsigned int seconds) */ \
  [37] = {"alarm", {UINT}, UINT}, \
  /*  int setitimer(int which, const struct itimerval *new_val, struct itimerval *old_val) */ \
  [38] = {"setitimer", {INT, STRUCT_PTR, STRUCT_PTR}, INT}, \
  /*  pid_t getpid(void) */ \
  [39] = {"getpid", {NONE}, INT}, \
  /*  ssize_t sendfile(int out_fd, int in_fd, off_t *offset, size_t count) */ \
  [40] = {"sendfile", {INT, INT, INT_PTR}, UINT}, \
  /*  int socket(int domain, int type, int protocol) */ \
  [41] = {"socket", {INT, INT, INT}, INT}, \
  /*  int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) */ \
  [42] = {"connect", {INT, STRUCT_PTR, UINT}, INT}, \
  /*  int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) */ \
  [43] = {"accept", {INT, STRUCT_PTR, INT_PTR}, INT}, \
  /*  ssize_t sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen) */ \
  [44] = {"sendto", {INT, UNDEFINED_PTR, UINT, INT, STRUCT_PTR, UINT}, UINT}, \
  /* ssize_t recvfrom(int sockfd, void buf[restrict .len], size_t len,int flags,struct sockaddr *_Nullable restrict src_addr,socklen_t *_Nullable restrict addrlen); */ \
  [45] = {"recvfrom", {INT, UNDEFINED_PTR, UINT, INT, STRUCT_PTR, INT_PTR}, UINT}, \
  /*  ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags); */ \
  [46] = {"sendmsg", {INT, STRUCT_PTR, INT}, INT}, \
  /*  ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags); */ \
  [47] = {"recvmsg", {INT, STRUCT_PTR, INT}, INT}, \
  /*  int shutdown(int sockfd, int how); */ \
  [48] = {"shutdown", {INT, INT}, INT}, \
  /*  int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen); */ \
  [49] = {"bind", {INT, STRUCT_PTR, UINT}, INT}, \
  /*  int listen(int sockfd, int backlog); */ \
  [50] = {"listen", {INT, INT}, INT}, \
  /*  int getsockname(int sockfd, struct sockaddr *restrict addr, socklen_t *restrict addrlen); */ \
  [51] = {"getsockname", {INT, STRUCT_PTR, INT_PTR}, INT}, \
  /*  int getpeername(int sockfd, struct sockaddr *restrict addr, socklen_t *restrict addrlen); */ \
  [52] = {"getpeername", {INT, STRUCT_PTR, INT_PTR}, INT}, \
  /*  int socketpair(int domain, int type, int protocol, int sv[2]); */  \
  [53] = {"socketpair", {INT, INT, INT, INT_PTR}, INT}, \
  /*  int setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen); */ \
  [54] = {"setsockopt", {INT, INT, INT, UNDEFINED_PTR, UINT}, INT}, \
  /*  int getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen); */ \
  [55] = {"getsockopt", {INT, INT, INT, UNDEFINED_PTR, INT_PTR}, INT}, \
  /*  int clone(int (*fn)(void *), void *stack, int flags, void *arg, ...); */ \
  [56] = {"clone", {UNDEFINED_PTR, UNDEFINED_PTR, INT, UNDEFINED_PTR}, INT}, \
  /*  pid_t fork(void); */ \
  [57] = {"fork", {NONE}, INT}, \
  /*  pid_t vfork(void); */ \
  [58] = {"vfork", {NONE}, INT}, \
  /*  int execve(const char *pathname, char *const argv[], char *const envp[]); */  \
  [59] = {"execve", {CHAR_PTR, UNDEFINED_PTR, UNDEFINED_PTR}, INT}, \
  /*  void _exit(int status); */ \
  [60] = {"exit", {INT}, NONE}, \
  /*  pid_t wait4(pid_t pid, int *wstatus, int options, struct rusage *rusage); */ \
  [61] = {"wait4", {INT, INT_PTR, INT, STRUCT_PTR}, INT}, \
  /*  int kill(pid_t pid, int sig); */ \
  [62] = {"kill", {INT, INT}, INT}, \
  /*  int uname(struct utsname *buf); */ \
  [63] = {"uname", {STRUCT_PTR}, INT}, \
  /*  int semget(key_t key, int nsems, int semflg); */ \
  [64] = {"semget", {INT, INT, INT}, INT}, \
  /*  int semop(int semid, struct sembuf *sops, size_t nsops); */ \
  [65] = {"semop", {INT, STRUCT_PTR, UINT}, INT}, \
  /*  int semctl(int semid, int semnum, int cmd, ...); */ \
  [66] = {"semctl", {INT, INT, INT}, INT}, \
  /*  int shmdt(const void *shmaddr); */ \
  [67] = {"shmdt", {UNDEFINED_PTR}, INT}, \
  /*  int msgget(key_t key, int msgflg); */ \
  [68] = {"msgget", {INT, INT}, INT}, \
  /*  int msgsnd(int msqid, const void *msgp, size_t msgsz, int msgflg); */ \
  [69] = {"msgsnd", {INT, UNDEFINED_PTR, UINT, INT}, INT}, \
  /*  ssize_t msgrcv(int msqid, void *msgp, size_t msgsz, long msgtyp, int msgflg); */ \
  [70] = {"msgrcv", {INT, UNDEFINED_PTR, UINT, LONG, INT}, INT}, \
  /*  int msgctl(int msqid, int cmd, struct msqid_ds *buf); */ \
  [71] = {"msgctl", {INT, INT, STRUCT_PTR}, INT}, \
  /*  int fcntl(int fd, int cmd, ...); */ \
  [72] = {"fcntl", {INT, INT, UNDEFINED_PTR}, INT}, \
  /*  int flock(int fd, int operation); */ \
  [73] = {"flock", {INT, INT}, INT}, \
  /*  int fsync(int fd); */ \
  [74] = {"fsync", {INT}, INT}, \
  /*  int fdatasync(int fd); */ \
  [75] = {"fdatasync", {INT}, INT}, \
  /*  int truncate(const char *path, off_t length); */ \
  [76] = {"truncate", {CHAR_PTR, LONG}, INT}, \
  /*  int ftruncate(int fd, off_t length); */ \
  [77] = {"ftruncate", {INT, LONG}, INT}, \
  /*  int getdents(unsigned int fd, struct linux_dirent *dirp, unsigned int count); */ \
  [78] = {"getdents", {UINT, STRUCT_PTR, UINT}, INT}, \
  /*  char *getcwd(char *buf, size_t size); */ \
  [79] = {"getcwd", {CHAR_PTR, UINT}, CHAR_PTR}, \
  /*  int chdir(const char *path); */ \
  [80] = {"chdir", {CHAR_PTR}, INT}, \
  /*  int fchdir(int fd); */ \
  [81] = {"fchdir", {INT}, INT}, \
  /*  int rename(const char *oldpath, const char *newpath); */ \
  [82] = {"rename", {CHAR_PTR, CHAR_PTR}, INT}, \
  /*  int mkdir(const char *pathname, mode_t mode); */ \
  [83] = {"mkdir", {CHAR_PTR, UINT}, INT}, \
  /*  int rmdir(const char *pathname); */ \
  [84] = {"rmdir", {CHAR_PTR}, INT}, \
  /*  int creat(const char *pathname, mode_t mode); */ \
  [85] = {"creat", {CHAR_PTR, UINT}, INT}, \
  /*  int link(const char *oldpath, const char *newpath); */ \
  [86] = {"link", {CHAR_PTR, CHAR_PTR}, INT}, \
  /*  int unlink(const char *pathname); */ \
  [87] = {"unlink", {CHAR_PTR}, INT}, \
  /*  int symlink(const char *target, const char *linkpath); */ \
  [88] = {"symlink", {CHAR_PTR, CHAR_PTR}, INT}, \
  /*  ssize_t readlink(const char *pathname, char *buf, size_t bufsiz); */ \
  [89] = {"readlink", {CHAR_PTR, CHAR_PTR, UINT}, INT}, \
  /*  int chmod(const char *pathname, mode_t mode); */ \
  [90] = {"chmod", {CHAR_PTR, UINT}, INT}, \
  /*  int fchmod(int fd, mode_t mode); */ \
  [91] = {"fchmod", {INT, UINT}, INT}, \
  /*  int chown(const char *pathname, uid_t owner, gid_t group); */ \
  [92] = {"chown", {CHAR_PTR, UINT, UINT}, INT}, \
  /*  int fchown(int fd, uid_t owner, gid_t group); */ \
  [93] = {"fchown", {INT, UINT, UINT}, INT}, \
  /*  int lchown(const char *pathname, uid_t owner, gid_t group); */ \
  [94] = {"lchown", {CHAR_PTR, UINT, UINT}, INT}, \
  /*  mode_t umask(mode_t mask); */ \
  [95] = {"umask", {UINT}, UINT}, \
  /*  int gettimeofday(struct timeval *tv, struct timezone *tz); */ \
  [96] = {"gettimeofday", {STRUCT_PTR, STRUCT_PTR}, INT}, \
  /*  int getrlimit(int resource, struct rlimit *rlim); */ \
  [97] = {"getrlimit", {INT, STRUCT_PTR}, INT}, \
  /*  int getrusage(int who, struct rusage *usage); */ \
  [98] = {"getrusage", {INT, STRUCT_PTR}, INT}, \
  /*  int sysinfo(struct sysinfo *info); */ \
  [99] = {"sysinfo", {STRUCT_PTR}, INT}, \
  /*  clock_t times(struct tms *buf); */ \
  [100] = {"times", {STRUCT_PTR}, LONG}, \
  /*  long ptrace(enum __ptrace_request request, pid_t pid, void *addr, void *data); */ \
  [101] = {"ptrace", {INT, INT, UNDEFINED_PTR, UNDEFINED_PTR}, LONG}, \
  /*  uid_t getuid(void); */ \
  [102] = {"getuid", {NONE}, UINT}, \
  /*  int syslog(int type, char *bufp, int len); */ \
  [103] = {"syslog", {INT, CHAR_PTR, INT}, INT}, \
  /*  gid_t getgid(void); */ \
  [104] = {"getgid", {NONE}, UINT}, \
  /*  int setuid(uid_t uid); */ \
  [105] = {"setuid", {UINT}, INT}, \
  /*  int setgid(gid_t gid); */ \
  [106] = {"setgid", {UINT}, INT}, \
  /*  uid_t geteuid(void); */ \
  [107] = {"geteuid", {NONE}, UINT}, \
  /*  gid_t getegid(void); */ \
  [108] = {"getegid", {NONE}, UINT}, \
  /*  int setpgid(pid_t pid, pid_t pgid); */ \
  [109] = {"setpgid", {INT, INT}, INT}, \
  /*  pid_t getppid(void); */ \
  [110] = {"getppid", {NONE}, INT}, \
  /*  pid_t getpgrp(void); */ \
  [111] = {"getpgrp", {NONE}, INT}, \
  /*  pid_t setsid(void); */ \
  [112] = {"setsid", {NONE}, INT}, \
  /*  int setreuid(uid_t ruid, uid_t euid); */ \
  [113] = {"setreuid", {UINT, UINT}, INT}, \
  /*  int setregid(gid_t rgid, gid_t egid); */ \
  [114] = {"setregid", {UINT, UINT}, INT}, \
  /*  int getgroups(int size, gid_t list[]); */  \
  [115] = {"getgroups", {INT, UNDEFINED_PTR}, INT}, \
  /*  int setgroups(size_t size, const gid_t *list); */ \
  [116] = {"setgroups", {UINT, UNDEFINED_PTR}, INT}, \
  /*  int setresuid(uid_t ruid, uid_t euid, uid_t suid); */ \
  [117] = {"setresuid", {UINT, UINT, UINT}, INT}, \
  /*  int getresuid(uid_t *ruid, uid_t *euid, uid_t *suid); */ \
  [118] = {"getresuid", {UNDEFINED_PTR, UNDEFINED_PTR, UNDEFINED_PTR}, INT}, \
  /*  int setresgid(gid_t rgid, gid_t egid, gid_t sgid); */ \
  [119] = {"setresgid", {UINT, UINT, UINT}, INT}, \
  /*  int getresgid(gid_t *rgid, gid_t *egid, gid_t *sgid); */ \
  [120] = {"getresgid", {UNDEFINED_PTR, UNDEFINED_PTR, UNDEFINED_PTR}, INT}, \
  /*  pid_t getpgid(pid_t pid); */ \
  [121] = {"getpgid", {INT}, INT}, \
  /*  int setfsuid(uid_t fsuid); */ \
  [122] = {"setfsuid", {UINT}, INT}, \
  /*  int setfsgid(gid_t fsgid); */ \
  [123] = {"setfsgid", {UINT}, INT}, \
  /*  pid_t getsid(pid_t pid); */ \
  [124] = {"getsid", {INT}, INT}, \
  /*  int capget(cap_user_header_t hdrp, cap_user_data_t datap); */ \
  [125] = {"capget", {STRUCT_PTR, STRUCT_PTR}, INT}, \
  /*  int capset(cap_user_header_t hdrp, const cap_user_data_t datap); */ \
  [126] = {"capset", {STRUCT_PTR, STRUCT_PTR}, INT}, \
  /*  int rt_sigpending(sigset_t *set, size_t sigsetsize); */ \
  [127] = {"rt_sigpending", {STRUCT_PTR, UINT}, INT}, \
  /*  int rt_sigtimedwait(const sigset_t *set, siginfo_t *info, const struct timespec *timeout, size_t sigsetsize); */ \
  [128] = {"rt_sigtimedwait", {STRUCT_PTR, STRUCT_PTR, STRUCT_PTR, UINT}, INT}, \
  /*  int rt_sigqueueinfo(pid_t tgid, int sig, siginfo_t *uinfo); */ \
  [129] = {"rt_sigqueueinfo", {INT, INT, STRUCT_PTR}, INT}, \
  /*  int rt_sigsuspend(const sigset_t *mask, size_t sigsetsize); */ \
  [130] = {"rt_sigsuspend", {STRUCT_PTR, UINT}, INT}, \
  /*  int sigaltstack(const stack_t *ss, stack_t *oss); */ \
  [131] = {"sigaltstack", {STRUCT_PTR, STRUCT_PTR}, INT}, \
  /*  int utime(const char *filename, const struct utimbuf *times); */ \
  [132] = {"utime", {CHAR_PTR, STRUCT_PTR}, INT}, \
  /*  int mknod(const char *pathname, mode_t mode, dev_t dev); */ \
  [133] = {"mknod", {CHAR_PTR, UINT, ULONG}, INT}, \
  /*  int uselib(const char *library); */ \
  [134] = {"uselib", {CHAR_PTR}, INT}, \
  /*  int personality(unsigned long persona); */ \
  [135] = {"personality", {ULONG}, INT}, \
  /*  int ustat(dev_t dev, struct ustat *ubuf); */ \
  [136] = {"ustat", {ULONG, STRUCT_PTR}, INT}, \
  /*  int statfs(const char *path, struct statfs *buf); */ \
  [137] = {"statfs", {CHAR_PTR, STRUCT_PTR}, INT}, \
  /*  int fstatfs(int fd, struct statfs *buf); */ \
  [138] = {"fstatfs", {INT, STRUCT_PTR}, INT}, \
  /*  int sysfs(int option, const char *fsname); */ \
  [139] = {"sysfs", {INT, CHAR_PTR}, INT}, \
  /*  int getpriority(int which, id_t who); */ \
  [140] = {"getpriority", {INT, INT}, INT}, \
  /*  int setpriority(int which, id_t who, int prio); */ \
  [141] = {"setpriority", {INT, INT, INT}, INT}, \
  /*  int sched_setparam(pid_t pid, const struct sched_param *param); */ \
  [142] = {"sched_setparam", {INT, STRUCT_PTR}, INT}, \
  /*  int sched_getparam(pid_t pid, struct sched_param *param); */ \
  [143] = {"sched_getparam", {INT, STRUCT_PTR}, INT}, \
  /*  int sched_setscheduler(pid_t pid, int policy, const struct sched_param *param); */ \
  [144] = {"sched_setscheduler", {INT, INT, STRUCT_PTR}, INT}, \
  /*  int sched_getscheduler(pid_t pid); */ \
  [145] = {"sched_getscheduler", {INT}, INT}, \
  /*  int sched_get_priority_max(int policy); */ \
  [146] = {"sched_get_priority_max", {INT}, INT}, \
  /*  int sched_get_priority_min(int policy); */ \
  [147] = {"sched_get_priority_min", {INT}, INT}, \
  /*  int sched_rr_get_interval(pid_t pid, struct timespec *tp); */ \
  [148] = {"sched_rr_get_interval", {INT, STRUCT_PTR}, INT}, \
  /*  int mlock(const void *addr, size_t len); */ \
  [149] = {"mlock", {UNDEFINED_PTR, UINT}, INT}, \
  /*  int munlock(const void *addr, size_t len); */ \
  [150] = {"munlock", {UNDEFINED_PTR, UINT}, INT}, \
  /*  int mlockall(int flags); */ \
  [151] = {"mlockall", {INT}, INT}, \
  /*  int munlockall(void); */ \
  [152] = {"munlockall", {NONE}, INT}, \
  /*  int vhangup(void); */ \
  [153] = {"vhangup", {NONE}, INT}, \
  /*  int modify_ldt(int func, void *ptr, unsigned long bytecount); */ \
  [154] = {"modify_ldt", {INT, UNDEFINED_PTR, ULONG}, INT}, \
  /*  int pivot_root(const char *new_root, const char *put_old); */ \
  [155] = {"pivot_root", {CHAR_PTR, CHAR_PTR}, INT}, \
  /*  int _sysctl(struct __sysctl_args *args); */ \
  [156] = {"_sysctl", {STRUCT_PTR}, INT}, \
  /*  int prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5); */ \
  [157] = {"prctl", {INT, ULONG, ULONG, ULONG, ULONG}, INT}, \
  /*  int arch_prctl(int code, unsigned long addr); */ \
  [158] = {"arch_prctl", {INT, ULONG}, INT}, \
  /*  int adjtimex(struct timex *buf); */ \
  [159] = {"adjtimex", {STRUCT_PTR}, INT}, \
  /*  int setrlimit(int resource, const struct rlimit *rlim); */ \
  [160] = {"setrlimit", {INT, STRUCT_PTR}, INT}, \
  /*  int chroot(const char *path); */ \
  [161] = {"chroot", {CHAR_PTR}, INT}, \
  /*  void sync(void); */ \
  [162] = {"sync", {NONE}, NONE}, \
  /*  int acct(const char *filename); */ \
  [163] = {"acct", {CHAR_PTR}, INT}, \
  /*  int settimeofday(const struct timeval *tv, const struct timezone *tz); */ \
  [164] = {"settimeofday", {STRUCT_PTR, STRUCT_PTR}, INT}, \
  /*  int mount(const char *source, const char *target, const char *filesystemtype, unsigned long mountflags, const void *data); */ \
  [165] = {"mount", {CHAR_PTR, CHAR_PTR, CHAR_PTR, ULONG, UNDEFINED_PTR}, INT}, \
  /*  int umount2(const char *target, int flags); */ \
  [166] = {"umount2", {CHAR_PTR, INT}, INT}, \
  /*  int swapon(const char *path, int swapflags); */ \
  [167] = {"swapon", {CHAR_PTR, INT}, INT}, \
  /*  int swapoff(const char *path); */ \
  [168] = {"swapoff", {CHAR_PTR}, INT}, \
  /*  int reboot(int magic, int magic2, int cmd, void *arg); */ \
  [169] = {"reboot", {INT, INT, INT, UNDEFINED_PTR}, INT}, \
  /*  int sethostname(const char *name, size_t len); */ \
  [170] = {"sethostname", {CHAR_PTR, UINT}, INT}, \
  /*  int setdomainname(const char *name, size_t len); */ \
  [171] = {"setdomainname", {CHAR_PTR, UINT}, INT}, \
  /*  int iopl(int level); */ \
  [172] = {"iopl", {INT}, INT}, \
  /*  int ioperm(unsigned long from, unsigned long num, int turn_on); */ \
  [173] = {"ioperm", {ULONG, ULONG, INT}, INT}, \
  /*  caddr_t create_module(const char *name, size_t size); */ \
  [174] = {"create_module", {CHAR_PTR, UINT}, UNDEFINED_PTR}, \
  /*  int init_module(void *module_image, unsigned long len, const char *param_values); */ \
  [175] = {"init_module", {UNDEFINED_PTR, ULONG, CHAR_PTR}, INT}, \
  /*  int delete_module(const char *name, unsigned int flags); */ \
  [176] = {"delete_module", {CHAR_PTR, UINT}, INT}, \
  /*  int get_kernel_syms(struct kernel_sym *table); */ \
  [177] = {"get_kernel_syms", {STRUCT_PTR}, INT}, \
  /*  int query_module(const char *name, int which, void *buf, size_t bufsize, size_t *retsize); */ \
  [178] = {"query_module", {CHAR_PTR, INT, UNDEFINED_PTR, UINT, UNDEFINED_PTR}, INT}, \
  /*  int quotactl(int cmd, const char *special, int id, caddr_t addr); */ \
  [179] = {"quotactl", {INT, CHAR_PTR, INT, UNDEFINED_PTR}, INT}, \
  /*  int nfsservctl(int cmd, struct nfsctl_arg *argp, union nfsctl_res *resp); */ \
  [180] = {"nfsservctl", {INT, STRUCT_PTR, STRUCT_PTR}, LONG}, \
  /*  int getpmsg(int fildes, struct strbuf *ctlptr, struct strbuf *dataptr, int *bandp, int *flagsp); */ \
  [181] = {"getpmsg", {INT, STRUCT_PTR, STRUCT_PTR, INT_PTR, INT_PTR}, INT}, \
  /*  int putpmsg(int fildes, const struct strbuf *ctlptr, const struct strbuf *dataptr, int band, int flags); */ \
  [182] = {"putpmsg", {INT, STRUCT_PTR, STRUCT_PTR, INT, INT}, INT}, \
  /*  int afs_syscall(void); */ \
  [183] = {"afs_syscall", {NONE}, INT}, \
  /*  int tuxcall(void); */ \
  [184] = {"tuxcall", {NONE}, INT}, \
  /*  int security(void); */ \
  [185] = {"security", {NONE}, INT}, \
  /*  pid_t gettid(void); */ \
  [186] = {"gettid", {NONE}, INT}, \
  /*  ssize_t readahead(int fd, off64_t offset, size_t count); */ \
  [187] = {"readahead", {INT, LONG_LONG, UINT}, INT}, \
  /*  int setxattr(const char *path, const char *name, const void *value, size_t size, int flags); */ \
  [188] = {"setxattr", {CHAR_PTR, CHAR_PTR, UNDEFINED_PTR, UINT, INT}, INT}, \
  /*  int lsetxattr(const char *path, const char *name, const void *value, size_t size, int flags); */ \
  [189] = {"lsetxattr", {CHAR_PTR, CHAR_PTR, UNDEFINED_PTR, UINT, INT}, INT}, \
  /*  int fsetxattr(int fd, const char *name, const void *value, size_t size, int flags); */ \
  [190] = {"fsetxattr", {INT, CHAR_PTR, UNDEFINED_PTR, UINT, INT}, INT}, \
  /*  ssize_t getxattr(const char *path, const char *name, void *value, size_t size); */ \
  [191] = {"getxattr", {CHAR_PTR, CHAR_PTR, UNDEFINED_PTR, UINT}, INT}, \
  /*  ssize_t lgetxattr(const char *path, const char *name, void *value, size_t size); */ \
  [192] = {"lgetxattr", {CHAR_PTR, CHAR_PTR, UNDEFINED_PTR, UINT}, INT}, \
  /*  ssize_t fgetxattr(int fd, const char *name, void *value, size_t size); */ \
  [193] = {"fgetxattr", {INT, CHAR_PTR, UNDEFINED_PTR, UINT}, INT}, \
  /*  ssize_t listxattr(const char *path, char *list, size_t size); */ \
  [194] = {"listxattr", {CHAR_PTR, CHAR_PTR, UINT}, INT}, \
  /*  ssize_t llistxattr(const char *path, char *list, size_t size); */ \
  [195] = {"llistxattr", {CHAR_PTR, CHAR_PTR, UINT}, INT}, \
  /*  ssize_t flistxattr(int fd, char *list, size_t size); */ \
  [196] = {"flistxattr", {INT, CHAR_PTR, UINT}, INT}, \
  /*  int removexattr(const char *path, const char *name); */ \
  [197] = {"removexattr", {CHAR_PTR, CHAR_PTR}, INT}, \
  /*  int lremovexattr(const char *path, const char *name); */ \
  [198] = {"lremovexattr", {CHAR_PTR, CHAR_PTR}, INT}, \
  /*  int fremovexattr(int fd, const char *name); */ \
  [199] = {"fremovexattr", {INT, CHAR_PTR}, INT}, \
  /*  int tkill(pid_t tid, int sig); */ \
  [200] = {"tkill", {INT, INT}, INT}, \
  /*  time_t time(time_t *tloc); */ \
  [201] = {"time", {UNDEFINED_PTR}, LONG}, \
  /*  long futex(uint32_t *uaddr, int futex_op, uint32_t val, const struct timespec *timeout, uint32_t *uaddr2, uint32_t val3); */ \
  [202] = {"futex", {UNDEFINED_PTR, INT, UINT, STRUCT_PTR, UNDEFINED_PTR, UINT}, LONG}, \
  /*  int sched_setaffinity(pid_t pid, size_t cpusetsize, const cpu_set_t *mask); */ \
  [203] = {"sched_setaffinity", {INT, UINT, UNDEFINED_PTR}, INT}, \
  /*  int sched_getaffinity(pid_t pid, size_t cpusetsize, cpu_set_t *mask); */ \
  [204] = {"sched_getaffinity", {INT, UINT, UNDEFINED_PTR}, INT}, \
  /*  int set_thread_area(struct user_desc *u_info); */ \
  [205] = {"set_thread_area", {STRUCT_PTR}, INT}, \
  /*  int io_setup(unsigned nr_events, aio_context_t *ctx_idp); */ \
  [206] = {"io_setup", {UINT, UNDEFINED_PTR}, LONG}, \
  /*  int io_destroy(aio_context_t ctx_id); */ \
  [207] = {"io_destroy", {ULONG}, INT}, \
  /*  int io_getevents(aio_context_t ctx_id, long min_nr, long nr, struct io_event *events, struct timespec *timeout); */ \
  [208] = {"io_getevents", {ULONG, LONG, LONG, STRUCT_PTR, STRUCT_PTR}, INT}, \
  /*  int io_submit(aio_context_t ctx_id, long nr, struct iocb **iocbpp); */ \
  [209] = {"io_submit", {ULONG, LONG, UNDEFINED_PTR}, INT}, \
  /*  int io_cancel(aio_context_t ctx_id, struct iocb *iocb, struct io_event *result); */ \
  [210] = {"io_cancel", {ULONG, STRUCT_PTR, STRUCT_PTR}, INT}, \
  /*  int get_thread_area(struct user_desc *u_info); */ \
  [211] = {"get_thread_area", {STRUCT_PTR}, INT}, \
  /*  int lookup_dcookie(u64 cookie, char *buffer, size_t len); */ \
  [212] = {"lookup_dcookie", {ULONG_LONG, CHAR_PTR, UINT}, INT}, \
  /*  int epoll_create(int size); */ \
  [213] = {"epoll_create", {INT}, INT}, \
  /*  int epoll_ctl_old(void); */ \
  [214] = {"epoll_ctl_old", {NONE}, INT}, \
  /*  int epoll_wait_old(void); */ \
  [215] = {"epoll_wait_old", {NONE}, INT}, \
  /*  int remap_file_pages(void *addr, size_t size, int prot, size_t pgoff, int flags); */ \
  [216] = {"remap_file_pages", {UNDEFINED_PTR, UINT, INT, UINT, INT}, INT}, \
  /*  int getdents64(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count); */ \
  [217] = {"getdents64", {UINT, STRUCT_PTR, UINT}, INT}, \
  /*  int set_tid_address(int *tidptr); */ \
  [218] = {"set_tid_address", {INT_PTR}, INT}, \
  /*  long restart_syscall(void); */ \
  [219] = {"restart_syscall", {NONE}, LONG}, \
  /*  int semtimedop(int semid, struct sembuf *sops, size_t nsops, const struct timespec *timeout); */ \
  [220] = {"semtimedop", {INT, STRUCT_PTR, UINT, STRUCT_PTR}, INT}, \
  /*  int fadvise64(int fd, off_t offset, size_t len, int advice); */ \
  [221] = {"fadvise64", {INT, LONG, UINT, INT}, LONG}, \
  /*  int timer_create(clockid_t clockid, struct sigevent *sevp, timer_t *timerid); */ \
  [222] = {"timer_create", {INT, STRUCT_PTR, UNDEFINED_PTR}, INT}, \
  /*  int timer_settime(timer_t timerid, int flags, const struct itimerspec *new_value, struct itimerspec *old_value); */ \
  [223] = {"timer_settime", {INT, INT, STRUCT_PTR, STRUCT_PTR}, INT}, \
  /*  int timer_gettime(timer_t timerid, struct itimerspec *curr_value); */ \
  [224] = {"timer_gettime", {INT, STRUCT_PTR}, INT}, \
  /*  int timer_getoverrun(timer_t timerid); */ \
  [225] = {"timer_getoverrun", {INT}, INT}, \
  /*  int timer_delete(timer_t timerid); */ \
  [226] = {"timer_delete", {INT}, INT}, \
  /*  int clock_settime(clockid_t clk_id, const struct timespec *tp); */ \
  [227] = {"clock_settime", {INT, STRUCT_PTR}, INT}, \
  /*  int clock_gettime(clockid_t clk_id, struct timespec *tp); */ \
  [228] = {"clock_gettime", {INT, STRUCT_PTR}, INT}, \
  /*  int clock_getres(clockid_t clk_id, struct timespec *res); */ \
  [229] = {"clock_getres", {INT, STRUCT_PTR}, INT}, \
  /*  int clock_nanosleep(clockid_t clockid, int flags, const struct timespec *request, struct timespec *remain); */ \
  [230] = {"clock_nanosleep", {INT, INT, STRUCT_PTR, STRUCT_PTR}, INT}, \
  /*  void exit_group(int status); */ \
  [231] = {"exit_group", {INT}, NONE}, \
  /*  int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout); */ \
  [232] = {"epoll_wait", {INT, STRUCT_PTR, INT, INT}, INT}, \
  /*  int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event); */ \
  [233] = {"epoll_ctl", {INT, INT, INT, STRUCT_PTR}, INT}, \
  /*  int tgkill(pid_t tgid, pid_t tid, int sig); */ \
  [234] = {"tgkill", {INT, INT, INT}, INT}, \
  /*  int utimes(const char *filename, const struct timeval times[2]); */  \
  [235] = {"utimes", {CHAR_PTR, STRUCT_PTR}, INT}, \
  /*  int vserver(void); */ \
  [236] = {"vserver", {NONE}, INT}, \
  /*  long mbind(void *addr, unsigned long len, int mode, const unsigned long *nodemask, unsigned long maxnode, unsigned flags); */ \
  [237] = {"mbind", {UNDEFINED_PTR, ULONG, INT, UNDEFINED_PTR, ULONG, UINT}, LONG}, \
  /*  long set_mempolicy(int mode, const unsigned long *nodemask, unsigned long maxnode); */ \
  [238] = {"set_mempolicy", {INT, UNDEFINED_PTR, ULONG}, LONG}, \
  /*  long get_mempolicy(int *mode, unsigned long *nodemask, unsigned long maxnode, void *addr, unsigned long flags); */ \
  [239] = {"get_mempolicy", {INT_PTR, UNDEFINED_PTR, ULONG, UNDEFINED_PTR, ULONG}, LONG}, \
  /*  int mq_open(const char *name, int oflag, mode_t mode, struct mq_attr *attr); */ \
  [240] = {"mq_open", {CHAR_PTR, INT, UINT, STRUCT_PTR}, INT}, \
  /*  int mq_unlink(const char *name); */ \
  [241] = {"mq_unlink", {CHAR_PTR}, INT}, \
  /*  int mq_timedsend(mqd_t mqdes, const char *msg_ptr, size_t msg_len, unsigned int msg_prio, const struct timespec *abs_timeout); */ \
  [242] = {"mq_timedsend", {INT, CHAR_PTR, UINT, UINT, STRUCT_PTR}, INT}, \
  /*  ssize_t mq_timedreceive(mqd_t mqdes, char *msg_ptr, size_t msg_len, unsigned int *msg_prio, const struct timespec *abs_timeout); */ \
  [243] = {"mq_timedreceive", {INT, CHAR_PTR, UINT, UNDEFINED_PTR, STRUCT_PTR}, INT}, \
  /*  int mq_notify(mqd_t mqdes, const struct sigevent *sevp); */ \
  [244] = {"mq_notify", {INT, STRUCT_PTR}, INT}, \
  /*  int mq_getsetattr(mqd_t mqdes, const struct mq_attr *newattr, struct mq_attr *oldattr); */ \
  [245] = {"mq_getsetattr", {INT, STRUCT_PTR, STRUCT_PTR}, INT}, \
  /*  long kexec_load(unsigned long entry, unsigned long nr_segments, struct kexec_segment *segments, unsigned long flags); */ \
  [246] = {"kexec_load", {ULONG, ULONG, STRUCT_PTR, ULONG}, LONG}, \
  /*  int waitid(idtype_t idtype, id_t id, siginfo_t *infop, int options); */ \
  [247] = {"waitid", {INT, INT, STRUCT_PTR, INT}, INT}, \
  /*  key_serial_t add_key(const char *type, const char *description, const void *payload, size_t plen, key_serial_t keyring); */ \
  [248] = {"add_key", {CHAR_PTR, CHAR_PTR, UNDEFINED_PTR, UINT, INT}, INT}, \
  /*  key_serial_t request_key(const char *type, const char *description, const char *callout_info, key_serial_t keyring); */ \
  [249] = {"request_key", {CHAR_PTR, CHAR_PTR, CHAR_PTR, INT}, INT}, \
  /*  long keyctl(int operation, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5); */ \
  [250] = {"keyctl", {INT, ULONG, ULONG, ULONG, ULONG}, LONG}, \
  /*  int ioprio_set(int which, int who, int ioprio); */ \
  [251] = {"ioprio_set", {INT, INT, INT}, INT}, \
  /*  int ioprio_get(int which, int who); */ \
  [252] = {"ioprio_get", {INT, INT}, INT}, \
  /*  int inotify_init(void); */ \
  [253] = {"inotify_init", {NONE}, INT}, \
  /*  int inotify_add_watch(int fd, const char *pathname, uint32_t mask); */ \
  [254] = {"inotify_add_watch", {INT, CHAR_PTR, UINT}, INT}, \
  /*  int inotify_rm_watch(int fd, int wd); */ \
  [255] = {"inotify_rm_watch", {INT, INT}, INT}, \
  /*  long migrate_pages(int pid, unsigned long maxnode, const unsigned long *old_nodes, const unsigned long *new_nodes); */ \
  [256] = {"migrate_pages", {INT, ULONG, UNDEFINED_PTR, UNDEFINED_PTR}, LONG}, \
  /*  int openat(int dirfd, const char *pathname, int flags, mode_t mode); */ \
  [257] = {"openat", {INT, CHAR_PTR, INT, UINT}, INT}, \
  /*  int mkdirat(int dirfd, const char *pathname, mode_t mode); */ \
  [258] = {"mkdirat", {INT, CHAR_PTR, UINT}, INT}, \
  /*  int mknodat(int dirfd, const char *pathname, mode_t mode, dev_t dev); */ \
  [259] = {"mknodat", {INT, CHAR_PTR, UINT, ULONG}, INT}, \
  /*  int fchownat(int dirfd, const char *pathname, uid_t owner, gid_t group, int flags); */ \
  [260] = {"fchownat", {INT, CHAR_PTR, UINT, UINT, INT}, INT}, \
  /*  int futimesat(int dirfd, const char *pathname, const struct timeval times[2]); */  \
  [261] = {"futimesat", {INT, CHAR_PTR, STRUCT_PTR}, INT}, \
  /*  int newfstatat(int dirfd, const char *pathname, struct stat *statbuf, int flags); */ \
  [262] = {"newfstatat", {INT, CHAR_PTR, STRUCT_PTR, INT}, INT}, \
  /*  int unlinkat(int dirfd, const char *pathname, int flags); */ \
  [263] = {"unlinkat", {INT, CHAR_PTR, INT}, INT}, \
  /*  int renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath); */ \
  [264] = {"renameat", {INT, CHAR_PTR, INT, CHAR_PTR}, INT}, \
  /*  int linkat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, int flags); */ \
  [265] = {"linkat", {INT, CHAR_PTR, INT, CHAR_PTR, INT}, INT}, \
  /*  int symlinkat(const char *target, int newdirfd, const char *linkpath); */ \
  [266] = {"symlinkat", {CHAR_PTR, INT, CHAR_PTR}, INT}, \
  /*  ssize_t readlinkat(int dirfd, const char *pathname, char *buf, size_t bufsiz); */ \
  [267] = {"readlinkat", {INT, CHAR_PTR, CHAR_PTR, UINT}, INT}, \
  /*  int fchmodat(int dirfd, const char *pathname, mode_t mode, int flags); */ \
  [268] = {"fchmodat", {INT, CHAR_PTR, UINT, INT}, INT}, \
  /*  int faccessat(int dirfd, const char *pathname, int mode, int flags); */ \
  [269] = {"faccessat", {INT, CHAR_PTR, INT, INT}, INT}, \
  /*  int pselect6(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, const struct timespec *timeout, const sigset_t *sigmask); */ \
  [270] = {"pselect6", {INT, STRUCT_PTR, STRUCT_PTR, STRUCT_PTR, STRUCT_PTR, STRUCT_PTR}, INT}, \
  /*  int ppoll(struct pollfd *fds, nfds_t nfds, const struct timespec *timeout_ts, const sigset_t *sigmask, size_t sigsetsize); */ \
  [271] = {"ppoll", {STRUCT_PTR, UINT, STRUCT_PTR, STRUCT_PTR, UINT}, INT}, \
  /*  int unshare(int flags); */ \
  [272] = {"unshare", {INT}, INT}, \
  /*  long set_robust_list(struct robust_list_head *head, size_t len); */ \
  [273] = {"set_robust_list", {STRUCT_PTR, UINT}, LONG}, \
  /*  long get_robust_list(int pid, struct robust_list_head **head_ptr, size_t *len_ptr); */ \
  [274] = {"get_robust_list", {INT, UNDEFINED_PTR, UNDEFINED_PTR}, LONG}, \
  /*  ssize_t splice(int fd_in, loff_t *off_in, int fd_out, loff_t *off_out, size_t len, unsigned int flags); */ \
  [275] = {"splice", {INT, UNDEFINED_PTR, INT, UNDEFINED_PTR, UINT, UINT}, INT}, \
  /*  ssize_t tee(int fd_in, int fd_out, size_t len, unsigned int flags); */ \
  [276] = {"tee", {INT, INT, UINT, UINT}, INT}, \
  /*  int sync_file_range(int fd, off64_t offset, off64_t nbytes, unsigned int flags); */ \
  [277] = {"sync_file_range", {INT, LONG_LONG, LONG_LONG, UINT}, INT}, \
  /*  ssize_t vmsplice(int fd, const struct iovec *iov, unsigned long nr_segs, unsigned int flags); */ \
  [278] = {"vmsplice", {INT, STRUCT_PTR, ULONG, UINT}, INT}, \
  /*  long move_pages(int pid, unsigned long count, void **pages, const int *nodes, int *status, int flags); */ \
  [279] = {"move_pages", {INT, ULONG, UNDEFINED_PTR, INT_PTR, INT_PTR, INT}, LONG}, \
  /*  int utimensat(int dirfd, const char *pathname, const struct timespec times[2], int flags); */  \
  [280] = {"utimensat", {INT, CHAR_PTR, STRUCT_PTR, INT}, INT}, \
  /*  int epoll_pwait(int epfd, struct epoll_event *events, int maxevents, int timeout, const sigset_t *sigmask); */ \
  [281] = {"epoll_pwait", {INT, STRUCT_PTR, INT, INT, STRUCT_PTR}, INT}, \
  /*  int signalfd(int fd, const sigset_t *mask, int flags); */ \
  [282] = {"signalfd", {INT, STRUCT_PTR, INT}, INT}, \
  /*  int timerfd_create(int clockid, int flags); */ \
  [283] = {"timerfd_create", {INT, INT}, INT}, \
  /*  int eventfd(unsigned int initval, int flags); */ \
  [284] = {"eventfd", {UINT, INT}, INT}, \
  /*  int fallocate(int fd, int mode, off_t offset, off_t len); */ \
  [285] = {"fallocate", {INT, INT, LONG, LONG}, INT}, \
  /*  int timerfd_settime(int fd, int flags, const struct itimerspec *new_value, struct itimerspec *old_value); */ \
  [286] = {"timerfd_settime", {INT, INT, STRUCT_PTR, STRUCT_PTR}, INT}, \
  /*  int timerfd_gettime(int fd, struct itimerspec *curr_value); */ \
  [287] = {"timerfd_gettime", {INT, STRUCT_PTR}, INT}, \
  /*  int accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags); */ \
  [288] = {"accept4", {INT, STRUCT_PTR, INT_PTR, INT}, INT}, \
  /*  int signalfd4(int fd, const sigset_t *mask, int flags); */ \
  [289] = {"signalfd4", {INT, STRUCT_PTR, INT}, INT}, \
  /*  int eventfd2(unsigned int initval, int flags); */ \
  [290] = {"eventfd2", {UINT, INT}, INT}, \
  /*  int epoll_create1(int flags); */ \
  [291] = {"epoll_create1", {INT}, INT}, \
  /*  int dup3(int oldfd, int newfd, int flags); */ \
  [292] = {"dup3", {INT, INT, INT}, INT}, \
  /*  int pipe2(int pipefd[2], int flags); */  \
  [293] = {"pipe2", {INT_PTR, INT}, INT}, \
  /*  int inotify_init1(int flags); */ \
  [294] = {"inotify_init1", {INT}, INT}, \
  /*  ssize_t preadv(int fd, const struct iovec *iov, int iovcnt, off_t offset); */ \
  [295] = {"preadv", {INT, STRUCT_PTR, INT, LONG}, INT}, \
  /*  ssize_t pwritev(int fd, const struct iovec *iov, int iovcnt, off_t offset); */ \
  [296] = {"pwritev", {INT, STRUCT_PTR, INT, LONG}, INT}, \
  /*  int rt_tgsigqueueinfo(pid_t tgid, pid_t tid, int sig, siginfo_t *uinfo); */ \
  [297] = {"rt_tgsigqueueinfo", {INT, INT, INT, STRUCT_PTR}, INT}, \
  /*  int perf_event_open(struct perf_event_attr *attr, pid_t pid, int cpu, int group_fd, unsigned long flags); */ \
  [298] = {"perf_event_open", {STRUCT_PTR, INT, INT, INT, ULONG}, INT}, \
  /*  int recvmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen, int flags, struct timespec *timeout); */ \
  [299] = {"recvmmsg", {INT, STRUCT_PTR, UINT, INT, STRUCT_PTR}, INT}, \
  /*  int fanotify_init(unsigned int flags, unsigned int event_f_flags); */ \
  [300] = {"fanotify_init", {UINT, UINT}, INT}, \
  /*  int fanotify_mark(int fanotify_fd, unsigned int flags, uint64_t mask, int dfd, const char *pathname); */ \
  [301] = {"fanotify_mark", {INT, UINT, ULONG_LONG, INT, CHAR_PTR}, INT}, \
  /*  int prlimit64(pid_t pid, int resource, const struct rlimit64 *new_limit, struct rlimit64 *old_limit); */ \
  [302] = {"prlimit64", {INT, INT, STRUCT_PTR, STRUCT_PTR}, INT}, \
  /*  int name_to_handle_at(int dirfd, const char *pathname, struct file_handle *handle, int *mount_id, int flags); */ \
  [303] = {"name_to_handle_at", {INT, CHAR_PTR, STRUCT_PTR, INT_PTR, INT}, INT}, \
  /*  int open_by_handle_at(int mount_fd, struct file_handle *handle, int flags); */ \
  [304] = {"open_by_handle_at", {INT, STRUCT_PTR, INT}, INT}, \
  /*  int clock_adjtime(clockid_t clk_id, struct timex *tx); */ \
  [305] = {"clock_adjtime", {INT, STRUCT_PTR}, INT}, \
  /*  int syncfs(int fd); */ \
  [306] = {"syncfs", {INT}, INT}, \
  /*  int sendmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen, int flags); */ \
  [307] = {"sendmmsg", {INT, STRUCT_PTR, UINT, INT}, INT}, \
  /*  int setns(int fd, int nstype); */ \
  [308] = {"setns", {INT, INT}, INT}, \
  /*  int getcpu(unsigned *cpu, unsigned *node, struct getcpu_cache *tcache); */ \
  [309] = {"getcpu", {UNDEFINED_PTR, UNDEFINED_PTR, STRUCT_PTR}, INT}, \
  /*  ssize_t process_vm_readv(pid_t pid, const struct iovec *local_iov, unsigned long liovcnt, const struct iovec *remote_iov, unsigned long riovcnt, unsigned long flags); */ \
  [310] = {"process_vm_readv", {INT, STRUCT_PTR, ULONG, STRUCT_PTR, ULONG, ULONG}, INT}, \
  /*  ssize_t process_vm_writev(pid_t pid, const struct iovec *local_iov, unsigned long liovcnt, const struct iovec *remote_iov, unsigned long riovcnt, unsigned long flags); */ \
  [311] = {"process_vm_writev", {INT, STRUCT_PTR, ULONG, STRUCT_PTR, ULONG, ULONG}, INT}, \
  /*  int kcmp(pid_t pid1, pid_t pid2, int type, unsigned long idx1, unsigned long idx2); */ \
  [312] = {"kcmp", {INT, INT, INT, ULONG, ULONG}, INT}, \
  /* int finit_module(int fd, const char *param_values, int flags); */ \
  [313] = {"finit_module", {INT, CHAR_PTR, INT}, INT}, \
  /* int sched_setattr(pid_t pid, struct sched_attr *attr, unsigned int flags); */ \
  [314] = {"sched_setattr", {INT, STRUCT_PTR, UINT}, INT}, \
  /* int sched_getattr(pid_t pid, struct sched_attr *attr, unsigned int size, unsigned int flags); */ \
  [315] = {"sched_getattr", {INT, STRUCT_PTR, UINT, UINT}, INT}, \
  /* int renameat2(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, unsigned int flags); */ \
  [316] = {"renameat2", {INT, CHAR_PTR, INT, CHAR_PTR, UINT}, INT}, \
  /* int seccomp(unsigned int operation, unsigned int flags, void *args); */ \
  [317] = {"seccomp", {UINT, UINT, UNDEFINED_PTR}, INT}, \
  /* ssize_t getrandom(void *buf, size_t buflen, unsigned int flags); */ \
  [318] = {"getrandom", {UNDEFINED_PTR, UINT, UINT}, INT}, \
  /* int memfd_create(const char *name, unsigned int flags); */ \
  [319] = {"memfd_create", {CHAR_PTR, UINT}, INT}, \
  /* long kexec_file_load(int kernel_fd, int initrd_fd, unsigned long cmdline_len, const char *cmdline_ptr, unsigned long flags); */ \
  [320] = {"kexec_file_load", {INT, INT, ULONG, CHAR_PTR, ULONG}, LONG}, \
  /* int bpf(int cmd, union bpf_attr *attr, unsigned int size); */ \
  [321] = {"bpf", {INT, STRUCT_PTR, UINT}, INT}, \
  /* int execveat(int dirfd, const char *pathname, char *const argv [], char *const envp [], int flags); */ \
  [322] = {"execveat", {INT, CHAR_PTR, UNDEFINED_PTR, UNDEFINED_PTR, INT}, INT}, \
  /* int userfaultfd(int flags); */ \
  [323] = {"userfaultfd", {INT}, INT}, \
  /* int membarrier(int cmd, unsigned int flags, int cpu_id); */ \
  [324] = {"membarrier", {INT, UINT, INT}, INT}, \
  /* int mlock2(const void *addr, size_t len, unsigned int flags); */ \
  [325] = {"mlock2", {UNDEFINED_PTR, UINT, UINT}, INT}, \
  /* ssize_t copy_file_range(int fd_in, loff_t *off_in, int fd_out, loff_t *off_out, size_t len, unsigned int flags); */ \
  [326] = {"copy_file_range", {INT, UNDEFINED_PTR, INT, UNDEFINED_PTR, UINT, UINT}, INT}, \
  /* ssize_t preadv2(int fd, const struct iovec *iov, int iovcnt, off_t offset, int flags); */ \
  [327] = {"preadv2", {INT, STRUCT_PTR, INT, LONG, INT}, INT}, \
  /* ssize_t pwritev2(int fd, const struct iovec *iov, int iovcnt, off_t offset, int flags); */ \
  [328] = {"pwritev2", {INT, STRUCT_PTR, INT, LONG, INT}, INT}, \
  /* int pkey_mprotect(void *addr, size_t len, int prot, int pkey); */ \
  [329] = {"pkey_mprotect", {UNDEFINED_PTR, UINT, INT, INT}, INT}, \
  /* int pkey_alloc(unsigned int flags, unsigned int access_rights); */ \
  [330] = {"pkey_alloc", {UINT, UINT}, INT}, \
  /* int pkey_free(int pkey); */ \
  [331] = {"pkey_free", {INT}, INT}, \
  /* int statx(int dirfd, const char *pathname, int flags, unsigned int mask, struct statx *statxbuf); */ \
  [332] = {"statx", {INT, CHAR_PTR, INT, UINT, STRUCT_PTR}, INT}, \
  /* int io_pgetevents(aio_context_t ctx_id, long min_nr, long nr, struct io_event *events, struct timespec *timeout, const struct io_getevents_sigset *sig); */ \
  [333] = {"io_pgetevents", {ULONG, LONG, LONG, STRUCT_PTR, STRUCT_PTR, STRUCT_PTR}, INT}, \
  /* int rseq(struct rseq *rseq, uint32_t rseq_len, int flags, uint32_t sig); */ \
  [334] = {"rseq", {STRUCT_PTR, UINT, INT, UINT}, INT}, \
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
