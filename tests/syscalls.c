#include <stdio.h>
#include <sys/syscall.h>      /* Definition of SYS_* constants */
#include <unistd.h>
// sudo apt-get install gcc-multilib -y

int main () {

  for(int i = 0; i < 450; ++i) {
    printf("syscall number = [%d]\n", i);
    if (sizeof(void*) == 8 &&  (i == 15 || i == 23 || i == 34 || i == 231 || i == 270|| i == 271|| i == 318)) continue;
    else if (sizeof(void*) == 4 && (i == 1 || i == 29|| i == 72 || i == 119|| i == 142|| i == 173|| i == 308|| i == 309|| (i >= 355 && i<= 449))) continue;
    syscall(i, 0, 0, 0, 0, 0, 0);
    printf("HANG\n");
  }

}
