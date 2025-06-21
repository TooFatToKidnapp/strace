#include <unistd.h>

int main() {
  char * s = NULL;

  write(1, (char*)s[10], 10);
}
