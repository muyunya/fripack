// Throwaway host process the payload is injected into.
#include <stdio.h>
#include <unistd.h>

int main(void) {
  printf("[host] pid=%d\n", getpid());
  fflush(stdout);
  sleep(1);
  printf("[host] done\n");
  return 0;
}
