#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
  struct tm *local;
  time_t t;

  while(1) {
    t = time(NULL);
    local = localtime(&t);
    printf("Local time and date: %s", asctime(local));
    sleep(1);
  }
  return 0;
}
