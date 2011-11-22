#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <unistd.h>

const char *thetime = "HAMMERTIME";

char *hooked_asctime(char *str) {
	char *s;
	s = (char *)malloc(strlen(thetime) + 2);
        sprintf(s, "%s\n", thetime);
	return s;
}

const char *hammertime(void) {
    return thetime;
}

void sayit(void) {
    printf("%s\n", thetime);
}

void* hammer_run(void *arg) {
    while( 1 ) {
        sleep(1);
        sayit();
    }
}

void hammer_on(void) {
    pthread_t thread;
    pthread_create(&thread, NULL, hammer_run, NULL);
}
