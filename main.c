//go:build exclude

#include <unistd.h>
#include <stdio.h>

void __attribute__ ((noinline)) r(int i) {
    // if (i > 10) {
        printf("hello");
        fflush(stdout);
        return;
}

void  __attribute__ ((noinline)) b(int i) {
    r(++i);
}
void  __attribute__ ((noinline)) c(int i) {
    b(++i);
}
void __attribute__ ((noinline)) d(int i) {
   c(++i);
}
int main() {
    for (int i = 0; i < 10000; i++) {
        //printf("%d\n", i);
        d(0);
    }
    
    int pid = getpid();
    printf("\n\n\n\n\n\n\n\n\n%d\n\n\n\n\n\n\n\n\n", pid);
   

    return 0;
}
