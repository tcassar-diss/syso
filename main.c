//go:build exclude

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

int main(int argc, char** argv) {

   fork();

    sleep(1);

   printf("%s %s\n", argv[1], argv[2]);


   return 0;
}
