//go:build exclude

#include <stdio.h>
#include <unistd.h>

int main(int argc, char** argv) {
   printf("%s %s\n", argv[1], argv[2]);
   
    return 0;
}
