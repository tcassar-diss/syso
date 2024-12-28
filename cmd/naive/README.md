# Naive

`naive` is a tracer that will report the library that system calls are made from.

`naive` reports the instruction address in the PC at the point the syscall instruction is made. This results in 
\> 99% of syscalls being made from `libc`. This means that the traces are not particularly interesting.
