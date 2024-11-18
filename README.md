# Syso

- Syso is a tool that can analyse how dynamically linked executables make system calls.

## How is it different from `strace`?

- Strace can show instruction pointer and syscall data, but it cannot align the program counter with the calling object file.

- Syso uses eBPF to
    - Log all system calls made by the monitored application (and any of it's child processes)
    - Use `/proc/PID/maps` to align instruction pointer value with a shared library object
    - Report each syscall as JSON

## Running Syso

### Docker

```shell
docker build . -t syso 
docker run -it --privileged syso
```

### Host

```shell
sysctl kernel.randomize_va_space=0  # turn off ASLR
make
./bin/syso /path/to/exec args...
```

## Limitations
- Fails to assign mappings for short lived forks (work in progess)
- No checks on ring buffer being full (also work in progress)
- Need to manually ctrl-c when executable finishes (also work in progress)
- Doesn't work in Docker container as PIDs in containers are namespaced differently to the host, which makes things less trivial.

