# Syso

- Syso is a tool that can analyse how dynamically linked executables make system calls.

## How is it different from `strace`?

- Strace can show instruction pointer and syscall data, but it cannot align the program counter with the calling object file.

- Syso uses eBPF to
    - Log all system calls made by the monitored application (and any of it's child processes)
    - Use `/proc/PID/maps` to align instruction pointer value with a shared library object
    - Report each syscall as JSON

## Running Syso

### `./run.sh`

`./run.sh` will take care of all build steps. Just supply the executable to trace and any arguments that it needs.

### Docker

```shell
docker build . -t naive 
docker run -it --privileged --pid=host -v ./stats:/app/stats naive ./main hello world
```

- Command breakdown
    - `--priviliged`: needed to attach bpf program onto the host kernel
    - `--pid=host`: force kernel and userspace frontend (running in the container) to associate the same processes with the same PIDs
    - `-v ./stats:/app/stats`: comprensive stats file is written to /app/stats as json.
    - `./main hello world` program + args being analysed


### Host

```shell
sysctl kernel.randomize_va_space=0  # turn off ASLR
make
./bin/naive /path/to/exec args...
```

## Limitations
- Fails to assign mappings for short lived forks (work in progess)
- Need to manually ctrl-c when executable finishes (also work in progress)

