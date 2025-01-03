# Syso

Syso is a tool that can analyse how dynamically linked executables make system calls.

## How is it different from `strace`?

- Strace can show instruction pointer and syscall data, but it cannot align the 
  program counter with the calling object file.

- Syso uses eBPF to
    - Log all system calls made by the monitored application (and any of its child processes)
    - Identify which (non-libc) shared object file made the syscall using `/proc/PID/maps` and the user stack
    - Report a summary of syscall counts as json.
  
---
## Running Syso

### Host

#### Targets
This program currently supports only Linux on x86_64. Given this is a research tool, support for other 
OSs/architectures is unlikely.

#### Installation
- Build with `make`. The binary will be a `./bin/syso`.
- Install by adding the binary to `/usr/local/bin`, either through `cp` or via a symlink.

#### Running
- Turn off ASLR with `sysctl kernel.randomize_va_space=0` (requires root)
- Run `syso` (also requires root), followed by the executable you are tracing.  

```shell
sysctl kernel.randomize_va_space=0  # turn off ASLR
syso /path/to/exec args...
```
---
### Docker

Running in docker (and by extension `./run.sh`) is currently broken. Run on the host.

For the time being, running in docker prevents the bpf program from accessing the entire user stack.
- Syscalls only show stack traces that are two frames deep: the PC and 0.
  - Was tested on a `fflush(stdout)` call in `main.c`: should be at least 5 frames deep.
- The PC is always in the memory space mapped to `/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2` - the loader.
- Strange behaviour, cause tbd. So far tried
  - Disabling docker's default seccomp profile - no difference in behaviour
  - Attaching to ./main (running in container) with GDB (from outside container) and dumping the stack. 
    Saw (expected) 5 frames.

```shell
docker build . -t syso 
docker run -it --privileged --pid=host -v ./stats:/app/stats syso ./main hello world
```

- Command breakdown
    - `--priviliged`: needed to attach bpf program onto the host kernel
    - `--pid=host`: force kernel and userspace frontend (running in the container) to associate the same processes with the same PIDs
    - `-v ./stats:/app/stats`: comprensive stats file is written to /app/stats as json.
    - `./main hello world` program + args being analysed

---
## Example output

When run on an executable created by `./main.c`, a `./stats/counts.json` file is generated. It contains

```json
{
  "/home/tom/syso/main": {
    "1": 10001,
    "12": 2,
    "231": 1,
    "318": 1,
    "39": 1,
    "5": 1
  },
  "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2": {
    "0": 1,
    "10": 3,
    "11": 1,
    "12": 1,
    "158": 1,
    "17": 2,
    "21": 1,
    "218": 1,
    "257": 2,
    "273": 1,
    "3": 2,
    "302": 1,
    "334": 1,
    "5": 2,
    "9": 8
  },
  "FAILED": {
    "13": 55,
    "14": 1,
    "160": 1,
    "292": 1,
    "59": 1,
    "72": 2
  }
}
```

- `./main.c` makes 10001 write system calls: 1 to write pid, and 10,000 writing "hello". This is shown by
  `"1": 10001`.
- The loader makes some system calls

### Where is libc?
- Unless a syscall is made via inline assembly, it probably goes via a libc wrapper function
- This means that all syscalls end up being made from libc: not very informative
- syso walks the user stack for each syscall. It finds and reports the first non-libc call site.
- If the first non-libc call site fails to map (see limitations), then it will be reported as libc.

---
## Limitations
- There are some "setup" syscalls, each with very small addresses (small meaning close to 0) that do not exist in
  `/proc/PID/maps`. These show up as "FAILED" in the summary.
- Fails to assign mappings for short-lived forks (work in progess)
- Need to manually ctrl-c when executable finishes (also work in progress)
