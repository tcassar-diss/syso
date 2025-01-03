FROM ubuntu:22.04

ARG KERNEL_VERSION=6.8.0-45-generic

RUN apt update -y && apt upgrade -y && \
    apt install -y \
    libbpf-dev \
    make \
    clang \
    llvm \
    libelf-dev \
    golang-1.23 \
    ca-certificates \
    linux-headers-${KERNEL_VERSION} \
    linux-tools-common \
    linux-tools-generic \
    linux-tools-${KERNEL_VERSION}

ENV PATH="/usr/lib/go-1.23/bin:${PATH}"

WORKDIR /app

RUN ln -s /usr/include/x86_64-linux-gnu/asm /usr/include/asm && \
    bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

COPY go.mod go.sum ./

RUN go mod download

# COPY ./addrspace ./addrspace/
# COPY ./bpf ./bpf
# COPY ./syso ./syso
# COPY main.go main.c Makefile ./

COPY . .

# RUN make && sysctl kernel.randomize_va_space=0

RUN sysctl kernel.randomize_va_space=0 &&  sysctl kernel.perf_event_max_stack=256

ENTRYPOINT ["./bin/syso"]
