FROM ubuntu:22.04

ARG GOVERSION=1.32.1
ARG ARCH=amd64

RUN apt update -y && apt upgrade -y && \
    apt install -y \
    libbpf-dev \
    make \
    clang \
    llvm \
    libelf-dev \
    golang-1.23 \
    ca-certificates \
    linux-headers-"$(uname -r)" \
    linux-tools-common \
    linux-tools-generic \
    linux-tools-$(uname -r)

ENV PATH="/usr/lib/go-1.23/bin:${PATH}"

WORKDIR /app

RUN ln -s /usr/include/x86_64-linux-gnu/asm /usr/include/asm && \
    bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

COPY go.mod go.sum ./

RUN go mod download

COPY *.go *.c *.sh Makefile ./
COPY ./cmd ./cmd

RUN make && go build -o bin/syso ./cmd

RUN chmod u+x ./entrypoint.sh

CMD ["./entrypoint.sh"]
