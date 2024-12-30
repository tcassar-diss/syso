all-naive: ./bpf/syso.ebpf.c sample naive
all-stackparse: ./bpf/stackparse.bpf.c sample stackparse

clean:
	rm bin/* main

sample: ./main.c
	gcc -o main ./main.c

naive: ./cmd/naive/main.go
	go generate ./internal/naive/gen.go
	go build -o bin/syso ./cmd/naive

stackparse: ./cmd/stackparse/main.go
	go generate ./internal/stackparse/gen.go
	go build -o bin/syso ./cmd/stackparse

vmlinux.h: /usr/include/x86_64-linux-gnu/asm $(which bpftool)
	ln -s /usr/include/x86_64-linux-gnu/asm /usr/include/asm && \
    bpftool btf dump file /sys/kernel/btf/vmlinux format c > ./bpf/vmlinux.h
