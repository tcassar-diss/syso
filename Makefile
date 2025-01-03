syso: ./bpf/syso.bpf.c sample trace

clean:
	rm bin/* main

sample: ./main.c
	gcc -g -O0  -o main ./main.c

trace: ./main.go
	go generate ./...
	go build -o bin/syso .

vmlinux.h: /usr/include/x86_64-linux-gnu/asm $(which bpftool)
	ln -s /usr/include/x86_64-linux-gnu/asm /usr/include/asm && \
    bpftool btf dump file /sys/kernel/btf/vmlinux format c > ./bpf/vmlinux.h
