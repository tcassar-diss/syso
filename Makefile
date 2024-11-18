all: syso.ebpf.c sample
	go generate
	go build -o bin/main ./cmd

clean:
	rm bin/* main

sample: ./main.c
	gcc -o main ./main.c


