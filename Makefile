syso: syso.ebpf.c sample trace

clean:
	rm bin/* main

sample: ./main.c
	gcc -o main ./main.c

trace: ./cmd/trace
	go generate
	go build -o bin/syso ./cmd/trace

maps: ./cmd/maps
	go build -o bin/main ./cmd/maps
