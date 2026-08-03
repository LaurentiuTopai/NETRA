APPS = edr network filer

CLANG ?= clang
CC ?= gcc
LIBS := -lbpf -lelf -lz

all: edr network filer


edr.bpf.o: edr.bpf.c vmlinux.h
	clang -g -O2 -I/usr/include -target bpf -D__TARGET_BPF -c edr.bpf.c -o edr.bpf.o

edr.bpf.skel.h: edr.bpf.o
	bpftool gen skeleton edr.bpf.o > edr.bpf.skel.h

edr: edr.c edr.bpf.skel.h
	gcc -g -O2 edr.c -lbpf -lelf -lz -o edr



network.bpf.o: network.bpf.c vmlinux.h
	clang -g -O2 -I/usr/include -target bpf -D__TARGET_BPF -c network.bpf.c -o network.bpf.o

network.bpf.skel.h: network.bpf.o
	bpftool gen skeleton network.bpf.o > network.bpf.skel.h

network: network.c network.bpf.skel.h
	gcc -g -O2 network.c -lbpf -lelf -lz -o network




filer.bpf.o: filer.bpf.c vmlinux.h
	clang -g -O2 -I/usr/include -target bpf -D__TARGET_BPF -c filer.bpf.c -o filer.bpf.o

filer.bpf.skel.h: filer.bpf.o
	bpftool gen skeleton filer.bpf.o > filer.bpf.skel.h

filer: filer.c filer.bpf.skel.h
	gcc -g -O2 filer.c -lbpf -lelf -lz -o filer


clean:
	rm -f *.o *.skel.h edr network
















