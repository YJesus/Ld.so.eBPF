clang-15 -D__KERNEL__ -D__ASM_SYSREG_H -Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types -Wunused -Wall -Werror -O2 -g -target bpf -c ld.so.ebpf.c
bpftool gen skeleton ld.so.ebpf.o > asunto.h
clang-15 -lbpf loader.c -o loader
