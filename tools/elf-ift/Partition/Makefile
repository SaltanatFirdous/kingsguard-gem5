# Toolchains
CC_ENCLAVE = riscv64-unknown-linux-gnu-gcc
CC_HOST    = riscv64-unknown-linux-gnu-gcc   # you wrote "riscv-64", assuming it's a typo

# Flags
ENCLAVE_CFLAGS = -fno-builtin -nostdlib -nostartfiles -static -no-pie
HOST_CFLAGS    = -static

# Targets
all: host enclave

enclave: enclave.c link.ld
	$(CC_ENCLAVE) $(ENCLAVE_CFLAGS) -T link.ld -o $@ $<

host: host.c
	$(CC_HOST) $(HOST_CFLAGS) -o $@ $<

clean:
	rm -f host enclave

.PHONY: all clean


