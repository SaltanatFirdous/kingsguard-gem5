# Toolchains
CC_ENCLAVE = riscv64-unknown-linux-gnu-gcc
CC_HOST    = riscv64-unknown-linux-gnu-gcc  

# Flags
ENCLAVE_CFLAGS = -march=rv64imafd -mabi=lp64d -mcmodel=medany -fno-builtin -nostdlib -nostartfiles -static -no-pie
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


