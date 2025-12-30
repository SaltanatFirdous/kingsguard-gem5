# Kingsguard

This repository contains Kingsguard project for RISC-V on gem5.

## Current contents

- `tools/elf-ift/`: ELF preprocessing tools using ELFIO that prepare binaries to run under Kingsguard.

  The Partition foldder conatisna n example program partitioned into enclave and host parts. To compile the two parts, run make inside the Partition directory.

  To attach metadata to the compiled binary:

  1. Build the tag tool by running make inside elf-ft directory.
  2. Run the compiled tag-elf binary by passing the desired bianry to be tested with KingsGuard:

     ```bash
     ./tag-elf <elfname>
     ```

     This will generate a modified ELF `<elfname.tag>` with required metadata.

- `linux`: Linux kernel adapted for KingsGuard.

  Run:

  ```bash
  make ARCH=riscv CROSS_COMPILE=riscv64-unknown-linux-gnu- defconfig

(in linux directory)

```bash
  make ARCH=riscv CROSS_COMPILE=riscv64-unknown-linux-gnu-  all -j16
```
(generates vmlinux)

- `riscv-pk`: Modified version of the RISC-V Proxy Kernel.
  ```bash
  ../configure --host=riscv64-unknown-linux-gnu --with-payload=<path to vmlinux> --prefix=<path to riscv cross compiler>
  ```
  (in riscv-pk/build)
  ```bash
  make -j<n>
  ```

- `gem5`: Modified gem5 simulator used to model the Kingsguard architecture.
  Run:
  ```bash
  scons build/RISCV/gem5.opt -j<n>
  ```
  (to build gem5 for RISCV)
  ```bash
  ./build/RISCV/gem5.opt configs/example/gem5_library/riscv-fs.py
  ```
  (to run a simulation of KingsGuard)
  ```bash
  ./build/RISCV/gem5.opt configs/example/gem5_library/riscv-fs-sass.py
  ```
  (to run KingsGuard with SassCache implementation)


Follow this repo to set up the disk image: https://gem5.googlesource.com/public/gem5-resources/+/HEAD/src/riscv-fs/README.md
Make sure the path to disk image and kernel is updated to the path on your system in the riscv-fs.py/riscv-fs-sass.py configuration files.

