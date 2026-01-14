# Kingsguard

This repository contains the KingsGuard project for RISC-V, implemented and evaluated using the gem5 simulator.

---

## Repository Contents

### 1. `tools/Partition/`
A sample program partitioned into **enclave** and **host** components.

#### Build
Compile the host and enclave programs using the provided Makefile:

```bash
cd tools/Partition
make
```
     
### 2. `tools/declass/`: 
This folder contains scripts to perform static analysis on RISC-V Binaries to enumerate all valid control flow paths within a program and compute cryptographic measurements (hashes) for those paths.
### Prerequisites
### System Packages
		- python3 
		- riscv gnu toolchain
### Python dependencies
		- pyelftools
		- capstone
```bash
    pip install capstone pyelftools
```
### Usage
The workflow involves three steps: compiling the binary, identifying control flow paths, and computing their hashes.
### Compiling the binary

Use the compiled enclave binary from the Partition folder.


### Path Enumeration

Use the find\_cf\_path.sh wrapper or run cf\_path\_finder.py directly to analyze the binary. This will enumerate paths and export them to a CSV file.

```bash
	./find_cf_path.sh <path_to_elf_binary>	
```

or

```bash
	python3 cf_path_finder.py <path_to_elf_binary> -s _start --csv paths.csv --csv-loops loops.csv
```

-s         : The symbol to start analysis from (default is entry point).
--csv      : Output file for the enumerated paths.
--csv-loops: Output file for detected loop information.

### Compute Path Hashes

Once the paths are generated (e.g., in paths.csv), use the hasher tool to generate cryptographic measurements for each path.

```bash
	./compute_path_hash.sh
```

or

```bash
	python3 path_hasher.py paths.csv -o path_hashes.csv
```


### 3. `tools/elf-ift/`: ELF preprocessing tools using ELFIO that prepare binaries to run under Kingsguard.
  
  To attach metadata to the compiled binary:

  1. Build the tag tool by running make inside elf-ft directory.
  2. Run the compiled tag-elf binary by passing the desired binary to be tested with KingsGuard:

     ```bash
     ./tag-elf <elfname>
     ```

     This will generate a modified ELF `<elfname.tag>` with required metadata.

### 4. `linux`: Linux kernel adapted for KingsGuard.

  Run (in linux directory) to generate vmlinux:

  ```bash
  make ARCH=riscv CROSS_COMPILE=riscv64-unknown-linux-gnu- defconfig

  make ARCH=riscv CROSS_COMPILE=riscv64-unknown-linux-gnu-  all -j<n>
```

### 5. `riscv-pk`: Modified version of the RISC-V Proxy Kernel.

  Run (in riscv-pk directory):
  ```bash
  mkdir build
  cd build
  ```
  ```bash
  ../configure --host=riscv64-unknown-linux-gnu --with-payload=<path to vmlinux> --prefix=<path to riscv cross compiler>
  ```
  ```bash
  make -j<n>
  ```
It generates a bbl image that should be provided as an input to the kernel field in the gem5 configuration script.
### 6. `gem5`: Modified gem5 simulator used to model the Kingsguard architecture.
### Build the gem5 image for KingsGuard
  Run (in gem5 directory):
  ```bash
  scons build/RISCV/gem5.opt -j<n>
  ```
  
Inside the configuration script (gem5/configs/example/gem5_library/riscv-fs.py), set the path to kernel and disk image based on your system. The kernel should point to the bbl image generated in riscv-pk and disk image can be set up by following this repo: https://gem5.googlesource.com/public/gem5-resources/+/HEAD/src/riscv-fs/README.md. The host and enclave binaries should be added to the disk image before booting. Once Linux boots, run the host binary.

### Run a simulation of KingsGuard:
  ```bash
  ./build/RISCV/gem5.opt configs/example/gem5_library/riscv-fs.py
  ```
In another terminal:
```bash
cd util/term
./m5term localhost 3456
```
This terminal will display the kernel boot logs and provide a login console, where the host binary can be run.
### To run KingsGuard with SassCache implementation:

  ```bash
  ./build/RISCV/gem5.opt configs/example/gem5_library/riscv-fs-sass.py
  ```


