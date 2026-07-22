# Kingsguard

This repository contains the KingsGuard project for RISC-V, implemented and evaluated using the gem5 simulator.
KingsGuard is a RISC-V TEE design that prevents unauthorized data leakage from enclaves using hardware-assisted information-flow tracking and controlled declassification.
This repository contains:
- modified gem5 simulator
- modified Linux 5.10 kernel
- modified RISC-V proxy kernel with Security Monitor
- binary instrumentation tools to add taints and declassification hashes
- sample host/enclave programs
---

## 1. Artifact Overview

### What this artifact demonstrates

This artifact supports the following paper claims:

| Claim | How to reproduce |
|---|---|
| KingsGuard runs enclave applications on modified gem5 | Build gem5, Linux, riscv-pk, instrument the application binary and boot full-system simulation |
| KingsGuard attaches taint and hash metadata to enclave binaries | Run tools/declass and tools/elf-ift |
| KingsGuard supports authorized declassification | Run valid host/enclave path |
| KingsGuard can run with SassCache | Run riscv-fs-sass.py |

## 2. Repository Layout

```text
KingsGuard/
├── gem5/              # Modified gem5 simulator with KingsGuard hardware model
├── linux/             # Modified Linux 5.10 kernel
├── riscv-pk/          # Modified RISC-V proxy kernel + Security Monitor
├── tools/
│   ├── Partition/     # Example host/enclave application
│   ├── declass/       # Control-flow path enumeration and ADP hash generation
│   └── elf-ift/       # ELF preprocessing/tagging tool
├── riscv-disk-img   # Disk image used to boot linux
└── README.md
```
## 3. System Requirements

Tested on:

- **OS:** Ubuntu 22.04 LTS
- **Disk:** 30 GB minimum
- **RISC-V GNU Toolchain:** built from source using the official [RISC-V GNU Toolchain](https://github.com/riscv-collab/riscv-gnu-toolchain) repository.
- **RISC-V GCC version tested:** GCC 10.2.0
- **Python:** Python 3.10.12
- **Python packages:**
  - `capstone`
  - `pyelftools`

Install the required Python packages:

```bash
pip install capstone pyelftools
```

## 4. End-to-End Build Instructions
### 4.1 Build Sample Host/Enclave Program
tools/Partition directory contains a sample program partitioned into **enclave** and **host** components. Compile the host and enclave programs using the provided Makefile:
```bash
cd tools/Partition
make
```

This generates the sample host and enclave binaries.

---
### 4.2 Generate Declassification Paths and Hashes
tools/declass folder contains scripts to perform static analysis on RISC-V Binaries to enumerate all valid control flow paths within a program and compute cryptographic measurements (hashes) for those paths. Use the find\_cf\_path.sh wrapper or run cf\_path\_finder.py directly to analyze the binary. This will enumerate paths and export them to a CSV file.
```bash
cd tools/declass
./find_cf_path.sh ../Partition/<enclave_binary>
```

Equivalent manual commands:

```bash
python3 cf_path_finder.py ../Partition/<enclave_binary> \
    -s _start \
    --csv paths.csv \
    --csv-loops loops.csv
```
-s         : The symbol to start analysis from (default is entry point).

--csv      : Output file for the enumerated paths.

--csv-loops: Output file for detected loop information.

Once the paths are generated (e.g., in paths.csv), use the hasher tool to generate cryptographic measurements for each path.
```bash
./compute_path_hash.sh
```

or
```bash
python3 path_hasher.py paths.csv -o path_hashes.csv
```

---

### 4.3 Tag Enclave ELF with Taint/Hash Metadata
tools/elf-ift directory contains ELF preprocessing tools using ELFIO that prepare binaries to run under Kingsguard.
To attach metadata to the compiled binary:

  1. Add the hash computed in the previous step to tag-elf.cpp at line 62.
  2. Build the tag tool by running make inside tools/elf-ft directory.
  3. Run the compiled tag-elf binary by passing the desired binary to be tested with KingsGuard:

```bash
cd tools/elf-ift
make
./tag-elf ../Partition/<enclave_binary>
```

This will generate a modified ELF `<enclave_binary.kg>` with required metadata in tools/Partition folder.


---
### 4.4 Build Linux Kernel
The linux directory contains the modified linux kernel to support KingsGuard.
```bash
cd linux
make ARCH=riscv CROSS_COMPILE=riscv64-unknown-linux-gnu- defconfig
make ARCH=riscv CROSS_COMPILE=riscv64-unknown-linux-gnu- all -j$(nproc)
```

This generates `vmlinux`, that should be used as payload to generate the `bbl` image explained below.

---

### 4.5 Build RISC-V Proxy Kernel

```bash
cd riscv-pk
mkdir -p build
cd build
```

```bash
../configure \
  --host=riscv64-unknown-linux-gnu \
  --with-payload=<absolute-path-to-linux/vmlinux> \
  --prefix=<absolute-path-to-riscv-toolchain>
```

```bash
make -j$(nproc)
```

This generates the `bbl` image. Use this image as the kernel input in the gem5 dull system configuration script (described later).

---
## 4.6. Disk Image Setup
KingsGuard runs in gem5 full-system mode and requires a RISC-V Linux disk image.

#### Option A: Use a Prebuilt Disk Image

If a prepared disk image is provided with this artifact, set its path in the gem5 configuration file described later.

Before booting gem5, copy the following files into the RISC-V disk image:

```text
<host_binary>
<enclave_binary>.kg
```
Place them inside the guest filesystem, for example inside `/home`.

This can be done by editing the disk image.

1. Open the disk image in write mode:

   ```bash
   sudo debugfs -w <absolute-path-to-riscv-disk-image>
   ```
2. Inside the debugfs prompt, write files into the disk image:
   ```bash
   write <path_to_binary> /home/<binary_name>
   ```

#### Option B: Build or Download a RISC-V Disk Image

If a disk image is not provided, create one using the official [gem5 RISC-V full-system resources](https://gem5.googlesource.com/public/gem5-resources/+/HEAD/src/riscv-fs/README.md).

After creating the disk image, copy the KingsGuard binaries into it explained above.

---
### 4.7 Build gem5
The gem5 directory contains the modified gem5 simulator used to model the Kingsguard architecture.
Refer to the [official gem5 documentation](https://www.gem5.org/documentation/general_docs/building) to install the dependencies.
To build the gem5 image for KingsGuard:
```bash
cd gem5
scons build/RISCV/gem5.opt -j$(nproc)
```

---

## 4.8. Running KingsGuard in gem5

Edit the following gem5 configuration script:

```text
gem5/configs/example/gem5_library/riscv-fs.py
```

Set the kernel and disk image paths:

```python
kernel = CustomResource("<absolute-path-to-riscv-pk/build/bbl>")
disk_image = CustomDiskImageResource("<absolute-path-to-riscv-disk-image>")
```

Run the gem5 full-system simulation:

```bash
cd gem5
./build/RISCV/gem5.opt configs/example/gem5_library/riscv-fs.py
```

In another terminal, connect to the simulated system:

```bash
cd gem5/util/term
./m5term localhost 3456
```

This terminal displays the kernel boot logs and eventually provides a login console. After Linux boots, login using username: root, password: root, and run the host binary from inside the guest system:

```bash
cd /home
./<host_binary>
```
### To run KingsGuard with SassCache implementation:

  ```bash
  ./build/RISCV/gem5.opt configs/example/gem5_library/riscv-fs-sass.py
  ```

