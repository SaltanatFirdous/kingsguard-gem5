# run_min_fs.py
from gem5.components.boards.riscv_board import RiscvBoard
from gem5.components.processors.simple_processor import SimpleProcessor
from gem5.components.memory.single_channel import SingleChannelDDR3_1600
from gem5.components.platforms.simple_platform import SimplePlatform
from gem5.isas import ISA
from gem5.simulate.simulator import Simulator
from gem5.resources.resource import CustomResource

# TimingSimpleCPU setup
processor = SimpleProcessor(cpu_type="timing", isa=ISA.RISCV, num_cores=1)
board = RiscvBoard(
    clk_freq="1GHz",
    processor=processor,
    memory=SingleChannelDDR3_1600("3GB"),
    platform=SimplePlatform()
)

# Explicit kernel and disk
board.set_kernel_disk_workload(
    kernel=CustomResource("~/gem5-resources/bootloader-vmlinux-5.10"),
    disk_image=CustomResource("~/gem5-resources/ubuntu-22.04.5-preinstalled-server-riscv64+unmatched.img"),
    bootargs="console=ttyS0 root=/dev/vda1 ro"
)

Simulator(board=board).run()

