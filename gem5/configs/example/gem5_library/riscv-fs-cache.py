# RISC-V FS + MinorCPU + classic caches
# L1I/L1D per core, two L2s (data + tag via AddrRange split)
# COHERENT system bus with proper I/O-coherence shim (fixes xbar assert)

from gem5.components.boards.riscv_board import RiscvBoard
from gem5.components.boards.abstract_board import AbstractBoard
from gem5.components.cachehierarchies.classic.private_l1_private_l2_cache_hierarchy import (
    PrivateL1PrivateL2CacheHierarchy,
)
from gem5.components.cachehierarchies.classic.caches.l2cache import L2Cache
from gem5.components.cachehierarchies.classic.caches.l1icache import L1ICache
from gem5.components.cachehierarchies.classic.caches.l1dcache import L1DCache
from gem5.components.memory import SingleChannelDDR3_1600
from gem5.components.processors.cpu_types import CPUTypes
from gem5.components.processors.simple_processor import SimpleProcessor
from gem5.isas import ISA
from gem5.simulate.simulator import Simulator
from gem5.utils.requires import requires
from gem5.resources.resource import BinaryResource, DiskImageResource

from m5.objects import (
    BadAddr,
    BaseCPU,
    Cache,
    L2XBar,
    SystemXBar,
    AddrRange,
)
from typing import Optional

requires(isa_required=ISA.RISCV)

# ---------- coherent I/O capable board ----------
class RiscvBoardCoIO(RiscvBoard):
    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        # a dedicated attach point for coherent devices
        self.coherent_io_bus = SystemXBar(width=64)
        self.add_child("coherent_io_bus", self.coherent_io_bus)

    def has_coherent_io(self) -> bool:
        return True

    # devices (virtio, etc.) will attach here
    def get_mem_side_coherent_io_port(self):
        return self.coherent_io_bus.mem_side_ports

    # optional upstream if something needs it
    def get_cpu_side_coherent_io_port(self):
        return self.coherent_io_bus.cpu_side_ports

# ---------- parameters for your shadow/tag window ----------
TAG_BASE = 0xF0000000
TAG_SIZE = "64MiB"

class PrivateL1_TwoL2_TagSplit(PrivateL1PrivateL2CacheHierarchy):
    """
    Per-core:
      L1I/L1D -> tol2 (coherent L2 XBar) -> { L2_data (complement), L2_tag (shadow) } -> membus (coherent)
    DMA devices attach to board.coherent_io_bus -> iocache -> membus (coherent)
    """

    def _get_default_membus(self) -> SystemXBar:
        membus = SystemXBar(width=64)
        membus.badaddr_responder = BadAddr()
        membus.default = membus.badaddr_responder.pio
        return membus

    def __init__(
        self,
        l1d_size: str,
        l1i_size: str,
        l2_size: str,
        l2_tag_size: str,
        tag_addr_base: int,
        tag_addr_size: str,
        membus: Optional[SystemXBar] = None,
    ) -> None:
        super().__init__(l1d_size=l1d_size, l1i_size=l1i_size, l2_size=l2_size, membus=membus)
        self.membus = membus if membus else self._get_default_membus()
        self._tag_range = AddrRange(tag_addr_base, size=tag_addr_size)
        self._l2_tag_size = l2_tag_size

    def _connect_table_walker(self, cpu_id: int, cpu: BaseCPU) -> None:
        # walkers uncached on membus
        cpu.connect_walker_ports(self.membus.cpu_side_ports, self.membus.cpu_side_ports)

    def _setup_io_cache(self, board: AbstractBoard) -> None:
        """I/O-coherence shim between devices and the coherent membus."""
        self.iocache = Cache(
            assoc=8,
            tag_latency=50,
            data_latency=50,
            response_latency=50,
            mshrs=20,
            size="1KiB",
            tgts_per_mshr=12,
            addr_ranges=board.mem_ranges,
        )
        # iocache sits BETWEEN devices and membus
        self.iocache.mem_side = self.membus.cpu_side_ports             # toward system bus
        self.iocache.cpu_side = board.get_mem_side_coherent_io_port()  # devices attach here

    def incorporate_cache(self, board: AbstractBoard) -> None:
        # system_port (requestor) -> membus, and hook DRAM/controllers (responders)
        board.connect_system_port(self.membus.cpu_side_ports)
        for _, port in board.get_mem_ports():
            self.membus.mem_side_ports = port

        # coherent per-core L2 crossbars
        self.l2buses = [L2XBar() for _ in range(board.get_processor().get_num_cores())]

        for i, cpu in enumerate(board.get_processor().get_cores()):
            # TWO L2s per core
            l2d_node = self.add_root_child(f"l2d-cache-{i}", L2Cache(size=self._l2_size))
            l2t_node = self.add_root_child(f"l2t-cache-{i}", L2Cache(size=self._l2_tag_size))

            # L1s (children for naming)
            l1i_node = l2d_node.add_child(f"l1i-cache-{i}", L1ICache(size=self._l1i_size))
            l1d_node = l2d_node.add_child(f"l1d-cache-{i}", L1DCache(size=self._l1d_size))

            # perfect partition: tag window + complement (use start+size)
            tag = self._tag_range
            MAX = (1 << 64) - 1
            s0 = int(tag.start)
            sz = int(tag.size())
            lo = AddrRange(0, s0 - 1) if s0 > 0 else None
            hi0 = s0 + sz
            hi = AddrRange(hi0, MAX) if hi0 <= MAX else None

            l2t_node.cache.addr_ranges = [tag]
            l2d_node.cache.addr_ranges = [r for r in (lo, hi) if r is not None]

            # tol2 -> each L2 (one endpoint per assignment)
            self.l2buses[i].mem_side_ports = l2d_node.cache.cpu_side
            self.l2buses[i].mem_side_ports = l2t_node.cache.cpu_side

            # both L2s -> membus (coherent)
            self.membus.cpu_side_ports = l2d_node.cache.mem_side
            self.membus.cpu_side_ports = l2t_node.cache.mem_side

            # L1s -> tol2
            l1i_node.cache.mem_side = self.l2buses[i].cpu_side_ports
            l1d_node.cache.mem_side = self.l2buses[i].cpu_side_ports

            # CPU ↔ L1s
            cpu.connect_icache(l1i_node.cache.cpu_side)
            cpu.connect_dcache(l1d_node.cache.cpu_side)

            # walkers + interrupts
            self._connect_table_walker(i, cpu)
            if board.get_processor().get_isa() == ISA.X86:
                cpu.connect_interrupt(self.membus.mem_side_ports, self.membus.cpu_side_ports)
            else:
                cpu.connect_interrupt()

        # enable coherent I/O shim (this is the key for DMA)
        if board.has_coherent_io():
            self._setup_io_cache(board)

# ---------- build the platform ----------
cache_hierarchy = PrivateL1_TwoL2_TagSplit(
    l1d_size="32KiB",
    l1i_size="32KiB",
    l2_size="512KiB",      # data L2 capacity
    l2_tag_size="256KiB",  # tag L2 capacity
    tag_addr_base=TAG_BASE,
    tag_addr_size=TAG_SIZE,
)

memory = SingleChannelDDR3_1600()
processor = SimpleProcessor(cpu_type=CPUTypes.MINOR, isa=ISA.RISCV, num_cores=1)

board = RiscvBoardCoIO(
    clk_freq="1GHz",
    processor=processor,
    memory=memory,
    cache_hierarchy=cache_hierarchy,
)

# Some builds need this; harmless if redundant
for core in board.get_processor().get_cores():
    cpu = getattr(core, "core", core)
    if hasattr(cpu, "createInterruptController"):
        cpu.createInterruptController()

# ---------- workload ----------
kernel = BinaryResource("/root/riscv-pk/build/bbl")
disk_image = DiskImageResource(local_path="/root/disk-image/riscv-disk-img")
board.set_kernel_disk_workload(kernel=kernel, disk_image=disk_image)

# ---------- run ----------
sim = Simulator(board=board)
print("Beginning simulation!")
sim.run()
