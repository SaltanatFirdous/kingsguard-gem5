# RISC-V FS + MinorCPU + classic caches
# Uses PrivateL1_TwoL2_TagSplit: per-core data L2 + tag L2 (shadow range)

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
    BaseXBar,
    Cache,
    L2XBar,
    Port,
    SystemXBar,
    AddrRange,
    NoncoherentXBar
)
from typing import Optional
from gem5.utils.override import *
# -----------------------------------------------------------------------------
# Sanity check
# -----------------------------------------------------------------------------
requires(isa_required=ISA.RISCV)



# -----------------------------------------------------------------------------
# Cache hierarchy: Data L2 + Tag L2 (tag range routes to tag L2)
# -----------------------------------------------------------------------------
# Set these to match your shadow mapping
TAG_BASE = 0xF0000000   # your shadow base
TAG_SIZE = "64MiB"      # your reserved shadow window size



class PrivateL1_TwoL2_TagSplit(PrivateL1PrivateL2CacheHierarchy):
    """
    Per-core:
      L1I/L1D  -> L2 XBar -> { L2_data (complement), L2_tag (shadow only) } -> membus
    """
    def _get_default_membus(self):
        membus = SystemXBar(width=64)
        membus.badaddr_responder = BadAddr()
        membus.default = membus.badaddr_responder.pio
        return membus
    def get_mem_side_coherent_io_port(self):
        # Only expose a coherent I/O port if the membus is coherent.
        if isinstance(self.membus, SystemXBar):
            return self.membus.mem_side_ports
        return None

    def __init__(
        self,
        l1d_size: str,
        l1i_size: str,
        l2_size: str,          # data L2 size
        l2_tag_size: str,      # tag L2 size
        tag_addr_base: int,    # shadow base (e.g., 0x80D00000)
        tag_addr_size: str,    # shadow size (e.g., "64MiB")
        membus: Optional[BaseXBar] = None,
    ) -> None:


        
        # Build everything as usual (membus, per-core tol2 buses, etc.).
        super().__init__(l1d_size=l1d_size, l1i_size=l1i_size, l2_size=l2_size, membus=membus)
        self.membus = membus if membus else self._get_default_membus()
        
        self._l2_tag_size = l2_tag_size
        self._tag_addr_base = tag_addr_base
        self._tag_addr_size = tag_addr_size
        self._tag_range = AddrRange(tag_addr_base, size=tag_addr_size)

    @overrides(PrivateL1PrivateL2CacheHierarchy)
    def get_mem_side_port(self) -> Port:
            return self.membus.mem_side_ports
    @overrides(PrivateL1PrivateL2CacheHierarchy)
    def get_cpu_side_port(self) -> Port:
            return self.membus.cpu_side_ports
    def _dump_ranges(self, name, ranges):
            # ranges is a list of AddrRange
            for i, r in enumerate(ranges):
                s = int(r.start)
                e = int(r.end)
                try:
                    sz = int(r.size())
                except Exception:
                    sz = (e - s + 1)
                print(f"[range:{name}#{i}] [{s:#018x} .. {e:#018x}]  size={sz:#x}")


    def _connect_table_walker(self, cpu_id: int, cpu: BaseCPU) -> None:
            cpu.connect_walker_ports(
                self.membus.cpu_side_ports, self.membus.cpu_side_ports
            )

    

    @overrides(PrivateL1PrivateL2CacheHierarchy)
    def incorporate_cache(self, board: AbstractBoard) -> None:
            # Let the base set up membus/system_port and get per-core L2 XBars ready.
            # We'll recreate the per-core caches manually instead of calling super().incorporate_cache
            # because we want two L2s, not one.
            # ---- Begin: minimal copy of base's preamble ----
            board.connect_system_port(self.membus.cpu_side_ports)
            for _, port in board.get_mem_ports():
                self.membus.mem_side_ports = port
            # self.l2buses = [L2XBar() for _ in range(board.get_processor().get_num_cores())]
            self.l2buses = [L2XBar() for _ in range(board.get_processor().get_num_cores())]  #is 1 bus enough, how is icache and dcache connected to core
            # ---- End: preamble ----

            for i, cpu in enumerate(board.get_processor().get_cores()):
                # Create TWO L2s: data + tag
                l2d_node = self.add_root_child(f"l2d-cache-{i}", L2Cache(size=self._l2_size))
                l2t_node = self.add_root_child(f"l2t-cache-{i}", L2Cache(size=self._l2_tag_size))

                

                # L1s (same as base; children just for naming)
                l1i_node = l2d_node.add_child(f"l1i-cache-{i}", L1ICache(size=self._l1i_size))
                l1d_node = l2d_node.add_child(f"l1d-cache-{i}", L1DCache(size=self._l1d_size))

                # Address ownership: tag L2 owns shadow; data L2 owns complement.
                tag = self._tag_range
                MAX = (1 << 64) - 1
                s0 = int(tag.start)
                sz = int(tag.size())            # robust (don’t use end+1)
                lo = AddrRange(0, s0 - 1) if s0 > 0 else None
                hi0 = s0 + sz                   # first address after the tag window
                hi = AddrRange(hi0, MAX) if hi0 <= MAX else None

                l2t_node.cache.addr_ranges = [tag]
                l2d_node.cache.addr_ranges = [r for r in (lo, hi) if r is not None]

                # self._dump_ranges(f"core{i}.L2_tag", l2t_node.cache.addr_ranges)
                # self._dump_ranges(f"core{i}.L2_data", l2d_node.cache.addr_ranges)

                # L2 XBar -> both L2s (mem_side fans out; addr_ranges pick the target)
                self.l2buses[i].mem_side_ports = l2d_node.cache.cpu_side
                self.l2buses[i].mem_side_ports = l2t_node.cache.cpu_side


                # Both L2s -> membus
                self.membus.cpu_side_ports = l2d_node.cache.mem_side
                self.membus.cpu_side_ports = l2t_node.cache.mem_side

                


                # L1s -> per-core L2 XBar (cpu_side of the xbar)
                l1i_node.cache.mem_side = self.l2buses[i].cpu_side_ports
                l1d_node.cache.mem_side = self.l2buses[i].cpu_side_ports

                # CPU ↔ L1s (same as base)
                cpu.connect_icache(l1i_node.cache.cpu_side)
                cpu.connect_dcache(l1d_node.cache.cpu_side)

                # Walkers (uncached on membus) and interrupts (same as base)
                self._connect_table_walker(i, cpu)
                if board.get_processor().get_isa() == ISA.X86:
                    int_req_port = self.membus.mem_side_ports
                    int_resp_port = self.membus.cpu_side_ports
                    cpu.connect_interrupt(int_req_port, int_resp_port)
                else:
                    cpu.connect_interrupt()

            if board.has_coherent_io():
                self._setup_io_cache(board)
        

cache_hierarchy = PrivateL1_TwoL2_TagSplit(
        l1d_size="32KiB",
        l1i_size="32KiB",
        l2_size="512KiB",      # data L2 capacity
        l2_tag_size="256KiB",  # tag L2 capacity (cache size, not the window)
        tag_addr_base=TAG_BASE,
        tag_addr_size=TAG_SIZE,
    )

    # -----------------------------------------------------------------------------
    # Memory + CPU
    # -----------------------------------------------------------------------------
memory = SingleChannelDDR3_1600()

processor = SimpleProcessor(
        cpu_type=CPUTypes.MINOR, isa=ISA.RISCV, num_cores=1
    )

    # -----------------------------------------------------------------------------
    # Board
    # -----------------------------------------------------------------------------
board = RiscvBoard(
        clk_freq="1GHz",
        processor=processor,
        memory=memory,
        cache_hierarchy=cache_hierarchy,
    )
    # print("coherent I/O? ->", board.has_coherent_io())


    # Some builds need this explicit call; harmless if already handled internally
for core in board.get_processor().get_cores():
        cpu = getattr(core, "core", core)
        if hasattr(cpu, "createInterruptController"):
            cpu.createInterruptController()

    # -----------------------------------------------------------------------------
    # Workload
    # -----------------------------------------------------------------------------
kernel = BinaryResource("/root/riscv-pk/build/bbl")
disk_image = DiskImageResource(local_path="/root/disk-image/riscv-disk-img")

board.set_kernel_disk_workload(
        kernel=kernel,
        disk_image=disk_image,
    )

    # -----------------------------------------------------------------------------
    # Run
    # -----------------------------------------------------------------------------
simulator = Simulator(board=board)

print("Beginning simulation!")
simulator.run()
