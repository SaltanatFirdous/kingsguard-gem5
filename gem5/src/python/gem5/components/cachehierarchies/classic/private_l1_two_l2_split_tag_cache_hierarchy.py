# Two-L2 split: data L2 + tag L2 (per-core), L1s shared for data+tags.
# Inherits all the good wiring from the stdlib base class.

from m5.objects import AddrRange, L2XBar
from gem5.components.cachehierarchies.classic.private_l1_private_l2_cache_hierarchy import (
    PrivateL1PrivateL2CacheHierarchy,
)
from gem5.components.cachehierarchies.classic.caches.l2cache import L2Cache
from gem5.components.cachehierarchies.classic.caches.l1icache import L1ICache
from gem5.components.cachehierarchies.classic.caches.l1dcache import L1DCache
from gem5.components.boards.abstract_board import AbstractBoard
from gem5.components.processors.cpu_types import BaseCPU
from gem5.components.cachehierarchies.classic.abstract_classic_cache_hierarchy import (
    AbstractClassicCacheHierarchy,
)
from gem5.components.cachehierarchies.abstract_cache_hierarchy import (
    AbstractCacheHierarchy,
)
from gem5.components.cachehierarchies.classic.abstract_two_level_cache_hierarchy import (
    AbstractTwoLevelCacheHierarchy,
)
from gem5.isas import ISA

class PrivateL1_TwoL2_TagSplit(PrivateL1PrivateL2CacheHierarchy):
    """
    Per-core:
      L1I/L1D  -> L2 XBar -> { L2_data (complement), L2_tag (shadow only) } -> membus

    * Page-table walkers remain on membus (uncached) via the base class.
    * get_mem_side_port/get_cpu_side_port come from the base and are correct.
    """

    def __init__(
        self,
        l1d_size: str,
        l1i_size: str,
        l2_size: str,          # data L2 size
        l2_tag_size: str,      # tag L2 size
        tag_addr_base: int,    # shadow base (e.g., 0x80D00000)
        tag_addr_size: str,    # shadow size (e.g., "64MiB")
        membus=None,
    ) -> None:
        # Build everything as usual (membus, per-core tol2 buses, etc.).
        super().__init__(l1d_size=l1d_size, l1i_size=l1i_size, l2_size=l2_size, membus=membus)
        self._tag_range = AddrRange(tag_addr_base, size=tag_addr_size)
        self._l2_tag_size = l2_tag_size

    # Unchanged from base: walkers go to membus (good for RISC-V, avoids coherence asserts).
    def _connect_table_walker(self, cpu_id: int, cpu: BaseCPU) -> None:
        cpu.connect_walker_ports(self.membus.cpu_side_ports, self.membus.cpu_side_ports)

    def incorporate_cache(self, board: AbstractBoard) -> None:
        # Let the base set up membus/system_port and get per-core L2 XBars ready.
        # We'll recreate the per-core caches manually instead of calling super().incorporate_cache
        # because we want two L2s, not one.
        # ---- Begin: minimal copy of base's preamble ----
        board.connect_system_port(self.membus.cpu_side_ports)
        for _, port in board.get_mem_ports():
            self.membus.mem_side_ports = port
        self.l2buses = [L2XBar() for _ in range(board.get_processor().get_num_cores())]
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
            s0, s1 = int(tag.start), int(tag.end)
            lo = AddrRange(0, s0 - 1) if s0 > 0 else None
            hi = AddrRange(s1 + 1, MAX) if s1 < MAX else None
            l2t_node.cache.addr_ranges = [tag]
            l2d_node.cache.addr_ranges = [r for r in (lo, hi) if r is not None]

            # L1s -> per-core L2 XBar (cpu_side of the xbar)
            l1i_node.cache.mem_side = self.l2buses[i].cpu_side_ports
            l1d_node.cache.mem_side = self.l2buses[i].cpu_side_ports

            # L2 XBar -> both L2s (mem_side fans out; addr_ranges pick the target)
            self.l2buses[i].mem_side_ports = l2d_node.cache.cpu_side
            self.l2buses[i].mem_side_ports = l2t_node.cache.cpu_side

            # Both L2s -> membus
            self.membus.cpu_side_ports = l2d_node.cache.mem_side
            self.membus.cpu_side_ports = l2t_node.cache.mem_side

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
