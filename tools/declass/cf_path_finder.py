#!/usr/bin/env python3
"""
RISC-V Control Flow Path Enumeration - WITH LOOP DETECTION
Handles loops separately to prevent path explosion.
Strategies:
1. Detect backward branches (negative offsets) as potential loops
2. Track visited (address, return_stack) tuples to detect loop cycles
3. Single-iteration loop handling - take branch once, then take fall-through
4. Optional: Generate separate loop report
"""

import sys
from capstone import *
from capstone.riscv import *
from elftools.elf.elffile import ELFFile


def get_symbol_address(elf, symbol_name):
    """Get the address of a symbol"""
    symtab = elf.get_section_by_name('.symtab')
    if symtab:
        for symbol in symtab.iter_symbols():
            if symbol.name == symbol_name:
                return symbol['st_value']
    return None


def build_instruction_map(elf, md):
    """Build a map of all instructions by address"""
    instructions_by_addr = {}
    
    for section in elf.iter_sections():
        if not (section['sh_flags'] & 0x4) or section['sh_size'] == 0:
            continue
        
        section_data = section.data()
        section_addr = section['sh_addr']
        
        for instr in md.disasm(section_data, section_addr):
            instructions_by_addr[instr.address] = instr
    
    return instructions_by_addr


class CFPathEnumerator:
    """Enumerates all possible control flow paths in a function"""
    
    def __init__(self, md, instructions_by_addr, elf, debug=False):
        self.md = md
        self.instructions_by_addr = instructions_by_addr
        self.elf = elf
        self.paths = []
        self.loops_detected = []  # Track detected loops
        self.debug = debug
        self.max_linear_instructions = 1000
        
    def get_instruction_at(self, addr):
        """Get instruction at given address"""
        return self.instructions_by_addr.get(addr)
    
    def is_control_flow_instruction(self, instr):
        """Check if instruction is a control flow instruction"""
        mnemonic = instr.mnemonic.lower()
        op_str = instr.op_str.lower()
        
        # Conditional branches
        if mnemonic in ['beq', 'bne', 'blt', 'bge', 'bltu', 'bgeu', 'bnez', 'beqz']:
            return 'branch'
        
        # ret instruction is explicit return
        if mnemonic == 'ret':
            return 'return'
        
        # explicit call mnemonic
        if mnemonic == 'call':
            return 'call'
        
        # jal with x1/ra destination is a CALL
        if mnemonic == 'jal':
            if 'x1' in op_str or 'ra' in op_str:
                return 'call'
            operands = op_str.split(',')
            if len(operands) == 1:
                return 'call'
            return 'jump'
        
        # jalr with x1/ra destination is a RETURN or CALL
        if mnemonic == 'jalr':
            parts = op_str.split(',')
            if len(parts) > 0:
                rd = parts[0].strip()
                if 'ra' in rd or 'x1' in rd:
                    if len(parts) > 1:
                        rs1 = parts[1].strip()
                        if 'ra' in rs1 or 'x1' in rs1:
                            return 'return'
                    return 'call'
            return 'jump'
        
        # j and jr are unconditional jumps
        if mnemonic in ['j', 'jr']:
            return 'jump'
        
        return None
    
    def extract_target_address(self, instr):
        """Extract target address from control flow instruction"""
        try:
            if hasattr(instr, 'operands') and len(instr.operands) > 0:
                for op in instr.operands:
                    if op.type == RISCV_OP_IMM:
                        imm = op.imm
                        target = instr.address + imm
                        if target < 0:
                            target = target & 0xFFFFFFFFFFFFFFFF
                        return target
            
            op_str = instr.op_str
            
            if '(' in op_str and ')' in op_str:
                return None
            
            if '0x' in op_str:
                parts = op_str.split()
                for part in parts:
                    if '0x' in part:
                        addr_str = part.strip(',').strip()
                        try:
                            addr = int(addr_str, 16)
                            if addr < 0x10000:
                                return instr.address + addr
                            else:
                                return addr
                        except:
                            pass
            
            parts = op_str.split(',')
            for part in parts:
                part = part.strip()
                if part.lstrip('-').isdigit() and not part.startswith('x'):
                    try:
                        imm = int(part)
                        return instr.address + imm
                    except:
                        pass
            
            return None
        except:
            return None
    
    def get_fallthrough_addr(self, instr):
        """Get the fall-through address"""
        return instr.address + len(instr.bytes)
    
    def is_backward_branch(self, instr):
        """Check if a branch instruction targets backward (potential loop)"""
        if self.is_control_flow_instruction(instr) != 'branch':
            return False
        
        target = self.extract_target_address(instr)
        if isinstance(target, int):
            return target < instr.address
        return False
    
    def follow_linear_sequence(self, start_addr, max_instructions=1000):
        """
        Follow a linear sequence of non-CF instructions until hitting a CF instruction or invalid address.
        Returns the address of the first CF instruction found, or None if we exceed max_instructions.
        """
        current_addr = start_addr
        instructions_followed = 0
        
        while instructions_followed < max_instructions:
            instr = self.get_instruction_at(current_addr)
            if instr is None:
                return None
            
            if self.is_control_flow_instruction(instr) is not None:
                return current_addr
            
            current_addr = self.get_fallthrough_addr(instr)
            instructions_followed += 1
        
        return None
    
    def dfs_enumerate_paths(self, start_addr, current_path, return_stack=None, cf_depth=0, 
                            max_cf_depth=100, initial_func_start=None, visited_states=None):
        """
        DFS-based path enumeration with loop detection.
        
        Loop Handling Strategy:
        1. Detect when we revisit the same (address, return_stack) combination → indicate loop
        2. For backward branches: take the branch ONCE, then take fall-through
        3. Track all detected loops for reporting
        
        Args:
            start_addr: Current instruction address to process
            current_path: List of control flow steps taken so far
            return_stack: Stack of return addresses
            cf_depth: Current control flow decision depth
            max_cf_depth: Maximum CF depth allowed
            initial_func_start: Address of initial function
            visited_states: Set of (address, return_stack_tuple) already visited in THIS path
        """
        if return_stack is None:
            return_stack = []
        
        if visited_states is None:
            visited_states = set()
        
        if initial_func_start is None:
            initial_func_start = start_addr
        
        # Prevent excessive CF depth
        if cf_depth > max_cf_depth:
            if self.debug:
                print(f"[DEBUG] Max CF depth exceeded at 0x{start_addr:08x}, cf_depth={cf_depth}")
            return
        
        # Follow linear sequence until we hit a CF instruction
        cf_addr = self.follow_linear_sequence(start_addr, self.max_linear_instructions)
        
        if cf_addr is None:
            if self.debug:
                print(f"[DEBUG] End of linear sequence at 0x{start_addr:08x}")
            return
        
        # Check for loop revisit
        state_key = (cf_addr, tuple(sorted(return_stack)))
        if state_key in visited_states:
            if self.debug:
                print(f"[DEBUG] Loop detected: Revisiting 0x{cf_addr:08x}, abandoning this path")
            return  # Don't explore this - it's a loop we've already seen
        
        visited_states.add(state_key)
        
        # Get the CF instruction
        instr = self.get_instruction_at(cf_addr)
        if instr is None:
            return
        
        cf_type = self.is_control_flow_instruction(instr)
        
        if self.debug:
            print(f"[DEBUG] CF_Depth={cf_depth}, Addr=0x{cf_addr:08x}, Type={cf_type}, Instr={instr.mnemonic} {instr.op_str}, RetStackLen={len(return_stack)}")
        
        # ===== RETURN INSTRUCTION =====
        if cf_type == 'return':
            if self.debug:
                print(f"[DEBUG] RETURN at 0x{cf_addr:08x}, return_stack empty: {len(return_stack) == 0}")
            
            if return_stack:
                return_addr = return_stack[-1]
                if self.debug:
                    print(f"[DEBUG]   -> Returning to 0x{return_addr:08x}")
                self.dfs_enumerate_paths(return_addr, current_path, return_stack[:-1], cf_depth + 1, 
                                        max_cf_depth, initial_func_start, visited_states.copy())
            else:
                # Root return - record the path
                if self.debug:
                    print(f"[DEBUG] ROOT RETURN: Recording path with {len(current_path)} steps")
                self.paths.append(current_path[:])
            return
        
        # ===== CONDITIONAL BRANCH =====
        if cf_type == 'branch':
            taken_target = self.extract_target_address(instr)
            fallthrough = self.get_fallthrough_addr(instr)
            is_backward = isinstance(taken_target, int) and taken_target < instr.address

            print("taken_target: ", hex(taken_target))
            print("fallthrough: ", hex(fallthrough))
            print("is_backward: ", hex(is_backward))
            
            if is_backward:
                # Log backward branch as potential loop
                loop_info = {
                    'branch_addr': instr.address,
                    'target': taken_target,
                    'instruction': f"{instr.mnemonic} {instr.op_str}",
                    'loop_depth': cf_depth
                }
                if loop_info not in self.loops_detected:
                    self.loops_detected.append(loop_info)
                if self.debug:
                    print(f"[DEBUG]   *** BACKWARD BRANCH (Loop) at 0x{instr.address:08x} -> 0x{taken_target:08x}")
            
            # Branch taken path (explore it ONCE for backward branches to avoid explosion)
            if isinstance(taken_target, int):
                cf_step = {
                    'source': instr.address,
                    'destination': taken_target,
                    'type': 'branch-taken',
                    'instruction': f"{instr.mnemonic} {instr.op_str}"
                }
                current_path.append(cf_step)
                
                # For backward branches, only explore taken once to prevent loop explosion
                if not is_backward:
                    # Forward branch - normal exploration
                    self.dfs_enumerate_paths(taken_target, current_path, list(return_stack), cf_depth + 1, 
                                            max_cf_depth, initial_func_start, visited_states.copy())
                else:
                    # Backward branch - take it once, record loop, then skip further iterations
                    if self.debug:
                        print(f"[DEBUG]   Taking backward branch once for loop coverage")
                    self.dfs_enumerate_paths(taken_target, current_path, list(return_stack), cf_depth + 1, 
                                            max_cf_depth, initial_func_start, visited_states.copy())
                if(not is_backward):
                    current_path.pop()
            
            # Branch not-taken path (always explore)
            cf_step = {
                'source': instr.address,
                'destination': fallthrough,
                'type': 'branch-not-taken',
                'instruction': f"{instr.mnemonic} {instr.op_str}"
            }
            if(not is_backward):
                current_path.append(cf_step)
            self.dfs_enumerate_paths(fallthrough, current_path, list(return_stack), cf_depth + 1, 
                                    max_cf_depth, initial_func_start, visited_states.copy())
            current_path.pop()
            
            return
        
        # ===== CALL INSTRUCTION =====
        if cf_type == 'call':
            target = self.extract_target_address(instr)
            
            if self.debug:
                print(f"[DEBUG]   Call target: 0x{target:08x}" if isinstance(target, int) else "[DEBUG]   Call target: UNKNOWN")
            
            cf_step = {
                'source': instr.address,
                'destination': target,
                'type': 'call',
                'instruction': f"{instr.mnemonic} {instr.op_str}"
            }
            current_path.append(cf_step)
            
            if isinstance(target, int):
                return_addr = self.get_fallthrough_addr(instr)
                new_return_stack = list(return_stack) + [return_addr]
                if self.debug:
                    print(f"[DEBUG]   Pushing return addr 0x{return_addr:08x}")
                self.dfs_enumerate_paths(target, current_path, new_return_stack, cf_depth + 1, 
                                        max_cf_depth, initial_func_start, visited_states.copy())
            
            current_path.pop()
            return
        
        # ===== UNCONDITIONAL JUMP =====
        if cf_type == 'jump':
            target = self.extract_target_address(instr)
            
            if self.debug:
                print(f"[DEBUG]   Jump target: 0x{target:08x}" if isinstance(target, int) else "[DEBUG]   Jump target: UNKNOWN")
            
            cf_step = {
                'source': instr.address,
                'destination': target,
                'type': 'jump',
                'instruction': f"{instr.mnemonic} {instr.op_str}"
            }
            current_path.append(cf_step)
            
            if isinstance(target, int):
                self.dfs_enumerate_paths(target, current_path, list(return_stack), cf_depth + 1, 
                                        max_cf_depth, initial_func_start, visited_states.copy())
            
            current_path.pop()
            return
    
    def enumerate_from_address(self, start_addr):
        """Start path enumeration from a given address"""
        self.paths = []
        self.loops_detected = []
        if self.debug:
            print(f"\n[DEBUG] ===== Starting enumeration from 0x{start_addr:08x} =====\n")
        self.dfs_enumerate_paths(start_addr, [], None, 0, 100, start_addr, None)
        return self.paths
    
    def print_paths(self, out=sys.stdout, max_paths=None, start_addr=None):
        """Print all enumerated paths"""
        out.write(f"\n{'='*90}\n")
        out.write(f"CONTROL FLOW PATH ENUMERATION\n")
        out.write(f"{'='*90}\n\n")
        
        out.write(f"Total paths found: {len(self.paths)}\n")
        if start_addr:
            out.write(f"Starting from: 0x{start_addr:08x}\n")
        out.write("\n")
        
        for path_idx, path in enumerate(self.paths[:max_paths] if max_paths else self.paths):
            if not path:
                continue
            
            out.write(f"PATH {path_idx + 1}:\n")
            out.write(f"  Start: 0x{start_addr:08x}\n")
            
            for step in path:
                src = step['source']
                dst = step['destination']
                cf_type = step['type']
                instr = step['instruction']
                
                if isinstance(dst, int):
                    out.write(f"  0x{src:08x} -> 0x{dst:08x}  | {cf_type:<20} | {instr}\n")
                else:
                    out.write(f"  0x{src:08x} -> ???       | {cf_type:<20} | {instr}\n")
            
            out.write("\n")
    
    def print_loops(self, out=sys.stdout):
        """Print detected loops"""
        out.write(f"\n{'='*90}\n")
        out.write(f"DETECTED LOOPS\n")
        out.write(f"{'='*90}\n\n")
        
        if not self.loops_detected:
            out.write("No loops detected.\n")
            return
        
        out.write(f"Total loops detected: {len(self.loops_detected)}\n\n")
        
        for loop_idx, loop in enumerate(self.loops_detected):
            out.write(f"LOOP {loop_idx + 1}:\n")
            out.write(f"  Branch Address: 0x{loop['branch_addr']:08x}\n")
            out.write(f"  Target Address: 0x{loop['target']:08x}\n")
            out.write(f"  Instruction: {loop['instruction']}\n")
            out.write(f"  CF Depth: {loop['loop_depth']}\n")
            out.write("\n")
    
    def export_paths_to_csv(self, filename):
        """Export paths to CSV format"""
        with open(filename, 'w') as f:
            f.write("path_id,source_address,destination_address,cf_type,instruction\n")
            
            for path_idx, path in enumerate(self.paths):
                for step in path:
                    src = f"0x{step['source']:08x}"
                    dst = f"0x{step['destination']:08x}" if isinstance(step['destination'], int) else "unknown"
                    cf_type = step['type']
                    instr = step['instruction'].replace(',', ';')
                    
                    f.write(f"{path_idx},{src},{dst},{cf_type},\"{instr}\"\n")
        
        print(f"[+] Paths exported to: {filename}")
    
    def export_loops_to_csv(self, filename):
        """Export detected loops to CSV format"""
        with open(filename, 'w') as f:
            f.write("loop_id,branch_address,target_address,instruction,cf_depth\n")
            
            for loop_idx, loop in enumerate(self.loops_detected):
                branch_addr = f"0x{loop['branch_addr']:08x}"
                target_addr = f"0x{loop['target']:08x}"
                instr = loop['instruction'].replace(',', ';')
                cf_depth = loop['loop_depth']
                
                f.write(f"{loop_idx},{branch_addr},{target_addr},\"{instr}\",{cf_depth}\n")
        
        print(f"[+] Loops exported to: {filename}")


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 cf_path_enum.py <binary> [options]")
        print("\nOptions:")
        print("  -s SYMBOL         Start from symbol (default: entry point)")
        print("  -m MAX_PATHS      Max paths to display (default: 50)")
        print("  --csv FILE        Export detailed paths to CSV")
        print("  --csv-loops FILE  Export detected loops to CSV")
        print("  --debug           Enable debug output")
        print("\nExamples:")
        print("  python3 cf_path_enum.py enclave.riscv -s _start")
        print("  python3 cf_path_enum.py enclave.riscv -s _start --csv paths.csv --csv-loops loops.csv")
        print("  python3 cf_path_enum.py enclave.riscv -s _start --debug")
        sys.exit(1)
    
    filepath = sys.argv[1]
    symbol_name = None
    max_paths = 50
    csv_file = None
    csv_loops_file = None
    debug = False
    
    i = 2
    while i < len(sys.argv):
        if sys.argv[i] == '-s' and i + 1 < len(sys.argv):
            symbol_name = sys.argv[i + 1]
            i += 2
        elif sys.argv[i] == '-m' and i + 1 < len(sys.argv):
            max_paths = int(sys.argv[i + 1])
            i += 2
        elif sys.argv[i] == '--csv' and i + 1 < len(sys.argv):
            csv_file = sys.argv[i + 1]
            i += 2
        elif sys.argv[i] == '--csv-loops' and i + 1 < len(sys.argv):
            csv_loops_file = sys.argv[i + 1]
            i += 2
        elif sys.argv[i] == '--debug':
            debug = True
            i += 1
        else:
            i += 1
    
    with open(filepath, 'rb') as f:
        elf = ELFFile(f)
        
        if elf.header['e_machine'] != 'EM_RISCV':
            print(f"[!] Error: Not a RISC-V binary")
            return
        
        print(f"[+] RISC-V binary detected")
        
        start_addr = None
        if symbol_name:
            start_addr = get_symbol_address(elf, symbol_name)
            if start_addr is None:
                print(f"[!] Symbol '{symbol_name}' not found")
                return
            print(f"[+] Starting from '{symbol_name}' at 0x{start_addr:08x}")
        else:
            start_addr = elf.header['e_entry']
            print(f"[+] Starting from entry point at 0x{start_addr:08x}")
        
        md = Cs(CS_ARCH_RISCV, CS_MODE_RISCV64)
        md.detail = True
        
        print(f"[+] Building instruction map...")
        instructions_by_addr = build_instruction_map(elf, md)
        print(f"[+] Found {len(instructions_by_addr)} instructions")
        
        enumerator = CFPathEnumerator(md, instructions_by_addr, elf, debug=debug)
        
        print(f"[+] Enumerating all control flow paths...")
        paths = enumerator.enumerate_from_address(start_addr)
        
        print(f"[+] Enumeration complete. Found {len(paths)} unique paths")
        print(f"[+] Found {len(enumerator.loops_detected)} loops")
        
        enumerator.print_paths(max_paths=max_paths, start_addr=start_addr)
        enumerator.print_loops()
        
        if csv_file:
            enumerator.export_paths_to_csv(csv_file)
        
        if csv_loops_file:
            enumerator.export_loops_to_csv(csv_loops_file)


if __name__ == '__main__':
    main()
