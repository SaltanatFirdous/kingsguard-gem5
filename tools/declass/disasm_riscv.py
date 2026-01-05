#!/usr/bin/env python3
"""
RISC-V RV64 Disassembler with Control Flow Analysis and Loop Detection
Correctly identifies loops: only CONDITIONAL BRANCHES backward are loops
Now records both branch taken and branch not-taken (fall-through) destinations.
"""

import sys
from capstone import *
from capstone.riscv import *
from elftools.elf.elffile import ELFFile


class LoopDetector:
    """Detects and analyzes loops in the control flow"""
    
    def __init__(self):
        self.loops = []
        self.back_edges = []
        self.loop_headers = {}
        
    def find_back_edges(self, control_flow_edges):
        """
        Find back-edges that create loops
        Only CONDITIONAL BRANCHES backward are loops
        """
        back_edges = []
        for edge in control_flow_edges:
            # Only conditional branches (beq, bne, blt, bge, etc.) backward are loops
            if (edge['type'] == 'branch' and 
                edge['target'] is not None and 
                edge['target'] < edge['source']):
                back_edges.append(edge)
                self.back_edges.append(edge)
        
        return back_edges
    
    def detect_loops(self, control_flow_edges, all_instructions):
        """
        Detect loops using back-edge analysis
        A loop exists when a conditional branch targets an earlier instruction
        """
        back_edges = self.find_back_edges(control_flow_edges)
        
        for back_edge in back_edges:
            loop_header = back_edge['target']
            loop_exit = back_edge['source']
            
            loop_info = {
                'header': loop_header,
                'exit': loop_exit,
                'back_edge': back_edge,
                'instructions': [],
                'nested_loops': [],
                'contains_calls': False,
                'loop_body_size': 0
            }
            
            # Find all instructions in the loop (from header to exit)
            for instr_addr in all_instructions:
                if loop_header <= instr_addr <= loop_exit:
                    loop_info['instructions'].append(instr_addr)
            
            loop_info['loop_body_size'] = len(loop_info['instructions'])
            
            # Check if loop contains function calls
            for edge in control_flow_edges:
                if edge['type'] == 'call' and loop_header <= edge['source'] <= loop_exit:
                    loop_info['contains_calls'] = True
            
            self.loops.append(loop_info)
            self.loop_headers[loop_header] = loop_info
        
        # Detect nested loops
        self._detect_nested_loops()
        
        return self.loops
    
    def _detect_nested_loops(self):
        """Detect loops nested inside other loops"""
        for i, loop1 in enumerate(self.loops):
            for j, loop2 in enumerate(self.loops):
                if i != j:
                    # Check if loop2 is nested inside loop1
                    if (loop1['header'] <= loop2['header'] and 
                        loop2['exit'] <= loop1['exit'] and
                        loop1['header'] != loop2['header']):
                        if loop2 not in loop1['nested_loops']:
                            loop1['nested_loops'].append(loop2)
    
    def print_report(self, out=sys.stdout):
        """Print loop analysis report"""
        if not self.loops:
            out.write("\n[*] No loops detected (only conditional branches backward are loops)\n")
            return
        
        out.write(f"\n{'='*70}\n")
        out.write(f"LOOP ANALYSIS REPORT\n")
        out.write(f"{'='*70}\n\n")
        
        out.write(f"Total loops detected: {len(self.loops)}\n")
        out.write(f"Back-edges (loop-creating branches): {len(self.back_edges)}\n\n")
        
        # Group loops by nesting level
        top_level_loops = [l for l in self.loops if not self._is_nested_in_another(l)]
        nested_loops = [l for l in self.loops if l in self._get_all_nested_loops()]
        
        out.write(f"Top-level loops: {len(top_level_loops)}\n")
        out.write(f"Nested loops: {len(nested_loops)}\n\n")
        
        # Print each loop
        for i, loop in enumerate(self.loops):
            nesting_level = self._get_nesting_level(loop)
            indent = "  " * nesting_level
            
            out.write(f"{indent}Loop {i+1}:\n")
            out.write(f"{indent}  Header (entry): 0x{loop['header']:08x}\n")
            out.write(f"{indent}  Conditional branch (back-edge): 0x{loop['back_edge']['source']:08x}\n")
            out.write(f"{indent}  Loop body size: {loop['loop_body_size']} instructions\n")
            out.write(f"{indent}  Contains function calls: {loop['contains_calls']}\n")
            out.write(f"{indent}  Nested loops: {len(loop['nested_loops'])}\n")
            out.write(f"{indent}  Instruction range: 0x{loop['header']:08x} to 0x{loop['exit']:08x}\n")
            out.write(f"{indent}  Branch type: {loop['back_edge']['instruction']}\n\n")
    
    def _is_nested_in_another(self, loop):
        """Check if loop is nested in another loop"""
        for other in self.loops:
            if loop != other:
                if (other['header'] <= loop['header'] and 
                    loop['exit'] <= other['exit']):
                    return True
        return False
    
    def _get_all_nested_loops(self):
        """Get all loops that are nested in other loops"""
        nested = []
        for loop in self.loops:
            if self._is_nested_in_another(loop):
                nested.append(loop)
        return nested
    
    def _get_nesting_level(self, loop):
        """Get nesting level of a loop (0 = top-level)"""
        level = 0
        for other in self.loops:
            if other != loop:
                if (other['header'] <= loop['header'] and 
                    loop['exit'] <= other['exit']):
                    level += 1
        return level


class ControlFlowAnalyzer:
    """Analyzes control flow in RISC-V code"""
    
    def __init__(self):
        self.control_flow_edges = []
        self.function_calls = []
        self.returns = []
        self.branches = []
        self.jumps = []
        self.instructions_dict = {}
        self.loop_detector = LoopDetector()
        
    def is_control_flow_instruction(self, instr):
        """Check if instruction is a control flow instruction"""
        mnemonic = instr.mnemonic.lower()
        
        # Conditional branches
        if mnemonic in ['beq', 'bne', 'blt', 'bge', 'bltu', 'bgeu']:
            return 'branch'
        
        # Jump-and-link instructions
        if mnemonic in ['jal', 'jalr']:
            if 'ra' in instr.op_str or 'x1' in instr.op_str:
                parts = instr.op_str.split(',')
                if len(parts) > 0 and ('ra' in parts[0] or 'x1' in parts[0]):
                    return 'call'
            if mnemonic == 'jalr' and len(instr.op_str.split(',')) > 1:
                src_reg = instr.op_str.split(',')[1].strip()
                if 'ra' in src_reg or 'x1' in src_reg:
                    return 'return'
            return 'jump'
        
        if mnemonic == 'ret':
            return 'return'
        
        if mnemonic == 'call':
            return 'call'
        
        # Unconditional jumps
        if mnemonic in ['j', 'jr']:
            return 'jump'
        
        return None
    
    def extract_target_address(self, instr):
        """Extract target address from control flow instruction"""
        try:
            # Prefer operand-immediate-based target (PC-relative)
            if hasattr(instr, 'operands') and len(instr.operands) > 0:
                for op in instr.operands:
                    if op.type == RISCV_OP_IMM:
                        imm = op.imm
                        target = instr.address + imm
                        if target < 0:
                            target = target & 0xFFFFFFFFFFFFFFFF
                        return target
            
            op_str = instr.op_str
            
            # Skip register-indirect targets like jalr x0, ra, 0
            if '(' in op_str and ')' in op_str:
                parts = op_str.split('(')
                if len(parts) > 0:
                    offset_part = parts[0].split(',')[-1].strip()
                    if offset_part.isdigit() or offset_part.startswith('-'):
                        return None
            
            # Look for explicit hex absolute/relative
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
            
            # Decimal immediate as relative offset
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
    
    def analyze_instruction(self, instr):
        """Analyze a single instruction for control flow"""
        cf_type = self.is_control_flow_instruction(instr)
        
        if cf_type is None:
            return
        
        source_addr = instr.address
        taken_target = self.extract_target_address(instr)
        
        # Fall-through is the not-taken destination (next sequential PC)
        fallthrough_target = None
        if cf_type in ['branch', 'call', 'jump']:
            # Use the actual instruction length so this works with 16-bit C-extension too
            fallthrough_target = source_addr + len(instr.bytes)
        
        edge = {
            'source': source_addr,
            'target': taken_target,           # taken branch / jump target
            'fallthrough': fallthrough_target, # branch-not-taken or next PC
            'type': cf_type,
            'instruction': f"{instr.mnemonic} {instr.op_str}",
            'bytes': instr.bytes
        }
        
        self.control_flow_edges.append(edge)
        self.instructions_dict[source_addr] = instr
        
        if cf_type == 'branch':
            self.branches.append(edge)
        elif cf_type == 'call':
            self.function_calls.append(edge)
        elif cf_type == 'jump':
            self.jumps.append(edge)
        elif cf_type == 'return':
            self.returns.append(edge)
    
    def detect_loops(self):
        """Detect loops in the control flow"""
        all_instructions = sorted(self.instructions_dict.keys())
        return self.loop_detector.detect_loops(self.control_flow_edges, all_instructions)
    
    def print_report(self, out=sys.stdout):
        """Print control flow analysis report"""
        out.write(f"\n{'='*70}\n")
        out.write(f"CONTROL FLOW ANALYSIS REPORT\n")
        out.write(f"{'='*70}\n\n")
        
        out.write(f"Total control flow instructions: {len(self.control_flow_edges)}\n")
        out.write(f"  - Conditional branches: {len(self.branches)}\n")
        out.write(f"  - Function calls: {len(self.function_calls)}\n")
        out.write(f"  - Jumps: {len(self.jumps)}\n")
        out.write(f"  - Returns: {len(self.returns)}\n\n")
        
        if self.branches:
            out.write(f"\n--- CONDITIONAL BRANCHES ({len(self.branches)}) ---\n")
            for edge in self.branches:
                taken = f"0x{edge['target']:08x}" if edge['target'] else "unknown"
                fallthrough = f"0x{edge['fallthrough']:08x}" if edge.get('fallthrough') else "unknown"
                is_loop = " [BACKWARD - potential loop]" if (edge['target'] and edge['target'] < edge['source']) else ""
                out.write(
                    f"0x{edge['source']:08x} -> taken:{taken:<15} "
                    f"not-taken:{fallthrough:<15} | {edge['instruction']}{is_loop}\n"
                )
        
        if self.function_calls:
            out.write(f"\n--- FUNCTION CALLS ({len(self.function_calls)}) ---\n")
            for edge in self.function_calls:
                taken = f"0x{edge['target']:08x}" if edge['target'] else "unknown"
                fallthrough = f"0x{edge['fallthrough']:08x}" if edge.get('fallthrough') else "unknown"
                out.write(
                    f"0x{edge['source']:08x} -> target:{taken:<15} "
                    f"fallthrough:{fallthrough:<15} | {edge['instruction']}\n"
                )
        
        if self.jumps:
            out.write(f"\n--- JUMPS (unconditional) ({len(self.jumps)}) ---\n")
            for edge in self.jumps:
                taken = f"0x{edge['target']:08x}" if edge['target'] else "unknown"
                fallthrough = f"0x{edge['fallthrough']:08x}" if edge.get('fallthrough') else "unknown"
                is_backward = " [backward - control flow]" if (edge['target'] and edge['target'] < edge['source']) else ""
                out.write(
                    f"0x{edge['source']:08x} -> target:{taken:<15} "
                    f"fallthrough:{fallthrough:<15} | {edge['instruction']}{is_backward}\n"
                )
        
        if self.returns:
            out.write(f"\n--- RETURNS ({len(self.returns)}) ---\n")
            for edge in self.returns:
                out.write(f"0x{edge['source']:08x} | {edge['instruction']}\n")
        
        # Print loop analysis
        self.loop_detector.print_report(out)
    
    def export_dot_graph(self, filename):
        """Export control flow graph in DOT format"""
        with open(filename, 'w') as f:
            f.write("digraph ControlFlow {\n")
            f.write("  rankdir=TB;\n")
            f.write("  node [shape=box, fontname=\"monospace\"];\n\n")
            
            for edge in self.control_flow_edges:
                # Taken edge
                if edge['target']:
                    color = {
                        'branch': 'blue',
                        'call': 'green',
                        'jump': 'red',
                        'return': 'orange'
                    }.get(edge['type'], 'black')
                    
                    # Highlight loop-creating branches with bold style
                    style = "solid"
                    width = "1"
                    if edge['type'] == 'branch' and edge['target'] < edge['source']:
                        style = "bold"
                        width = "2"
                        color = "darkblue"
                    
                    label = edge['instruction'].replace('"', '\\"')
                    f.write(f"  \"0x{edge['source']:08x}\" -> \"0x{edge['target']:08x}\" ")
                    f.write(f"[label=\"{label}\", color={color}, style={style}, penwidth={width}];\n")
                
                # Fall-through edge (not-taken path or next PC)
                if edge.get('fallthrough'):
                    ft_color = "gray"
                    ft_style = "dotted"
                    ft_label = "fallthrough"
                    f.write(f"  \"0x{edge['source']:08x}\" -> \"0x{edge['fallthrough']:08x}\" ")
                    f.write(f"[label=\"{ft_label}\", color={ft_color}, style={ft_style}, penwidth=1];\n")
            
            f.write("}\n")
        
        print(f"[+] Control flow graph exported to: {filename}")
        print(f"    Bold/thick edges = loop-creating branches (conditional backward jumps)")
        print(f"    Gray dotted edges = fall-through (branch not-taken / next PC)")
        print(f"    Visualize with: dot -Tpng {filename} -o cfg.png")
    
    def export_csv(self, filename):
        """Export control flow edges to CSV"""
        with open(filename, 'w') as f:
            f.write("source_address,taken_target,fallthrough_target,type,instruction,is_backward,creates_loop\n")
            for edge in self.control_flow_edges:
                taken = f"0x{edge['target']:08x}" if edge['target'] else "unknown"
                fallthrough = f"0x{edge['fallthrough']:08x}" if edge.get('fallthrough') else "unknown"
                is_backward = "yes" if (edge['target'] and edge['target'] < edge['source']) else "no"
                creates_loop = "yes" if (edge['type'] == 'branch' and edge['target'] and edge['target'] < edge['source']) else "no"
                f.write(
                    f"0x{edge['source']:08x},{taken},{fallthrough},"
                    f"{edge['type']},{edge['instruction']},{is_backward},{creates_loop}\n"
                )
        
        print(f"[+] Control flow data exported to: {filename}")


def get_symbol_address(elf, symbol_name):
    """Get the address of a symbol"""
    symtab = elf.get_section_by_name('.symtab')
    if symtab:
        for symbol in symtab.iter_symbols():
            if symbol.name == symbol_name:
                return symbol['st_value']
    return None


def disassemble_with_control_flow(filepath, symbol_name=None, output_file=None, 
                                   max_instructions=None, export_dot=None, export_csv=None):
    """Disassemble and analyze control flow with corrected loop detection"""
    
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
                start_addr = elf.header['e_entry']
            print(f"[+] Starting from '{symbol_name}' at 0x{start_addr:08x}")
        
        md = Cs(CS_ARCH_RISCV, CS_MODE_RISCV64)
        md.detail = True
        
        cf_analyzer = ControlFlowAnalyzer()
        
        out = open(output_file, 'w') if output_file else sys.stdout
        
        try:
            out.write(f"{'='*70}\n")
            out.write(f"RISC-V RV64 Disassembly with Control Flow & Loop Analysis\n")
            out.write(f"File: {filepath}\n")
            if symbol_name:
                out.write(f"Starting from: {symbol_name} (0x{start_addr:08x})\n")
            out.write(f"Loop Detection: Only conditional branches backward are loops\n")
            out.write(f"{'='*70}\n\n")
            
            total_instructions = 0
            
            sections_to_disasm = []
            for section in elf.iter_sections():
                if not (section['sh_flags'] & 0x4) or section['sh_size'] == 0:
                    continue
                
                if start_addr:
                    if section['sh_addr'] <= start_addr < section['sh_addr'] + section['sh_size']:
                        sections_to_disasm.append(section)
                    elif section['sh_addr'] >= start_addr:
                        sections_to_disasm.append(section)
                else:
                    sections_to_disasm.append(section)
            
            first_section = True
            for section in sections_to_disasm:
                section_data = section.data()
                section_addr = section['sh_addr']
                
                if first_section and start_addr and section['sh_addr'] <= start_addr < section['sh_addr'] + section['sh_size']:
                    offset = start_addr - section_addr
                    data_to_disasm = section_data[offset:]
                    disasm_addr = start_addr
                    first_section = False
                else:
                    data_to_disasm = section_data
                    disasm_addr = section_addr
                
                out.write(f"\n--- Section: {section.name} ---\n")
                out.write(f"Address: 0x{disasm_addr:08x} - 0x{disasm_addr + len(data_to_disasm):08x}\n\n")
                
                for instr in md.disasm(data_to_disasm, disasm_addr):
                    cf_analyzer.analyze_instruction(instr)
                    cf_type = cf_analyzer.is_control_flow_instruction(instr)
                    cf_marker = ""
                    
                    if cf_type and cf_analyzer.control_flow_edges:
                        last_edge = cf_analyzer.control_flow_edges[-1]
                        taken = last_edge['target']
                        fallthrough = last_edge.get('fallthrough')

                        # Pre-format safely
                        taken_str = f"0x{taken:08x}" if isinstance(taken, int) else "unknown"
                        ft_str = f"0x{fallthrough:08x}" if isinstance(fallthrough, int) else "unknown"
                        
                        if cf_type == 'branch':
                            if isinstance(taken, int):
                                loop_flag = ""
                                if taken < last_edge['source']:
                                    loop_flag = " [LOOP]"
                                cf_marker = (
                                    f"  <-- BRANCH taken->{taken_str}, "
                                    f"not-taken->{ft_str}{loop_flag}"
                                )
                            else:
                                cf_marker = f"  <-- BRANCH not-taken->{ft_str}"
                        elif cf_type in ['call', 'jump']:
                            if isinstance(taken, int):
                                cf_marker = (
                                    f"  <-- {cf_type.upper()} -> {taken_str} "
                                    f"(fallthrough {ft_str})"
                                )
                            else:
                                cf_marker = (
                                    f"  <-- {cf_type.upper()} "
                                    f"(fallthrough {ft_str})"
                                )
                        else:
                            # returns, etc. – no fallthrough address
                            cf_marker = f"  <-- {cf_type.upper()}"
                    
                    out.write(f"0x{instr.address:08x}  ")
                    out.write(f"{' '.join(f'{b:02x}' for b in instr.bytes):<16}  ")
                    out.write(f"{instr.mnemonic:<8} {instr.op_str:<30}")
                    out.write(f"{cf_marker}\n")

                    
                    total_instructions += 1
                    
                    if max_instructions and total_instructions >= max_instructions:
                        break
                
                if max_instructions and total_instructions >= max_instructions:
                    break
            
            out.write(f"\nTotal instructions: {total_instructions}\n")
            
            # Detect and print loops
            print(f"[+] Detecting loops (conditional branches backward only)...")
            loops = cf_analyzer.detect_loops()
            print(f"[+] Found {len(loops)} loops")
            
            cf_analyzer.print_report(out)
            
            if export_dot:
                cf_analyzer.export_dot_graph(export_dot)
            
            if export_csv:
                cf_analyzer.export_csv(export_csv)
        
        finally:
            if output_file:
                out.close()
                print(f"[+] Disassembly saved to: {output_file}")


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 disasm_riscv_cfg.py <binary> [options]")
        print("\nOptions:")
        print("  -s SYMBOL      Start from symbol")
        print("  -o FILE        Save disassembly to file")
        print("  -n COUNT       Max instructions")
        print("  --dot FILE     Export control flow graph in DOT format")
        print("  --csv FILE     Export control flow edges to CSV")
        print("\nLoop Detection:")
        print("  - Only CONDITIONAL BRANCHES backward are loops")
        print("  - Unconditional jumps backward are just control flow")
        print("\nExamples:")
        print("  python3 disasm_riscv_cfg.py hello.riscv -s _start -o out.txt")
        print("  python3 disasm_riscv_cfg.py hello.riscv --dot cfg.dot --csv cfg.csv")
        sys.exit(1)
    
    filepath = sys.argv[1]
    symbol_name = None
    output_file = None
    max_instructions = None
    dot_file = None
    csv_file = None
    
    i = 2
    while i < len(sys.argv):
        if sys.argv[i] == '-s' and i + 1 < len(sys.argv):
            symbol_name = sys.argv[i + 1]
            i += 2
        elif sys.argv[i] == '-o' and i + 1 < len(sys.argv):
            output_file = sys.argv[i + 1]
            i += 2
        elif sys.argv[i] == '-n' and i + 1 < len(sys.argv):
            max_instructions = int(sys.argv[i + 1])
            i += 2
        elif sys.argv[i] == '--dot' and i + 1 < len(sys.argv):
            dot_file = sys.argv[i + 1]
            i += 2
        elif sys.argv[i] == '--csv' and i + 1 < len(sys.argv):
            csv_file = sys.argv[i + 1]
            i += 2
        else:
            i += 1
    
    disassemble_with_control_flow(filepath, symbol_name, output_file, 
                                   max_instructions, dot_file, csv_file)


if __name__ == '__main__':
    main()
