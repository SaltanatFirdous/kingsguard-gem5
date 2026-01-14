#!/usr/bin/env python3
"""
Control Flow Path Hashing Tool
Computes running hash for each control flow path matching gem5 C++ BranchHash.
"""

import sys
import hashlib
import csv
from collections import defaultdict

def parse_hex_address(addr_str):
    """Parse hex address string to integer (handles 0x prefix or bare hex)"""
    if not addr_str:
        return None
    try:
        # Handle "0x..." or just "..."
        if addr_str.lower().startswith('0x'):
            return int(addr_str, 16)
        elif addr_str.isdigit():
            return int(addr_str)
        else:
            # Try interpreting as hex even without 0x
            return int(addr_str, 16)
    except ValueError:
        return None

def compute_path_hash(path_steps, return_intermediates=False):
    """
    Compute path hash matching the C++ BranchHash implementation.
    
    Args:
        path_steps: List of tuples (source_addr, dest_addr)
        return_intermediates: If True, returns list of (step_str, hash) for every step.
                              If False, returns only final hex string.
    """
    hasher = hashlib.sha256()
    intermediates = []
    
    for src_addr, dst_addr in path_steps:
        # 1. Format exactly like C++: ss << std::hex << src << "-" << tgt
        # format(x, 'x') produces lowercase hex without '0x' or padding
        step_string = f"{format(src_addr, 'x')}-{format(dst_addr, 'x')}"
        
        # 2. Update the existing context (Cumulative)
        # Equivalent to: SHA256_Update(&ctx, s.c_str(), s.size())
        hasher.update(step_string.encode('ascii'))
        
        # 3. Store intermediate result if requested
        if return_intermediates:
            intermediates.append((step_string, hasher.hexdigest()))
            
    if return_intermediates:
        return intermediates
    else:
        return hasher.hexdigest()

def run_verification():
    """
    Internal test suite using the exact snippet logic you provided.
    """
    print(f"{'='*80}")
    print(f"VERIFICATION MODE")
    print(f"{'='*80}")
    
    # The 'path_101' test case
    path_101 = [
        (0x410184, 0x410190),
        (0x4101c4, 0x4100d8),
        (0x410100, 0x410124)
    ]
    
    print(f"Running test on 'path_101' (3 steps)...")
    print(f"{'Step':<5} | {'Input String':<20} | {'Cumulative Hash (So Far)'}")
    print("-" * 88)

    # Replicating your snippet's logic exactly for verification
    results = compute_path_hash(path_101, return_intermediates=True)
    
    for i, (step_str, h_val) in enumerate(results, 1):
        print(f"{i:<5} | {step_str:<20} | {h_val}")
        
    print("-" * 88)
    print("[+] Verification Complete.")

def process_paths_csv(input_csv, output_csv=None, verbose=False, trace_mode=False):
    """
    Read paths from CSV and compute hashes.
    """
    # Read CSV and group by path_id
    paths = defaultdict(list)
    
    try:
        with open(input_csv, 'r') as f:
            reader = csv.DictReader(f)
            if not reader.fieldnames:
                print(f"[!] Error: CSV file is empty")
                return
            
            # Clean field names
            reader.fieldnames = [name.strip() for name in reader.fieldnames]

            for row in reader:
                try:
                    path_id = int(row['path_id'])
                    src = parse_hex_address(row['source_address'].strip())
                    dst = parse_hex_address(row['destination_address'].strip())
                    
                    if src is None or dst is None:
                        continue
                    
                    paths[path_id].append((src, dst))
                except (ValueError, KeyError):
                    continue
    except Exception as e:
        print(f"[!] Error reading CSV: {e}")
        return

    if not paths:
        print("[!] No valid paths found.")
        return

    print(f"[+] Loaded {len(paths)} unique paths.")
    
    # Output structure
    path_hashes = {}
    
    for path_id in sorted(paths.keys()):
        steps = paths[path_id]
        
        if trace_mode:
            # If tracing, we print every single step as it happens
            print(f"\n[Path {path_id}] Trace:")
            results = compute_path_hash(steps, return_intermediates=True)
            for i, (step_str, h_val) in enumerate(results, 1):
                 print(f"  Step {i}: {step_str:<18} -> {h_val}")
            final_hash = results[-1][1]
        else:
            final_hash = compute_path_hash(steps, return_intermediates=False)

        path_hashes[path_id] = {
            'path_id': path_id,
            'num_steps': len(steps),
            'hash': final_hash
        }

    # CSV Export
    if output_csv:
        try:
            with open(output_csv, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=['path_id', 'num_steps', 'hash'])
                writer.writeheader()
                for pid in sorted(path_hashes.keys()):
                    writer.writerow(path_hashes[pid])
            print(f"\n[+] Saved results to {output_csv}")
        except Exception as e:
            print(f"[!] Error writing output: {e}")
    
    # Stdout Summary (if not tracing, since tracing is already verbose)
    if not trace_mode:
        print(f"\n{'Path ID':<10} {'Steps':<10} {'Final Hash'}")
        print("-" * 85)
        for pid in sorted(path_hashes.keys()):
            info = path_hashes[pid]
            print(f"{info['path_id']:<10} {info['num_steps']:<10} {info['hash']}")

def main():
    # 1. Handle Test Mode
    if '--test' in sys.argv:
        run_verification()
        sys.exit(0)

    # 2. Parse Arguments
    if len(sys.argv) < 2:
        print("Usage: python3 path_hasher.py <input_csv> [options]")
        print("Options:")
        print("  -o FILE       Output CSV")
        print("  --trace       Print the cumulative hash after every step (Debug mode)")
        print("  --test        Run verification against fixed input")
        sys.exit(1)

    input_csv = sys.argv[1]
    output_csv = None
    trace = False
    
    # Simple manual arg parsing to avoid dependencies
    args = sys.argv[2:]
    idx = 0
    while idx < len(args):
        if args[idx] == '-o' and idx+1 < len(args):
            output_csv = args[idx+1]
            idx += 2
        elif args[idx] == '--trace':
            trace = True
            idx += 1
        elif args[idx] in ['-v', '--verbose']:
            # Verbose is now implicit in trace, but kept for compatibility
            idx += 1
        else:
            idx += 1
            
    process_paths_csv(input_csv, output_csv, trace_mode=trace)

if __name__ == '__main__':
    main()
