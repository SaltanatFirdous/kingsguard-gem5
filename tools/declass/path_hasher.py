#!/usr/bin/env python3
"""
Control Flow Path Hashing Tool
Computes running hash for each control flow path.

For each path:
1. Initialize H_curr = 0
2. For each step in the path:
   - H_new = Hash(H_curr, source_address, destination_address)
   - H_curr = H_new
3. Output final hash for the path

Hash function: SHA256(H_curr || source_addr || dest_addr)
"""

import sys
import hashlib
import csv
from collections import defaultdict


def parse_hex_address(addr_str):
    """Parse hex address string to integer"""
    try:
        # Handle "0x00010240" format
        if addr_str.startswith('0x'):
            return int(addr_str, 16)
        # Handle just numeric strings
        elif addr_str.isdigit():
            return int(addr_str)
        else:
            return None
    except:
        return None


def compute_path_hash(path_steps, hash_type='sha256'):
    """
    Compute running hash for a path.
    
    Args:
        path_steps: List of tuples (source_addr, dest_addr) for this path
        hash_type: Type of hash to use ('sha256', 'sha1', 'md5')
    
    Returns:
        Final hash as hex string
    """
    H_curr = 0  # Initialize to zero
    
    for src_addr, dst_addr in path_steps:
        # Convert addresses to bytes (8 bytes each for 64-bit addresses)
        h_curr_bytes = H_curr.to_bytes(32, byteorder='big')  # 256-bit hash -> 32 bytes
        src_bytes = src_addr.to_bytes(8, byteorder='big')
        dst_bytes = dst_addr.to_bytes(8, byteorder='big')
        
        # Concatenate: H_curr || src_addr || dst_addr
        data_to_hash = h_curr_bytes + src_bytes + dst_bytes
        
        # Compute hash
        if hash_type == 'sha256':
            hasher = hashlib.sha256()
        elif hash_type == 'sha1':
            hasher = hashlib.sha1()
        elif hash_type == 'md5':
            hasher = hashlib.md5()
        else:
            hasher = hashlib.sha256()
        
        hasher.update(data_to_hash)
        hash_result = hasher.digest()
        
        # Convert hash to integer for next iteration
        H_curr = int.from_bytes(hash_result, byteorder='big')
    
    # Return final hash as hex string
    if hash_type == 'md5':
        return H_curr.to_bytes(16, byteorder='big').hex()
    elif hash_type == 'sha1':
        return H_curr.to_bytes(20, byteorder='big').hex()
    else:  # sha256
        return H_curr.to_bytes(32, byteorder='big').hex()


def process_paths_csv(input_csv, output_csv=None, hash_type='sha256', verbose=False):
    """
    Read paths from CSV, compute running hash for each path, and output results.
    
    Args:
        input_csv: Input CSV file with columns: path_id, source_address, destination_address, cf_type, instruction
        output_csv: Output CSV file (if None, prints to stdout)
        hash_type: Type of hash ('sha256', 'sha1', 'md5')
        verbose: Print detailed information
    """
    
    # Read CSV and group by path_id
    paths = defaultdict(list)
    
    try:
        with open(input_csv, 'r') as f:
            reader = csv.DictReader(f)
            
            if not reader.fieldnames:
                print(f"[!] Error: CSV file is empty or malformed")
                return
            
            for row in reader:
                try:
                    path_id = int(row['path_id'])
                    src_addr_str = row['source_address'].strip()
                    dst_addr_str = row['destination_address'].strip()
                    
                    src_addr = parse_hex_address(src_addr_str)
                    dst_addr = parse_hex_address(dst_addr_str)
                    
                    # Skip rows with invalid addresses
                    if src_addr is None or dst_addr is None:
                        if verbose:
                            print(f"[!] Warning: Skipping row with invalid addresses: {src_addr_str} -> {dst_addr_str}")
                        continue
                    
                    paths[path_id].append((src_addr, dst_addr))
                    
                except Exception as e:
                    if verbose:
                        print(f"[!] Warning: Error processing row: {e}")
                    continue
    
    except FileNotFoundError:
        print(f"[!] Error: Input file '{input_csv}' not found")
        return
    except Exception as e:
        print(f"[!] Error reading CSV: {e}")
        return
    
    if not paths:
        print(f"[!] Error: No valid paths found in CSV")
        return
    
    print(f"[+] Loaded {len(paths)} paths from {input_csv}")
    print(f"[+] Using hash function: {hash_type.upper()}")
    print()
    
    # Compute hash for each path
    path_hashes = {}
    
    for path_id in sorted(paths.keys()):
        path_steps = paths[path_id]
        path_hash = compute_path_hash(path_steps, hash_type)
        path_hashes[path_id] = {
            'path_id': path_id,
            'num_steps': len(path_steps),
            'hash': path_hash
        }
        
        if verbose:
            print(f"Path {path_id}: {len(path_steps)} steps -> Hash: {path_hash[:16]}...")
    
    print()
    
    # Write output
    if output_csv:
        try:
            with open(output_csv, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=['path_id', 'num_steps', 'hash'])
                writer.writeheader()
                
                for path_id in sorted(path_hashes.keys()):
                    writer.writerow(path_hashes[path_id])
            
            print(f"[+] Path hashes exported to: {output_csv}")
        except Exception as e:
            print(f"[!] Error writing output CSV: {e}")
            return
    else:
        # Print to stdout
        print(f"{'='*80}")
        print(f"PATH HASHES")
        print(f"{'='*80}\n")
        print(f"{'Path ID':<10} {'Steps':<10} {'Hash':<68}")
        print(f"{'-'*88}")
        
        for path_id in sorted(path_hashes.keys()):
            info = path_hashes[path_id]
            print(f"{info['path_id']:<10} {info['num_steps']:<10} {info['hash']:<68}")
        
        print()
    
    # Print summary statistics
    print(f"[+] Summary:")
    print(f"    Total paths: {len(path_hashes)}")
    print(f"    Total steps across all paths: {sum(info['num_steps'] for info in path_hashes.values())}")
    print(f"    Average steps per path: {sum(info['num_steps'] for info in path_hashes.values()) / len(path_hashes):.2f}")
    
    return path_hashes


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 path_hasher.py <input_csv> [options]")
        print("\nOptions:")
        print("  -o OUTPUT_CSV     Output CSV file (default: print to stdout)")
        print("  -H HASH_TYPE      Hash type: sha256, sha1, md5 (default: sha256)")
        print("  -v, --verbose     Enable verbose output")
        print("\nExamples:")
        print("  python3 path_hasher.py paths.csv")
        print("  python3 path_hasher.py paths.csv -o path_hashes.csv")
        print("  python3 path_hasher.py paths.csv -o path_hashes.csv -H sha256 -v")
        sys.exit(1)
    
    input_csv = sys.argv[1]
    output_csv = None
    hash_type = 'sha256'
    verbose = False
    
    i = 2
    while i < len(sys.argv):
        if sys.argv[i] == '-o' and i + 1 < len(sys.argv):
            output_csv = sys.argv[i + 1]
            i += 2
        elif sys.argv[i] == '-H' and i + 1 < len(sys.argv):
            hash_type = sys.argv[i + 1].lower()
            if hash_type not in ['sha256', 'sha1', 'md5']:
                print(f"[!] Error: Invalid hash type '{hash_type}'. Must be sha256, sha1, or md5")
                sys.exit(1)
            i += 2
        elif sys.argv[i] in ['-v', '--verbose']:
            verbose = True
            i += 1
        else:
            i += 1
    
    process_paths_csv(input_csv, output_csv, hash_type, verbose)


if __name__ == '__main__':
    main()
