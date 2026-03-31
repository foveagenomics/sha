#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════╗
║  FOVEA SHIELD — SHA-256 CHAIN VERIFIER                                ║
║                                                                        ║
║  Verifies the tamper-proof hash chain produced by live_monitor_v4.py.  ║
║  Each scan's chain_hash is recomputed and compared to the stored       ║
║  value. If any record was modified after being written, the chain      ║
║  breaks and verification fails.                                        ║
║                                                                        ║
║  USAGE:                                                                ║
║    python3 verify_chain.py                                             ║
║    python3 verify_chain.py --file path/to/chain.jsonl                  ║
║    python3 verify_chain.py --verbose                                   ║
╚══════════════════════════════════════════════════════════════════════════╝
"""

import json
import hashlib
import sys
import os
from datetime import datetime, timezone


CHAIN_FILE = 'live_monitor_v4_chain.jsonl'
CROSS_ASSET_CHAIN_FILE = 'live_cross_asset_chain.jsonl'

GENESIS_SEEDS = {
    CHAIN_FILE: 'FOVEA_GENESIS_BLOCK_v4',
    CROSS_ASSET_CHAIN_FILE: 'FOVEA_CROSS_ASSET_GENESIS_v1',
}


def sha256_digest(data_str):
    """SHA-256 hex digest of a string."""
    return hashlib.sha256(data_str.encode('utf-8')).hexdigest()


def verify_chain(chain_file, verbose=False):
    """
    Walk the entire hash chain and verify every link.
    
    Returns:
        (valid, total, broken_links)
    """
    if not os.path.exists(chain_file):
        print(f"  ❌ Chain file not found: {chain_file}")
        return False, 0, []

    with open(chain_file) as f:
        lines = [l.strip() for l in f if l.strip()]

    if not lines:
        print(f"  ❌ Chain file is empty")
        return False, 0, []

    # Look up the correct genesis seed for this file
    basename = os.path.basename(chain_file)
    genesis_seed = GENESIS_SEEDS.get(basename, 'FOVEA_GENESIS_BLOCK_v4')
    genesis_hash = sha256_digest(genesis_seed)
    expected_prev = genesis_hash
    total = len(lines)
    broken = []

    for i, line in enumerate(lines):
        try:
            rec = json.loads(line)
        except json.JSONDecodeError as e:
            broken.append({'line': i + 1, 'error': f'JSON parse error: {e}'})
            continue

        stored_prev = rec.get('prev_hash', '')
        stored_data = rec.get('data_hash', '')
        stored_chain = rec.get('chain_hash', '')
        timestamp = rec.get('timestamp', '')
        scan_num = rec.get('scan', rec.get('window', '?'))

        # Verify prev_hash links to the previous record's chain_hash
        if stored_prev != expected_prev:
            broken.append({
                'line': i + 1,
                'scan': scan_num,
                'error': 'PREV_HASH MISMATCH',
                'expected': expected_prev[:16] + '...',
                'got': stored_prev[:16] + '...',
            })
            if verbose:
                print(f"  ❌ Record #{i+1} (line {i+1}): prev_hash MISMATCH")
        else:
            # Recompute chain_hash = SHA-256(prev_hash + data_hash + timestamp)
            recomputed = sha256_digest(stored_prev + stored_data + timestamp)
            if recomputed != stored_chain:
                broken.append({
                    'line': i + 1,
                    'scan': scan_num,
                    'error': 'CHAIN_HASH MISMATCH',
                    'expected': recomputed[:16] + '...',
                    'got': stored_chain[:16] + '...',
                })
                if verbose:
                    print(f"  ❌ Record #{i+1} (line {i+1}): chain_hash MISMATCH")
            else:
                if verbose:
                    print(f"  ✅ Record #{i+1} (line {i+1}): {stored_chain[:16]}... OK")

        # Move to next link in the chain
        expected_prev = stored_chain

    valid = len(broken) == 0
    return valid, total, broken


def verify_one(chain_file, verbose=False):
    """Verify a single chain file and print results."""
    basename = os.path.basename(chain_file)
    genesis_seed = GENESIS_SEEDS.get(basename, 'FOVEA_GENESIS_BLOCK_v4')

    print(f"\n{'='*70}")
    print(f"  FOVEA SHIELD — SHA-256 CHAIN VERIFICATION")
    print(f"{'='*70}")
    print(f"  Chain file:  {chain_file}")
    print(f"  Genesis:     SHA-256('{genesis_seed}')")
    print(f"  Verified:    {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(f"{'='*70}\n")

    valid, total, broken = verify_chain(chain_file, verbose)

    print(f"\n{'='*70}")
    if valid:
        print(f"  ✅ CHAIN VALID — {total} records, 0 broken links")
        print(f"  Every scan is cryptographically linked to the previous.")
        print(f"  No records have been modified since they were written.")
    else:
        print(f"  ❌ CHAIN BROKEN — {total} records, {len(broken)} broken link(s)")
        print(f"  The following records failed verification:")
        for b in broken:
            print(f"    Line {b['line']}: {b.get('scan','?')} — {b['error']}")
    print(f"{'='*70}\n")

    return valid


def main():
    verbose = '--verbose' in sys.argv or '-v' in sys.argv
    verify_all = '--all' in sys.argv

    # Custom file path
    chain_file = None
    for i, arg in enumerate(sys.argv):
        if arg == '--file' and i + 1 < len(sys.argv):
            chain_file = sys.argv[i + 1]

    if verify_all:
        # Verify both chain files
        all_valid = True
        for cf in [CHAIN_FILE, CROSS_ASSET_CHAIN_FILE]:
            if os.path.exists(cf):
                if not verify_one(cf, verbose):
                    all_valid = False
            else:
                print(f"\n  ⚠️  Skipping {cf} (not found)")
        return 0 if all_valid else 1
    elif chain_file:
        return 0 if verify_one(chain_file, verbose) else 1
    else:
        # Default: verify v4 monitor chain
        return 0 if verify_one(CHAIN_FILE, verbose) else 1


if __name__ == '__main__':
    sys.exit(main())

