# Fovea Shield — SHA-256 Hash Chain Verification

Tamper-proof cryptographic evidence of real-time market risk predictions.

## What This Contains
- `live_monitor_v4_chain.jsonl` — Hash chain from per-asset monitor (22 tickers × 3 windows)
- `live_cross_asset_chain.jsonl` — Hash chain from cross-asset systemic risk monitor (13 channels)
- `verify_chain.py` — Standalone verification script

## How to Verify

```bash
# Verify per-asset chain:
python3 verify_chain.py

# Verify cross-asset chain:
python3 verify_chain.py --file live_cross_asset_chain.jsonl

# Verify all chains:
python3 verify_chain.py --all --verbose
```

## Hash Chain Structure

Each record is chained to the previous via:
```
chain_hash = SHA-256(prev_hash + data_hash + timestamp)
```

If any record is modified after creation, all subsequent hashes break.

## Third-Party Attestation

Git commit timestamps are controlled by GitHub (Microsoft) servers and serve as
independent proof that each hash existed at the recorded time.
