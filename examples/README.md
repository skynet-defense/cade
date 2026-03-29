# CADE Examples

This directory contains example scripts that demonstrate how to use the CADE engine pipeline.

## Scripts

| Script | Description |
|---|---|
| [`basic_detection.py`](basic_detection.py) | End-to-end pipeline walkthrough using mock data: graph construction, path finding, scoring, and explanation |

## Running Examples

```bash
# From the repository root
python examples/basic_detection.py
```

No additional dependencies are required — all examples use only the CADE engine and Python stdlib.

## Adding Examples

When contributing a new example:
1. Use only `engine/`, `api/`, or `integrations/` public interfaces
2. Include inline comments explaining each pipeline stage
3. Use clearly named mock data (no real IP addresses, hostnames, or credentials)
4. Add an entry to the table above
