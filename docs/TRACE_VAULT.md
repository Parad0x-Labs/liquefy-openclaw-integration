# Trace Vault

Pack agent run folders into verified `.null` archives. Restore bit-perfect.

## What is a run folder?

A directory containing outputs from an agent framework execution:
JSONL traces, tool call logs, HTML reports, configuration files.
Any structure works -- the packer walks recursively.

## What gets packed

All files under the run directory, excluding: `.git`, `__pycache__`, `venv`, `node_modules`.
Each file is compressed through the Liquefy pipeline (engine selection, MRTV verification, optional per-org encryption).
Large files are chunked automatically (default threshold: 64 MB, default chunk size: 64 MB) to avoid single-file memory spikes.

## Index file

The packer writes `tracevault_index.json` in the output directory:

```json
{
  "version": "tracevault-index-v2",
  "run_dir": "./runs/run_001",
  "org_id": "dev",
  "input_bytes": 524288,
  "output_bytes": 12400,
  "ratio": 42.28,
  "files_processed": 14,
  "files_skipped": 0,
  "chunked_files": 1,
  "receipts": [
    {
      "run_relpath": "trace.jsonl",
      "output_path": "./vault/run_001/trace.jsonl.null",
      "engine_used": "liquefy-json-v1",
      "original_bytes": 102400,
      "sha256_original": "abc123...",
      "encrypted": true,
      "verified": true
    }
  ],
  "bigfile_groups": [
    {
      "run_relpath": "errors/huge.log",
      "original_bytes": 314572800,
      "chunk_bytes": 67108864,
      "chunk_count": 5,
      "sha256_original": "def456...",
      "parts": [
        {
          "run_relpath": "errors/huge.log::chunk000000",
          "output_path": "./vault/run_001/errors__huge.log.__chunk_000000_of_000005.null",
          "engine_used": "liquefy-apache-rep-v1"
        }
      ]
    }
  ]
}
```

## Pack

```bash
python tools/tracevault_pack.py ./runs/run_001 --org dev --out ./vault/run_001
```

Options:
- `--no-encrypt` -- skip per-org AES-256-GCM encryption
- `--no-verify` -- skip MRTV round-trip verification
- `--bigfile-threshold-mb` -- chunk files at/above this size (default `64`)
- `--chunk-mb` -- chunk size for big-file splitting (default `64`)
- `--max-file-mb` -- hard skip for files above this size (`0` disables max-size skipping)

## Restore

```bash
python tools/tracevault_restore.py ./vault/run_001 --out ./restored/run_001
```

Uses `./liquefy decompress` if available, otherwise falls back to a Python-based decoder.
Original directory structure is preserved.
Chunked files are restored by decompressing each chunk and concatenating in order.

## Search While Compressed

Search without restoring the full run directory:

```bash
python tools/tracevault_search.py ./vault/run_001 --query "HTTP/1.1" --limit 20
```

Or via wrapper:

```bash
./liquefy search ./vault/run_001 --query "HTTP/1.1" --limit 20
```

Notes:
- Searches operate directly on `.null` archives from the index.
- For files chunked at pack time, chunks are searched in-order.
- Exit code `0` means at least one match, `1` means no match, `2` means invalid input/usage.

## Integrity

Every packed file is MRTV-verified by default: compress, decompress, compare xxhash.
If verification fails, the pipeline falls back to Zstd -- no data is lost.
The `sha256_original` field in each receipt allows post-restore integrity checks.
For chunked files, `bigfile_groups[].sha256_original` is validated after reassembly.
