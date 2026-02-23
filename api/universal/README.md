# Universal Compression Engines

This folder contains universal engines designed to handle any data types not covered by specialized engines.

## Champions

### 1. Event Horizon (Max Ratio)
- **File**: `UniversalChampion_MaxRatio_EventHorizon.py`
- **Logic**: Global Skeletonization + Move-To-Front (MTF) + Var-Buckets + Zstd + AUTO-EOL.
- **Best for**: Structured logs, data with variables (IPs, UUIDs, Numbers), and high-ratio archival.
- **Features**: 100% Byte-Perfect Lossless, Searchable (Adaptive Bloom Filter), handles both LF and CRLF automatically.

### 2. Universal RLE (Max Speed)
- **File**: `UniversalChampion_MaxSpeed_RLE.py`
- **Logic**: Line-Level Run-Length Encoding (RLE) + Zstd.
- **Best for**: Highly repetitive burst data (e.g., repeating error logs, heartbeats) where speed is the priority.
- **Features**: 100% Lossless, Extremely fast compression and decompression, Searchable.

## Usage

### Compression
```bash
python UniversalChampion_MaxRatio_EventHorizon.py compress <input> <output.evhz>
```

### Decompression
```bash
python UniversalChampion_MaxRatio_EventHorizon.py decompress <archive.evhz> <output>
```

### Search (Grep)
```bash
python UniversalChampion_MaxRatio_EventHorizon.py grep <archive.evhz> "<query>"
```
