# JSON Log Champions

## 1. JSON Compact (Complex)
- **Filename:** `JsonChampion_Complex_Compact.py`
- **Best For:** Structured telemetry, metrics, and complex nested JSON.
- **Tech:** Field-aware Delta Encoding + ZigZag + Varint.
- **Ratio:** 30x+ on predictable numeric telemetry.
- **Features:** Lossless, Searchable.

## 2. JSON Universal (Repetitive)
- **Filename:** `JsonChampion_Repetitive_Universal.py`
- **Best For:** Repeating heartbeats or identical status JSON objects.
- **Tech:** Line-level RLE + Zstd.
