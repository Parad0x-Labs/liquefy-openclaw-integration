# Apache Log Champions

## 1. Apache Liquefy (Complex)
- **Filename:** `ApacheChampion_Complex_Liquefy.py`
- **Best For:** Production server logs with high variability (different IPs, User-Agents, and timestamps).
- **Tech:** Template-based extraction + Columnar Zstd.
- **Ratio:** ~13x on real logs.
- **Features:** 100% Lossless, Searchable.

## 2. Apache Universal (Repetitive)
- **Filename:** `ApacheChampion_Repetitive_Universal.py`
- **Best For:** Heartbeats, status pings, or highly repetitive dev/test logs.
- **Tech:** Pattern Deduplication + Line-Level RLE.
- **Ratio:** 30x+ on repetitive data.
- **Features:** Searchable, Ultra-fast on repeats.
