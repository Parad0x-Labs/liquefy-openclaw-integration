# SQL Log Champions

## 1. SQL Unicorn (Max Ratio)
- **Filename:** `SqlChampion_MaxRatio_Unicorn.py`
- **Best For:** Archiving long-term slow query logs where size is the priority.
- **Tech:** Full Columnar Transposition + Safe-Delta + Zstd-22.
- **Ratio:** **16x+ (The King)**.

## 2. SQL Native (Max Speed)
- **Filename:** `SqlChampion_MaxSpeed_Native.py`
- **Best For:** Real-time production servers with heavy logging.
- **Tech:** Compiled C-Core Tokenizer (`sql_scanner.c`).
- **Speed:** **12 MB/s+**.

## 3. SQL Universal (Repetitive)
- **Filename:** `SqlChampion_Repetitive_Universal.py`
- **Best For:** Identical repeating queries (e.g., polling).
- **Tech:** Pattern ID + RLE.
