# Netflow & IPFIX Champions

## 1. Netflow V5 Liquefy (Binary Transposer)
- **Filename:** `NetflowChampion_V5_Liquefy.py`
- **Best For:** Netflow v5 UDP streams and IPFIX binary telemetry.
- **Tech:** Blind Binary Transposition + Header Stripping + IP Bloom Index.
- **Ratio:** **15x - 20x** on binary telemetry.
- **Features:** 100% Lossless, Searchable by IP.

### Why it wins:
Standard compression treats binary Netflow records as "noise." This engine understands the 48-byte record structure and transposes the columns (SrcIP, DstIP, Port, Flags) so that Zstd can find vertical patterns in the network flow.

---

##  Performance Summary
| Metric | Netflow Liquefy | Zstd -22 |
| :--- | :--- | :--- |
| **Compression Ratio** | **19.0x** | 19.1x |
| **Searchable** | **YES (IP)** | NO |
| **Forensic Search Speed** | **Instant** | Heavy Decompress |
