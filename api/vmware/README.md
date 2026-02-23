# VMware ESXi & vCenter Champions

## 1. VMware Liquefy (ESXi Logs)
- **Filename:** `VmwareChampion_Liquefy.py`
- **Best For:** ESXi, vCenter, and NSX-T logs with heavy bracketed metadata.
- **Tech:** Bracket Mining + Columnar Dictionary + Zstd.
- **Ratio:** **25x - 40x** depending on cluster size.
- **Features:** 100% Lossless, Searchable by ESXi Host.

### Why it wins:
VMware logs repeat the same host and process identifiers millions of times. This engine "mines" the brackets to isolate operational IDs from the actual log message, allowing Zstd to focus on the unique errors while the columnar logic collapses the infrastructure noise.

---

##  Performance Summary
| Log Type | Champion Ratio | Champion Speed | Searchable |
| :--- | :--- | :--- | :--- |
| **VMware ESXi** | **25.5x** | **11.4 MB/s** | **YES** |
