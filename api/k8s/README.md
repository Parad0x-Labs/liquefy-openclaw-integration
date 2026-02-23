# K8s Container Log Champions

## 1. K8s Nitro (Speed King)
- **Filename:** `K8sChampion_MaxSpeed_Nitro.py`
- **Best For:** High-velocity production clusters where logs must be compressed at wire speed.
- **Tech:** Structural Regex + Vectorized Columnar + RLE.
- **Speed:** **5-6 MB/s** (7x faster than Unicorn).
- **Ratio:** **10.5x**.
- **Features:** 100% Lossless, Searchable.

## 2. K8s Unicorn (Ratio King)
- **Filename:** `K8sChampion_Complex_Unicorn.py`
- **Best For:** Long-term archival and cold storage.
- **Tech:** Full JSON Wrapper Stripping + Deep Columnar.
- **Ratio:** **11.4x+**.
- **Features:** 100% Lossless, Searchable.

### When to use:
- **Nitro:** For active log shipping where CPU overhead is a concern.
- **Unicorn:** When you need the absolute smallest footprint for compliance/history.
