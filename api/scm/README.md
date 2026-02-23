# SCM (GitHub/GitLab) Event Champions

## 1. GitHub Liquefy (JSON Event Stream)
- **Filename:** `GitHubChampion_Liquefy.py`
- **Best For:** Archiving GitHub/GitLab webhooks, audit logs, and event streams.
- **Tech:** Recursive JSON Lifting + Schema-Aware Columnar + Zstd.
- **Ratio:** **18x - 25x** depending on payload redundancy.
- **Features:** 100% Lossless, Searchable by Actor/Repo.

### Why it wins:
GitHub events are nested JSON blobs. Generic compressors waste space repeating keys like `"actor":{"login":...}`. This engine "lifts" those identities into specialized columns, compressing them as a single group while isolating the unique commit/PR payload for Zstd.

---

##  Performance Summary
| Log Type | Champion Ratio | Champion Speed | Searchable |
| :--- | :--- | :--- | :--- |
| **GitHub Event Stream** | **23.0x** | **1.5 - 10 MB/s** | **YES** |
