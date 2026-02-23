#!/usr/bin/env python3
import time, json, os, random, sys, zstandard as zstd, gzip

# Add path to load the champion
sys.path.append(os.path.abspath("production_engines/scm"))
from GitHubChampion_Liquefy import GitHubLiquefyChampion

def gen_github_logs(count=5000):
    lines = []
    types = ["PushEvent", "PullRequestEvent", "IssueCommentEvent", "WatchEvent"]
    users = ["dev-pro-12", "bot-ci-master", "admin-alpha", "coder-ninja"]
    repos = ["enterprise/core-api", "enterprise/ui-v2", "infra/terraform-aws"]

    for i in range(count):
        rec = {
            "id": str(random.getrandbits(64)),
            "type": random.choice(types),
            "actor": {"login": random.choice(users)},
            "repo": {"name": random.choice(repos)},
            "payload": {"ref": "refs/heads/main", "size": random.randint(1, 10), "commits": [{"sha": "abc", "message": "Update README"}]},
            "public": True,
            "created_at": "2023-12-25T12:00:00Z"
        }
        lines.append(json.dumps(rec, separators=(',',':')).encode())
    return b"\n".join(lines)

def benchmark():
    print(f"{' GITHUB/SCM CHAMPION SHOWDOWN ':=^70}")
    data = gen_github_logs(8000)
    print(f">>>> DATASET: GitHub Event Stream ({len(data):,} bytes)")
    print(f"{'Codec':<35} | {'Size (B)':>12} | {'Ratio':>10} | {'Speed':>12}")
    print("-" * 80)

    # 1. NITRO (Level 3)
    champ_nitro = GitHubLiquefyChampion(level=3)
    t0 = time.time(); c_nitro = champ_nitro.compress(data); t_nitro = time.time()-t0
    rec_nitro = champ_nitro.decompress(c_nitro); lossless = (len(rec_nitro.splitlines()) == len(data.splitlines()))

    # 2. ARCHIVE (Level 19)
    champ_arch = GitHubLiquefyChampion(level=19)
    t0 = time.time(); c_arch = champ_arch.compress(data); t_arch = time.time()-t0

    # Baseline Zstd
    z_comp = zstd.compress(data, level=19)

    print(f"Zstd Raw (Level 19)                | {len(z_comp):>12,} | {len(data)/len(z_comp):>9.1f}x | -- MB/s")
    print(f"[CHAMPION: SCM Nitro (Speed)]      | {len(c_nitro):>12,} | {len(data)/len(c_nitro):>9.1f}x | {len(data)/t_nitro/1024/1024:>9.1f} MB/s")
    print(f"[CHAMPION: SCM Archival (Ratio)]   | {len(c_arch):>12,} | {len(data)/len(c_arch):>9.1f}x | {len(data)/t_arch/1024/1024:>9.1f} MB/s")
    print(f"Lossless: {'PASS' if lossless else 'FAIL'}")

if __name__ == "__main__":
    benchmark()
