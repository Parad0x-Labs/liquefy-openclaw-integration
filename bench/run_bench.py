#!/usr/bin/env python3
import argparse
import csv
import hashlib
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
import zipfile
from pathlib import Path
from typing import Dict, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent
BENCH_RUNS = 1
SEARCH_QUERY = "HTTP/1.1"


def run_cmd(cmd: str, check: bool = True) -> Tuple[float, str, str]:
    t0 = time.perf_counter()
    res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    t1 = time.perf_counter()
    if check and res.returncode != 0:
        print(f"Command failed: {cmd}\n{res.stderr}")
        res.check_returncode()
    return (t1 - t0), res.stdout, res.stderr


def get_dir_size(path: Path) -> int:
    total = 0
    for f in path.rglob("*"):
        if f.is_file():
            total += f.stat().st_size
    return total


def hash_dir(path: Path) -> str:
    hasher = hashlib.sha256()
    for f in sorted(path.rglob("*")):
        if f.is_file():
            hasher.update(str(f.relative_to(path)).encode("utf-8"))
            with open(f, "rb") as bf:
                for chunk in iter(lambda: bf.read(65536), b""):
                    hasher.update(chunk)
    return hasher.hexdigest()


def get_zstd_cmd() -> Optional[str]:
    zstd_exe = shutil.which("zstd")
    if not zstd_exe and platform.system() == "Windows":
        zstd_dir = REPO_ROOT / "bench" / "bin"
        zstd_dir.mkdir(parents=True, exist_ok=True)
        if not list(zstd_dir.rglob("zstd.exe")):
            print("Downloading zstd.exe for Windows...")
            url = "https://github.com/facebook/zstd/releases/download/v1.5.5/zstd-v1.5.5-win64.zip"
            zip_path = zstd_dir / "zstd.zip"
            urllib.request.urlretrieve(url, zip_path)
            with zipfile.ZipFile(zip_path, "r") as zip_ref:
                zip_ref.extractall(zstd_dir)
            zip_path.unlink()
        found = list(zstd_dir.rglob("zstd.exe"))
        if found:
            zstd_exe = str(found[0])
    return zstd_exe


def get_zstd_info() -> Dict[str, str]:
    info: Dict[str, str] = {}
    zstd_cmd = get_zstd_cmd()
    if zstd_cmd:
        info["Zstd Backend"] = "CLI"
        info["Zstd Path"] = str(zstd_cmd)
        try:
            res = subprocess.run([zstd_cmd, "--version"], capture_output=True, text=True, check=True)
            info["Zstd Version"] = res.stdout.strip()
        except Exception:
            info["Zstd Version"] = "Error checking version"
    else:
        info["Zstd Backend"] = "python-zstandard"
        info["Zstd Path"] = "CLI not found"
        try:
            import zstandard as zstd  # type: ignore
            info["Zstd Version"] = f"python-zstandard {zstd.__version__}"
        except Exception:
            info["Zstd Version"] = "python-zstandard unavailable"
    return info


def get_system_info() -> Dict[str, str]:
    info = {
        "OS": f"{platform.system()} {platform.release()} ({platform.version()})",
        "CPU": platform.processor(),
        "Python": sys.version.split()[0],
    }
    info.update(get_zstd_info())
    try:
        res = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=True, cwd=REPO_ROOT)
        info["Liquefy Commit"] = res.stdout.strip()[:8]
    except Exception:
        info["Liquefy Commit"] = "Unknown"
    return info


def ensure_dataset(size: str):
    base = REPO_ROOT / "bench" / "datasets" / "openclaw_like" / size
    if not (base / "run_0001").exists():
        print(f"Generating dataset '{size}'...")
        run_cmd(f"{sys.executable} {REPO_ROOT}/bench/generate_data.py --sizes {size}")


def safe_rename(src: Path, dst: Path):
    for _ in range(10):
        try:
            src.rename(dst)
            return
        except PermissionError:
            time.sleep(0.5)
    src.rename(dst)


def benchmark_liquefy(
    run_path: Path,
    out_dir: Path,
    no_verify: bool = False,
    workers: int = 0,
    verify_mode: str = "full",
    liquefy_profile: str = "default",
) -> Tuple[float, int, float]:
    extra = ""
    if no_verify:
        extra += " --no-verify"
    if verify_mode in {"full", "fast", "off"}:
        extra += f" --verify-mode {verify_mode}"
    if workers > 0:
        extra += f" --workers {workers}"
    env_prefix = ""
    if liquefy_profile and liquefy_profile != "default":
        env_prefix = f"LIQUEFY_PROFILE={liquefy_profile} "
    pack_cmd = (
        f"{env_prefix}{sys.executable} {REPO_ROOT}/tools/tracevault_pack.py "
        f"{run_path} --org bench --out {out_dir}/pack --no-encrypt{extra}"
    )
    restore_cmd = f"{sys.executable} {REPO_ROOT}/tools/tracevault_restore.py {out_dir}/pack --out {out_dir}/restore"

    pack_times = []
    restore_times = []
    hidden_run_path = run_path.with_name(run_path.name + "_hidden")

    for i in range(BENCH_RUNS):
        shutil.rmtree(out_dir / "pack", ignore_errors=True)
        shutil.rmtree(out_dir / "restore", ignore_errors=True)

        t_pack, _, _ = run_cmd(pack_cmd)

        if run_path.exists():
            safe_rename(run_path, hidden_run_path)

        t_res, _, _ = run_cmd(restore_cmd)

        if hidden_run_path.exists():
            safe_rename(hidden_run_path, run_path)

        if BENCH_RUNS == 1 or i > 0:
            pack_times.append(t_pack)
            restore_times.append(t_res)

    pack_time = sorted(pack_times)[len(pack_times) // 2]
    restore_time = sorted(restore_times)[len(restore_times) // 2]
    out_size = get_dir_size(out_dir / "pack")
    return pack_time, out_size, restore_time


def zstd_pack_python(run_path: Path, archive: Path, level: int):
    import zstandard as zstd  # type: ignore

    with tempfile.NamedTemporaryFile(prefix="zstd_pack_", suffix=".tar", delete=False, dir=str(archive.parent)) as tf:
        tar_path = Path(tf.name)
    try:
        run_cmd(f"tar -cf {tar_path} -C {run_path.parent} {run_path.name}")
        cctx = zstd.ZstdCompressor(level=level)
        with tar_path.open("rb") as src, archive.open("wb") as dst:
            cctx.copy_stream(src, dst)
    finally:
        tar_path.unlink(missing_ok=True)


def zstd_restore_python(archive: Path, restore_dir: Path):
    import zstandard as zstd  # type: ignore

    with tempfile.NamedTemporaryFile(prefix="zstd_restore_", suffix=".tar", delete=False, dir=str(restore_dir)) as tf:
        tar_path = Path(tf.name)
    try:
        dctx = zstd.ZstdDecompressor()
        with archive.open("rb") as src, tar_path.open("wb") as dst:
            dctx.copy_stream(src, dst)
        run_cmd(f"tar -xf {tar_path} -C {restore_dir}")
    finally:
        tar_path.unlink(missing_ok=True)


def benchmark_zstd(run_path: Path, out_dir: Path, level: int) -> Tuple[float, int, float]:
    archive = out_dir / "pack.tar.zst"
    restore_dir = out_dir / "restore"
    pack_times = []
    restore_times = []
    hidden_run_path = run_path.with_name(run_path.name + "_hidden")

    zstd_cmd = get_zstd_cmd()

    for i in range(BENCH_RUNS):
        archive.unlink(missing_ok=True)
        shutil.rmtree(restore_dir, ignore_errors=True)
        restore_dir.mkdir(parents=True, exist_ok=True)

        if zstd_cmd:
            ultra = " --ultra" if level > 19 else ""
            pack_cmd = f"tar -cf - -C {run_path.parent} {run_path.name} | {zstd_cmd}{ultra} -{level} -T0 -o {archive}"
            restore_cmd = f"{zstd_cmd} -d -T0 -c {archive} | tar -xf - -C {restore_dir}"
            t_pack, _, _ = run_cmd(pack_cmd)
        else:
            t0 = time.perf_counter()
            zstd_pack_python(run_path, archive, level)
            t_pack = time.perf_counter() - t0

        if run_path.exists():
            safe_rename(run_path, hidden_run_path)

        if zstd_cmd:
            t_res, _, _ = run_cmd(restore_cmd)
        else:
            t0 = time.perf_counter()
            zstd_restore_python(archive, restore_dir)
            t_res = time.perf_counter() - t0

        if hidden_run_path.exists():
            safe_rename(hidden_run_path, run_path)

        if BENCH_RUNS == 1 or i > 0:
            pack_times.append(t_pack)
            restore_times.append(t_res)

    pack_time = sorted(pack_times)[len(pack_times) // 2]
    restore_time = sorted(restore_times)[len(restore_times) // 2]
    out_size = archive.stat().st_size
    return pack_time, out_size, restore_time


def _stream_contains_query(stream, query_bytes: bytes, ignore_case: bool = True) -> bool:
    if not query_bytes:
        return False
    needle = query_bytes.lower() if ignore_case else query_bytes
    tail = b""
    while True:
        chunk = stream.read(1 << 20)
        if not chunk:
            break
        data = tail + chunk
        hay = data.lower() if ignore_case else data
        if needle in hay:
            return True
        if len(needle) > 1:
            tail = data[-(len(needle) - 1):]
    return False


def _search_tar_stream(fileobj, query: str) -> bool:
    query_bytes = query.encode("utf-8", errors="ignore")
    if not query_bytes:
        return False
    try:
        with tarfile.open(fileobj=fileobj, mode="r|") as tar:
            for member in tar:
                if not member.isfile():
                    continue
                extracted = tar.extractfile(member)
                if extracted is None:
                    continue
                if _stream_contains_query(extracted, query_bytes, ignore_case=True):
                    return True
    except tarfile.TarError:
        return False
    return False


def search_zstd_archive(archive: Path, query: str) -> bool:
    zstd_cmd = get_zstd_cmd()
    if zstd_cmd:
        proc = subprocess.Popen(
            [zstd_cmd, "-d", "-c", str(archive)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        found = False
        try:
            if proc.stdout is not None:
                found = _search_tar_stream(proc.stdout, query)
        finally:
            if proc.stdout is not None:
                proc.stdout.close()
            _stdout, _stderr = proc.communicate()
        return found and proc.returncode == 0

    try:
        import zstandard as zstd  # type: ignore
        with archive.open("rb") as src:
            dctx = zstd.ZstdDecompressor()
            with dctx.stream_reader(src) as reader:
                return _search_tar_stream(reader, query)
    except Exception:
        return False


def search_liquefy_pack(pack_dir: Path, query: str) -> bool:
    cmd = [
        sys.executable,
        str(REPO_ROOT / "tools" / "tracevault_search.py"),
        str(pack_dir),
        "--query",
        query,
        "--limit",
        "1",
        "--quiet",
        "--ignore-case",
    ]
    res = subprocess.run(cmd, capture_output=True, text=True)
    return res.returncode == 0


def main():
    global BENCH_RUNS

    parser = argparse.ArgumentParser(description="Run Trace Vault vs Zstd benchmark.")
    parser.add_argument(
        "--sizes",
        nargs="+",
        default=["small", "medium"],
        help="Dataset sizes to benchmark (e.g. small medium medium2g).",
    )
    parser.add_argument(
        "--runs",
        type=int,
        default=1,
        help="Number of runs per method (median is used).",
    )
    parser.add_argument(
        "--zstd-levels",
        nargs="+",
        type=int,
        default=[19, 22],
        help="Zstd compression levels to compare against Liquefy.",
    )
    parser.add_argument(
        "--liquefy-no-verify",
        action="store_true",
        help="Run Liquefy pack without MRTV verification for speed-mode benchmarking.",
    )
    parser.add_argument(
        "--liquefy-workers",
        type=int,
        default=0,
        help="Parallel workers for Liquefy packing (0 = auto).",
    )
    parser.add_argument(
        "--liquefy-verify-mode",
        choices=["full", "fast", "off"],
        default="full",
        help="Liquefy verification mode (full|fast|off).",
    )
    parser.add_argument(
        "--liquefy-profile",
        choices=["default", "ratio", "speed"],
        default="default",
        help="Optional Liquefy engine profile.",
    )
    args = parser.parse_args()
    if args.liquefy_no_verify:
        args.liquefy_verify_mode = "off"
    BENCH_RUNS = max(1, args.runs)

    bench_dir = REPO_ROOT / "bench"
    out_base = bench_dir / "out"
    results_dir = bench_dir / "results"
    results_dir.mkdir(parents=True, exist_ok=True)

    results = []

    for size in args.sizes:
        ensure_dataset(size)
        run_path = bench_dir / "datasets" / "openclaw_like" / size / "run_0001"
        in_bytes = get_dir_size(run_path)
        in_mb = in_bytes / (1024 * 1024)
        orig_hash = hash_dir(run_path)

        methods = [
            {
                "name": "Liquefy (.null)",
                "level": "engine-router",
                "kind": "liquefy",
                "fn": lambda: benchmark_liquefy(
                    run_path,
                    out_base / "liquefy" / size,
                    no_verify=args.liquefy_no_verify,
                    workers=args.liquefy_workers,
                    verify_mode=args.liquefy_verify_mode,
                    liquefy_profile=args.liquefy_profile,
                ),
            }
        ]
        for level in args.zstd_levels:
            methods.append({
                "name": f"zstd -{level}",
                "level": level,
                "kind": "zstd",
                "fn": (lambda lvl=level: benchmark_zstd(run_path, out_base / f"zstd{lvl}" / size, lvl)),
            })

        for method in methods:
            print(f"Running {method['name']} on {size}...")
            p_time, out_bytes, r_time = method["fn"]()

            if out_bytes > 0:
                if method["kind"] == "liquefy":
                    restored = out_base / "liquefy" / size / "restore"
                else:
                    level = method["level"]
                    restored = out_base / f"zstd{level}" / size / "restore" / "run_0001"

                try:
                    res_hash = hash_dir(restored)
                    verified = "PASS" if res_hash == orig_hash else "FAIL"
                except Exception as exc:
                    verified = f"ERROR: {exc}"
            else:
                verified = "N/A"
                out_bytes = in_bytes
                p_time = r_time = 0.001

            ratio = in_bytes / max(1, out_bytes)
            p_mb_s = in_mb / max(0.001, p_time)
            r_mb_s = in_mb / max(0.001, r_time)
            if method["kind"] == "liquefy":
                search_ok = search_liquefy_pack(out_base / "liquefy" / size / "pack", SEARCH_QUERY)
                stream_search = "Yes (tracevault_search)" if search_ok else "No"
            else:
                level = method["level"]
                zstd_archive = out_base / f"zstd{level}" / size / "pack.tar.zst"
                search_ok = search_zstd_archive(zstd_archive, SEARCH_QUERY)
                stream_search = "Yes (streaming)" if search_ok else "No"
            partial = "No" if method["kind"] == "zstd" else "Yes (file-by-file .null)"

            results.append({
                "Size": size,
                "Method": method["name"],
                "Level": method["level"],
                "Input Bytes": in_bytes,
                "Output Bytes": out_bytes,
                "Ratio": f"{ratio:.2f}x",
                "Compress Time (s)": f"{p_time:.2f}",
                "Compress MB/s": f"{p_mb_s:.1f}",
                "Restore Time (s)": f"{r_time:.2f}",
                "Restore MB/s": f"{r_mb_s:.1f}",
                "Hash Verify": verified,
                "Search Query": SEARCH_QUERY,
                "Search Check": "PASS" if search_ok else "FAIL",
                "Search While Compressed": stream_search,
                "Partial Extract": partial,
            })

    csv_path = results_dir / "bench.csv"
    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)

    md_path = results_dir / "REPORT.md"
    info = get_system_info()
    with open(md_path, "w") as f:
        f.write("# Trace Vault Compression Benchmark\n\n")
        f.write("## Environment\n")
        for k, v in info.items():
            f.write(f"- **{k}**: {v}\n")
        f.write(f"- **Liquefy Verify**: {args.liquefy_verify_mode}\n")
        f.write(f"- **Liquefy Workers**: {args.liquefy_workers if args.liquefy_workers > 0 else 'auto'}\n")

        f.write("\n## Results\n\n")
        f.write("| Size | Method | Level | In (Bytes) | Out (Bytes) | Ratio | Compress (s) | Compress MB/s | Restore (s) | Restore MB/s | Hash Verify | Search Query | Search Check | Search While Compressed | Partial Extract |\n")
        f.write("|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|\n")
        for r in results:
            f.write(
                f"| {r['Size']} | {r['Method']} | {r['Level']} | {r['Input Bytes']:,} | {r['Output Bytes']:,} | "
                f"{r['Ratio']} | {r['Compress Time (s)']} | {r['Compress MB/s']} | {r['Restore Time (s)']} | "
                f"{r['Restore MB/s']} | {r['Hash Verify']} | {r['Search Query']} | {r['Search Check']} | "
                f"{r['Search While Compressed']} | {r['Partial Extract']} |\n"
            )

        f.write("\n## Notes\n\n")
        f.write("- Datasets are synthetic OpenClaw-like traces with server-style logs, JSONL sessions, and HTML/markdown artifacts.\n")
        f.write("- Hash verification compares directory trees byte-for-byte after restore.\n")
        f.write("- Source dataset is renamed away during restore timing to prevent hardlink/copy-on-write shortcuts.\n")

    print(f"Benchmark complete. View {md_path} and {csv_path}")


if __name__ == "__main__":
    main()
