"""
liquefy_fleet.py
================
Multi-agent fleet coordination layer.

"I run 47 agents and they all talk to the same .null index."

Provides:
    - Shared namespace with file-lock coordination
    - Atomic index updates (temp-write + rename)
    - Cross-agent merge with conflict resolution
    - Per-agent resource quotas (storage, rate, file count)
    - Fleet-wide GC (garbage collect orphaned/expired vaults)
    - Agent heartbeat + health monitoring

Architecture:
    All coordination happens through the filesystem (no external deps).
    File locks via fcntl.flock (Unix) or msvcrt.locking (Windows).
    The shared index is a single JSON file updated atomically.
    Each agent has its own namespace partition within the shared vault.

Usage:
    from liquefy_fleet import Fleet

    fleet = Fleet("/shared/vault")
    fleet.register_agent("agent-47", quota_mb=500)
    with fleet.lock("agent-47"):
        fleet.ingest("agent-47", source_dir, pack_options)
    fleet.status()
"""
from __future__ import annotations

import contextlib
import fcntl
import json
import os
import shutil
import time
import threading
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional, Set, Tuple


FLEET_INDEX_NAME = "fleet_index.json"
FLEET_LOCK_NAME = ".fleet.lock"
AGENT_HEARTBEAT_STALE_S = 300  # 5 minutes


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _utc_ts() -> float:
    return datetime.now(timezone.utc).timestamp()


def _fmt_bytes(n: int) -> str:
    if n >= 1 << 30: return f"{n / (1 << 30):.2f} GB"
    if n >= 1 << 20: return f"{n / (1 << 20):.1f} MB"
    if n >= 1 << 10: return f"{n / (1 << 10):.0f} KB"
    return f"{n} B"


# ── Data Models ──


@dataclass
class AgentQuota:
    max_storage_bytes: int = 0       # 0 = unlimited
    max_files: int = 0               # 0 = unlimited
    max_sessions_per_day: int = 0    # 0 = unlimited
    priority: int = 10               # higher = gets resources first during GC


@dataclass
class AgentState:
    agent_id: str
    registered_at: str = ""
    last_heartbeat: str = ""
    last_heartbeat_ts: float = 0.0
    status: str = "active"           # active | paused | quarantined | deregistered
    quota: AgentQuota = field(default_factory=AgentQuota)
    usage_bytes: int = 0
    usage_files: int = 0
    sessions_today: int = 0
    sessions_today_date: str = ""
    vaults: List[str] = field(default_factory=list)
    tags: Dict[str, str] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)


@dataclass
class MergeConflict:
    path: str
    agent_a: str
    agent_b: str
    strategy_used: str
    winner: str
    ts: str = ""


@dataclass
class FleetIndex:
    schema: str = "liquefy.fleet.v1"
    created_at: str = ""
    updated_at: str = ""
    agents: Dict[str, AgentState] = field(default_factory=dict)
    merge_log: List[MergeConflict] = field(default_factory=list)
    gc_log: List[Dict[str, Any]] = field(default_factory=list)


# ── File Locking ──


class FleetLock:
    """Cross-process file lock for coordinating fleet operations."""

    def __init__(self, lock_path: Path, timeout: float = 30.0):
        self._lock_path = lock_path
        self._timeout = timeout
        self._fd: Optional[int] = None

    def acquire(self) -> None:
        self._lock_path.parent.mkdir(parents=True, exist_ok=True)
        self._fd = os.open(str(self._lock_path), os.O_CREAT | os.O_RDWR)

        deadline = time.monotonic() + self._timeout
        while True:
            try:
                fcntl.flock(self._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                os.write(self._fd, f"{os.getpid()}:{_utc_now()}\n".encode())
                return
            except (OSError, BlockingIOError):
                if time.monotonic() > deadline:
                    os.close(self._fd)
                    self._fd = None
                    raise TimeoutError(
                        f"Could not acquire fleet lock after {self._timeout}s. "
                        f"Another agent may be holding the lock. "
                        f"Check: {self._lock_path}"
                    )
                time.sleep(0.05)

    def release(self) -> None:
        if self._fd is not None:
            try:
                fcntl.flock(self._fd, fcntl.LOCK_UN)
            finally:
                os.close(self._fd)
                self._fd = None

    def __enter__(self) -> "FleetLock":
        self.acquire()
        return self

    def __exit__(self, *exc: Any) -> None:
        self.release()


# ── Merge Strategies ──


class MergeStrategy:
    """Conflict resolution strategies for cross-agent vault merges."""

    LAST_WRITE_WINS = "last_write_wins"
    LARGEST_WINS = "largest_wins"
    HIGHEST_PRIORITY = "highest_priority"
    KEEP_BOTH = "keep_both"

    @staticmethod
    def resolve(
        path: str,
        agent_a: str,
        agent_b: str,
        meta_a: Dict,
        meta_b: Dict,
        strategy: str,
        agent_priorities: Dict[str, int],
    ) -> Tuple[str, MergeConflict]:
        """Returns (winner_agent_id, conflict_record)."""

        if strategy == MergeStrategy.LAST_WRITE_WINS:
            ts_a = meta_a.get("packed_at", "") or meta_a.get("ts", "")
            ts_b = meta_b.get("packed_at", "") or meta_b.get("ts", "")
            winner = agent_b if ts_b >= ts_a else agent_a

        elif strategy == MergeStrategy.LARGEST_WINS:
            size_a = meta_a.get("output_bytes", 0) or meta_a.get("size", 0)
            size_b = meta_b.get("output_bytes", 0) or meta_b.get("size", 0)
            winner = agent_a if size_a >= size_b else agent_b

        elif strategy == MergeStrategy.HIGHEST_PRIORITY:
            pri_a = agent_priorities.get(agent_a, 10)
            pri_b = agent_priorities.get(agent_b, 10)
            winner = agent_a if pri_a >= pri_b else agent_b

        elif strategy == MergeStrategy.KEEP_BOTH:
            winner = "both"

        else:
            winner = agent_b  # default fallback

        conflict = MergeConflict(
            path=path,
            agent_a=agent_a,
            agent_b=agent_b,
            strategy_used=strategy,
            winner=winner,
            ts=_utc_now(),
        )
        return winner, conflict


# ── Fleet Core ──


class Fleet:
    """
    Multi-agent fleet coordinator.

    All agents share one vault root. Each agent gets a namespace partition:
        {vault_root}/{agent_id}/session_XXXX/...

    The fleet index tracks all agents, their quotas, usage, and health.
    File-level locking ensures safe concurrent access from multiple processes.
    """

    def __init__(self, vault_root: str | Path):
        self.vault_root = Path(vault_root).expanduser().resolve()
        self.vault_root.mkdir(parents=True, exist_ok=True)
        self._index_path = self.vault_root / FLEET_INDEX_NAME
        self._lock_path = self.vault_root / FLEET_LOCK_NAME
        self._lock = FleetLock(self._lock_path)

    @contextlib.contextmanager
    def lock(self, agent_id: Optional[str] = None) -> Generator[None, None, None]:
        """Acquire fleet-wide lock. Optionally updates agent heartbeat."""
        with self._lock:
            if agent_id:
                self._heartbeat(agent_id)
            yield

    # ── Index I/O ──

    def _read_index(self) -> FleetIndex:
        if not self._index_path.exists():
            return FleetIndex(created_at=_utc_now(), updated_at=_utc_now())
        try:
            raw = json.loads(self._index_path.read_text(encoding="utf-8"))
            idx = FleetIndex()
            idx.schema = raw.get("schema", idx.schema)
            idx.created_at = raw.get("created_at", _utc_now())
            idx.updated_at = raw.get("updated_at", _utc_now())

            for aid, adata in raw.get("agents", {}).items():
                q = adata.pop("quota", {})
                quota = AgentQuota(**{k: v for k, v in q.items() if k in AgentQuota.__dataclass_fields__})
                vaults = adata.pop("vaults", [])
                tags = adata.pop("tags", {})
                errors = adata.pop("errors", [])
                skip_keys = {"quota", "vaults", "tags", "errors", "agent_id"}
                safe = {k: v for k, v in adata.items() if k in AgentState.__dataclass_fields__ and k not in skip_keys}
                state = AgentState(agent_id=aid, quota=quota, vaults=vaults, tags=tags, errors=errors, **safe)
                idx.agents[aid] = state

            idx.merge_log = [
                MergeConflict(**{k: v for k, v in m.items() if k in MergeConflict.__dataclass_fields__})
                for m in raw.get("merge_log", [])
            ]
            idx.gc_log = raw.get("gc_log", [])
            return idx
        except Exception:
            return FleetIndex(created_at=_utc_now(), updated_at=_utc_now())

    def _write_index(self, idx: FleetIndex) -> None:
        """Atomic write: temp file + rename."""
        idx.updated_at = _utc_now()
        data = {
            "schema": idx.schema,
            "created_at": idx.created_at,
            "updated_at": idx.updated_at,
            "agents": {aid: asdict(state) for aid, state in idx.agents.items()},
            "merge_log": [asdict(m) for m in idx.merge_log[-500:]],  # cap history
            "gc_log": idx.gc_log[-200:],
        }

        tmp_path = self._index_path.with_suffix(".tmp")
        tmp_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        tmp_path.rename(self._index_path)

    # ── Agent Management ──

    def register_agent(
        self,
        agent_id: str,
        *,
        quota_mb: int = 0,
        max_files: int = 0,
        max_sessions_per_day: int = 0,
        priority: int = 10,
        tags: Optional[Dict[str, str]] = None,
    ) -> AgentState:
        """Register a new agent in the fleet. Safe to call if already registered (updates quota)."""
        with self._lock:
            idx = self._read_index()

            if agent_id in idx.agents:
                state = idx.agents[agent_id]
                state.quota.max_storage_bytes = quota_mb * (1 << 20) if quota_mb else 0
                state.quota.max_files = max_files
                state.quota.max_sessions_per_day = max_sessions_per_day
                state.quota.priority = priority
                state.status = "active"
                if tags:
                    state.tags.update(tags)
            else:
                state = AgentState(
                    agent_id=agent_id,
                    registered_at=_utc_now(),
                    last_heartbeat=_utc_now(),
                    last_heartbeat_ts=_utc_ts(),
                    status="active",
                    quota=AgentQuota(
                        max_storage_bytes=quota_mb * (1 << 20) if quota_mb else 0,
                        max_files=max_files,
                        max_sessions_per_day=max_sessions_per_day,
                        priority=priority,
                    ),
                    tags=tags or {},
                )
                idx.agents[agent_id] = state

            agent_dir = self.vault_root / agent_id
            agent_dir.mkdir(exist_ok=True)

            self._write_index(idx)
            return state

    def deregister_agent(self, agent_id: str, *, purge: bool = False) -> bool:
        """Remove agent from fleet. If purge=True, deletes all its vault data."""
        with self._lock:
            idx = self._read_index()
            if agent_id not in idx.agents:
                return False

            idx.agents[agent_id].status = "deregistered"

            if purge:
                agent_dir = self.vault_root / agent_id
                if agent_dir.exists():
                    shutil.rmtree(agent_dir)
                del idx.agents[agent_id]

            self._write_index(idx)
            return True

    def _heartbeat(self, agent_id: str) -> None:
        """Update agent heartbeat (called inside lock context)."""
        idx = self._read_index()
        if agent_id in idx.agents:
            idx.agents[agent_id].last_heartbeat = _utc_now()
            idx.agents[agent_id].last_heartbeat_ts = _utc_ts()
            self._write_index(idx)

    def heartbeat(self, agent_id: str) -> None:
        """Public heartbeat method (acquires lock)."""
        with self._lock:
            self._heartbeat(agent_id)

    # ── Quota Enforcement ──

    def check_quota(self, agent_id: str) -> Dict[str, Any]:
        """Check if agent is within quota. Returns enforcement decision."""
        with self._lock:
            idx = self._read_index()

        if agent_id not in idx.agents:
            return {"allowed": False, "reason": "agent_not_registered"}

        state = idx.agents[agent_id]
        if state.status != "active":
            return {"allowed": False, "reason": f"agent_status_{state.status}"}

        self._recalculate_usage(state)

        violations: List[str] = []

        if state.quota.max_storage_bytes > 0 and state.usage_bytes > state.quota.max_storage_bytes:
            violations.append(
                f"storage: {_fmt_bytes(state.usage_bytes)} / {_fmt_bytes(state.quota.max_storage_bytes)}"
            )

        if state.quota.max_files > 0 and state.usage_files > state.quota.max_files:
            violations.append(
                f"files: {state.usage_files} / {state.quota.max_files}"
            )

        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        if state.quota.max_sessions_per_day > 0:
            if state.sessions_today_date == today and state.sessions_today >= state.quota.max_sessions_per_day:
                violations.append(
                    f"sessions_today: {state.sessions_today} / {state.quota.max_sessions_per_day}"
                )

        if violations:
            return {
                "allowed": False,
                "reason": "quota_exceeded",
                "violations": violations,
                "usage_bytes": state.usage_bytes,
                "quota_bytes": state.quota.max_storage_bytes,
            }

        return {
            "allowed": True,
            "usage_bytes": state.usage_bytes,
            "quota_bytes": state.quota.max_storage_bytes,
            "headroom_bytes": max(0, state.quota.max_storage_bytes - state.usage_bytes)
                if state.quota.max_storage_bytes > 0 else None,
        }

    def _recalculate_usage(self, state: AgentState) -> None:
        """Scan agent's vault directory to compute actual usage."""
        agent_dir = self.vault_root / state.agent_id
        if not agent_dir.exists():
            state.usage_bytes = 0
            state.usage_files = 0
            return

        total_bytes = 0
        total_files = 0
        vaults: List[str] = []

        for f in agent_dir.rglob("*"):
            if f.is_file():
                total_bytes += f.stat().st_size
                total_files += 1

        for d in agent_dir.iterdir():
            if d.is_dir() and (d / "tracevault_index.json").exists():
                vaults.append(d.name)

        state.usage_bytes = total_bytes
        state.usage_files = total_files
        state.vaults = sorted(vaults)

    def record_session(self, agent_id: str, vault_name: str) -> None:
        """Record that an agent created a new session vault."""
        with self._lock:
            idx = self._read_index()
            if agent_id not in idx.agents:
                return

            state = idx.agents[agent_id]
            today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
            if state.sessions_today_date != today:
                state.sessions_today = 0
                state.sessions_today_date = today
            state.sessions_today += 1

            if vault_name not in state.vaults:
                state.vaults.append(vault_name)

            self._recalculate_usage(state)
            self._write_index(idx)

    # ── Cross-Agent Merge ──

    def merge_vaults(
        self,
        target_agent: str,
        source_agents: List[str],
        *,
        strategy: str = MergeStrategy.LAST_WRITE_WINS,
        dry_run: bool = False,
    ) -> Dict[str, Any]:
        """
        Merge vaults from source agents into target agent's namespace.
        Handles conflicts based on chosen strategy.
        """
        with self._lock:
            idx = self._read_index()

        if target_agent not in idx.agents:
            return {"ok": False, "error": f"Target agent '{target_agent}' not registered"}

        priorities = {aid: s.quota.priority for aid, s in idx.agents.items()}
        target_dir = self.vault_root / target_agent
        merged_count = 0
        conflict_count = 0
        conflicts: List[Dict] = []
        skipped: List[str] = []

        for source_agent in source_agents:
            if source_agent not in idx.agents:
                skipped.append(source_agent)
                continue

            source_dir = self.vault_root / source_agent
            if not source_dir.exists():
                skipped.append(source_agent)
                continue

            for vault_dir in sorted(source_dir.iterdir()):
                if not vault_dir.is_dir():
                    continue

                target_vault = target_dir / vault_dir.name

                if target_vault.exists():
                    meta_a = self._load_vault_meta(target_vault)
                    meta_b = self._load_vault_meta(vault_dir)

                    winner, conflict = MergeStrategy.resolve(
                        vault_dir.name, target_agent, source_agent,
                        meta_a, meta_b, strategy, priorities,
                    )

                    conflicts.append(asdict(conflict))
                    conflict_count += 1

                    if winner == "both":
                        deduped_name = f"{vault_dir.name}__from_{source_agent}"
                        target_deduped = target_dir / deduped_name
                        if not dry_run:
                            shutil.copytree(vault_dir, target_deduped, dirs_exist_ok=True)
                        merged_count += 1
                    elif winner == source_agent:
                        if not dry_run:
                            shutil.rmtree(target_vault)
                            shutil.copytree(vault_dir, target_vault)
                        merged_count += 1
                    # else target_agent wins — keep existing, skip copy
                else:
                    if not dry_run:
                        shutil.copytree(vault_dir, target_vault)
                    merged_count += 1

        if not dry_run:
            with self._lock:
                idx = self._read_index()
                for c in conflicts:
                    idx.merge_log.append(MergeConflict(**{
                        k: v for k, v in c.items() if k in MergeConflict.__dataclass_fields__
                    }))
                self._recalculate_usage(idx.agents.get(target_agent, AgentState(agent_id=target_agent)))
                self._write_index(idx)

        return {
            "ok": True,
            "dry_run": dry_run,
            "target": target_agent,
            "sources": source_agents,
            "merged_vaults": merged_count,
            "conflicts": conflict_count,
            "conflict_details": conflicts,
            "skipped_agents": skipped,
            "strategy": strategy,
        }

    def _load_vault_meta(self, vault_dir: Path) -> Dict:
        index_path = vault_dir / "tracevault_index.json"
        if index_path.exists():
            try:
                data = json.loads(index_path.read_text(encoding="utf-8"))
                return data.get("metadata", data)
            except Exception:
                pass
        return {"packed_at": "", "output_bytes": sum(
            f.stat().st_size for f in vault_dir.rglob("*") if f.is_file()
        )}

    # ── Fleet-Wide GC ──

    def gc(
        self,
        *,
        max_age_days: int = 0,
        respect_quotas: bool = True,
        dry_run: bool = False,
    ) -> Dict[str, Any]:
        """
        Fleet-wide garbage collection.
        Removes: expired vaults, deregistered agents, over-quota data (lowest priority first).
        """
        with self._lock:
            idx = self._read_index()

        now = time.time()
        freed_bytes = 0
        removed_vaults: List[Dict] = []
        removed_agents: List[str] = []

        deregistered = [aid for aid, s in idx.agents.items() if s.status == "deregistered"]
        for aid in deregistered:
            agent_dir = self.vault_root / aid
            if agent_dir.exists():
                size = sum(f.stat().st_size for f in agent_dir.rglob("*") if f.is_file())
                if not dry_run:
                    shutil.rmtree(agent_dir)
                freed_bytes += size
                removed_agents.append(aid)

        if max_age_days > 0:
            cutoff = now - (max_age_days * 86400)
            for aid, state in idx.agents.items():
                if state.status != "active":
                    continue
                agent_dir = self.vault_root / aid
                if not agent_dir.exists():
                    continue

                for vault_dir in sorted(agent_dir.iterdir()):
                    if not vault_dir.is_dir():
                        continue
                    meta = self._load_vault_meta(vault_dir)
                    packed_at = meta.get("packed_at", "")
                    try:
                        vault_time = datetime.fromisoformat(packed_at.replace("Z", "+00:00")).timestamp()
                    except (ValueError, AttributeError):
                        vault_time = vault_dir.stat().st_mtime

                    if vault_time < cutoff:
                        size = sum(f.stat().st_size for f in vault_dir.rglob("*") if f.is_file())
                        removed_vaults.append({
                            "agent": aid,
                            "vault": vault_dir.name,
                            "bytes": size,
                            "age_days": round((now - vault_time) / 86400, 1),
                        })
                        if not dry_run:
                            shutil.rmtree(vault_dir)
                        freed_bytes += size

        if respect_quotas:
            over_quota = []
            for aid, state in idx.agents.items():
                if state.status != "active":
                    continue
                self._recalculate_usage(state)
                if state.quota.max_storage_bytes > 0 and state.usage_bytes > state.quota.max_storage_bytes:
                    over_quota.append((aid, state))

            over_quota.sort(key=lambda x: x[1].quota.priority)

            for aid, state in over_quota:
                agent_dir = self.vault_root / aid
                vaults_by_age = []
                for vd in agent_dir.iterdir():
                    if vd.is_dir() and (vd / "tracevault_index.json").exists():
                        vaults_by_age.append((vd.stat().st_mtime, vd))
                vaults_by_age.sort()

                excess = state.usage_bytes - state.quota.max_storage_bytes
                for mtime, vd in vaults_by_age:
                    if excess <= 0:
                        break
                    size = sum(f.stat().st_size for f in vd.rglob("*") if f.is_file())
                    removed_vaults.append({
                        "agent": aid,
                        "vault": vd.name,
                        "bytes": size,
                        "reason": "over_quota",
                    })
                    if not dry_run:
                        shutil.rmtree(vd)
                    freed_bytes += size
                    excess -= size

        gc_entry = {
            "ts": _utc_now(),
            "dry_run": dry_run,
            "freed_bytes": freed_bytes,
            "removed_vaults": len(removed_vaults),
            "removed_agents": len(removed_agents),
        }

        if not dry_run:
            with self._lock:
                idx = self._read_index()
                idx.gc_log.append(gc_entry)
                for aid in removed_agents:
                    if aid in idx.agents:
                        del idx.agents[aid]
                for aid, state in idx.agents.items():
                    self._recalculate_usage(state)
                self._write_index(idx)

        return {
            "ok": True,
            "dry_run": dry_run,
            "freed_bytes": freed_bytes,
            "freed_human": _fmt_bytes(freed_bytes),
            "removed_vaults": removed_vaults,
            "removed_agents": removed_agents,
        }

    # ── Status / Dashboard ──

    def status(self) -> Dict[str, Any]:
        """Full fleet status dashboard."""
        with self._lock:
            idx = self._read_index()

        now = _utc_ts()
        agents: List[Dict] = []
        total_bytes = 0
        total_files = 0
        total_vaults = 0

        for aid, state in sorted(idx.agents.items()):
            self._recalculate_usage(state)

            stale = (now - state.last_heartbeat_ts) > AGENT_HEARTBEAT_STALE_S if state.last_heartbeat_ts else True
            health = "stale" if stale else "healthy"
            if state.status != "active":
                health = state.status

            quota_pct = None
            if state.quota.max_storage_bytes > 0:
                quota_pct = round(state.usage_bytes / state.quota.max_storage_bytes * 100, 1)

            agents.append({
                "agent_id": aid,
                "status": state.status,
                "health": health,
                "usage_bytes": state.usage_bytes,
                "usage_human": _fmt_bytes(state.usage_bytes),
                "usage_files": state.usage_files,
                "vault_count": len(state.vaults),
                "quota_bytes": state.quota.max_storage_bytes,
                "quota_pct": quota_pct,
                "priority": state.quota.priority,
                "sessions_today": state.sessions_today,
                "last_heartbeat": state.last_heartbeat,
                "tags": state.tags,
            })

            total_bytes += state.usage_bytes
            total_files += state.usage_files
            total_vaults += len(state.vaults)

        return {
            "ok": True,
            "fleet_root": str(self.vault_root),
            "agent_count": len(agents),
            "total_bytes": total_bytes,
            "total_human": _fmt_bytes(total_bytes),
            "total_files": total_files,
            "total_vaults": total_vaults,
            "agents": agents,
            "recent_merges": len(idx.merge_log),
            "recent_gc": len(idx.gc_log),
        }

    def agent_namespace(self, agent_id: str) -> Path:
        """Return the filesystem path for an agent's vault namespace."""
        return self.vault_root / agent_id
