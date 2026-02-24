#!/usr/bin/env python3
"""
Liquefy Engine Map
==================
Central registry mapping engine IDs to their Python module path and class name.
All lazy imports happen through get_engine_instance().
"""

# ─── Engine ID → (module_path, class_name) ───────────────────────────

ENGINE_MAP = {
    # ── JSON Family (4 engines) ──────────────────────────────────────
    "liquefy-json-v1":             ("json.liquefy_json_v1",              "LiquefyJsonV1"),
    "liquefy-json-rep-v1":         ("json.liquefy_json_repetition_v1",   "LiquefyJsonRepetitionV1"),
    "liquefy-json-columnar-v1":    ("json.liquefy_columnar_gun_v1",      "LiquefyColumnarGunV1"),
    "liquefy-json-hypernebula-v1": ("json.liquefy_hyper_nebula_v1",      "LiquefyHyperNebulaV1"),

    # ── Apache Family (2 engines) ────────────────────────────────────
    "liquefy-apache-v1":           ("apache.liquefy_apache_v1",          "LiquefyApacheV1"),
    "liquefy-apache-rep-v1":       ("apache.liquefy_apache_repetition_v1", "LiquefyApacheRepetitionV1"),

    # ── Nginx Family (2 engines) ─────────────────────────────────────
    "liquefy-nginx-v1":            ("nginx.liquefy_nginx_v1",            "LiquefyNginxV1"),
    "liquefy-nginx-rep-v1":        ("nginx.liquefy_nginx_repetition_v1", "LiquefyNginxRepetitionV1"),

    # ── SQL Family (3 engines) ───────────────────────────────────────
    "liquefy-sql-v1":              ("sql.liquefy_sql_v1",                "LiquefySqlV1"),
    "liquefy-sql-rep-v1":          ("sql.liquefy_sql_repetition_v1",     "LiquefySqlRepetitionV1"),
    "liquefy-sql-velocity-v1":     ("sql.liquefy_sql_velocity_v1",       "LiquefySqlVelocityV1"),

    # ── Syslog Family (2 engines) ────────────────────────────────────
    "liquefy-syslog-v1":           ("syslog.liquefy_syslog_v1",          "LiquefySyslogV1"),
    "liquefy-syslog-rep-v1":       ("syslog.liquefy_syslog_repetition_v1", "LiquefySyslogRepetitionV1"),

    # ── Kubernetes Family (2 engines) ────────────────────────────────
    "liquefy-k8s-v1":              ("k8s.liquefy_k8s_v1",               "LiquefyK8sV1"),
    "liquefy-k8s-velocity-v1":     ("k8s.liquefy_k8s_velocity_v1",      "LiquefyK8sVelocityV1"),

    # ── AWS Family (2 engines) ───────────────────────────────────────
    "liquefy-cloudtrail-v1":       ("aws.liquefy_cloudtrail_v1",         "LiquefyCloudTrailV1"),
    "liquefy-vpcflow-v1":          ("aws.liquefy_vpcflow_v1",            "LiquefyVpcFlowV1"),

    # ── Network Family (1 engine) ────────────────────────────────────
    "liquefy-netflow-v1":          ("netflow.liquefy_netflow_v1",        "LiquefyNetflowV1"),

    # ── Platform Family (3 engines) ──────────────────────────────────
    "liquefy-vmware-v1":           ("vmware.liquefy_vmware_v1",          "LiquefyVmwareV1"),
    "liquefy-windows-v1":          ("windows.liquefy_windows_v1",        "LiquefyWindowsV1"),
    "liquefy-github-v1":           ("scm.liquefy_github_v1",             "LiquefyGithubV1"),

    # ── Universal Family (2 engines) ─────────────────────────────────
    "liquefy-universal-v1":        ("universal.liquefy_universal_v1",    "LiquefyUniversalV1"),
    "liquefy-fallback-v1":         ("universal.liquefy_fallback_v1",     "LiquefyFallbackV1"),
}

# Total: 23 engines
_ENGINE_INSTANCE_CACHE = {}


def _parse_engine_levels_env():
    """Parse LIQUEFY_ENGINE_LEVELS='engine-id=22,other-engine=19'."""
    try:
        import os

        raw = os.environ.get("LIQUEFY_ENGINE_LEVELS", "").strip()
        if not raw:
            return {}
        out = {}
        for part in raw.split(","):
            part = part.strip()
            if not part or "=" not in part:
                continue
            k, v = part.split("=", 1)
            k = k.strip()
            v = v.strip()
            if not k or not v:
                continue
            out[k] = int(v)
        return out
    except Exception:
        return {}


def _engine_ctor_overrides(engine_id: str):
    """
    Optional runtime tuning hooks. Default behavior is unchanged when env vars are absent.

    Supported:
      - LIQUEFY_PROFILE=ratio
      - LIQUEFY_PROFILE=speed
      - LIQUEFY_ENGINE_LEVELS='engine-id=22,...'
    """
    try:
        import os
    except Exception:
        return {}

    overrides = {}

    profile = os.environ.get("LIQUEFY_PROFILE", "").strip().lower()
    if profile == "ratio":
        ratio_levels = {
            "liquefy-json-hypernebula-v1": 22,
            "liquefy-k8s-velocity-v1": 22,
            "liquefy-cloudtrail-v1": 22,
            "liquefy-vpcflow-v1": 22,
            "liquefy-sql-velocity-v1": 22,
            "liquefy-syslog-rep-v1": 22,
        }
        if engine_id in ratio_levels:
            overrides["level"] = ratio_levels[engine_id]
        if engine_id == "liquefy-universal-v1":
            # Keep the same low-latency heuristic but raise the high-compression branch.
            overrides["high_compression_level"] = 22
    elif profile == "speed":
        speed_levels = {
            # Lower zstd levels for Python-heavy engines to prioritize throughput.
            "liquefy-json-hypernebula-v1": 3,
            "liquefy-k8s-velocity-v1": 3,
            "liquefy-cloudtrail-v1": 3,
            "liquefy-vpcflow-v1": 3,
            "liquefy-sql-velocity-v1": 3,
            "liquefy-syslog-rep-v1": 3,
            "liquefy-apache-rep-v1": 3,
            "liquefy-json-rep-v1": 3,
            "liquefy-sql-rep-v1": 3,
        }
        if engine_id in speed_levels:
            overrides["level"] = speed_levels[engine_id]
        if engine_id == "liquefy-universal-v1":
            # Keep universal on the fast path more often.
            overrides["level"] = 1
            overrides["high_compression_level"] = 9

    explicit_levels = _parse_engine_levels_env()
    if engine_id in explicit_levels:
        overrides["level"] = explicit_levels[engine_id]

    return overrides


def get_engine_instance(engine_id: str):
    """
    Lazily imports and instantiates the engine class for the given ID.
    Returns None if the engine is not found.
    """
    if engine_id not in ENGINE_MAP:
        return None

    module_path, class_name = ENGINE_MAP[engine_id]
    try:
        import importlib
        import importlib.util
        import inspect
        import os

        # Resolve the file path relative to the api/ directory
        api_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        parts = module_path.split(".")
        py_file = os.path.join(api_dir, *parts[:-1], parts[-1] + ".py")

        if os.path.exists(py_file):
            # Direct file-based load avoids name collisions (e.g. json vs builtins)
            spec = importlib.util.spec_from_file_location(module_path, py_file)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
        else:
            mod = importlib.import_module(module_path)

        cls = getattr(mod, class_name)
        kwargs = _engine_ctor_overrides(engine_id)
        filtered = {}
        if kwargs:
            try:
                sig = inspect.signature(cls)
                filtered = {k: v for k, v in kwargs.items() if k in sig.parameters}
            except Exception:
                filtered = {}

        cache_key = (engine_id, tuple(sorted(filtered.items())))
        if cache_key in _ENGINE_INSTANCE_CACHE:
            return _ENGINE_INSTANCE_CACHE[cache_key]

        if filtered:
            instance = cls(**filtered)
        else:
            instance = cls()
        _ENGINE_INSTANCE_CACHE[cache_key] = instance
        return instance
    except Exception as e:
        print(f"[WARN] Failed to load engine '{engine_id}': {e}")
        return None
