#!/usr/bin/env python3
"""
liquefy_telemetry_forward.py
============================
Push audit chain events to external SIEM / monitoring systems in real-time.

Supports:
    - Webhook (HTTP POST JSON) — Splunk HEC, Datadog, PagerDuty, Slack, custom
    - Syslog (RFC 5424 UDP/TCP) — any syslog collector
    - File (JSONL append) — local log aggregation

Modes:
    push     — one-shot: forward all new events since last cursor
    stream   — continuous: tail the audit chain and forward in real-time
    test     — send a test event to verify endpoint connectivity
    status   — show forwarding state (cursor position, last push, errors)

Usage:
    python tools/liquefy_telemetry_forward.py push   --webhook https://splunk:8088/services/collector --token xxx
    python tools/liquefy_telemetry_forward.py stream --webhook https://hooks.slack.com/xxx --interval 10
    python tools/liquefy_telemetry_forward.py push   --syslog 10.0.0.1:514
    python tools/liquefy_telemetry_forward.py push   --file /var/log/liquefy-events.jsonl
    python tools/liquefy_telemetry_forward.py test   --webhook https://my-siem/api/events
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.request import Request, urlopen
from urllib.error import URLError

from cli_runtime import resolve_repo_root

REPO_ROOT = resolve_repo_root(__file__)
API_DIR = REPO_ROOT / "api"
TOOLS_DIR = REPO_ROOT / "tools"
for _p in (API_DIR, TOOLS_DIR):
    ps = str(_p)
    if ps not in sys.path:
        sys.path.insert(0, ps)

SCHEMA = "liquefy.telemetry-forward.v1"
STATE_DIR_NAME = ".liquefy-forward"
STATE_FILE = "forward_state.json"


def _state_dir() -> Path:
    return Path.home() / ".liquefy" / "forward"


def _load_state() -> Dict:
    sf = _state_dir() / STATE_FILE
    if sf.exists():
        return json.loads(sf.read_text("utf-8"))
    return {"cursor": 0, "last_push": None, "events_sent": 0, "errors": 0}


def _save_state(state: Dict):
    sd = _state_dir()
    sd.mkdir(parents=True, exist_ok=True)
    (sd / STATE_FILE).write_text(json.dumps(state, indent=2), encoding="utf-8")


def _find_chain_file() -> Optional[Path]:
    candidates = [
        Path.home() / ".liquefy" / "audit" / "default" / "chain.jsonl",
    ]
    vault_env = os.environ.get("LIQUEFY_VAULT")
    if vault_env:
        candidates.insert(0, Path(vault_env) / "audit" / "chain.jsonl")

    for p in candidates:
        if p.exists():
            return p
    return None


def _load_events_from(chain_file: Path, cursor: int) -> List[Dict]:
    events = []
    with chain_file.open("r", encoding="utf-8") as f:
        for i, line in enumerate(f):
            if i < cursor:
                continue
            line = line.strip()
            if line:
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return events


def _format_event(event: Dict, source: str = "liquefy") -> Dict:
    return {
        "source": source,
        "schema": SCHEMA,
        "timestamp": event.get("ts", datetime.now(timezone.utc).isoformat()),
        "event": event.get("event", "unknown"),
        "seq": event.get("seq", 0),
        "data": event,
    }


def _send_webhook(url: str, events: List[Dict], token: Optional[str] = None,
                   headers: Optional[Dict] = None) -> Dict:
    all_headers = {"Content-Type": "application/json"}
    if token:
        all_headers["Authorization"] = f"Bearer {token}"
    if headers:
        all_headers.update(headers)

    payload = json.dumps({"events": events}).encode("utf-8")

    req = Request(url, data=payload, headers=all_headers, method="POST")
    try:
        resp = urlopen(req, timeout=15)
        return {"ok": True, "status": resp.status, "sent": len(events)}
    except URLError as e:
        return {"ok": False, "error": str(e), "sent": 0}
    except Exception as e:
        return {"ok": False, "error": str(e), "sent": 0}


def _send_syslog(host: str, port: int, events: List[Dict], protocol: str = "udp") -> Dict:
    try:
        for event in events:
            msg = f"<14>1 {event.get('timestamp', '-')} liquefy - - - {json.dumps(event)}"
            msg_bytes = msg.encode("utf-8")

            if protocol == "tcp":
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(10)
                    s.connect((host, port))
                    s.sendall(msg_bytes + b"\n")
            else:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.sendto(msg_bytes, (host, port))

        return {"ok": True, "sent": len(events)}
    except Exception as e:
        return {"ok": False, "error": str(e), "sent": 0}


def _send_file(filepath: Path, events: List[Dict]) -> Dict:
    try:
        filepath.parent.mkdir(parents=True, exist_ok=True)
        with filepath.open("a", encoding="utf-8") as f:
            for event in events:
                f.write(json.dumps(event, separators=(",", ":")) + "\n")
        return {"ok": True, "sent": len(events)}
    except Exception as e:
        return {"ok": False, "error": str(e), "sent": 0}


def _forward_events(events: List[Dict], args: argparse.Namespace) -> Dict:
    formatted = [_format_event(e) for e in events]

    if args.webhook:
        token = getattr(args, "token", None) or os.environ.get("LIQUEFY_WEBHOOK_TOKEN")
        return _send_webhook(args.webhook, formatted, token)
    elif args.syslog:
        parts = args.syslog.split(":")
        host = parts[0]
        port = int(parts[1]) if len(parts) > 1 else 514
        protocol = getattr(args, "protocol", "udp") or "udp"
        return _send_syslog(host, port, formatted, protocol)
    elif args.file:
        return _send_file(Path(args.file), formatted)
    else:
        return {"ok": False, "error": "No destination specified (--webhook, --syslog, or --file)"}


def cmd_push(args: argparse.Namespace) -> int:
    chain_file = _find_chain_file()
    if not chain_file:
        print(json.dumps({"ok": False, "error": "No audit chain found"}))
        return 1

    state = _load_state()
    events = _load_events_from(chain_file, state["cursor"])

    if not events:
        result = {"ok": True, "events_sent": 0, "message": "No new events"}
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print("  No new events to forward.")
        return 0

    send_result = _forward_events(events, args)

    if send_result["ok"]:
        state["cursor"] += len(events)
        state["last_push"] = datetime.now(timezone.utc).isoformat()
        state["events_sent"] += len(events)
        _save_state(state)

        result = {"ok": True, "events_sent": len(events), **send_result}
    else:
        state["errors"] += 1
        _save_state(state)
        result = {"ok": False, "events_pending": len(events), **send_result}

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        if send_result["ok"]:
            print(f"  Telemetry Forward — Push")
            print(f"    Events sent:  {len(events)}")
            print(f"    Total sent:   {state['events_sent']}")
            dest = args.webhook or args.syslog or args.file
            print(f"    Destination:  {dest}")
        else:
            print(f"  Telemetry Forward — FAILED")
            print(f"    Error: {send_result.get('error')}")

    return 0 if send_result["ok"] else 1


def cmd_stream(args: argparse.Namespace) -> int:
    chain_file = _find_chain_file()
    if not chain_file:
        print(json.dumps({"ok": False, "error": "No audit chain found"}))
        return 1

    interval = args.interval or 10
    state = _load_state()
    dest = args.webhook or args.syslog or args.file

    print(f"  Telemetry Forward — Stream Mode")
    print(f"    Destination: {dest}")
    print(f"    Interval:    {interval}s")
    print(f"    Cursor:      {state['cursor']}")
    print(f"    Streaming... (Ctrl+C to stop)")
    print()

    try:
        while True:
            events = _load_events_from(chain_file, state["cursor"])
            ts = datetime.now(timezone.utc).strftime("%H:%M:%S")

            if events:
                send_result = _forward_events(events, args)
                if send_result["ok"]:
                    state["cursor"] += len(events)
                    state["events_sent"] += len(events)
                    _save_state(state)
                    print(f"    [{ts}] Sent {len(events)} events (total: {state['events_sent']})")
                else:
                    state["errors"] += 1
                    _save_state(state)
                    print(f"    [{ts}] ERROR: {send_result.get('error')}")
            else:
                print(f"    [{ts}] No new events")

            time.sleep(interval)
    except KeyboardInterrupt:
        print(f"\n    Stream stopped. Total sent: {state['events_sent']}")
        return 0


def cmd_test(args: argparse.Namespace) -> int:
    test_event = {
        "seq": 0,
        "ts": datetime.now(timezone.utc).isoformat(),
        "event": "telemetry.test",
        "message": "Liquefy telemetry forwarding test",
        "_hash": "test",
    }

    send_result = _forward_events([test_event], args)
    dest = args.webhook or args.syslog or args.file

    result = {"ok": send_result["ok"], "destination": dest, **send_result}

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        if send_result["ok"]:
            print(f"  Telemetry Forward — Test OK")
            print(f"    Destination: {dest}")
        else:
            print(f"  Telemetry Forward — Test FAILED")
            print(f"    Destination: {dest}")
            print(f"    Error: {send_result.get('error')}")

    return 0 if send_result["ok"] else 1


def cmd_status(args: argparse.Namespace) -> int:
    state = _load_state()
    chain_file = _find_chain_file()
    total_events = 0
    if chain_file:
        with chain_file.open("r") as f:
            total_events = sum(1 for line in f if line.strip())

    pending = total_events - state["cursor"]

    result = {
        "ok": True,
        "cursor": state["cursor"],
        "total_events": total_events,
        "pending": pending,
        "events_sent": state["events_sent"],
        "last_push": state["last_push"],
        "errors": state["errors"],
        "chain_file": str(chain_file) if chain_file else None,
    }

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"  Telemetry Forward — Status")
        print(f"    Chain file:  {chain_file or 'not found'}")
        print(f"    Total:       {total_events} events")
        print(f"    Sent:        {state['events_sent']}")
        print(f"    Pending:     {pending}")
        print(f"    Last push:   {state['last_push'] or 'never'}")
        print(f"    Errors:      {state['errors']}")

    return 0


def main():
    parser = argparse.ArgumentParser(
        prog="liquefy-telemetry-forward",
        description="Forward audit chain events to SIEM / monitoring systems.",
    )
    sub = parser.add_subparsers(dest="command")

    for name, help_text in [
        ("push", "Forward new events (one-shot)"),
        ("stream", "Continuous tail + forward"),
        ("test", "Send test event to verify connectivity"),
    ]:
        p = sub.add_parser(name, help=help_text)
        p.add_argument("--webhook", help="Webhook URL (HTTP POST)")
        p.add_argument("--syslog", help="Syslog host:port (UDP)")
        p.add_argument("--file", help="Output JSONL file path")
        p.add_argument("--token", help="Auth token for webhook")
        p.add_argument("--json", action="store_true")
        if name == "stream":
            p.add_argument("--interval", type=int, default=10, help="Poll interval (seconds)")

    p_status = sub.add_parser("status", help="Show forwarding state")
    p_status.add_argument("--json", action="store_true")

    args = parser.parse_args()
    commands = {"push": cmd_push, "stream": cmd_stream, "test": cmd_test, "status": cmd_status}

    if args.command in commands:
        return commands[args.command](args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
