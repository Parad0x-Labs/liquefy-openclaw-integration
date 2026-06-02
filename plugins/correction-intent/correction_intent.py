"""
correction_intent.py — Correction vs Instruction Tagger for OpenClaw
=====================================================================

The problem nobody benchmarks:
  "use Redis" -> msg 20
  "actually use Postgres" -> msg 47

Standard compression: both survive. Agent calls Redis.
With correction-intent: Redis superseded. Agent gets Postgres.

Works standalone (pure Python, zero deps) or alongside
@parad0x_labs/context-capsule for the full JS pipeline.

Usage:
    from correction_intent import tag_messages, build_active_state, inject_active_state
"""

from __future__ import annotations
import re
import hashlib
import json
from dataclasses import dataclass
from typing import Literal

MessageIntent = Literal["instruction", "correction", "additive", "query", "ack"]

CORRECTION_SIGNALS = [
    r"\bactually\b", r"\bwait\b", r"\bscratch that\b", r"\bforget that\b",
    r"\binstead\b", r"\bi meant\b", r"\bcorrection:\b", r"\bnot that\b",
    r"\bignore that\b", r"\bcancel that\b", r"\bnever mind\b",
    r"\bon second thought\b", r"\brather than\b", r"\bdisregard\b",
]

ADDITIVE_SIGNALS = [
    r"\balso\b", r"\badditionally\b", r"\band also\b", r"\bone more thing\b",
    r"\banother\b", r"\bfurthermore\b", r"\bplus\b",
]

ACK_WORDS = {"ok", "got it", "sure", "yes", "no", "thanks", "perfect",
             "great", "understood", "noted", "will do", "done", "confirmed"}

TOPICS = {
    "storage": ["redis", "postgres", "database", "db", "cache", "sqlite", "mongo"],
    "auth": ["auth", "login", "password", "token", "jwt", "oauth", "session"],
    "api": ["endpoint", "route", "api", "url", "http", "rest", "graphql"],
    "testing": ["test", "spec", "jest", "pytest", "vitest", "assert", "expect"],
    "ui": ["color", "style", "button", "layout", "css", "font", "theme"],
    "infra": ["docker", "k8s", "deploy", "server", "host", "env", "production"],
}


def detect_topic(content: str) -> str:
    low = content.lower()
    for topic, keywords in TOPICS.items():
        if any(k in low for k in keywords):
            return topic
    return "general"


def tag_intent(content: str, role: str) -> MessageIntent:
    low = content.lower().strip()

    if len(low) < 30 and any(a in low for a in ACK_WORDS):
        return "ack"

    if low.endswith("?") or re.match(
        r"^(what|how|why|when|where|who|which|can|should|is|are|do|does)\b", low
    ):
        return "query"

    if any(re.search(sig, low) for sig in CORRECTION_SIGNALS):
        return "correction"

    if any(re.search(sig, low) for sig in ADDITIVE_SIGNALS):
        return "additive"

    if role == "assistant":
        return "ack" if len(low) < 50 else "instruction"

    return "instruction"


@dataclass
class TaggedMessage:
    index: int
    role: str
    content: str
    intent: MessageIntent
    topic: str
    active: bool = True
    superseded_by: int = None
    supersedes: int = None


@dataclass
class ActiveState:
    nodes: list
    active_instructions: list
    corrections: list
    summary: str


def tag_messages(messages: list) -> list:
    tagged = []
    for i, m in enumerate(messages):
        content = m.get("content", "")
        if isinstance(content, list):
            content = " ".join(
                b.get("text", "") if isinstance(b, dict) else str(b)
                for b in content
            )
        role = m.get("role", "user")
        intent = tag_intent(content, role)
        topic = detect_topic(content)
        tagged.append(TaggedMessage(
            index=i, role=role, content=content,
            intent=intent, topic=topic
        ))
    return tagged


def build_active_state(tagged: list) -> ActiveState:
    instruction_slots = {}

    for msg in tagged:
        if msg.intent == "instruction" and msg.role == "user":
            instruction_slots[msg.topic] = msg.index
        elif msg.intent == "correction" and msg.role == "user":
            prior_index = instruction_slots.get(msg.topic)
            if prior_index is not None and prior_index < msg.index:
                tagged[prior_index].active = False
                tagged[prior_index].superseded_by = msg.index
                msg.supersedes = prior_index
            instruction_slots[msg.topic] = msg.index

    active_instructions = [
        m for m in tagged
        if m.active and m.intent in ("instruction", "correction") and m.role == "user"
    ]
    corrections = [m for m in tagged if m.intent == "correction"]

    summary = (
        f"{len(active_instructions)} active instruction(s), "
        f"{len(corrections)} correction(s) applied"
    )
    return ActiveState(
        nodes=tagged,
        active_instructions=active_instructions,
        corrections=corrections,
        summary=summary,
    )


def inject_active_state(state: ActiveState) -> str:
    lines = [f"[ACTIVE STATE: {state.summary}]"]
    for inst in state.active_instructions[:8]:
        prefix = "C" if inst.intent == "correction" else "I"
        snippet = inst.content[:80].replace("\n", " ")
        lines.append(f"  [{prefix}][{inst.topic}] {snippet}")
    return "\n".join(lines)


def correction_chain_receipt(state: ActiveState, session_id: str = "") -> dict:
    chain = []
    for corr in state.corrections:
        original = ""
        if corr.supersedes is not None:
            original = state.nodes[corr.supersedes].content[:60]
        entry = {
            "index": corr.index,
            "topic": corr.topic,
            "before": original,
            "after": corr.content[:60],
            "hash": hashlib.sha256(
                f"{original}|{corr.content}|{corr.topic}|{session_id}".encode()
            ).hexdigest()[:16],
        }
        chain.append(entry)

    chain_root = hashlib.sha256(
        json.dumps(chain, sort_keys=True).encode()
    ).hexdigest()

    return {
        "session_id": session_id,
        "corrections": chain,
        "chain_root": chain_root,
        "anchor_note": f"anchor chain_root on Solana via receipt_anchor (6HSRGivd...)",
    }


if __name__ == "__main__":
    demo = [
        {"role": "user", "content": "Use Redis for session storage"},
        {"role": "assistant", "content": "Got it, setting up Redis."},
        {"role": "user", "content": "Also add rate limiting to the API"},
        {"role": "user", "content": "Actually, use Postgres instead of Redis"},
    ]
    tagged = tag_messages(demo)
    state = build_active_state(tagged)
    print(inject_active_state(state))
    receipt = correction_chain_receipt(state, "demo")
    print(f"\nChain root: {receipt['chain_root']}")
    print(f"Redis superseded, Postgres active: {receipt['corrections'][0]['after'][:40]}")
