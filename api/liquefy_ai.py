#!/usr/bin/env python3
"""
Liquefy AI - [LIQUEFY BRAIN V1]
================================
MISSION: The AI Soul of the Liquefy v1 stack.
FEAT:    Knowledge Access, Persona Injection, Intent Analysis.
STATUS:  Production Grade - Verified Baseline.
"""

import json
import os
from pathlib import Path

class LiquefyAI:
    def __init__(self, knowledge_path=None):
        if knowledge_path is None:
            self.knowledge_base_path = Path(r"F:\nulla_ai\nulla-app\NULLA_KNOWLEDGE_BASE.md")
        else:
            self.knowledge_base_path = Path(knowledge_path)

        self.identity = {
            "name": "NULLA",
            "title": "Liquefy v1 Assistant",
            "role": "Autonomous Task Executioner",
            "manifestation": "Hyper-attentive Task Matrix"
        }

    def get_identity(self):
        return self.identity

    def analyze_intent(self, user_query: str) -> dict:
        query = user_query.lower()
        if "log" in query or "compress" in query:
            return {"action": "COMPRESS", "target": "LIQUEFY_V1_MIXED"}
        elif "secure" in query or "encrypt" in query:
            return {"action": "SECURE", "target": "fortress"}
        elif "search" in query or "find" in query:
            return {"action": "GREP", "target": "needle_eye"}
        return {"action": "TASK", "target": "execution"}

    def get_knowledge_snippet(self, topic: str) -> str:
        if not self.knowledge_base_path.exists():
            return "Task context unavailable. Ready for direct instructions."

        try:
            with open(self.knowledge_base_path, "r", encoding="utf-8") as f:
                content = f.read()
                lines = content.split('\n')
                for i, line in enumerate(lines):
                    if topic.lower() in line.lower() and (line.startswith('#') or line.startswith('##')):
                        return "\n".join(lines[i:i+10])
        except Exception as e:
            return f"Error fetching task data: {e}"

        return f"Searching shards for '{topic}'. I'll find it."

    def speak(self, message: str):
        return f"[NULLA]: {message}"
