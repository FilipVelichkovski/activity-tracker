#!/usr/bin/env python3
"""Run a small local model (via Ollama /api/chat) with activity_tool.py tools."""

from __future__ import annotations

import argparse
import json
import urllib.request
from pathlib import Path

from activity_tool import TOOL_DISPATCH

SCHEMA_PATH = Path(__file__).resolve().parent / "tool_schema.json"

SYSTEM_PROMPT = (
    "You are a concise personal activity analyst. "
    "Use the provided tools (get_activity_digest, get_focus_blocks, search_activity) "
    "to inspect the user's tracked computer activity. "
    "Never invent numbers, file paths, or websites that were not returned by a tool."
)


def call_ollama(endpoint: str, payload: dict) -> dict:
    req = urllib.request.Request(
        endpoint,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=120) as resp:
        return json.loads(resp.read().decode("utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser(description="Ask a local Ollama model to analyze activity data")
    parser.add_argument("question", help="Question to ask about your activity")
    parser.add_argument("--model", default="qwen2.5:7b", help="Local Ollama model name")
    parser.add_argument("--url", default="http://127.0.0.1:11434/api/chat", help="Ollama /api/chat URL")
    parser.add_argument("--db", help="Optional path to activity.db")
    parser.add_argument("--max-turns", type=int, default=4, help="Max tool-calling rounds")
    args = parser.parse_args()

    tools = json.loads(SCHEMA_PATH.read_text())
    messages: list[dict] = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": args.question},
    ]

    for _ in range(args.max_turns):
        resp = call_ollama(
            args.url,
            {
                "model": args.model,
                "messages": messages,
                "tools": tools,
                "stream": False,
            },
        )
        msg = resp.get("message", {})
        messages.append(msg)

        tool_calls = msg.get("tool_calls") or []
        if not tool_calls:
            print(msg.get("content", ""))
            return 0

        for tc in tool_calls:
            fn = tc.get("function", {})
            name = fn.get("name", "")
            raw_args = fn.get("arguments") or {}
            if isinstance(raw_args, str):
                raw_args = json.loads(raw_args)
            if args.db:
                raw_args["db_path"] = args.db

            handler = TOOL_DISPATCH.get(name)
            if handler is None:
                result = {"error": f"Unknown tool: {name}"}
            else:
                try:
                    result = handler(**raw_args)
                except Exception as exc:
                    result = {"error": str(exc)}

            messages.append({
                "role": "tool",
                "name": name,
                "content": json.dumps(result),
            })

    print("Reached max tool-calling turns without a final response.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
