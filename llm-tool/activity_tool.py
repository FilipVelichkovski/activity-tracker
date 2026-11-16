#!/usr/bin/env python3
"""Thin Python wrapper & tool interface over `activity-tracker llm`.

All privacy filtering, domain/app/keyword redaction, and database queries live
in the Rust `activity-tracker` binary so there is no duplicated logic.

- Default (`classify=True`): includes heuristic categories for smaller/weaker LLMs.
- `--no-classify` (`classify=False`): omits heuristic categories and includes
  sample window titles so larger LLMs can classify activity on their own.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any


def _find_binary() -> str:
    env_bin = os.environ.get("ACTIVITY_TRACKER_BIN", "").strip()
    if env_bin:
        return env_bin
    which = shutil.which("activity-tracker")
    if which:
        return which
    repo_root = Path(__file__).resolve().parent.parent
    for profile in ("release", "debug"):
        candidate = repo_root / "target" / profile / "activity-tracker"
        if candidate.is_file():
            return str(candidate)
    raise FileNotFoundError(
        "Could not find `activity-tracker` binary. Build with `cargo build --release` "
        "or set ACTIVITY_TRACKER_BIN."
    )


def _run_cli(
    subargs: list[str],
    db_path: str | Path | None = None,
    privacy_config: str | Path | None = None,
) -> Any:
    cmd = [_find_binary()]
    db = db_path or os.environ.get("ACTIVITY_TRACKER_DB")
    if db:
        cmd.extend(["--db", str(Path(db).expanduser())])
    pcfg = privacy_config or os.environ.get("ACTIVITY_TRACKER_PRIVACY_CONFIG")
    if pcfg:
        cmd.extend(["--privacy-config", str(Path(pcfg).expanduser())])
    cmd.append("llm")
    cmd.extend(subargs)

    res = subprocess.run(cmd, capture_output=True, text=True, check=True)
    return json.loads(res.stdout)


def get_activity_digest(
    days: int = 0,
    since: str | None = None,
    top_n: int = 10,
    db_path: str | Path | None = None,
    classify: bool = True,
    privacy_config: str | Path | None = None,
) -> dict[str, Any]:
    """Return a compact, privacy-filtered JSON digest for LLMs."""
    args = ["digest", "--top", str(top_n)]
    if days > 0:
        args.extend(["--days", str(days)])
    if since:
        args.extend(["--since", since])
    if not classify:
        args.append("--no-classify")
    return _run_cli(args, db_path=db_path, privacy_config=privacy_config)


def get_focus_blocks(
    days: int = 0,
    since: str | None = None,
    min_duration_sec: int = 30,
    merge_gap_sec: int = 20,
    limit: int = 25,
    db_path: str | Path | None = None,
    classify: bool = True,
    privacy_config: str | Path | None = None,
) -> list[dict[str, Any]]:
    """Return merged, privacy-filtered focus blocks."""
    args = [
        "focus",
        "--min-sec", str(min_duration_sec),
        "--gap-sec", str(merge_gap_sec),
        "--limit", str(limit),
    ]
    if days > 0:
        args.extend(["--days", str(days)])
    if since:
        args.extend(["--since", since])
    if not classify:
        args.append("--no-classify")
    return _run_cli(args, db_path=db_path, privacy_config=privacy_config)


def search_activity(
    query: str,
    days: int = 7,
    limit: int = 15,
    db_path: str | Path | None = None,
    privacy_config: str | Path | None = None,
) -> dict[str, Any]:
    """Search sessions, opened files, and visited websites by keyword."""
    args = ["search", "--query", query, "--days", str(days), "--limit", str(limit)]
    return _run_cli(args, db_path=db_path, privacy_config=privacy_config)


TOOL_DISPATCH = {
    "get_activity_digest": get_activity_digest,
    "get_focus_blocks": get_focus_blocks,
    "search_activity": search_activity,
}


def main() -> int:
    parser = argparse.ArgumentParser(description="Privacy-filtered activity data tool for LLMs")
    parser.add_argument("--db", help="Optional path to activity.db")
    parser.add_argument("--privacy-config", help="Optional path to privacy.json")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_dig = sub.add_parser("digest", help="Compact app/site/file summary")
    p_dig.add_argument("--days", type=int, default=0)
    p_dig.add_argument("--since")
    p_dig.add_argument("--top-n", type=int, default=10)
    p_dig.add_argument("--no-classify", action="store_true", help="Omit heuristic categories (for larger LLMs)")

    p_fb = sub.add_parser("focus-blocks", help="Merged focus timeline blocks")
    p_fb.add_argument("--days", type=int, default=0)
    p_fb.add_argument("--since")
    p_fb.add_argument("--min-sec", type=int, default=30)
    p_fb.add_argument("--merge-gap", type=int, default=20)
    p_fb.add_argument("--limit", type=int, default=25)
    p_fb.add_argument("--no-classify", action="store_true", help="Omit heuristic categories (for larger LLMs)")

    p_sr = sub.add_parser("search", help="Keyword search across sessions, files, and sites")
    p_sr.add_argument("query")
    p_sr.add_argument("--days", type=int, default=7)
    p_sr.add_argument("--limit", type=int, default=15)

    args = parser.parse_args()
    if args.cmd == "digest":
        out = get_activity_digest(
            days=args.days,
            since=args.since,
            top_n=args.top_n,
            db_path=args.db,
            classify=not args.no_classify,
            privacy_config=args.privacy_config,
        )
    elif args.cmd == "focus-blocks":
        out = get_focus_blocks(
            days=args.days,
            since=args.since,
            min_duration_sec=args.min_sec,
            merge_gap_sec=args.merge_gap,
            limit=args.limit,
            db_path=args.db,
            classify=not args.no_classify,
            privacy_config=args.privacy_config,
        )
    else:
        out = search_activity(
            query=args.query,
            days=args.days,
            limit=args.limit,
            db_path=args.db,
            privacy_config=args.privacy_config,
        )

    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
