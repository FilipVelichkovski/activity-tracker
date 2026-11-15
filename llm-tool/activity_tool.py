#!/usr/bin/env python3
"""Token-efficient activity analysis tool for small local LLMs."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import sqlite3
from pathlib import Path
from typing import Any

DEFAULT_DB = Path.home() / ".local" / "share" / "activity-tracker" / "activity.db"

DEV_APPS = (
    "zed", "antigravity", "code", "codium", "clion", "intellij", "pycharm",
    "rustrover", "kate", "kwrite", "nvim", "neovim", "vim", "emacs",
    "konsole", "alacritty", "kitty", "wezterm", "ghostty", "ptyxis",
)
DEV_TITLE_KW = (
    "github", "gitlab", "docs.rs", "crates.io", "cppreference", "stackoverflow",
    "127.0.0.1", "localhost", "activity tracker", "variant", ".cpp", ".hpp", ".rs", ".py",
)
LEARNING_KW = (
    "memrise", "blinklearning", "coursera", "udemy", "edx", "khan academy",
    "anki", "duolingo", "wikipedia", "explainer", "netzwerk", "lecture", "homework",
)
COMM_APPS = ("discord", "slack", "telegram", "signal", "element", "thunderbird", "kmail", "zoom", "teams")
SOCIAL_KW = ("witchsky", "bsky", "bluesky", "twitter", "reddit", "mastodon", "instagram", "facebook", "threads")
MEDIA_KW = ("youtube", "twitch", "netflix", "spotify", "vlc", "mpv", "elisa", "steam", "gwenview")
SYSTEM_APPS = ("dolphin", "plasmashell", "systemsettings", "krunner", "discover", "ark", "spectacle")
BROWSER_APPS = ("firefox", "librewolf", "chrome", "chromium", "brave", "vivaldi", "zen")


def classify_activity(app_name: str, window_title: str) -> str:
    app = (app_name or "").lower()
    title = (window_title or "").lower()
    if any(k in app for k in COMM_APPS) or any(k in title for k in ("gmail", "proton mail", "meet.google")):
        return "Communication"
    if any(k in app for k in DEV_APPS) or any(k in title for k in DEV_TITLE_KW):
        return "Development"
    if "okular" in app or "zotero" in app or any(k in title for k in LEARNING_KW):
        return "Learning"
    if any(k in title or k in app for k in SOCIAL_KW):
        return "Social"
    if any(k in app or k in title for k in MEDIA_KW):
        return "Media & Entertainment"
    if any(k in app for k in SYSTEM_APPS):
        return "System & Files"
    if any(k in app for k in BROWSER_APPS):
        return "Web Browsing"
    return "Other"


def fmt_dur(sec: float) -> str:
    total = max(0, int(round(sec)))
    h, rem = divmod(total, 3600)
    m, s = divmod(rem, 60)
    if h > 0:
        return f"{h}h {m:02d}m"
    if m > 0:
        return f"{m}m {s:02d}s"
    return f"{s}s"


def fmt_ts(ts: float) -> str:
    return dt.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M")


def resolve_range(days: int = 0, since: str | None = None) -> tuple[float, float]:
    now = dt.datetime.now()
    until_ts = now.timestamp() + 1.0
    if since:
        start = dt.datetime.strptime(since, "%Y-%m-%d")
        return start.timestamp(), until_ts
    if days > 0:
        return (now - dt.timedelta(days=days)).timestamp(), until_ts
    midnight = now.replace(hour=0, minute=0, second=0, microsecond=0)
    return midnight.timestamp(), until_ts


def _open_ro(db_path: str | Path | None = None) -> sqlite3.Connection:
    path = Path(db_path or os.environ.get("ACTIVITY_TRACKER_DB") or DEFAULT_DB).expanduser()
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def get_activity_digest(
    days: int = 0,
    since: str | None = None,
    top_n: int = 10,
    db_path: str | Path | None = None,
) -> dict[str, Any]:
    """Return a compact, pre-aggregated JSON digest for small local LLMs."""
    since_ts, until_ts = resolve_range(days=days, since=since)
    conn = _open_ro(db_path)
    try:
        sessions = conn.execute(
            "SELECT app_name, window_title, duration_sec FROM sessions WHERE started_at >= ? AND started_at <= ?",
            (since_ts, until_ts),
        ).fetchall()

        total_sec = sum(r["duration_sec"] for r in sessions)
        cat_agg: dict[str, dict[str, Any]] = {}
        app_agg: dict[str, dict[str, Any]] = {}
        for r in sessions:
            app = r["app_name"]
            dur = r["duration_sec"]
            cat = classify_activity(app, r["window_title"])
            c = cat_agg.setdefault(cat, {"sec": 0.0, "sessions": 0})
            c["sec"] += dur
            c["sessions"] += 1
            a = app_agg.setdefault(app, {"sec": 0.0, "sessions": 0})
            a["sec"] += dur
            a["sessions"] += 1

        categories = [
            {
                "category": k,
                "time": fmt_dur(v["sec"]),
                "seconds": round(v["sec"]),
                "share_pct": round((v["sec"] / total_sec * 100.0) if total_sec > 0 else 0.0, 1),
                "sessions": v["sessions"],
            }
            for k, v in sorted(cat_agg.items(), key=lambda kv: kv[1]["sec"], reverse=True)
        ]

        top_apps = [
            {
                "app": k,
                "time": fmt_dur(v["sec"]),
                "seconds": round(v["sec"]),
                "share_pct": round((v["sec"] / total_sec * 100.0) if total_sec > 0 else 0.0, 1),
                "sessions": v["sessions"],
            }
            for k, v in sorted(app_agg.items(), key=lambda kv: kv[1]["sec"], reverse=True)[:top_n]
        ]

        files_rows = conn.execute(
            """
            SELECT app_name, file_path, source, MAX(last_seen_at) AS last_seen
            FROM opened_files
            WHERE last_seen_at >= ? AND last_seen_at <= ?
            GROUP BY app_name, file_path
            ORDER BY last_seen DESC
            LIMIT ?
            """,
            (since_ts, until_ts, top_n),
        ).fetchall()

        sites_rows = conn.execute(
            """
            SELECT domain, MAX(page_title) AS title, COUNT(*) AS visits, MAX(last_seen_at) AS last_seen
            FROM visited_sites
            WHERE last_seen_at >= ? AND last_seen_at <= ?
            GROUP BY domain
            ORDER BY last_seen DESC
            LIMIT ?
            """,
            (since_ts, until_ts, top_n),
        ).fetchall()
    finally:
        conn.close()

    return {
        "period": {
            "start": fmt_ts(since_ts),
            "end": fmt_ts(until_ts),
            "total_active_time": fmt_dur(total_sec),
            "total_active_seconds": round(total_sec),
            "session_count": len(sessions),
        },
        "categories": categories,
        "top_apps": top_apps,
        "top_sites": [
            {"domain": r["domain"], "sample_title": r["title"], "pages": r["visits"], "last_seen": fmt_ts(r["last_seen"])}
            for r in sites_rows
        ],
        "opened_files": [
            {"app": r["app_name"], "file": r["file_path"], "source": r["source"], "last_seen": fmt_ts(r["last_seen"])}
            for r in files_rows
        ],
    }


def get_focus_blocks(
    days: int = 0,
    since: str | None = None,
    min_duration_sec: int = 30,
    merge_gap_sec: int = 20,
    limit: int = 25,
    db_path: str | Path | None = None,
) -> list[dict[str, Any]]:
    """Merge consecutive sessions of the same category/app into readable focus blocks."""
    since_ts, until_ts = resolve_range(days=days, since=since)
    conn = _open_ro(db_path)
    try:
        rows = conn.execute(
            """
            SELECT app_name, window_title, started_at, ended_at, duration_sec
            FROM sessions
            WHERE started_at >= ? AND started_at <= ?
            ORDER BY started_at ASC
            """,
            (since_ts, until_ts),
        ).fetchall()
    finally:
        conn.close()

    blocks: list[dict[str, Any]] = []
    for r in rows:
        cat = classify_activity(r["app_name"], r["window_title"])
        app = r["app_name"]
        s, e, d = float(r["started_at"]), float(r["ended_at"]), float(r["duration_sec"])
        title = r["window_title"]

        if blocks:
            prev = blocks[-1]
            same_focus = prev["category"] == cat and prev["app"] == app
            if same_focus and (s - prev["_end_ts"]) <= merge_gap_sec:
                prev["_end_ts"] = max(prev["_end_ts"], e)
                prev["_dur"] += d
                if title and title not in prev["titles"] and len(prev["titles"]) < 3:
                    prev["titles"].append(title)
                continue

        blocks.append({
            "_start_ts": s,
            "_end_ts": e,
            "_dur": d,
            "category": cat,
            "app": app,
            "titles": [title] if title else [],
        })

    filtered = [b for b in blocks if b["_dur"] >= min_duration_sec]
    filtered = filtered[-limit:]
    return [
        {
            "start": fmt_ts(b["_start_ts"]),
            "end": fmt_ts(b["_end_ts"]),
            "duration": fmt_dur(b["_dur"]),
            "seconds": round(b["_dur"]),
            "category": b["category"],
            "app": b["app"],
            "sample_titles": b["titles"],
        }
        for b in filtered
    ]


def search_activity(
    query: str,
    days: int = 7,
    limit: int = 15,
    db_path: str | Path | None = None,
) -> dict[str, Any]:
    """Search sessions, opened files, and visited websites by keyword."""
    since_ts, until_ts = resolve_range(days=days)
    pat = f"%{query.lower()}%"
    conn = _open_ro(db_path)
    try:
        sess_rows = conn.execute(
            """
            SELECT app_name, window_title, started_at, duration_sec
            FROM sessions
            WHERE started_at >= ? AND started_at <= ?
              AND (LOWER(app_name) LIKE ? OR LOWER(window_title) LIKE ?)
            ORDER BY started_at DESC
            LIMIT ?
            """,
            (since_ts, until_ts, pat, pat, limit),
        ).fetchall()

        file_rows = conn.execute(
            """
            SELECT app_name, file_path, source, last_seen_at
            FROM opened_files
            WHERE last_seen_at >= ? AND last_seen_at <= ?
              AND (LOWER(app_name) LIKE ? OR LOWER(file_path) LIKE ?)
            ORDER BY last_seen_at DESC
            LIMIT ?
            """,
            (since_ts, until_ts, pat, pat, limit),
        ).fetchall()

        site_rows = conn.execute(
            """
            SELECT domain, url, page_title, last_seen_at
            FROM visited_sites
            WHERE last_seen_at >= ? AND last_seen_at <= ?
              AND (LOWER(domain) LIKE ? OR LOWER(url) LIKE ? OR LOWER(page_title) LIKE ?)
            ORDER BY last_seen_at DESC
            LIMIT ?
            """,
            (since_ts, until_ts, pat, pat, pat, limit),
        ).fetchall()
    finally:
        conn.close()

    return {
        "query": query,
        "matching_sessions": [
            {"time": fmt_ts(r["started_at"]), "duration": fmt_dur(r["duration_sec"]), "app": r["app_name"], "title": r["window_title"]}
            for r in sess_rows
        ],
        "matching_files": [
            {"app": r["app_name"], "file": r["file_path"], "source": r["source"], "last_seen": fmt_ts(r["last_seen_at"])}
            for r in file_rows
        ],
        "matching_sites": [
            {"domain": r["domain"], "title": r["page_title"], "url": r["url"], "last_seen": fmt_ts(r["last_seen_at"])}
            for r in site_rows
        ],
    }


TOOL_DISPATCH = {
    "get_activity_digest": get_activity_digest,
    "get_focus_blocks": get_focus_blocks,
    "search_activity": search_activity,
}


def main() -> int:
    parser = argparse.ArgumentParser(description="Compact activity data tool for small local LLMs")
    parser.add_argument("--db", help="Optional path to activity.db")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_dig = sub.add_parser("digest", help="Compact category/app/site/file summary")
    p_dig.add_argument("--days", type=int, default=0)
    p_dig.add_argument("--since")
    p_dig.add_argument("--top-n", type=int, default=10)

    p_fb = sub.add_parser("focus-blocks", help="Merged focus timeline blocks")
    p_fb.add_argument("--days", type=int, default=0)
    p_fb.add_argument("--since")
    p_fb.add_argument("--min-sec", type=int, default=30)
    p_fb.add_argument("--merge-gap", type=int, default=20)
    p_fb.add_argument("--limit", type=int, default=25)

    p_sr = sub.add_parser("search", help="Keyword search across sessions, files, and sites")
    p_sr.add_argument("query")
    p_sr.add_argument("--days", type=int, default=7)
    p_sr.add_argument("--limit", type=int, default=15)

    args = parser.parse_args()
    if args.cmd == "digest":
        out = get_activity_digest(days=args.days, since=args.since, top_n=args.top_n, db_path=args.db)
    elif args.cmd == "focus-blocks":
        out = get_focus_blocks(
            days=args.days, since=args.since, min_duration_sec=args.min_sec,
            merge_gap_sec=args.merge_gap, limit=args.limit, db_path=args.db,
        )
    else:
        out = search_activity(query=args.query, days=args.days, limit=args.limit, db_path=args.db)

    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
