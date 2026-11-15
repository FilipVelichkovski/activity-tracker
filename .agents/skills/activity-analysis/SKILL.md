---
name: activity-analysis
description: >-
  Analyze tracked desktop activity (time spent by category and app, opened user files,
  visited websites, and merged focus blocks) using compact, token-efficient tools
  instead of raw SQLite dumps. Use when asked how time was spent, what files were
  edited, what websites were visited, or to summarize daily/weekly focus.
---

# Activity Analysis Skill

Use the pre-aggregated analysis tools in `/var/home/silver/repos/activity-tracker/llm-tool/activity_tool.py` (or the `activity-tracker` CLI). **Do not** query `~/.local/share/activity-tracker/activity.db` with raw `SELECT *` queries—raw session rows are noisy and waste context tokens.

## Tool Selection

1. **Daily or multi-day overview** (time by category, top apps, top domains, opened files):
   ```bash
   python3 /var/home/silver/repos/activity-tracker/llm-tool/activity_tool.py digest --days 0 --top-n 10
   ```
   - `--days 0`: today since midnight
   - `--days 7`: last 7 days
   - `--since YYYY-MM-DD`: custom start date

2. **Chronological deep-work / focus timeline** (merges rapid tab/window switches into clean blocks):
   ```bash
   python3 /var/home/silver/repos/activity-tracker/llm-tool/activity_tool.py focus-blocks --days 0 --min-sec 30 --limit 25
   ```

3. **Find when a specific project, file, or website was used**:
   ```bash
   python3 /var/home/silver/repos/activity-tracker/llm-tool/activity_tool.py search "keyword" --days 7 --limit 15
   ```

## Analysis Rules

- **Only report facts returned by the tool.** Never invent durations, file paths, or URLs.
- **Note that minimized, inactive, and screen-locked periods are excluded** by the tracker, so gaps in the timeline represent AFK/locked/minimized time, not missing data.
- **Keep summaries structured**:
  1. Total active time & top categories (Development, Learning, Communication, Social, Media, etc.)
  2. Key focus blocks (when deep work happened)
  3. Notable files opened & websites visited
- If using a local Ollama model directly, use `tool_schema.json` and `ask_local_model.py` in `/var/home/silver/repos/activity-tracker/llm-tool/`.
