# KDE Wayland Activity & Opened File Tracker (Rust)

![AI-Generated](https://img.shields.io/badge/AI--Generated-LLM%20Code-blue)

> [!NOTE]
> **AI-Generated Code:** This repository and its codebase were generated with an LLM.

Tracks active, **non-minimized** application time and opened user files on KDE Plasma (Wayland / KWin 6), storing everything locally in SQLite (`~/.local/share/activity-tracker/activity.db`).

## How It Works
- **Window & Minimize Tracking (`kwin_bridge.js` -> `src/daemon.rs`)**: Loads a KWin 6 script that listens to `workspace.windowActivated`, `minimizedChanged`, `captionChanged`, and `showingDesktopChanged`. Only when a window is active, not minimized, and not hidden by Show Desktop is it counted.
- **Screen Lock Detection (`src/daemon.rs`)**: Subscribes to `org.freedesktop.ScreenSaver` `ActiveChanged` so locked/idle screen time is excluded.
- **DBus Activity & File Monitoring (`src/dbus_monitor.rs`)**: Uses `org.freedesktop.DBus.Monitoring.BecomeMonitor` on a dedicated session connection to watch:
  - `org.kde.ActivityManager.Resources` (`RegisterResourceEvent`)
  - `org.kde.ActivityManager.ResourcesScoring` (`ResourceScoreUpdated`)
  - `org.freedesktop.Application` (`Open`)
  - `org.freedesktop.portal.OpenURI` (`OpenURI`)
- **`~/.local/share/recently-used.xbel` Watcher (`src/xbel.rs`)**: Watches `~/.local/share/recently-used.xbel` with `notify` and parses `<bookmark>` + `<bookmark:application>` entries with `quick-xml`.
- **`/proc/<pid>/fd` Fallback (`src/proc_scanner.rs`)**: Optional fallback for apps that bypass DBus and XBEL (can be disabled with `--no-proc-fallback`).

## Workspace Layout
- **`activity-tracker`** (root): KDE Wayland daemon, SQLite storage, CLI reports, and embedded Web UI.
- **`crates/activity-protocol`**: Shared JSON payload types for daemon ↔ server ↔ mobile app communication.
- **`crates/remote-server`**: Lightweight, zero-C-dependency in-memory LAN HTTP server (`activity-remote-server`), cross-compiled statically for `aarch64-unknown-linux-musl` (Termux on Android).

## Build & Usage

```bash
cargo build --release --workspace
```

Run in the foreground:
```bash
./target/release/activity-tracker run -v
```

Run with LAN remote sync (pushes today's summary & live status to `activity-remote-server`):
```bash
./target/release/activity-tracker run -v \
  --remote-url http://192.168.1.50:7879 \
  --remote-token my-lan-secret
```
(`ACTIVITY_TRACKER_REMOTE_URL` and `ACTIVITY_TRACKER_REMOTE_TOKEN` environment variables are also supported.)

Import existing `~/.local/share/recently-used.xbel` history:
```bash
./target/release/activity-tracker import-xbel
```

View reports:
```bash
./target/release/activity-tracker report
./target/release/activity-tracker report --days 7
./target/release/activity-tracker files --days 7
./target/release/activity-tracker sites --days 7
./target/release/activity-tracker sessions --limit 20
```

Install & start as a `systemd --user` background service:
```bash
./target/release/activity-tracker install-service
```

## Remote LAN Server (Termux / ARM64) & API Spec

See [crates/remote-server/README.md](crates/remote-server/README.md) for Termux build/run instructions and [docs/API_SPEC.md](docs/API_SPEC.md) for the full HTTP API specification (including the Android app and home screen widget endpoints).

CI builds a statically linked `aarch64-unknown-linux-musl` binary automatically on push via [.github/workflows/build.yml](.github/workflows/build.yml).

## Privacy, Redaction & Reporter Plugins

Activity Tracker includes a runtime-hot-reloaded privacy pipeline (`~/.config/activity-tracker/privacy.json`, or `--privacy-config <PATH>` / `ACTIVITY_TRACKER_PRIVACY_CONFIG`):

```bash
./target/release/activity-tracker privacy init                  # Write default privacy.json
./target/release/activity-tracker privacy show                  # Show active config & path
./target/release/activity-tracker privacy domains               # List built-in sensitive domains
./target/release/activity-tracker privacy fetch-lists           # Download MISP global bank-website list
./target/release/activity-tracker privacy fetch-lists --include-adult --include-gambling
```

- **Per-sink controls (`storage`, `ui`, `remote`, `llm`)**: Independently toggle `enabled`, `include_app`, `include_title`, `include_files`, `include_sites`, and `include_category` (e.g., save only app + category to SQLite, show full details in local UI, send only category to the remote server, and hide or redact for `llm-tool/activity_tool.py`).
- **Premade & default sensitive domain lists**: Supports loading external premade lists (`sensitive_domain_files` or auto-loading `~/.config/activity-tracker/lists/*`) in **MISP warninglist JSON** (`MISP/misp-warninglists` `bank-website/list.json`), **hosts-file** (`StevenBlack/hosts`), **Adblock** (`||domain^`), or plain text formats—combined with a built-in default list, `sensitive_domains` additions, and `allow_domains` overrides (`sensitive_domain_action`: `"ignore"` or `"redact"`).
- **Per-app/title/domain/category rules**: Override any sink or all sinks per rule.
- **Reporter plugins (`plugins.discord_rpc`)**: Disabled by default. When enabled, operates as a strict whitelist (`hide_by_default: true`, `show_title: false`) over Discord's local IPC socket (`discord-ipc-0`), hiding/clearing presence for any app or category not in `allowed_apps` / `allowed_categories`.


