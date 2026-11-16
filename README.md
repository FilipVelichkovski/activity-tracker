# KDE Wayland Activity & Opened File Tracker (Rust)

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

