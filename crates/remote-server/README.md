# activity-remote-server

Lightweight, in-memory LAN HTTP server for today's activity summary, designed to run on Android via Termux (statically linked `aarch64-unknown-linux-musl`) and serve a mobile app + home screen widget.

## Building for Termux (ARM64 static binary)

Since `activity-remote-server` has zero C dependencies, you can cross-compile it from Linux/macOS/Windows using `rust-lld` (configured in `.cargo/config.toml`):

```bash
rustup target add aarch64-unknown-linux-musl
cargo build --release -p activity-remote-server --target aarch64-unknown-linux-musl
```

The statically linked binary will be at:
`target/aarch64-unknown-linux-musl/release/activity-remote-server`

Verify it is statically linked:
```bash
file target/aarch64-unknown-linux-musl/release/activity-remote-server
```

## Running on Termux

Copy the binary to your phone (e.g., via `scp` or `adb push`), make it executable, and run:

```bash
chmod +x activity-remote-server
./activity-remote-server --addr 0.0.0.0:7879 --token my-lan-secret -v
```

Environment variables are also supported:
- `ACTIVITY_REMOTE_ADDR` (default: `0.0.0.0:7879`)
- `ACTIVITY_REMOTE_TOKEN` (optional bearer token)
- `ACTIVITY_REMOTE_STALE_SECS` (default: `60`)

## Connecting the Desktop Daemon

Start `activity-tracker` with `--remote-url` pointing to your phone's LAN IP:

```bash
activity-tracker run --remote-url http://192.168.1.50:7879 --remote-token my-lan-secret -v
```

## HTTP API Specification

See [docs/API_SPEC.md](../../docs/API_SPEC.md) for the full endpoint and payload specification (daemon push, mobile app summary/status, and home screen widget endpoints).
