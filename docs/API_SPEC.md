# Activity Remote Server — HTTP API Specification (v1)

This specification defines the HTTP/1.1 LAN API implemented by `activity-remote-server` (`crates/remote-server`) and consumed by both:
1. The desktop `activity-tracker` daemon (`PUT /api/v1/summary/today`).
2. The Android mobile app and home screen widget (`GET /api/v1/widget/today`, `GET /api/v1/summary/today`, `GET /api/v1/status`, `GET /api/v1/health`).

---

## General Behavior

- **Default Bind Address**: `0.0.0.0:7879` (configurable via `--addr` or `ACTIVITY_REMOTE_ADDR`).
- **Base URL**:
  - Same device (Termux on Android): `http://127.0.0.1:7879`
  - Over LAN: `http://<host-lan-ip>:7879`
- **Authentication**:
  - Optional Bearer token authentication. When the server is started with `--token <secret>` (or `ACTIVITY_REMOTE_TOKEN`), all endpoints **except** `GET /api/v1/health` require:
    ```http
    Authorization: Bearer <secret>
    ```
  - If `--token` is not set, all endpoints are open on the LAN.
- **In-Memory Daily Storage & Rollover**:
  - The server stores a single `DailySummaryPayload` in memory (`RwLock<Option<DailySummaryPayload>>`).
  - When a `PUT /api/v1/summary/today` arrives for a new `date` (`YYYY-MM-DD`), it replaces the previous day's summary.
  - Read endpoints check that the stored `date` matches today's local date on the server; if no data has been pushed for today, they return `200 OK` with `has_data: false` and `state: "offline"`.
- **Staleness Detection**:
  - `is_stale` is `true` when `has_data == false` or `(now - updated_at) > stale_secs` (default `60` seconds, configurable via `--stale-secs` / `ACTIVITY_REMOTE_STALE_SECS`).
  - When `is_stale` is `true`, `state` is reported as `"offline"`.
- **Android Cleartext HTTP Note**:
  - Android 9+ blocks `http://` traffic by default. Configure `android:usesCleartextTraffic="true"` in `AndroidManifest.xml` or allow `127.0.0.1` / LAN hosts in `network_security_config.xml`.

---

## Endpoints

### 1. Health Check
`GET /api/v1/health` *(no auth required)*

Used for connectivity checks (e.g., "Test Connection" in the Android app settings).

**Response `200 OK`**
```json
{
  "status": "ok",
  "has_data": true,
  "date": "2026-11-15",
  "updated_at": 1794762087.42
}
```
When no data has been pushed for today:
```json
{
  "status": "ok",
  "has_data": false,
  "date": null,
  "updated_at": null
}
```

---

### 2. Daemon Push (Ingest)
`PUT /api/v1/summary/today`

Idempotent snapshot push sent by `activity-tracker run --remote-url ...` on startup, on window/pause/screen-lock changes, and on the 5-second heartbeat.

**Request Body (`application/json`)**
```json
{
  "date": "2026-11-15",
  "source_host": "desktop-linux",
  "updated_at": 1794762087.42,
  "total_active_sec": 14520.5,
  "status": {
    "tracking": true,
    "paused": false,
    "screen_locked": false,
    "current_app": "dev.zed.Zed",
    "current_title": "main.rs — activity-tracker",
    "current_category": "Development",
    "current_duration_sec": 342.1
  },
  "categories": [
    {
      "category": "Development",
      "total_sec": 9800.0,
      "share_pct": 67.5,
      "session_count": 24,
      "app_count": 3
    }
  ],
  "apps": [
    {
      "app_name": "dev.zed.Zed",
      "category": "Development",
      "total_sec": 7200.0,
      "session_count": 15,
      "file_count": 8
    }
  ],
  "top_sites": [
    {
      "domain": "docs.rs",
      "page_title": "axum - Rust",
      "app_name": "org.mozilla.firefox",
      "last_seen_at": 1794761900.0
    }
  ],
  "recent_files": [
    {
      "app_name": "dev.zed.Zed",
      "file_path": "/home/user/project/src/main.rs",
      "source": "title",
      "last_seen_at": 1794762080.0
    }
  ]
}
```
- `date` must be non-empty (`400 Bad Request` otherwise).
- `updated_at`: Unix epoch seconds (`f64`). If `<= 0.0`, the server fills in its current timestamp.
- `top_sites` and `recent_files` are optional (default to `[]` if omitted).

**Response `200 OK`**
```json
{
  "ok": true,
  "date": "2026-11-15",
  "updated_at": 1794762087.42
}
```

---

### 3. Home Screen Widget Summary
`GET /api/v1/widget/today`

Compact payload tailored for Android `AppWidgetProvider` / Glance widgets.

**Query Parameters**
| Parameter | Type | Default | Range | Description |
| :--- | :--- | :--- | :--- | :--- |
| `top` | integer | `4` | `1..=10` | Max items returned in `top_categories` and `top_apps` |

**Response `200 OK`**
```json
{
  "date": "2026-11-15",
  "has_data": true,
  "is_stale": false,
  "updated_at": 1794762087.42,
  "total_active_sec": 14520.5,
  "state": "active",
  "current_app": "dev.zed.Zed",
  "current_category": "Development",
  "current_duration_sec": 342.1,
  "top_categories": [
    {
      "category": "Development",
      "total_sec": 9800.0,
      "share_pct": 67.5
    },
    {
      "category": "Learning",
      "total_sec": 2400.0,
      "share_pct": 16.5
    }
  ],
  "top_apps": [
    {
      "app_name": "dev.zed.Zed",
      "total_sec": 7200.0
    },
    {
      "app_name": "org.mozilla.firefox",
      "total_sec": 3900.0
    }
  ]
}
```

**State Values**
- `"active"`: `tracking == true`, not paused, not locked, and `!is_stale`
- `"paused"`: `tracking == true`, `paused == true`, not locked, and `!is_stale`
- `"locked"`: `tracking == true`, `screen_locked == true`, and `!is_stale`
- `"offline"`: `has_data == false`, `tracking == false`, or `is_stale == true`

---

### 4. Full Daily Summary (Main App)
`GET /api/v1/summary/today`

Full daily breakdown for the mobile app's dashboard (categories, apps, visited sites, recent files, and live status).

**Response `200 OK`**
```json
{
  "has_data": true,
  "is_stale": false,
  "date": "2026-11-15",
  "source_host": "desktop-linux",
  "updated_at": 1794762087.42,
  "total_active_sec": 14520.5,
  "status": {
    "tracking": true,
    "paused": false,
    "screen_locked": false,
    "current_app": "dev.zed.Zed",
    "current_title": "main.rs — activity-tracker",
    "current_category": "Development",
    "current_duration_sec": 342.1
  },
  "categories": [
    {
      "category": "Development",
      "total_sec": 9800.0,
      "share_pct": 67.5,
      "session_count": 24,
      "app_count": 3
    }
  ],
  "apps": [
    {
      "app_name": "dev.zed.Zed",
      "category": "Development",
      "total_sec": 7200.0,
      "session_count": 15,
      "file_count": 8
    }
  ],
  "top_sites": [
    {
      "domain": "docs.rs",
      "page_title": "axum - Rust",
      "app_name": "org.mozilla.firefox",
      "last_seen_at": 1794761900.0
    }
  ],
  "recent_files": [
    {
      "app_name": "dev.zed.Zed",
      "file_path": "/home/user/project/src/main.rs",
      "source": "title",
      "last_seen_at": 1794762080.0
    }
  ]
}
```
When `has_data == false`: `source_host` is `null`, `updated_at` and `total_active_sec` are `0.0`, `status.tracking` is `false`, and all arrays are `[]`.

---

### 5. Live Status Poll
`GET /api/v1/status`

Lightweight endpoint for polling the currently active window/state while the app is open in the foreground.

**Response `200 OK`**
```json
{
  "has_data": true,
  "is_stale": false,
  "updated_at": 1794762087.42,
  "state": "active",
  "tracking": true,
  "paused": false,
  "screen_locked": false,
  "current_app": "dev.zed.Zed",
  "current_title": "main.rs — activity-tracker",
  "current_category": "Development",
  "current_duration_sec": 342.1
}
```

---

## Error Responses

| HTTP Status | Body | Cause |
| :--- | :--- | :--- |
| `400 Bad Request` | `{"error": "<message>"}` | Invalid payload (e.g., empty `date` on `PUT`) |
| `401 Unauthorized` | `{"error": "unauthorized"}` | `--token` is configured and `Authorization: Bearer <token>` is missing or invalid |
