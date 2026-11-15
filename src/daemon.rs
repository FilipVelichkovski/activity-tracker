//! Async daemon coordinating KWin active-window events, DBus monitoring, XBEL watching, and SQLite.

use futures_util::StreamExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::process::Command;
use tokio::sync::{Notify, mpsc};
use zbus::{Connection, Proxy, interface};

use crate::browser::{FirefoxSessionCache, detect_site_visit};
use crate::dbus_monitor::{DbusFileEvent, run_dbus_monitor};
use crate::proc_scanner::scan_open_files;
use crate::remote_sync::{RemoteConfig, spawn_remote_sync};
use crate::storage::TrackerDb;
use crate::title_files::extract_file_from_title;
use crate::tray::spawn_tray;
use crate::web_ui::{WebContext, serve_web_ui};
use crate::xbel::{XbelEntry, default_xbel_path, watch_xbel};

const DBUS_SERVICE: &str = "org.antigravity.ActivityTracker";
const DBUS_PATH: &str = "/Tracker";
const KWIN_SCRIPT_NAME: &str = "agy_activity_tracker";
const FLUSH_INTERVAL_SECS: u64 = 5;

fn now_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

#[derive(Debug, Clone)]
pub struct ActiveSession {
    pub session_id: i64,
    pub app_name: String,
    pub window_title: String,
    pub pid: i64,
    pub started_at: f64,
}

pub struct TrackerState {
    pub db: TrackerDb,
    pub current: Option<ActiveSession>,
    pub screen_locked: bool,
    pub manually_paused: bool,
    pub last_window_state: Option<(String, String, i64, bool)>,
    pub verbose: bool,
    pub proc_fallback: bool,
    pub ff_cache: FirefoxSessionCache,
    pub remote_notify: Option<Arc<Notify>>,
}

impl TrackerState {
    pub fn new(db: TrackerDb, verbose: bool, proc_fallback: bool) -> Self {
        Self {
            db,
            current: None,
            screen_locked: false,
            manually_paused: false,
            last_window_state: None,
            verbose,
            proc_fallback,
            ff_cache: FirefoxSessionCache::new(),
            remote_notify: None,
        }
    }

    fn notify_remote(&self) {
        if let Some(ref notify) = self.remote_notify {
            notify.notify_one();
        }
    }

    pub fn toggle_manual_pause(&mut self) {
        self.manually_paused = !self.manually_paused;
        self.log(&format!("Manual pause={}", self.manually_paused));
        let now = now_secs();
        if self.manually_paused {
            self.close_current_session(now);
        } else if !self.screen_locked {
            if let Some((app, title, pid, is_vis)) = self.last_window_state.clone() {
                if is_vis && !app.is_empty() && self.current.is_none() {
                    self.start_session(&app, &title, pid, now);
                }
            }
        }
        self.notify_remote();
    }

    fn log(&self, msg: &str) {
        if self.verbose {
            let ts = chrono::Local::now().format("%H:%M:%S");
            eprintln!("[{ts}] {msg}");
        }
    }

    pub fn close_current_session(&mut self, now: f64) {
        let Some(sess) = self.current.take() else {
            return;
        };
        let _ = self.db.update_session_end(sess.session_id, now);
        if self.proc_fallback && sess.pid > 0 {
            for path in scan_open_files(sess.pid) {
                let _ = self.db.record_file(
                    Some(sess.session_id),
                    &sess.app_name,
                    &path,
                    "proc-fd",
                    now,
                );
            }
        }
        self.log(&format!(
            "STOP  app={:?} dur={:.1}s title={:?}",
            sess.app_name,
            (now - sess.started_at).max(0.0),
            sess.window_title
        ));
    }

    fn start_session(&mut self, app_name: &str, window_title: &str, pid: i64, now: f64) {
        let Ok(session_id) = self.db.start_session(app_name, window_title, pid, now) else {
            return;
        };
        self.current = Some(ActiveSession {
            session_id,
            app_name: app_name.to_string(),
            window_title: window_title.to_string(),
            pid,
            started_at: now,
        });
        if let Some((file_path, source)) = extract_file_from_title(app_name, window_title) {
            let _ = self
                .db
                .record_file(Some(session_id), app_name, &file_path, source, now);
        }
        if let Some(visit) = detect_site_visit(app_name, window_title, &mut self.ff_cache) {
            let _ = self.db.record_site(
                Some(session_id),
                &visit.app_name,
                &visit.domain,
                &visit.url,
                &visit.page_title,
                visit.source,
                now,
            );
        }
        let mut proc_count = 0;
        if self.proc_fallback && pid > 0 {
            let files = scan_open_files(pid);
            proc_count = files.len();
            for path in files {
                let _ = self.db.record_file(
                    Some(session_id),
                    app_name,
                    &path,
                    "proc-fd",
                    now,
                );
            }
        }
        self.log(&format!(
            "START app={app_name:?} pid={pid} proc_files={proc_count} title={window_title:?}"
        ));
    }

    pub fn handle_window_update(
        &mut self,
        app_name: &str,
        window_title: &str,
        pid: i64,
        is_visible_active: bool,
    ) {
        self.last_window_state = Some((
            app_name.to_string(),
            window_title.to_string(),
            pid,
            is_visible_active,
        ));
        let now = now_secs();

        if self.screen_locked || self.manually_paused || !is_visible_active || app_name.is_empty() {
            let had_session = self.current.is_some();
            self.close_current_session(now);
            if had_session {
                self.notify_remote();
            }
            return;
        }

        if let Some(ref cur) = self.current {
            if cur.app_name == app_name && cur.window_title == window_title && cur.pid == pid {
                return;
            }
        }

        self.close_current_session(now);
        self.start_session(app_name, window_title, pid, now);
        self.notify_remote();
    }

    pub fn handle_screensaver_changed(&mut self, active: bool) {
        self.screen_locked = active;
        self.log(&format!("ScreenSaver Active={active}"));
        let now = now_secs();
        if active {
            self.close_current_session(now);
        } else if !self.manually_paused {
            if let Some((app, title, pid, is_vis)) = self.last_window_state.clone() {
                if is_vis && !app.is_empty() && self.current.is_none() {
                    self.start_session(&app, &title, pid, now);
                }
            }
        }
        self.notify_remote();
    }

    pub fn heartbeat(&mut self) {
        if self.screen_locked || self.manually_paused {
            self.notify_remote();
            return;
        }
        let Some(cur) = self.current.clone() else {
            self.notify_remote();
            return;
        };
        let now = now_secs();
        let _ = self.db.update_session_end(cur.session_id, now);
        if let Some(visit) = detect_site_visit(&cur.app_name, &cur.window_title, &mut self.ff_cache) {
            let _ = self.db.record_site(
                Some(cur.session_id),
                &visit.app_name,
                &visit.domain,
                &visit.url,
                &visit.page_title,
                visit.source,
                now,
            );
        }
        if self.proc_fallback && cur.pid > 0 {
            for path in scan_open_files(cur.pid) {
                let _ = self.db.record_file(
                    Some(cur.session_id),
                    &cur.app_name,
                    &path,
                    "proc-fd",
                    now,
                );
            }
        }
        self.notify_remote();
    }

    pub fn record_external_file(
        &self,
        app_hint: Option<&str>,
        file_path: &str,
        source: &str,
        ts: f64,
    ) {
        let session_id = self.current.as_ref().map(|c| c.session_id);
        let app_name = app_hint
            .filter(|s| !s.is_empty())
            .or_else(|| self.current.as_ref().map(|c| c.app_name.as_str()))
            .unwrap_or("unknown");

        let _ = self
            .db
            .record_file(session_id, app_name, file_path, source, ts);
        self.log(&format!("FILE  [{source}] app={app_name:?} path={file_path:?}"));
    }
}

struct TrackerInterface {
    state: Arc<Mutex<TrackerState>>,
}

#[interface(name = "org.antigravity.ActivityTracker")]
impl TrackerInterface {
    fn update_window(
        &self,
        app_name: String,
        window_title: String,
        pid: i32,
        is_visible_active: bool,
    ) {
        if let Ok(mut guard) = self.state.lock() {
            guard.handle_window_update(&app_name, &window_title, i64::from(pid), is_visible_active);
        }
    }
}

fn find_kwin_bridge_js() -> Result<PathBuf, String> {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let candidate = dir.join("kwin_bridge.js");
            if candidate.exists() {
                return Ok(candidate);
            }
            // Also check two levels up (target/release -> project root)
            if let Some(grand) = dir.parent().and_then(|p| p.parent()) {
                let candidate2 = grand.join("kwin_bridge.js");
                if candidate2.exists() {
                    return Ok(candidate2);
                }
            }
        }
    }
    let cwd_candidate = PathBuf::from("kwin_bridge.js");
    if cwd_candidate.exists() {
        return Ok(cwd_candidate.canonicalize().unwrap_or(cwd_candidate));
    }
    Err("Could not locate kwin_bridge.js".to_string())
}

async fn unload_kwin_script() {
    let _ = Command::new("qdbus-qt6")
        .args(["org.kde.KWin", "/Scripting", "unloadScript", KWIN_SCRIPT_NAME])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await;
}

async fn load_kwin_script(js_path: &Path) -> Result<String, String> {
    unload_kwin_script().await;
    let output = Command::new("qdbus-qt6")
        .args([
            "org.kde.KWin",
            "/Scripting",
            "loadScript",
            &js_path.to_string_lossy(),
            KWIN_SCRIPT_NAME,
        ])
        .output()
        .await
        .map_err(|e| format!("Failed to execute qdbus-qt6: {e}"))?;

    if !output.status.success() {
        return Err(format!(
            "qdbus-qt6 loadScript failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let script_id = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if script_id == "-1" {
        return Err(format!("KWin refused to load {}", js_path.display()));
    }

    let start_status = Command::new("qdbus-qt6")
        .args(["org.kde.KWin", "/Scripting", "start"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .map_err(|e| format!("Failed to start KWin script: {e}"))?;

    if !start_status.success() {
        return Err("qdbus-qt6 Scripting.start failed".to_string());
    }
    Ok(script_id)
}

pub async fn run_daemon(
    db_path: Option<&Path>,
    verbose: bool,
    proc_fallback: bool,
    web_addr: Option<String>,
    enable_tray: bool,
    remote_cfg: Option<RemoteConfig>,
) -> Result<(), String> {
    let db = TrackerDb::open(db_path).map_err(|e| format!("Failed to open DB: {e}"))?;
    let db_file_path = db.path().to_path_buf();
    let db_display = db_file_path.display().to_string();
    let state = Arc::new(Mutex::new(TrackerState::new(db, verbose, proc_fallback)));

    if let Some(cfg) = remote_cfg {
        let notify = spawn_remote_sync(Arc::clone(&state), cfg, verbose)?;
        if let Ok(mut guard) = state.lock() {
            guard.remote_notify = Some(notify);
        }
    }

    let conn = Connection::session()
        .await
        .map_err(|e| format!("DBus session error: {e}"))?;

    conn.object_server()
        .at(
            DBUS_PATH,
            TrackerInterface {
                state: Arc::clone(&state),
            },
        )
        .await
        .map_err(|e| format!("Failed to export DBus object: {e}"))?;

    conn.request_name(DBUS_SERVICE)
        .await
        .map_err(|e| format!("Failed to acquire DBus name {DBUS_SERVICE}: {e}"))?;

    // Check initial ScreenSaver state & subscribe to ActiveChanged
    if let Ok(ss_proxy) = Proxy::new(
        &conn,
        "org.freedesktop.ScreenSaver",
        "/ScreenSaver",
        "org.freedesktop.ScreenSaver",
    )
    .await
    {
        if let Ok(active) = ss_proxy.call::<_, _, bool>("GetActive", &()).await {
            if let Ok(mut guard) = state.lock() {
                guard.screen_locked = active;
            }
        }
        if let Ok(mut sig_stream) = ss_proxy.receive_signal("ActiveChanged").await {
            let ss_state = Arc::clone(&state);
            tokio::spawn(async move {
                while let Some(msg) = sig_stream.next().await {
                    if let Ok(active) = msg.body().deserialize::<bool>() {
                        if let Ok(mut guard) = ss_state.lock() {
                            guard.handle_screensaver_changed(active);
                        }
                    }
                }
            });
        }
    }

    // Spawn DBus Monitor (org.kde.ActivityManager, XDG Application.Open, Portal OpenURI)
    let (dbus_tx, mut dbus_rx) = mpsc::channel::<DbusFileEvent>(128);
    tokio::spawn(async move {
        if let Err(e) = run_dbus_monitor(dbus_tx).await {
            eprintln!("DBus monitor exited: {e}");
        }
    });
    let dbus_state = Arc::clone(&state);
    tokio::spawn(async move {
        while let Some(ev) = dbus_rx.recv().await {
            if let Ok(guard) = dbus_state.lock() {
                guard.record_external_file(
                    ev.app_name.as_deref(),
                    &ev.file_path,
                    ev.source,
                    now_secs(),
                );
            }
        }
    });

    // Spawn ~/.local/share/recently-used.xbel watcher
    let (xbel_tx, mut xbel_rx) = mpsc::channel::<XbelEntry>(128);
    let xbel_path = default_xbel_path();
    let start_ts = now_secs();
    tokio::spawn(async move {
        if let Err(e) = watch_xbel(xbel_path, start_ts, xbel_tx).await {
            eprintln!("XBEL watcher exited: {e}");
        }
    });
    let xbel_state = Arc::clone(&state);
    tokio::spawn(async move {
        while let Some(entry) = xbel_rx.recv().await {
            if let Ok(guard) = xbel_state.lock() {
                guard.record_external_file(
                    Some(&entry.app_name),
                    &entry.file_path,
                    "xbel",
                    entry.modified_ts,
                );
            }
        }
    });

    // Spawn Web UI if enabled
    let web_url = if let Some(ref addr) = web_addr {
        let ctx = WebContext {
            db_path: db_file_path,
            state: Some(Arc::clone(&state)),
        };
        let addr_clone = addr.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_web_ui(&addr_clone, ctx).await {
                eprintln!("{e}");
            }
        });
        format!("http://{addr}")
    } else {
        "http://127.0.0.1:7878".to_string()
    };

    // Spawn KDE/Freedesktop System Tray icon
    let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(4);
    let tray_handle = if enable_tray {
        spawn_tray(Arc::clone(&state), web_url.clone(), shutdown_tx).await
    } else {
        None
    };

    // Load KWin bridge script
    let js_path = find_kwin_bridge_js()?;
    let script_id = load_kwin_script(&js_path).await?;
    if verbose {
        eprintln!("Loaded KWin script {KWIN_SCRIPT_NAME} (id={script_id})");
        eprintln!("Tracking active non-minimized windows + DBus + XBEL -> {db_display}");
        if web_addr.is_some() {
            eprintln!("Web UI available at {web_url}");
        }
    }

    // Heartbeat + signal handling
    let mut ticker = tokio::time::interval(Duration::from_secs(FLUSH_INTERVAL_SECS));
    let mut sigterm =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .map_err(|e| format!("Failed to register SIGTERM handler: {e}"))?;

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                if let Ok(mut guard) = state.lock() {
                    guard.heartbeat();
                }
                if let Some(ref handle) = tray_handle {
                    handle.update(|_| {}).await;
                }
            }
            _ = shutdown_rx.recv() => {
                break;
            }
            _ = tokio::signal::ctrl_c() => {
                break;
            }
            _ = sigterm.recv() => {
                break;
            }
        }
    }

    if let Ok(mut guard) = state.lock() {
        guard.close_current_session(now_secs());
    }
    unload_kwin_script().await;
    if verbose {
        eprintln!("Stopped cleanly");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimized_and_locked_windows_are_not_counted() {
        let dir = std::env::temp_dir().join(format!("agy_daemon_test_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let db_path = dir.join("daemon.db");
        let _ = std::fs::remove_file(&db_path);

        let db = TrackerDb::open(Some(&db_path)).unwrap();
        let mut st = TrackerState::new(db, false, false);

        st.handle_window_update("org.kde.kate", "notes.txt", 100, true);
        assert!(st.current.is_some());

        // Minimized window closes session and does not start one
        st.handle_window_update("org.kde.kate", "notes.txt", 100, false);
        assert!(st.current.is_none());

        // Screen lock closes session and blocks new ones
        st.handle_window_update("org.mozilla.firefox", "Docs", 200, true);
        assert!(st.current.is_some());
        st.handle_screensaver_changed(true);
        assert!(st.current.is_none());

        st.handle_window_update("org.mozilla.firefox", "Docs", 200, true);
        assert!(st.current.is_none());

        // Unlocking resumes last visible active window
        st.handle_screensaver_changed(false);
        assert!(st.current.is_some());
        assert_eq!(st.current.as_ref().unwrap().app_name, "org.mozilla.firefox");

        st.close_current_session(now_secs());
        let sessions = st.db.query_recent_sessions(10).unwrap();
        assert_eq!(sessions.len(), 3);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
