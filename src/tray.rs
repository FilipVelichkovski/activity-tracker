//! Native KDE/Freedesktop StatusNotifierItem system tray icon via ksni.

use ksni::menu::StandardItem;
use ksni::{MenuItem, ToolTip, Tray, TrayMethods};
use std::process::Command;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

use crate::daemon::TrackerState;

pub struct ActivityTray {
    pub state: Arc<Mutex<TrackerState>>,
    pub web_url: String,
    pub shutdown_tx: mpsc::Sender<()>,
}

impl ActivityTray {
    fn status_label(&self) -> String {
        let Ok(guard) = self.state.lock() else {
            return "Status: unknown".to_string();
        };
        if guard.manually_paused {
            "Paused by user".to_string()
        } else if guard.screen_locked {
            "Paused (Screen locked)".to_string()
        } else if let Some(ref cur) = guard.current {
            format!("Tracking: {}", cur.app_name)
        } else {
            "Idle (No active non-minimized window)".to_string()
        }
    }

    fn is_paused(&self) -> bool {
        self.state
            .lock()
            .map(|g| g.manually_paused)
            .unwrap_or(false)
    }

    fn open_web_ui(&self) {
        let _ = Command::new("xdg-open").arg(&self.web_url).spawn();
    }
}

impl std::fmt::Debug for ActivityTray {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ActivityTray")
            .field("web_url", &self.web_url)
            .finish()
    }
}

impl Tray for ActivityTray {
    fn id(&self) -> String {
        "activity-tracker".to_string()
    }

    fn title(&self) -> String {
        "Activity Tracker".to_string()
    }

    fn icon_name(&self) -> String {
        if self.is_paused() {
            "media-playback-pause".to_string()
        } else {
            "preferences-system-time".to_string()
        }
    }

    fn tool_tip(&self) -> ToolTip {
        ToolTip {
            icon_name: self.icon_name(),
            icon_pixmap: Vec::new(),
            title: "Activity Tracker".to_string(),
            description: self.status_label(),
        }
    }

    fn activate(&mut self, _x: i32, _y: i32) {
        self.open_web_ui();
    }

    fn menu(&self) -> Vec<MenuItem<Self>> {
        let paused = self.is_paused();
        vec![
            MenuItem::Standard(StandardItem {
                label: self.status_label(),
                enabled: false,
                ..Default::default()
            }),
            MenuItem::Separator,
            MenuItem::Standard(StandardItem {
                label: "Open Web Dashboard".to_string(),
                icon_name: "internet-web-browser".to_string(),
                activate: Box::new(|tray: &mut Self| {
                    tray.open_web_ui();
                }),
                ..Default::default()
            }),
            MenuItem::Standard(StandardItem {
                label: if paused {
                    "Resume Tracking".to_string()
                } else {
                    "Pause Tracking".to_string()
                },
                icon_name: if paused {
                    "media-playback-start".to_string()
                } else {
                    "media-playback-pause".to_string()
                },
                activate: Box::new(|tray: &mut Self| {
                    if let Ok(mut guard) = tray.state.lock() {
                        guard.toggle_manual_pause();
                    }
                }),
                ..Default::default()
            }),
            MenuItem::Separator,
            MenuItem::Standard(StandardItem {
                label: "Quit".to_string(),
                icon_name: "application-exit".to_string(),
                activate: Box::new(|tray: &mut Self| {
                    let _ = tray.shutdown_tx.try_send(());
                }),
                ..Default::default()
            }),
        ]
    }
}

pub async fn spawn_tray(
    state: Arc<Mutex<TrackerState>>,
    web_url: String,
    shutdown_tx: mpsc::Sender<()>,
) -> Option<ksni::Handle<ActivityTray>> {
    let tray = ActivityTray {
        state,
        web_url,
        shutdown_tx,
    };
    match tray.spawn().await {
        Ok(handle) => Some(handle),
        Err(e) => {
            eprintln!("System tray unavailable (continuing without tray): {e}");
            None
        }
    }
}
