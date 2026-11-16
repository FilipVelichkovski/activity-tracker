//! Discord Rich Presence reporter plugin.
//!
//! Disabled by default. When enabled, operates as a strict whitelist (`hide_by_default = true`):
//! any app or category not explicitly listed in `allowed_apps` / `allowed_categories`
//! clears the Discord Rich Presence status instead of broadcasting it.

use serde_json::json;
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::{ActivityReporterPlugin, PluginActivity};
use crate::privacy::{DiscordRpcConfig, PluginsConfig};

pub struct DiscordRpcPlugin {
    socket: Option<UnixStream>,
    connected_client_id: String,
    last_sent_key: Option<String>,
    nonce: u64,
}

impl DiscordRpcPlugin {
    pub fn new() -> Self {
        Self {
            socket: None,
            connected_client_id: String::new(),
            last_sent_key: None,
            nonce: 1,
        }
    }

    pub fn encode_frame(opcode: u32, payload: &serde_json::Value) -> Vec<u8> {
        let body = serde_json::to_vec(payload).unwrap_or_default();
        let len = body.len() as u32;
        let mut buf = Vec::with_capacity(8 + body.len());
        buf.extend_from_slice(&opcode.to_le_bytes());
        buf.extend_from_slice(&len.to_le_bytes());
        buf.extend_from_slice(&body);
        buf
    }

    fn find_ipc_socket() -> Option<PathBuf> {
        let mut dirs = Vec::new();
        for var in ["XDG_RUNTIME_DIR", "TMPDIR", "TMP", "TEMP"] {
            if let Ok(val) = std::env::var(var) {
                if !val.trim().is_empty() {
                    dirs.push(PathBuf::from(val));
                }
            }
        }
        dirs.push(PathBuf::from("/tmp"));

        for dir in dirs {
            for i in 0..10 {
                let candidate = dir.join(format!("discord-ipc-{i}"));
                if candidate.exists() {
                    return Some(candidate);
                }
            }
        }
        None
    }

    fn ensure_connected(&mut self, client_id: &str) -> bool {
        if client_id.trim().is_empty() {
            return false;
        }
        if self.socket.is_some() && self.connected_client_id == client_id {
            return true;
        }
        self.socket = None;
        let Some(path) = Self::find_ipc_socket() else {
            return false;
        };
        let Ok(mut stream) = UnixStream::connect(&path) else {
            return false;
        };
        let _ = stream.set_write_timeout(Some(Duration::from_millis(500)));
        let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));

        let handshake = json!({
            "v": 1,
            "client_id": client_id,
        });
        let frame = Self::encode_frame(0, &handshake);
        if stream.write_all(&frame).is_err() {
            return false;
        }
        self.socket = Some(stream);
        self.connected_client_id = client_id.to_string();
        true
    }

    fn send_frame(&mut self, payload: &serde_json::Value) {
        let frame = Self::encode_frame(1, payload);
        if let Some(ref mut stream) = self.socket {
            if stream.write_all(&frame).is_err() {
                self.socket = None;
            }
        }
    }

    fn clear_presence(&mut self) {
        if self.socket.is_none() {
            self.last_sent_key = None;
            return;
        }
        if self.last_sent_key.as_deref() == Some("__cleared__") {
            return;
        }
        self.nonce += 1;
        let payload = json!({
            "cmd": "SET_ACTIVITY",
            "args": {
                "pid": std::process::id(),
            },
            "nonce": format!("at-{}", self.nonce),
        });
        self.send_frame(&payload);
        self.last_sent_key = Some("__cleared__".to_string());
    }

    pub fn is_whitelisted(cfg: &DiscordRpcConfig, activity: &PluginActivity) -> bool {
        if activity.paused || activity.screen_locked {
            return false;
        }
        let app_l = activity.app_name.to_lowercase();
        let cat_l = activity.category.to_lowercase();

        let app_match = cfg
            .allowed_apps
            .iter()
            .any(|a| !a.trim().is_empty() && app_l.contains(&a.to_lowercase()));
        let cat_match = cfg
            .allowed_categories
            .iter()
            .any(|c| !c.trim().is_empty() && cat_l == c.to_lowercase());

        if cfg.hide_by_default {
            app_match || cat_match
        } else {
            // Even if hide_by_default is false, empty whitelists allow all non-paused activity
            true
        }
    }

    pub fn format_presence(
        cfg: &DiscordRpcConfig,
        activity: &PluginActivity,
    ) -> Option<(String, Option<String>)> {
        if !cfg.enabled || !Self::is_whitelisted(cfg, activity) {
            return None;
        }
        let details = if cfg.show_category && !activity.category.is_empty() {
            format!("{} — {}", activity.category, activity.app_name)
        } else {
            activity.app_name.clone()
        };
        let state = if cfg.show_title && !activity.window_title.is_empty() {
            Some(activity.window_title.chars().take(120).collect())
        } else {
            None
        };
        Some((details, state))
    }
}

impl ActivityReporterPlugin for DiscordRpcPlugin {
    fn name(&self) -> &'static str {
        "discord_rpc"
    }

    fn on_activity_update(&mut self, activity: Option<&PluginActivity>, cfg: &PluginsConfig) {
        let rpc = &cfg.discord_rpc;
        if !rpc.enabled {
            self.clear_presence();
            self.socket = None;
            return;
        }

        let Some(act) = activity else {
            self.clear_presence();
            return;
        };

        let Some((details, state)) = Self::format_presence(rpc, act) else {
            self.clear_presence();
            return;
        };

        let key = format!("{details}|{state:?}|{:.0}", act.started_at);
        if self.last_sent_key.as_deref() == Some(&key) {
            return;
        }

        if !self.ensure_connected(&rpc.client_id) {
            return;
        }

        let mut activity_obj = serde_json::Map::new();
        activity_obj.insert("details".to_string(), json!(details));
        if let Some(st) = state {
            activity_obj.insert("state".to_string(), json!(st));
        }
        if rpc.show_elapsed {
            let start_sec = if act.started_at > 0.0 {
                act.started_at.floor() as u64
            } else {
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
            };
            activity_obj.insert("timestamps".to_string(), json!({ "start": start_sec }));
        }

        self.nonce += 1;
        let payload = json!({
            "cmd": "SET_ACTIVITY",
            "args": {
                "pid": std::process::id(),
                "activity": serde_json::Value::Object(activity_obj),
            },
            "nonce": format!("at-{}", self.nonce),
        });
        self.send_frame(&payload);
        self.last_sent_key = Some(key);
    }

    fn on_shutdown(&mut self) {
        self.clear_presence();
        self.socket = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_act(app: &str, title: &str, cat: &str) -> PluginActivity {
        PluginActivity {
            app_name: app.to_string(),
            window_title: title.to_string(),
            category: cat.to_string(),
            started_at: 1000.0,
            paused: false,
            screen_locked: false,
        }
    }

    #[test]
    fn disabled_by_default_and_whitelist_hides_unlisted() {
        let mut cfg = DiscordRpcConfig::default();
        assert!(!cfg.enabled);
        assert!(cfg.hide_by_default);
        let act = sample_act("dev.zed.Zed", "secret.rs", "Development");
        assert!(DiscordRpcPlugin::format_presence(&cfg, &act).is_none());

        // Enable with empty whitelist -> still hidden by default
        cfg.enabled = true;
        assert!(DiscordRpcPlugin::format_presence(&cfg, &act).is_none());

        // Whitelist Development category -> visible, but title still hidden by default
        cfg.allowed_categories = vec!["Development".to_string()];
        let (details, state) = DiscordRpcPlugin::format_presence(&cfg, &act).unwrap();
        assert_eq!(details, "Development — dev.zed.Zed");
        assert!(state.is_none());

        // Non-whitelisted app/category remains hidden
        let chat = sample_act("org.telegram.desktop", "Private Chat", "Communication");
        assert!(DiscordRpcPlugin::format_presence(&cfg, &chat).is_none());
    }

    #[test]
    fn encodes_valid_ipc_frame_header() {
        let frame = DiscordRpcPlugin::encode_frame(0, &json!({"v": 1}));
        assert_eq!(&frame[0..4], &0u32.to_le_bytes());
        let len = u32::from_le_bytes(frame[4..8].try_into().unwrap()) as usize;
        assert_eq!(frame.len(), 8 + len);
    }
}
