//! Session DBus monitor watching org.kde.ActivityManager, XDG Application.Open, and Portals.

use futures_util::StreamExt;
use std::collections::HashMap;
use tokio::sync::mpsc;
use zbus::fdo::MonitoringProxy;
use zbus::zvariant::OwnedValue;
use zbus::{Connection, Message, MessageStream};

use crate::uri::normalize_file_uri;

#[derive(Debug, Clone)]
pub struct DbusFileEvent {
    pub app_name: Option<String>,
    pub file_path: String,
    pub source: &'static str,
}

fn extract_events_from_message(msg: &Message) -> Vec<DbusFileEvent> {
    let header = msg.header();
    let iface = header.interface().map(|i| i.as_str()).unwrap_or("");
    let member = header.member().map(|m| m.as_str()).unwrap_or("");
    let mut out = Vec::new();

    match (iface, member) {
        ("org.kde.ActivityManager.Resources", "RegisterResourceEvent") => {
            // (QString application, uint windowId, QString uri, uint event)
            if let Ok((app, _win_id, uri, _event)) = msg.body().deserialize::<(String, u32, String, u32)>() {
                if let Some(path) = normalize_file_uri(&uri) {
                    out.push(DbusFileEvent {
                        app_name: if app.is_empty() { None } else { Some(app) },
                        file_path: path,
                        source: "dbus:activity-manager",
                    });
                }
            }
        }
        ("org.kde.ActivityManager.ResourcesScoring", "ResourceScoreUpdated") => {
            // (QString activity, QString client, QString resource, double score, uint lastUpdate, uint firstUpdate)
            if let Ok((_act, client, resource, _score, _last, _first)) =
                msg.body().deserialize::<(String, String, String, f64, u32, u32)>()
            {
                if let Some(path) = normalize_file_uri(&resource) {
                    out.push(DbusFileEvent {
                        app_name: if client.is_empty() { None } else { Some(client) },
                        file_path: path,
                        source: "dbus:activity-scoring",
                    });
                }
            }
        }
        ("org.freedesktop.Application", "Open") => {
            // (as uris, a{sv} platform_data)
            if let Ok((uris, _platform)) =
                msg.body().deserialize::<(Vec<String>, HashMap<String, OwnedValue>)>()
            {
                let dest = header.destination().map(|d| d.as_str().to_string());
                for uri in uris {
                    if let Some(path) = normalize_file_uri(&uri) {
                        out.push(DbusFileEvent {
                            app_name: dest.clone(),
                            file_path: path,
                            source: "dbus:xdg-open",
                        });
                    }
                }
            }
        }
        ("org.freedesktop.portal.OpenURI", "OpenURI") => {
            // (s parent_window, s uri, a{sv} options)
            if let Ok((_parent, uri, _opts)) =
                msg.body().deserialize::<(String, String, HashMap<String, OwnedValue>)>()
            {
                if let Some(path) = normalize_file_uri(&uri) {
                    out.push(DbusFileEvent {
                        app_name: None,
                        file_path: path,
                        source: "dbus:portal",
                    });
                }
            }
        }
        _ => {}
    }

    out
}

/// Become a passive DBus monitor on a dedicated session connection and forward file events.
pub async fn run_dbus_monitor(tx: mpsc::Sender<DbusFileEvent>) -> zbus::Result<()> {
    let conn = Connection::session().await?;
    let proxy = MonitoringProxy::new(&conn).await?;
    let mut rule_strs = Vec::new();
    for iface in [
        "org.kde.ActivityManager.Resources",
        "org.kde.ActivityManager.ResourcesScoring",
        "org.freedesktop.Application",
        "org.freedesktop.portal.OpenURI",
    ] {
        for msg_type in ["method_call", "signal"] {
            rule_strs.push(format!("type='{msg_type}',interface='{iface}'"));
        }
    }
    let rules: Vec<zbus::MatchRule<'_>> = rule_strs
        .iter()
        .filter_map(|s| zbus::MatchRule::try_from(s.as_str()).ok())
        .collect();
    proxy.become_monitor(&rules, 0).await?;

    let mut stream = MessageStream::from(&conn);
    while let Some(msg_res) = stream.next().await {
        if let Ok(msg) = msg_res {
            for ev in extract_events_from_message(&msg) {
                if tx.send(ev).await.is_err() {
                    return Ok(());
                }
            }
        }
    }
    Ok(())
}
