//! Parser and filesystem watcher for ~/.local/share/recently-used.xbel.

use chrono::DateTime;
use notify::{Event, RecommendedWatcher, RecursiveMode, Watcher};
use quick_xml::Reader;
use quick_xml::events::Event as XmlEvent;
use std::path::{Path, PathBuf};
use tokio::sync::mpsc;

use crate::uri::normalize_file_uri;

#[derive(Debug, Clone, PartialEq)]
pub struct XbelEntry {
    pub app_name: String,
    pub file_path: String,
    pub modified_ts: f64,
}

pub fn default_xbel_path() -> PathBuf {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    home.join(".local/share/recently-used.xbel")
}

fn parse_rfc3339_ts(s: &str) -> Option<f64> {
    DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|dt| dt.timestamp() as f64 + (dt.timestamp_subsec_nanos() as f64 / 1e9))
}

/// Parse `recently-used.xbel` XML bytes into `(app_name, file_path, modified_ts)` entries.
pub fn parse_xbel_bytes(data: &[u8]) -> Vec<XbelEntry> {
    let mut reader = Reader::from_reader(data);
    reader.config_mut().trim_text(true);

    let mut entries = Vec::new();
    let mut current_href: Option<String> = None;
    let mut current_bookmark_ts: f64 = 0.0;
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(XmlEvent::Start(ref e)) | Ok(XmlEvent::Empty(ref e)) => {
                let name_bytes = e.name();
                let local = name_bytes.local_name();
                let local_str = std::str::from_utf8(local.as_ref()).unwrap_or("");

                if local_str == "bookmark" {
                    let mut href = None;
                    let mut mod_ts = 0.0;
                    for attr in e.attributes().flatten() {
                        let key_local = attr.key.local_name();
                        let key = std::str::from_utf8(key_local.as_ref()).unwrap_or("");
                        let val = attr.unescape_value().unwrap_or_default();
                        match key {
                            "href" => href = normalize_file_uri(&val),
                            "modified" | "visited" => {
                                if let Some(ts) = parse_rfc3339_ts(&val) {
                                    if ts > mod_ts {
                                        mod_ts = ts;
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                    current_href = href;
                    current_bookmark_ts = mod_ts;
                } else if local_str == "application" {
                    if let Some(ref file_path) = current_href {
                        let mut app_name = String::new();
                        let mut app_ts = current_bookmark_ts;
                        for attr in e.attributes().flatten() {
                            let key_local = attr.key.local_name();
                            let key = std::str::from_utf8(key_local.as_ref()).unwrap_or("");
                            let val = attr.unescape_value().unwrap_or_default();
                            match key {
                                "name" => app_name = val.into_owned(),
                                "modified" => {
                                    if let Some(ts) = parse_rfc3339_ts(&val) {
                                        app_ts = ts;
                                    }
                                }
                                _ => {}
                            }
                        }
                        if !app_name.is_empty() && app_ts > 0.0 {
                            entries.push(XbelEntry {
                                app_name,
                                file_path: file_path.clone(),
                                modified_ts: app_ts,
                            });
                        }
                    }
                }
            }
            Ok(XmlEvent::End(ref e)) => {
                if e.name().local_name().as_ref() == b"bookmark" {
                    current_href = None;
                    current_bookmark_ts = 0.0;
                }
            }
            Ok(XmlEvent::Eof) => break,
            Err(_) => break,
            _ => {}
        }
        buf.clear();
    }

    entries
}

/// Watch `recently-used.xbel` (via its parent directory for atomic renames) and emit new entries.
pub async fn watch_xbel(
    xbel_path: PathBuf,
    initial_watermark: f64,
    tx: mpsc::Sender<XbelEntry>,
) -> Result<(), String> {
    let parent = xbel_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();
    let target_name = xbel_path
        .file_name()
        .map(|s| s.to_os_string())
        .unwrap_or_default();

    let (ev_tx, mut ev_rx) = mpsc::channel::<()>(32);

    let mut watcher: RecommendedWatcher = notify::recommended_watcher(move |res: Result<Event, _>| {
        if let Ok(event) = res {
            let touches_xbel = event.paths.iter().any(|p| {
                p.file_name()
                    .map(|n| n == target_name)
                    .unwrap_or(false)
            });
            if touches_xbel {
                let _ = ev_tx.try_send(());
            }
        }
    })
    .map_err(|e| format!("Failed to create XBEL watcher: {e}"))?;

    watcher
        .watch(&parent, RecursiveMode::NonRecursive)
        .map_err(|e| format!("Failed to watch {}: {e}", parent.display()))?;

    let mut watermark = initial_watermark;

    while ev_rx.recv().await.is_some() {
        // Small debounce so atomic write/rename finishes
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        while ev_rx.try_recv().is_ok() {}

        let Ok(bytes) = std::fs::read(&xbel_path) else {
            continue;
        };
        let mut max_ts = watermark;
        for entry in parse_xbel_bytes(&bytes) {
            if entry.modified_ts > watermark {
                if entry.modified_ts > max_ts {
                    max_ts = entry.modified_ts;
                }
                let _ = tx.send(entry).await;
            }
        }
        watermark = max_ts;
    }

    drop(watcher);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_xbel_bookmarks_and_apps() {
        let sample = br#"<?xml version="1.0" encoding="UTF-8"?>
<xbel version="1.0" xmlns:bookmark="http://www.freedesktop.org/standards/desktop-bookmarks">
  <bookmark href="file:///home/user/My%20Notes.md" added="2026-11-15T10:00:00Z" modified="2026-11-15T10:05:00Z">
    <info>
      <metadata owner="http://freedesktop.org">
        <bookmark:applications>
          <bookmark:application name="org.kde.kate" exec="kate %u" modified="2026-11-15T10:05:00Z" count="2"/>
        </bookmark:applications>
      </metadata>
    </info>
  </bookmark>
</xbel>"#;

        let entries = parse_xbel_bytes(sample);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].app_name, "org.kde.kate");
        assert_eq!(entries[0].file_path, "/home/user/My Notes.md");
        assert!(entries[0].modified_ts > 0.0);
    }
}
