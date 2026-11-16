//! Asynchronous LAN push client sending today's summary to `activity-remote-server`.

use activity_protocol::{
    AppItem, CategoryItem, DailySummaryPayload, FileItem, LiveStatus, SiteItem,
};
use chrono::{Local, TimeZone};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Notify;

use crate::categorizer::classify_activity;
use crate::daemon::TrackerState;
use crate::privacy::Sink;

const HTTP_TIMEOUT_SECS: u64 = 3;

#[derive(Debug, Clone)]
pub struct RemoteConfig {
    pub url: String,
    pub token: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ParsedEndpoint {
    pub connect_addr: String,
    pub host_header: String,
    pub put_path: String,
}

pub fn parse_remote_url(raw: &str) -> Result<ParsedEndpoint, String> {
    let trimmed = raw.trim().trim_end_matches('/');
    if trimmed.starts_with("https://") {
        return Err("HTTPS is not supported for LAN remote sync; use http://<host>:<port>".to_string());
    }
    let rest = trimmed
        .strip_prefix("http://")
        .unwrap_or(trimmed);
    if rest.is_empty() {
        return Err("Remote URL is empty".to_string());
    }

    let (authority, base_path) = match rest.find('/') {
        Some(idx) => (&rest[..idx], &rest[idx..]),
        None => (rest, ""),
    };

    if authority.is_empty() {
        return Err(format!("Invalid remote URL: {raw}"));
    }

    let connect_addr = if authority.contains(':') {
        authority.to_string()
    } else {
        format!("{authority}:80")
    };

    let base_clean = base_path.trim_end_matches('/');
    let put_path = if base_clean.is_empty() {
        "/api/v1/summary/today".to_string()
    } else {
        format!("{base_clean}/api/v1/summary/today")
    };

    Ok(ParsedEndpoint {
        connect_addr,
        host_header: authority.to_string(),
        put_path,
    })
}

fn now_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

fn local_hostname() -> String {
    if let Ok(h) = std::env::var("HOSTNAME") {
        let t = h.trim();
        if !t.is_empty() {
            return t.to_string();
        }
    }
    if let Ok(contents) = std::fs::read_to_string("/etc/hostname") {
        let t = contents.trim();
        if !t.is_empty() {
            return t.to_string();
        }
    }
    "unknown".to_string()
}

pub fn build_today_payload(state: &TrackerState, now: f64) -> Result<DailySummaryPayload, String> {
    let local_now = Local::now();
    let date = local_now.format("%Y-%m-%d").to_string();
    let policy = state.privacy.sink_policy(Sink::Remote).clone();

    if !policy.enabled {
        return Ok(DailySummaryPayload {
            date,
            source_host: local_hostname(),
            updated_at: now,
            total_active_sec: 0.0,
            status: LiveStatus {
                tracking: false,
                paused: state.manually_paused,
                screen_locked: state.screen_locked,
                current_app: None,
                current_title: None,
                current_category: None,
                current_duration_sec: 0.0,
            },
            categories: Vec::new(),
            apps: Vec::new(),
            top_sites: Vec::new(),
            recent_files: Vec::new(),
        });
    }

    let today_midnight = local_now.date_naive().and_hms_opt(0, 0, 0).unwrap();
    let since_ts = Local
        .from_local_datetime(&today_midnight)
        .single()
        .map(|dt| dt.timestamp() as f64)
        .unwrap_or_else(|| now - 86400.0);
    let until_ts = now + 1.0;

    let raw_cats = state
        .db
        .query_category_summary(since_ts, until_ts, None)
        .map_err(|e| e.to_string())?;
    let raw_apps = state
        .db
        .query_app_summary(since_ts, until_ts, None)
        .map_err(|e| e.to_string())?;
    let raw_sites = if policy.include_sites {
        state
            .db
            .query_visited_sites(since_ts, until_ts, None, 20)
            .map_err(|e| e.to_string())?
    } else {
        Vec::new()
    };
    let raw_files = if policy.include_files {
        state
            .db
            .query_opened_files(since_ts, until_ts, None, 20)
            .map_err(|e| e.to_string())?
    } else {
        Vec::new()
    };

    let apps: Vec<AppItem> = raw_apps
        .into_iter()
        .filter_map(|a| {
            let d = state
                .privacy
                .evaluate_activity(Sink::Remote, &a.app_name, "", "");
            if !d.allow {
                return None;
            }
            let cat = if policy.include_category {
                classify_activity(&a.app_name, "").to_string()
            } else {
                policy.redact_text.clone()
            };
            Some(AppItem {
                app_name: d.app_name,
                category: cat,
                total_sec: a.total_sec,
                session_count: a.session_count,
                file_count: if d.allow_files { a.file_count } else { 0 },
            })
        })
        .collect();

    let total_active_sec: f64 = apps.iter().map(|a| a.total_sec).sum();

    let categories: Vec<CategoryItem> = if policy.include_category {
        raw_cats
            .into_iter()
            .filter_map(|c| {
                let d = state
                    .privacy
                    .evaluate_activity(Sink::Remote, "", "", "");
                if !d.allow {
                    return None;
                }
                let share_pct = if total_active_sec > 0.0 {
                    (c.total_sec / total_active_sec) * 100.0
                } else {
                    0.0
                };
                Some(CategoryItem {
                    category: c.category,
                    total_sec: c.total_sec,
                    share_pct,
                    session_count: c.session_count,
                    app_count: c.app_count,
                })
            })
            .collect()
    } else {
        Vec::new()
    };

    let top_sites = raw_sites
        .into_iter()
        .filter_map(|s| {
            if !state
                .privacy
                .allow_site(Sink::Remote, &s.app_name, &s.domain, &s.page_title)
            {
                return None;
            }
            let d = state
                .privacy
                .evaluate_activity(Sink::Remote, &s.app_name, &s.page_title, &s.domain);
            if !d.allow || !d.allow_sites {
                return None;
            }
            Some(SiteItem {
                domain: s.domain,
                page_title: d.window_title,
                app_name: d.app_name,
                last_seen_at: s.last_seen_at,
            })
        })
        .collect();

    let recent_files = raw_files
        .into_iter()
        .filter_map(|f| {
            if !state
                .privacy
                .allow_file(Sink::Remote, &f.app_name, &f.file_path)
            {
                return None;
            }
            let d = state
                .privacy
                .evaluate_activity(Sink::Remote, &f.app_name, &f.file_path, "");
            if !d.allow || !d.allow_files {
                return None;
            }
            Some(FileItem {
                app_name: d.app_name,
                file_path: f.file_path,
                source: f.source,
                last_seen_at: f.last_seen_at,
            })
        })
        .collect();

    let (current_app, current_title, current_category, current_duration_sec) = match &state.current
    {
        Some(cur) => {
            let d = state
                .privacy
                .evaluate_activity(Sink::Remote, &cur.app_name, &cur.window_title, "");
            if d.allow {
                (
                    Some(d.app_name),
                    Some(d.window_title),
                    Some(d.category),
                    (now - cur.started_at).max(0.0),
                )
            } else {
                (None, None, None, 0.0)
            }
        }
        None => (None, None, None, 0.0),
    };

    Ok(DailySummaryPayload {
        date,
        source_host: local_hostname(),
        updated_at: now,
        total_active_sec,
        status: LiveStatus {
            tracking: true,
            paused: state.manually_paused,
            screen_locked: state.screen_locked,
            current_app,
            current_title,
            current_category,
            current_duration_sec,
        },
        categories,
        apps,
        top_sites,
        recent_files,
    })
}

pub async fn push_payload(
    endpoint: &ParsedEndpoint,
    token: Option<&str>,
    payload: &DailySummaryPayload,
) -> Result<(), String> {
    let body = serde_json::to_vec(payload).map_err(|e| format!("JSON encode error: {e}"))?;
    let timeout = Duration::from_secs(HTTP_TIMEOUT_SECS);

    let mut stream = tokio::time::timeout(timeout, TcpStream::connect(&endpoint.connect_addr))
        .await
        .map_err(|_| format!("Connect timeout to {}", endpoint.connect_addr))?
        .map_err(|e| format!("Connect failed to {}: {e}", endpoint.connect_addr))?;

    let mut req = format!(
        "PUT {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
        endpoint.put_path,
        endpoint.host_header,
        body.len()
    );
    if let Some(tok) = token.filter(|t| !t.is_empty()) {
        req.push_str(&format!("Authorization: Bearer {tok}\r\n"));
    }
    req.push_str("\r\n");

    tokio::time::timeout(timeout, async {
        stream.write_all(req.as_bytes()).await?;
        stream.write_all(&body).await?;
        stream.flush().await?;
        Ok::<(), std::io::Error>(())
    })
    .await
    .map_err(|_| "Write timeout".to_string())?
    .map_err(|e| format!("Write error: {e}"))?;

    let mut resp_buf = [0u8; 256];
    let n = tokio::time::timeout(timeout, stream.read(&mut resp_buf))
        .await
        .map_err(|_| "Read timeout".to_string())?
        .map_err(|e| format!("Read error: {e}"))?;

    let status_line = String::from_utf8_lossy(&resp_buf[..n]);
    let first_line = status_line.lines().next().unwrap_or("");
    let status_code = first_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);

    if !(200..300).contains(&status_code) {
        return Err(format!("Remote server returned HTTP {status_code} ({first_line})"));
    }
    Ok(())
}

pub fn spawn_remote_sync(
    state: Arc<Mutex<TrackerState>>,
    cfg: RemoteConfig,
    verbose: bool,
) -> Result<Arc<Notify>, String> {
    let endpoint = parse_remote_url(&cfg.url)?;
    let notify = Arc::new(Notify::new());
    let notify_rx = Arc::clone(&notify);
    let token = cfg.token;

    if verbose {
        eprintln!(
            "Remote sync enabled -> http://{}{}",
            endpoint.host_header, endpoint.put_path
        );
    }

    tokio::spawn(async move {
        let mut last_err_log = 0.0_f64;
        loop {
            notify_rx.notified().await;
            let now = now_secs();
            let payload_res = {
                let Ok(guard) = state.lock() else {
                    continue;
                };
                build_today_payload(&guard, now)
            };

            match payload_res {
                Ok(payload) => {
                    if let Err(e) = push_payload(&endpoint, token.as_deref(), &payload).await {
                        if verbose && (now - last_err_log) > 30.0 {
                            eprintln!("[remote-sync] {e}");
                            last_err_log = now;
                        }
                    }
                }
                Err(e) => {
                    if verbose && (now - last_err_log) > 30.0 {
                        eprintln!("[remote-sync] build payload failed: {e}");
                        last_err_log = now;
                    }
                }
            }
        }
    });

    // Trigger an initial sync immediately on startup
    notify.notify_one();
    Ok(notify)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_remote_urls() {
        let ep = parse_remote_url("http://192.168.1.50:7879").unwrap();
        assert_eq!(ep.connect_addr, "192.168.1.50:7879");
        assert_eq!(ep.host_header, "192.168.1.50:7879");
        assert_eq!(ep.put_path, "/api/v1/summary/today");

        let ep2 = parse_remote_url("192.168.1.50:7879/custom/").unwrap();
        assert_eq!(ep2.connect_addr, "192.168.1.50:7879");
        assert_eq!(ep2.put_path, "/custom/api/v1/summary/today");

        assert!(parse_remote_url("https://192.168.1.50:7879").is_err());
    }
}
