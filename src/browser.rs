//! Browser website tracking via window title + Firefox recovery.jsonlz4.

use serde_json::Value;
use std::fs;
use std::path::PathBuf;
use std::time::SystemTime;

#[derive(Debug, Clone)]
pub struct SiteVisit {
    pub app_name: String,
    pub domain: String,
    pub url: String,
    pub page_title: String,
    pub source: &'static str,
}

#[derive(Debug, Clone)]
struct FirefoxTabInfo {
    title: String,
    url: String,
}

pub struct FirefoxSessionCache {
    last_mtime: Option<SystemTime>,
    tabs: Vec<FirefoxTabInfo>,
}

impl FirefoxSessionCache {
    pub fn new() -> Self {
        Self {
            last_mtime: None,
            tabs: Vec::new(),
        }
    }

    fn refresh_if_needed(&mut self) {
        let Some(path) = find_recovery_jsonlz4() else {
            return;
        };
        let Ok(meta) = fs::metadata(&path) else {
            return;
        };
        let mtime = meta.modified().ok();
        if mtime.is_some() && mtime == self.last_mtime {
            return;
        }
        if let Ok(bytes) = fs::read(&path) {
            if let Some(tabs) = parse_mozlz4_tabs(&bytes) {
                self.tabs = tabs;
                self.last_mtime = mtime;
            }
        }
    }

    pub fn lookup_url(&mut self, page_title: &str) -> Option<String> {
        self.refresh_if_needed();
        if page_title.is_empty() {
            return None;
        }
        // Exact title match first
        if let Some(tab) = self.tabs.iter().find(|t| t.title == page_title) {
            return Some(tab.url.clone());
        }
        // Fallback: prefix/substring match
        self.tabs
            .iter()
            .find(|t| !t.title.is_empty() && (t.title.contains(page_title) || page_title.contains(&t.title)))
            .map(|t| t.url.clone())
    }
}

fn find_recovery_jsonlz4() -> Option<PathBuf> {
    let home = std::env::var_os("HOME").map(PathBuf::from)?;
    for base in [
        home.join(".config/mozilla/firefox"),
        home.join(".mozilla/firefox"),
    ] {
        let Ok(entries) = fs::read_dir(&base) else {
            continue;
        };
        let mut best: Option<(SystemTime, PathBuf)> = None;
        for entry in entries.flatten() {
            let candidate = entry.path().join("sessionstore-backups/recovery.jsonlz4");
            if let Ok(meta) = fs::metadata(&candidate) {
                let mtime = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
                if best.as_ref().map(|(t, _)| mtime > *t).unwrap_or(true) {
                    best = Some((mtime, candidate));
                }
            }
        }
        if let Some((_, p)) = best {
            return Some(p);
        }
    }
    None
}

fn parse_mozlz4_tabs(data: &[u8]) -> Option<Vec<FirefoxTabInfo>> {
    if data.len() < 12 || &data[0..8] != b"mozLz40\0" {
        return None;
    }
    let size = u32::from_le_bytes([data[8], data[9], data[10], data[11]]) as usize;
    if size == 0 || size > 64 * 1024 * 1024 {
        return None;
    }
    let decompressed = lz4_flex::block::decompress(&data[12..], size).ok()?;
    let root: Value = serde_json::from_slice(&decompressed).ok()?;

    let mut out = Vec::new();
    let windows = root.get("windows")?.as_array()?;
    for win in windows {
        let Some(tabs) = win.get("tabs").and_then(|v| v.as_array()) else {
            continue;
        };
        for tab in tabs {
            let idx = tab.get("index").and_then(|v| v.as_u64()).unwrap_or(1) as usize;
            let Some(entries) = tab.get("entries").and_then(|v| v.as_array()) else {
                continue;
            };
            let entry_idx = idx.saturating_sub(1);
            let Some(entry) = entries.get(entry_idx).or_else(|| entries.last()) else {
                continue;
            };
            let url = entry.get("url").and_then(|v| v.as_str()).unwrap_or("");
            let title = entry.get("title").and_then(|v| v.as_str()).unwrap_or("");
            if !url.is_empty() {
                out.push(FirefoxTabInfo {
                    title: title.to_string(),
                    url: url.to_string(),
                });
            }
        }
    }
    Some(out)
}

pub fn extract_domain(url: &str) -> String {
    if let Some(rest) = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
    {
        let host_port = rest.split('/').next().unwrap_or(rest);
        let host = host_port.split(':').next().unwrap_or(host_port);
        return host.to_string();
    }
    if let Some(scheme_end) = url.find(':') {
        return url[..scheme_end].to_string();
    }
    "unknown".to_string()
}

pub fn is_browser_app(app_name: &str) -> bool {
    let lower = app_name.to_lowercase();
    lower.contains("firefox")
        || lower.contains("librewolf")
        || lower.contains("chrome")
        || lower.contains("chromium")
        || lower.contains("brave")
        || lower.contains("vivaldi")
        || lower.contains("zen")
}

pub fn strip_browser_suffix(title: &str) -> String {
    for suffix in [
        " — Mozilla Firefox",
        " - Mozilla Firefox",
        " — LibreWolf",
        " - Google Chrome",
        " - Chromium",
        " - Brave",
        " — Zen Browser",
    ] {
        if let Some(stripped) = title.strip_suffix(suffix) {
            return stripped.trim().to_string();
        }
    }
    title.trim().to_string()
}

pub fn detect_site_visit(
    app_name: &str,
    window_title: &str,
    ff_cache: &mut FirefoxSessionCache,
) -> Option<SiteVisit> {
    if !is_browser_app(app_name) {
        return None;
    }
    let page_title = strip_browser_suffix(window_title);
    if page_title.is_empty()
        || page_title == "Mozilla Firefox"
        || page_title == "New Tab"
        || page_title == "Private Browsing"
    {
        return None;
    }

    let lower = app_name.to_lowercase();
    if lower.contains("firefox") || lower.contains("librewolf") || lower.contains("zen") {
        if let Some(url) = ff_cache.lookup_url(&page_title) {
            let domain = extract_domain(&url);
            return Some(SiteVisit {
                app_name: app_name.to_string(),
                domain,
                url,
                page_title,
                source: "firefox:sessionstore",
            });
        }
    }

    // Fallback: extract site/page from window title
    let domain_hint = page_title
        .rsplit(" — ")
        .next()
        .or_else(|| page_title.rsplit(" - ").next())
        .unwrap_or(&page_title)
        .trim()
        .to_string();

    Some(SiteVisit {
        app_name: app_name.to_string(),
        domain: domain_hint,
        url: String::new(),
        page_title,
        source: "browser:title",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_domain_and_strips_firefox_suffix() {
        assert_eq!(
            extract_domain("https://docs.rs/zbus/latest/zbus/"),
            "docs.rs"
        );
        assert_eq!(extract_domain("http://127.0.0.1:7878/"), "127.0.0.1");
        assert_eq!(
            strip_browser_suffix("Discover — Witchsky — Mozilla Firefox"),
            "Discover — Witchsky"
        );
    }
}
