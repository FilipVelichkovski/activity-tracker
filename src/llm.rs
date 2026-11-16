//! Privacy-filtered activity digests, focus blocks, and search for LLMs.
//!
//! Supports two modes:
//! - `classify = true` (default, for smaller/weaker LLMs): includes heuristic `categories`.
//! - `classify = false` (`--no-classify`, for larger LLMs): omits heuristic `categories`
//!   so capable models can classify directly from apps, sample titles, sites, and files.

use chrono::{DateTime, Local};
use serde::Serialize;
use std::collections::HashMap;

use crate::privacy::{PrivacyEngine, Sink};
use crate::storage::TrackerDb;

fn fmt_dur(sec: f64) -> String {
    let total = sec.max(0.0).round() as i64;
    let h = total / 3600;
    let m = (total % 3600) / 60;
    let s = total % 60;
    if h > 0 {
        format!("{h}h {m:02}m")
    } else if m > 0 {
        format!("{m}m {s:02}s")
    } else {
        format!("{s}s")
    }
}

fn fmt_ts(ts: f64) -> String {
    DateTime::from_timestamp(ts.floor() as i64, 0)
        .map(|dt| dt.with_timezone(&Local).format("%Y-%m-%d %H:%M").to_string())
        .unwrap_or_else(|| "-".to_string())
}

#[derive(Debug, Serialize)]
pub struct DigestPeriod {
    pub start: String,
    pub end: String,
    pub total_active_time: String,
    pub total_active_seconds: i64,
    pub session_count: usize,
}

#[derive(Debug, Serialize)]
pub struct DigestCategory {
    pub category: String,
    pub time: String,
    pub seconds: i64,
    pub share_pct: f64,
    pub sessions: usize,
}

#[derive(Debug, Serialize)]
pub struct DigestApp {
    pub app: String,
    pub time: String,
    pub seconds: i64,
    pub share_pct: f64,
    pub sessions: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub sample_titles: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct DigestSite {
    pub domain: String,
    pub sample_title: String,
    pub pages: i64,
    pub last_seen: String,
}

#[derive(Debug, Serialize)]
pub struct DigestFile {
    pub app: String,
    pub file: String,
    pub source: String,
    pub last_seen: String,
}

#[derive(Debug, Serialize)]
pub struct LlmDigest {
    pub period: DigestPeriod,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub categories: Option<Vec<DigestCategory>>,
    pub top_apps: Vec<DigestApp>,
    pub top_sites: Vec<DigestSite>,
    pub opened_files: Vec<DigestFile>,
}

#[derive(Debug, Serialize)]
pub struct FocusBlock {
    pub start: String,
    pub end: String,
    pub duration: String,
    pub seconds: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    pub app: String,
    pub sample_titles: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct SearchSessionHit {
    pub time: String,
    pub duration: String,
    pub app: String,
    pub title: String,
}

#[derive(Debug, Serialize)]
pub struct SearchSiteHit {
    pub domain: String,
    pub title: String,
    pub url: String,
    pub last_seen: String,
}

#[derive(Debug, Serialize)]
pub struct LlmSearchResult {
    pub query: String,
    pub matching_sessions: Vec<SearchSessionHit>,
    pub matching_files: Vec<DigestFile>,
    pub matching_sites: Vec<SearchSiteHit>,
}

pub fn build_digest(
    db: &TrackerDb,
    privacy: &PrivacyEngine,
    since_ts: f64,
    until_ts: f64,
    top_n: usize,
    classify: bool,
) -> rusqlite::Result<LlmDigest> {
    if !privacy.sink_policy(Sink::Llm).enabled {
        return Ok(LlmDigest {
            period: DigestPeriod {
                start: fmt_ts(since_ts),
                end: fmt_ts(until_ts),
                total_active_time: "0s".to_string(),
                total_active_seconds: 0,
                session_count: 0,
            },
            categories: if classify { Some(Vec::new()) } else { None },
            top_apps: Vec::new(),
            top_sites: Vec::new(),
            opened_files: Vec::new(),
        });
    }

    let sessions = db.query_sessions_in_range(since_ts, until_ts)?;
    let mut total_sec = 0.0_f64;
    let mut allowed_sessions = 0_usize;
    let mut cat_agg: HashMap<String, (f64, usize)> = HashMap::new();
    let mut app_agg: HashMap<String, (f64, usize, Vec<String>)> = HashMap::new();

    for s in sessions {
        let dec = privacy.evaluate_activity(Sink::Llm, &s.app_name, &s.window_title, "");
        if !dec.allow {
            continue;
        }
        total_sec += s.duration_sec;
        allowed_sessions += 1;

        if classify {
            let c = cat_agg.entry(dec.category).or_insert((0.0, 0));
            c.0 += s.duration_sec;
            c.1 += 1;
        }

        let a = app_agg
            .entry(dec.app_name)
            .or_insert_with(|| (0.0, 0, Vec::new()));
        a.0 += s.duration_sec;
        a.1 += 1;
        if !classify
            && !dec.window_title.is_empty()
            && !a.2.contains(&dec.window_title)
            && a.2.len() < 3
        {
            a.2.push(dec.window_title);
        }
    }

    let categories = if classify {
        let mut list: Vec<DigestCategory> = cat_agg
            .into_iter()
            .map(|(cat, (sec, count))| DigestCategory {
                category: cat,
                time: fmt_dur(sec),
                seconds: sec.round() as i64,
                share_pct: if total_sec > 0.0 {
                    ((sec / total_sec) * 1000.0).round() / 10.0
                } else {
                    0.0
                },
                sessions: count,
            })
            .collect();
        list.sort_by(|a, b| b.seconds.cmp(&a.seconds));
        Some(list)
    } else {
        None
    };

    let mut top_apps: Vec<DigestApp> = app_agg
        .into_iter()
        .map(|(app, (sec, count, sample_titles))| DigestApp {
            app,
            time: fmt_dur(sec),
            seconds: sec.round() as i64,
            share_pct: if total_sec > 0.0 {
                ((sec / total_sec) * 1000.0).round() / 10.0
            } else {
                0.0
            },
            sessions: count,
            sample_titles,
        })
        .collect();
    top_apps.sort_by(|a, b| b.seconds.cmp(&a.seconds));
    top_apps.truncate(top_n);

    let raw_sites = db.query_visited_sites(since_ts, until_ts, None, (top_n * 10) as i64)?;
    let mut site_agg: HashMap<String, (String, i64, f64)> = HashMap::new();
    for site in raw_sites {
        let dec = privacy.evaluate_activity(Sink::Llm, &site.app_name, &site.page_title, &site.domain);
        if !dec.allow || !dec.allow_sites {
            continue;
        }
        let entry = site_agg
            .entry(site.domain)
            .or_insert_with(|| (dec.window_title.clone(), 0, site.last_seen_at));
        entry.1 += 1;
        if site.last_seen_at >= entry.2 {
            entry.2 = site.last_seen_at;
            entry.0 = dec.window_title;
        }
    }
    let mut top_sites_with_ts: Vec<(f64, DigestSite)> = site_agg
        .into_iter()
        .map(|(domain, (sample_title, pages, last_seen))| {
            (
                last_seen,
                DigestSite {
                    domain,
                    sample_title,
                    pages,
                    last_seen: fmt_ts(last_seen),
                },
            )
        })
        .collect();
    top_sites_with_ts.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
    let top_sites: Vec<DigestSite> = top_sites_with_ts
        .into_iter()
        .take(top_n)
        .map(|(_, s)| s)
        .collect();

    let raw_files = db.query_opened_files(since_ts, until_ts, None, (top_n * 3) as i64)?;
    let mut opened_files = Vec::new();
    for file in raw_files {
        let dec = privacy.evaluate_activity(Sink::Llm, &file.app_name, &file.file_path, "");
        if !dec.allow || !dec.allow_files {
            continue;
        }
        opened_files.push(DigestFile {
            app: dec.app_name,
            file: file.file_path,
            source: file.source,
            last_seen: fmt_ts(file.last_seen_at),
        });
        if opened_files.len() >= top_n {
            break;
        }
    }

    Ok(LlmDigest {
        period: DigestPeriod {
            start: fmt_ts(since_ts),
            end: fmt_ts(until_ts),
            total_active_time: fmt_dur(total_sec),
            total_active_seconds: total_sec.round() as i64,
            session_count: allowed_sessions,
        },
        categories,
        top_apps,
        top_sites,
        opened_files,
    })
}

pub fn build_focus_blocks(
    db: &TrackerDb,
    privacy: &PrivacyEngine,
    since_ts: f64,
    until_ts: f64,
    min_duration_sec: f64,
    merge_gap_sec: f64,
    limit: usize,
    classify: bool,
) -> rusqlite::Result<Vec<FocusBlock>> {
    if !privacy.sink_policy(Sink::Llm).enabled {
        return Ok(Vec::new());
    }

    struct AccBlock {
        start_ts: f64,
        end_ts: f64,
        dur: f64,
        category: Option<String>,
        app: String,
        titles: Vec<String>,
    }

    let sessions = db.query_sessions_in_range(since_ts, until_ts)?;
    let mut blocks: Vec<AccBlock> = Vec::new();

    for s in sessions {
        let dec = privacy.evaluate_activity(Sink::Llm, &s.app_name, &s.window_title, "");
        if !dec.allow {
            continue;
        }
        let cat = if classify { Some(dec.category) } else { None };
        let app = dec.app_name;
        let title = dec.window_title;

        if let Some(prev) = blocks.last_mut() {
            let same_focus = prev.app == app && (!classify || prev.category == cat);
            if same_focus && (s.started_at - prev.end_ts) <= merge_gap_sec {
                prev.end_ts = prev.end_ts.max(s.ended_at);
                prev.dur += s.duration_sec;
                if !title.is_empty() && !prev.titles.contains(&title) && prev.titles.len() < 3 {
                    prev.titles.push(title);
                }
                continue;
            }
        }

        blocks.push(AccBlock {
            start_ts: s.started_at,
            end_ts: s.ended_at,
            dur: s.duration_sec,
            category: cat,
            app,
            titles: if title.is_empty() {
                Vec::new()
            } else {
                vec![title]
            },
        });
    }

    let mut filtered: Vec<FocusBlock> = blocks
        .into_iter()
        .filter(|b| b.dur >= min_duration_sec)
        .map(|b| FocusBlock {
            start: fmt_ts(b.start_ts),
            end: fmt_ts(b.end_ts),
            duration: fmt_dur(b.dur),
            seconds: b.dur.round() as i64,
            category: b.category,
            app: b.app,
            sample_titles: b.titles,
        })
        .collect();

    if filtered.len() > limit {
        let start = filtered.len() - limit;
        filtered = filtered.split_off(start);
    }
    Ok(filtered)
}

pub fn search_activity(
    db: &TrackerDb,
    privacy: &PrivacyEngine,
    query: &str,
    since_ts: f64,
    until_ts: f64,
    limit: usize,
) -> rusqlite::Result<LlmSearchResult> {
    if !privacy.sink_policy(Sink::Llm).enabled {
        return Ok(LlmSearchResult {
            query: query.to_string(),
            matching_sessions: Vec::new(),
            matching_files: Vec::new(),
            matching_sites: Vec::new(),
        });
    }

    let q_lower = query.to_lowercase();

    let mut sessions = db.query_sessions_in_range(since_ts, until_ts)?;
    sessions.reverse();
    let mut matching_sessions = Vec::new();
    for s in sessions {
        if !s.app_name.to_lowercase().contains(&q_lower)
            && !s.window_title.to_lowercase().contains(&q_lower)
        {
            continue;
        }
        let dec = privacy.evaluate_activity(Sink::Llm, &s.app_name, &s.window_title, "");
        if !dec.allow {
            continue;
        }
        matching_sessions.push(SearchSessionHit {
            time: fmt_ts(s.started_at),
            duration: fmt_dur(s.duration_sec),
            app: dec.app_name,
            title: dec.window_title,
        });
        if matching_sessions.len() >= limit {
            break;
        }
    }

    let raw_files = db.query_opened_files(since_ts, until_ts, None, (limit * 4) as i64)?;
    let mut matching_files = Vec::new();
    for f in raw_files {
        if !f.app_name.to_lowercase().contains(&q_lower)
            && !f.file_path.to_lowercase().contains(&q_lower)
        {
            continue;
        }
        let dec = privacy.evaluate_activity(Sink::Llm, &f.app_name, &f.file_path, "");
        if !dec.allow || !dec.allow_files {
            continue;
        }
        matching_files.push(DigestFile {
            app: dec.app_name,
            file: f.file_path,
            source: f.source,
            last_seen: fmt_ts(f.last_seen_at),
        });
        if matching_files.len() >= limit {
            break;
        }
    }

    let raw_sites = db.query_visited_sites(since_ts, until_ts, None, (limit * 4) as i64)?;
    let mut matching_sites = Vec::new();
    for site in raw_sites {
        if !site.domain.to_lowercase().contains(&q_lower)
            && !site.url.to_lowercase().contains(&q_lower)
            && !site.page_title.to_lowercase().contains(&q_lower)
        {
            continue;
        }
        let dec = privacy.evaluate_activity(Sink::Llm, &site.app_name, &site.page_title, &site.domain);
        if !dec.allow || !dec.allow_sites {
            continue;
        }
        matching_sites.push(SearchSiteHit {
            domain: site.domain,
            title: dec.window_title,
            url: site.url,
            last_seen: fmt_ts(site.last_seen_at),
        });
        if matching_sites.len() >= limit {
            break;
        }
    }

    Ok(LlmSearchResult {
        query: query.to_string(),
        matching_sessions,
        matching_files,
        matching_sites,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::privacy::PrivacyConfig;

    #[test]
    fn digest_and_focus_respect_classify_flag_and_llm_privacy() {
        let dir = std::env::temp_dir().join(format!("agy_llm_test_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let db_path = dir.join("llm.db");
        let _ = std::fs::remove_file(&db_path);

        let db = TrackerDb::open_with_key(Some(&db_path), "test-llm-key-0123456789abcdef").unwrap();
        let s1 = db.start_session("dev.zed.Zed", "main.rs", 100, 1000.0).unwrap();
        db.update_session_end(s1, 1060.0).unwrap();
        db.record_file(Some(s1), "dev.zed.Zed", "/tmp/main.rs", "title", 1050.0)
            .unwrap();

        // Sensitive session should be filtered out for LLM sink
        let s2 = db
            .start_session("com.bitwarden.desktop", "Bitwarden", 101, 1065.0)
            .unwrap();
        db.update_session_end(s2, 1125.0).unwrap();

        let mut cfg = PrivacyConfig::default();
        cfg.auto_load_lists_dir = false;
        let privacy = PrivacyEngine::from_config(cfg);

        // Weaker LLM mode: classify = true includes categories & focus block category
        let digest_cls = build_digest(&db, &privacy, 900.0, 1200.0, 10, true).unwrap();
        assert_eq!(digest_cls.period.session_count, 1);
        assert!(digest_cls.categories.is_some());
        assert_eq!(digest_cls.categories.as_ref().unwrap()[0].category, "Development");
        assert!(digest_cls.top_apps[0].sample_titles.is_empty());

        let blocks_cls =
            build_focus_blocks(&db, &privacy, 900.0, 1200.0, 30.0, 20.0, 10, true).unwrap();
        assert_eq!(blocks_cls.len(), 1);
        assert_eq!(blocks_cls[0].category.as_deref(), Some("Development"));

        // Bigger LLM mode: classify = false omits categories & includes sample_titles for self-classification
        let digest_raw = build_digest(&db, &privacy, 900.0, 1200.0, 10, false).unwrap();
        assert!(digest_raw.categories.is_none());
        assert_eq!(digest_raw.top_apps[0].sample_titles, vec!["main.rs"]);

        let blocks_raw =
            build_focus_blocks(&db, &privacy, 900.0, 1200.0, 30.0, 20.0, 10, false).unwrap();
        assert_eq!(blocks_raw.len(), 1);
        assert!(blocks_raw[0].category.is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
