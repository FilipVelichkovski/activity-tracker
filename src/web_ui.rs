//! Embedded Axum Web UI server for Activity Tracker.

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{Html, Json};
use axum::routing::get;
use axum::Router;
use chrono::{Duration, Local, NaiveDate, TimeZone};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::daemon::TrackerState;
use crate::privacy::{PrivacyEngine, Sink};
use crate::storage::{
    AppSummary, CategorySummary, OpenedFileRecord, SessionRecord, TrackerDb, VisitedSiteRecord,
};

#[derive(Clone)]
pub struct WebContext {
    pub db_path: PathBuf,
    pub privacy_path: Option<PathBuf>,
    pub state: Option<Arc<Mutex<TrackerState>>>,
}

#[derive(Serialize)]
pub struct StatusResponse {
    pub tracking: bool,
    pub paused: bool,
    pub screen_locked: bool,
    pub current_app: Option<String>,
    pub current_title: Option<String>,
    pub current_duration_sec: f64,
}

#[derive(Deserialize)]
pub struct ReportQuery {
    pub days: Option<i64>,
    pub date: Option<String>,
    pub app: Option<String>,
    pub file_limit: Option<i64>,
}

#[derive(Serialize)]
pub struct LlmVisibilitySummary {
    pub llm_enabled: bool,
    pub total_seconds: f64,
    pub hidden_seconds: f64,
    pub hidden_pct: f64,
    pub hidden_sessions: usize,
    pub redacted_titles: usize,
    pub hidden_sites: usize,
    pub hidden_files: usize,
    pub sizable_hidden: bool,
    pub hidden_apps: Vec<String>,
}

#[derive(Serialize)]
pub struct ReportResponse {
    pub categories: Vec<CategorySummary>,
    pub apps: Vec<AppSummary>,
    pub files: Vec<OpenedFileRecord>,
    pub sites: Vec<VisitedSiteRecord>,
    pub llm_visibility: LlmVisibilitySummary,
}

#[derive(Deserialize)]
pub struct SessionsQuery {
    pub limit: Option<i64>,
    pub date: Option<String>,
}

#[derive(Deserialize)]
pub struct WeekQuery {
    pub end: Option<String>,
}

#[derive(Serialize)]
pub struct WeekDayCategory {
    pub category: String,
    pub total_sec: f64,
}

#[derive(Serialize)]
pub struct WeekDaySummary {
    pub date: String,
    pub label: String,
    pub total_sec: f64,
    pub is_today: bool,
    pub categories: Vec<WeekDayCategory>,
}

#[derive(Serialize)]
pub struct WeekResponse {
    pub start_date: String,
    pub end_date: String,
    pub days: Vec<WeekDaySummary>,
}

fn resolve_time_range(days: Option<i64>, date: Option<&str>) -> Result<(f64, f64), StatusCode> {
    if let Some(d_str) = date.map(str::trim).filter(|s| !s.is_empty()) {
        let d = NaiveDate::parse_from_str(d_str, "%Y-%m-%d").map_err(|_| StatusCode::BAD_REQUEST)?;
        let start_naive = d.and_hms_opt(0, 0, 0).ok_or(StatusCode::BAD_REQUEST)?;
        let start_dt = Local
            .from_local_datetime(&start_naive)
            .earliest()
            .ok_or(StatusCode::BAD_REQUEST)?;
        let end_naive = d.and_hms_opt(23, 59, 59).ok_or(StatusCode::BAD_REQUEST)?;
        let end_dt = Local
            .from_local_datetime(&end_naive)
            .latest()
            .ok_or(StatusCode::BAD_REQUEST)?;
        return Ok((start_dt.timestamp() as f64, (end_dt.timestamp() as f64) + 0.999));
    }

    let now = Local::now();
    let until_ts = (now.timestamp_millis() as f64 / 1000.0) + 1.0;
    let since_ts = match days {
        Some(n) if n > 0 => (now - Duration::days(n)).timestamp() as f64,
        _ => {
            let today = now.date_naive().and_hms_opt(0, 0, 0).unwrap();
            let midnight = Local.from_local_datetime(&today).unwrap();
            midnight.timestamp() as f64
        }
    };
    Ok((since_ts, until_ts))
}

async fn index() -> Html<&'static str> {
    Html(include_str!("ui.html"))
}

async fn api_status(State(ctx): State<WebContext>) -> Json<StatusResponse> {
    if let Some(ref st_arc) = ctx.state {
        if let Ok(guard) = st_arc.lock() {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs_f64();
            let (current_app, current_title, current_duration_sec) = match &guard.current {
                Some(cur) => {
                    let d = guard.privacy.evaluate_activity(
                        Sink::Ui,
                        &cur.app_name,
                        &cur.window_title,
                        "",
                    );
                    if d.allow {
                        (
                            Some(d.app_name),
                            Some(d.window_title),
                            (now - cur.started_at).max(0.0),
                        )
                    } else {
                        (None, None, 0.0)
                    }
                }
                None => (None, None, 0.0),
            };
            return Json(StatusResponse {
                tracking: true,
                paused: guard.manually_paused,
                screen_locked: guard.screen_locked,
                current_app,
                current_title,
                current_duration_sec,
            });
        }
    }
    Json(StatusResponse {
        tracking: false,
        paused: false,
        screen_locked: false,
        current_app: None,
        current_title: None,
        current_duration_sec: 0.0,
    })
}

pub fn compute_llm_visibility(
    db: &TrackerDb,
    privacy: &PrivacyEngine,
    since_ts: f64,
    until_ts: f64,
) -> Result<LlmVisibilitySummary, StatusCode> {
    let llm_policy = privacy.sink_policy(Sink::Llm);
    let llm_enabled = llm_policy.enabled;

    let sessions = db
        .query_sessions_in_range(since_ts, until_ts)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let files = db
        .query_opened_files(since_ts, until_ts, None, 500)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let sites = db
        .query_visited_sites(since_ts, until_ts, None, 500)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut total_seconds = 0.0_f64;
    let mut hidden_seconds = 0.0_f64;
    let mut hidden_sessions = 0_usize;
    let mut redacted_titles = 0_usize;
    let total_sessions = sessions.len();
    let mut hidden_app_secs: std::collections::HashMap<String, f64> = std::collections::HashMap::new();

    for s in sessions {
        total_seconds += s.duration_sec;
        let dec = privacy.evaluate_activity(Sink::Llm, &s.app_name, &s.window_title, "");
        if !dec.allow {
            hidden_seconds += s.duration_sec;
            hidden_sessions += 1;
            *hidden_app_secs.entry(s.app_name).or_insert(0.0) += s.duration_sec;
        } else if !s.window_title.is_empty() && dec.window_title != s.window_title {
            redacted_titles += 1;
        }
    }

    let hidden_sites = sites
        .iter()
        .filter(|s| {
            let dec = privacy.evaluate_activity(Sink::Llm, &s.app_name, &s.page_title, &s.domain);
            !dec.allow || !dec.allow_sites
        })
        .count();

    let hidden_files = files
        .iter()
        .filter(|f| {
            let dec = privacy.evaluate_activity(Sink::Llm, &f.app_name, &f.file_path, "");
            !dec.allow || !dec.allow_files
        })
        .count();

    let hidden_pct = if total_seconds > 0.0 {
        ((hidden_seconds / total_seconds) * 1000.0).round() / 10.0
    } else {
        0.0
    };

    let mut app_list: Vec<(String, f64)> = hidden_app_secs.into_iter().collect();
    app_list.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    let hidden_apps: Vec<String> = app_list.into_iter().take(5).map(|(a, _)| a).collect();

    let sizable_hidden = (!llm_enabled && (total_seconds > 0.0 || !sites.is_empty() || !files.is_empty()))
        || hidden_pct >= 10.0
        || hidden_sites >= 3
        || hidden_files >= 3
        || (total_sessions > 0 && (redacted_titles as f64 / total_sessions as f64) >= 0.25);

    Ok(LlmVisibilitySummary {
        llm_enabled,
        total_seconds,
        hidden_seconds,
        hidden_pct,
        hidden_sessions,
        redacted_titles,
        hidden_sites,
        hidden_files,
        sizable_hidden,
        hidden_apps,
    })
}

async fn api_report(
    State(ctx): State<WebContext>,
    Query(q): Query<ReportQuery>,
) -> Result<Json<ReportResponse>, StatusCode> {
    let privacy = PrivacyEngine::load(ctx.privacy_path.as_deref());
    let policy = privacy.sink_policy(Sink::Ui).clone();
    let (since_ts, until_ts) = resolve_time_range(q.days, q.date.as_deref())?;
    let db = TrackerDb::open(Some(&ctx.db_path)).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let llm_visibility = compute_llm_visibility(&db, &privacy, since_ts, until_ts)?;

    if !policy.enabled {
        return Ok(Json(ReportResponse {
            categories: Vec::new(),
            apps: Vec::new(),
            files: Vec::new(),
            sites: Vec::new(),
            llm_visibility,
        }));
    }

    let app_filter = q.app.as_deref().filter(|s| !s.trim().is_empty());
    let file_limit = q.file_limit.unwrap_or(100).clamp(1, 500);

    let categories = if policy.include_category {
        db.query_category_summary(since_ts, until_ts, app_filter)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    } else {
        Vec::new()
    };
    let apps = db
        .query_app_summary(since_ts, until_ts, app_filter)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .into_iter()
        .filter_map(|mut a| {
            let d = privacy.evaluate_activity(Sink::Ui, &a.app_name, "", "");
            if !d.allow {
                return None;
            }
            a.app_name = d.app_name;
            if !d.allow_files {
                a.file_count = 0;
            }
            Some(a)
        })
        .collect();
    let files = if policy.include_files {
        db.query_opened_files(since_ts, until_ts, app_filter, file_limit)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
            .into_iter()
            .filter_map(|mut f| {
                if !privacy.allow_file(Sink::Ui, &f.app_name, &f.file_path) {
                    return None;
                }
                let d = privacy.evaluate_activity(Sink::Ui, &f.app_name, &f.file_path, "");
                if !d.allow || !d.allow_files {
                    return None;
                }
                f.app_name = d.app_name;
                Some(f)
            })
            .collect()
    } else {
        Vec::new()
    };
    let sites = if policy.include_sites {
        db.query_visited_sites(since_ts, until_ts, app_filter, file_limit)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
            .into_iter()
            .filter_map(|mut s| {
                if !privacy.allow_site(Sink::Ui, &s.app_name, &s.domain, &s.page_title) {
                    return None;
                }
                let d = privacy.evaluate_activity(Sink::Ui, &s.app_name, &s.page_title, &s.domain);
                if !d.allow || !d.allow_sites {
                    return None;
                }
                s.app_name = d.app_name;
                s.page_title = d.window_title;
                Some(s)
            })
            .collect()
    } else {
        Vec::new()
    };

    Ok(Json(ReportResponse {
        categories,
        apps,
        files,
        sites,
        llm_visibility,
    }))
}

async fn api_sessions(
    State(ctx): State<WebContext>,
    Query(q): Query<SessionsQuery>,
) -> Result<Json<Vec<SessionRecord>>, StatusCode> {
    let privacy = PrivacyEngine::load(ctx.privacy_path.as_deref());
    if !privacy.sink_policy(Sink::Ui).enabled {
        return Ok(Json(Vec::new()));
    }
    let limit = q.limit.unwrap_or(30).clamp(1, 200);
    let db = TrackerDb::open(Some(&ctx.db_path)).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let raw_sessions = if let Some(d_str) = q.date.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        let (since_ts, until_ts) = resolve_time_range(None, Some(d_str))?;
        let mut list = db
            .query_sessions_in_range(since_ts, until_ts)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        list.reverse();
        list.truncate(limit as usize);
        list
    } else {
        db.query_recent_sessions(limit)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    };
    let sessions = raw_sessions
        .into_iter()
        .filter_map(|mut s| {
            let d = privacy.evaluate_activity(Sink::Ui, &s.app_name, &s.window_title, "");
            if !d.allow {
                return None;
            }
            s.app_name = d.app_name;
            s.window_title = d.window_title;
            Some(s)
        })
        .collect();
    Ok(Json(sessions))
}

async fn api_week(
    State(ctx): State<WebContext>,
    Query(q): Query<WeekQuery>,
) -> Result<Json<WeekResponse>, StatusCode> {
    let privacy = PrivacyEngine::load(ctx.privacy_path.as_deref());
    let today = Local::now().date_naive();
    let end_date = match q.end.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(s) => NaiveDate::parse_from_str(s, "%Y-%m-%d").map_err(|_| StatusCode::BAD_REQUEST)?,
        None => today,
    };
    let start_date = end_date - Duration::days(6);

    let ui_enabled = privacy.sink_policy(Sink::Ui).enabled;
    let db = TrackerDb::open(Some(&ctx.db_path)).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let mut days = Vec::with_capacity(7);

    for offset in 0..7 {
        let d = start_date + Duration::days(offset);
        let d_str = d.format("%Y-%m-%d").to_string();
        let mut total_sec = 0.0_f64;
        let mut cat_map: std::collections::HashMap<String, f64> = std::collections::HashMap::new();

        if ui_enabled {
            let (since_ts, until_ts) = resolve_time_range(None, Some(&d_str))?;
            let sessions = db
                .query_sessions_in_range(since_ts, until_ts)
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            for s in sessions {
                let dec = privacy.evaluate_activity(Sink::Ui, &s.app_name, &s.window_title, "");
                if dec.allow {
                    total_sec += s.duration_sec;
                    let cat = crate::categorizer::classify_activity(&dec.app_name, &dec.window_title);
                    *cat_map.entry(cat).or_insert(0.0) += s.duration_sec;
                }
            }
        }

        let mut categories: Vec<WeekDayCategory> = cat_map
            .into_iter()
            .map(|(category, total_sec)| WeekDayCategory {
                category,
                total_sec,
            })
            .collect();
        categories.sort_by(|a, b| b.total_sec.total_cmp(&a.total_sec));

        days.push(WeekDaySummary {
            date: d_str,
            label: d.format("%a").to_string(),
            total_sec,
            is_today: d == today,
            categories,
        });
    }

    Ok(Json(WeekResponse {
        start_date: start_date.format("%Y-%m-%d").to_string(),
        end_date: end_date.format("%Y-%m-%d").to_string(),
        days,
    }))
}

pub async fn serve_web_ui(bind_addr: &str, ctx: WebContext) -> Result<(), String> {
    let app = Router::new()
        .route("/", get(index))
        .route("/api/status", get(api_status))
        .route("/api/report", get(api_report))
        .route("/api/sessions", get(api_sessions))
        .route("/api/week", get(api_week))
        .with_state(ctx);

    let listener = tokio::net::TcpListener::bind(bind_addr)
        .await
        .map_err(|e| format!("Failed to bind Web UI on {bind_addr}: {e}"))?;

    axum::serve(listener, app)
        .await
        .map_err(|e| format!("Web UI server error: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::privacy::PrivacyConfig;

    #[test]
    fn llm_visibility_flags_sizable_hidden_chunk() {
        let dir = std::env::temp_dir().join(format!("agy_webui_test_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let db_path = dir.join("webui.db");
        let _ = std::fs::remove_file(&db_path);

        let db = TrackerDb::open_with_key(Some(&db_path), "webui-test-key-0123456789abcdef").unwrap();
        let s1 = db.start_session("dev.zed.Zed", "main.rs", 10, 100.0).unwrap();
        db.update_session_end(s1, 180.0).unwrap(); // 80s allowed
        let s2 = db.start_session("com.bitwarden.desktop", "Bitwarden", 11, 200.0).unwrap();
        db.update_session_end(s2, 220.0).unwrap(); // 20s hidden (20%)

        let mut cfg = PrivacyConfig::default();
        cfg.auto_load_lists_dir = false;
        let privacy = PrivacyEngine::from_config(cfg);

        let vis = compute_llm_visibility(&db, &privacy, 0.0, 500.0).unwrap();
        assert!(vis.llm_enabled);
        assert_eq!(vis.hidden_sessions, 1);
        assert!((vis.hidden_pct - 20.0).abs() < 0.1);
        assert!(vis.sizable_hidden);
        assert_eq!(vis.hidden_apps, vec!["com.bitwarden.desktop"]);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
