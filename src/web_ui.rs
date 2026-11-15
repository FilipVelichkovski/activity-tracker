//! Embedded Axum Web UI server for Activity Tracker.

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{Html, Json};
use axum::routing::get;
use axum::Router;
use chrono::{Duration, Local};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::daemon::TrackerState;
use crate::storage::{
    AppSummary, CategorySummary, OpenedFileRecord, SessionRecord, TrackerDb, VisitedSiteRecord,
};

#[derive(Clone)]
pub struct WebContext {
    pub db_path: PathBuf,
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
    pub app: Option<String>,
    pub file_limit: Option<i64>,
}

#[derive(Serialize)]
pub struct ReportResponse {
    pub categories: Vec<CategorySummary>,
    pub apps: Vec<AppSummary>,
    pub files: Vec<OpenedFileRecord>,
    pub sites: Vec<VisitedSiteRecord>,
}

#[derive(Deserialize)]
pub struct SessionsQuery {
    pub limit: Option<i64>,
}

fn time_range_for_days(days: Option<i64>) -> (f64, f64) {
    let now = Local::now();
    let until_ts = (now.timestamp_millis() as f64 / 1000.0) + 1.0;
    let since_ts = match days {
        Some(n) if n > 0 => (now - Duration::days(n)).timestamp() as f64,
        _ => {
            let today = now.date_naive().and_hms_opt(0, 0, 0).unwrap();
            let midnight = chrono::TimeZone::from_local_datetime(&Local, &today).unwrap();
            midnight.timestamp() as f64
        }
    };
    (since_ts, until_ts)
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
                Some(cur) => (
                    Some(cur.app_name.clone()),
                    Some(cur.window_title.clone()),
                    (now - cur.started_at).max(0.0),
                ),
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

async fn api_report(
    State(ctx): State<WebContext>,
    Query(q): Query<ReportQuery>,
) -> Result<Json<ReportResponse>, StatusCode> {
    let (since_ts, until_ts) = time_range_for_days(q.days);
    let app_filter = q.app.as_deref().filter(|s| !s.trim().is_empty());
    let file_limit = q.file_limit.unwrap_or(100).clamp(1, 500);

    let db = TrackerDb::open(Some(&ctx.db_path)).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let categories = db
        .query_category_summary(since_ts, until_ts, app_filter)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let apps = db
        .query_app_summary(since_ts, until_ts, app_filter)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let files = db
        .query_opened_files(since_ts, until_ts, app_filter, file_limit)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let sites = db
        .query_visited_sites(since_ts, until_ts, app_filter, file_limit)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(ReportResponse {
        categories,
        apps,
        files,
        sites,
    }))
}

async fn api_sessions(
    State(ctx): State<WebContext>,
    Query(q): Query<SessionsQuery>,
) -> Result<Json<Vec<SessionRecord>>, StatusCode> {
    let limit = q.limit.unwrap_or(30).clamp(1, 200);
    let db = TrackerDb::open(Some(&ctx.db_path)).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let sessions = db
        .query_recent_sessions(limit)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(sessions))
}

pub async fn serve_web_ui(bind_addr: &str, ctx: WebContext) -> Result<(), String> {
    let app = Router::new()
        .route("/", get(index))
        .route("/api/status", get(api_status))
        .route("/api/report", get(api_report))
        .route("/api/sessions", get(api_sessions))
        .with_state(ctx);

    let listener = tokio::net::TcpListener::bind(bind_addr)
        .await
        .map_err(|e| format!("Failed to bind Web UI on {bind_addr}: {e}"))?;

    axum::serve(listener, app)
        .await
        .map_err(|e| format!("Web UI server error: {e}"))
}
