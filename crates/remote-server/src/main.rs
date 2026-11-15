//! Lightweight in-memory LAN HTTP server for today's activity summary.
//! Designed to compile statically for aarch64-unknown-linux-musl (Termux on Android).

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{get, put};
use axum::Router;
use chrono::Local;
use clap::Parser;
use serde::Deserialize;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use activity_protocol::{
    DailySummaryPayload, ErrorResponse, HealthResponse, IngestAck, LiveStatus, StatusResponse,
    SummaryResponse, WidgetAppItem, WidgetCategoryItem, WidgetSummaryResponse,
};

#[derive(Parser)]
#[command(
    name = "activity-remote-server",
    about = "In-memory LAN HTTP server for today's activity summary"
)]
struct Cli {
    /// Address to bind to (env: ACTIVITY_REMOTE_ADDR)
    #[arg(long)]
    addr: Option<String>,

    /// Optional bearer token for API authentication (env: ACTIVITY_REMOTE_TOKEN)
    #[arg(long)]
    token: Option<String>,

    /// Seconds before stored data is considered stale/offline (env: ACTIVITY_REMOTE_STALE_SECS)
    #[arg(long)]
    stale_secs: Option<f64>,

    /// Log incoming updates and requests to stderr
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Clone)]
struct AppState {
    summary: Arc<RwLock<Option<DailySummaryPayload>>>,
    token: Option<String>,
    stale_secs: f64,
    verbose: bool,
}

#[derive(Deserialize)]
struct WidgetQuery {
    top: Option<usize>,
}

fn now_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

fn today_date_str() -> String {
    Local::now().format("%Y-%m-%d").to_string()
}

fn json_error(status: StatusCode, msg: impl Into<String>) -> Response {
    (
        status,
        Json(ErrorResponse {
            error: msg.into(),
        }),
    )
        .into_response()
}

fn check_auth(headers: &HeaderMap, expected_token: Option<&str>) -> Result<(), Response> {
    let Some(expected) = expected_token.filter(|t| !t.is_empty()) else {
        return Ok(());
    };
    let Some(auth_val) = headers.get(header::AUTHORIZATION) else {
        return Err(json_error(StatusCode::UNAUTHORIZED, "unauthorized"));
    };
    let Ok(auth_str) = auth_val.to_str() else {
        return Err(json_error(StatusCode::UNAUTHORIZED, "unauthorized"));
    };
    let Some(provided) = auth_str.strip_prefix("Bearer ") else {
        return Err(json_error(StatusCode::UNAUTHORIZED, "unauthorized"));
    };
    if provided != expected {
        return Err(json_error(StatusCode::UNAUTHORIZED, "unauthorized"));
    }
    Ok(())
}

fn compute_state(status: &LiveStatus, is_stale: bool) -> String {
    if is_stale || !status.tracking {
        "offline".to_string()
    } else if status.screen_locked {
        "locked".to_string()
    } else if status.paused {
        "paused".to_string()
    } else {
        "active".to_string()
    }
}

fn empty_status() -> LiveStatus {
    LiveStatus {
        tracking: false,
        paused: false,
        screen_locked: false,
        current_app: None,
        current_title: None,
        current_category: None,
        current_duration_sec: 0.0,
    }
}

fn current_valid_summary(state: &AppState, now: f64) -> Option<(DailySummaryPayload, bool)> {
    let guard = state.summary.read().ok()?;
    let payload = guard.as_ref()?;
    let today = today_date_str();
    if payload.date != today {
        return None;
    }
    let is_stale = (now - payload.updated_at).max(0.0) > state.stale_secs;
    Some((payload.clone(), is_stale))
}

async fn api_health(State(state): State<AppState>) -> Json<HealthResponse> {
    let today = today_date_str();
    let guard = state.summary.read().ok();
    let valid = guard
        .as_ref()
        .and_then(|g| g.as_ref())
        .filter(|p| p.date == today);

    match valid {
        Some(p) => Json(HealthResponse {
            status: "ok".to_string(),
            has_data: true,
            date: Some(p.date.clone()),
            updated_at: Some(p.updated_at),
        }),
        None => Json(HealthResponse {
            status: "ok".to_string(),
            has_data: false,
            date: None,
            updated_at: None,
        }),
    }
}

async fn api_ingest_today(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(mut payload): Json<DailySummaryPayload>,
) -> Response {
    if let Err(resp) = check_auth(&headers, state.token.as_deref()) {
        return resp;
    }

    if payload.date.trim().is_empty() {
        return json_error(StatusCode::BAD_REQUEST, "date must not be empty");
    }
    if payload.updated_at <= 0.0 {
        payload.updated_at = now_secs();
    }

    let ack = IngestAck {
        ok: true,
        date: payload.date.clone(),
        updated_at: payload.updated_at,
    };

    if state.verbose {
        eprintln!(
            "[ingest] date={} host={} total_sec={:.1} app={:?}",
            payload.date,
            payload.source_host,
            payload.total_active_sec,
            payload.status.current_app
        );
    }

    if let Ok(mut guard) = state.summary.write() {
        *guard = Some(payload);
    }

    (StatusCode::OK, Json(ack)).into_response()
}

async fn api_widget_today(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<WidgetQuery>,
) -> Response {
    if let Err(resp) = check_auth(&headers, state.token.as_deref()) {
        return resp;
    }

    let top = q.top.unwrap_or(4).clamp(1, 10);
    let now = now_secs();

    let body = match current_valid_summary(&state, now) {
        Some((p, is_stale)) => {
            let state_str = compute_state(&p.status, is_stale);
            let top_categories = p
                .categories
                .iter()
                .take(top)
                .map(|c| WidgetCategoryItem {
                    category: c.category.clone(),
                    total_sec: c.total_sec,
                    share_pct: c.share_pct,
                })
                .collect();
            let top_apps = p
                .apps
                .iter()
                .take(top)
                .map(|a| WidgetAppItem {
                    app_name: a.app_name.clone(),
                    total_sec: a.total_sec,
                })
                .collect();

            WidgetSummaryResponse {
                date: p.date,
                has_data: true,
                is_stale,
                updated_at: p.updated_at,
                total_active_sec: p.total_active_sec,
                state: state_str,
                current_app: p.status.current_app,
                current_category: p.status.current_category,
                current_duration_sec: p.status.current_duration_sec,
                top_categories,
                top_apps,
            }
        }
        None => WidgetSummaryResponse {
            date: today_date_str(),
            has_data: false,
            is_stale: true,
            updated_at: 0.0,
            total_active_sec: 0.0,
            state: "offline".to_string(),
            current_app: None,
            current_category: None,
            current_duration_sec: 0.0,
            top_categories: Vec::new(),
            top_apps: Vec::new(),
        },
    };

    (StatusCode::OK, Json(body)).into_response()
}

async fn api_summary_today(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(resp) = check_auth(&headers, state.token.as_deref()) {
        return resp;
    }

    let now = now_secs();
    let body = match current_valid_summary(&state, now) {
        Some((p, is_stale)) => SummaryResponse {
            has_data: true,
            is_stale,
            date: p.date,
            source_host: Some(p.source_host),
            updated_at: p.updated_at,
            total_active_sec: p.total_active_sec,
            status: p.status,
            categories: p.categories,
            apps: p.apps,
            top_sites: p.top_sites,
            recent_files: p.recent_files,
        },
        None => SummaryResponse {
            has_data: false,
            is_stale: true,
            date: today_date_str(),
            source_host: None,
            updated_at: 0.0,
            total_active_sec: 0.0,
            status: empty_status(),
            categories: Vec::new(),
            apps: Vec::new(),
            top_sites: Vec::new(),
            recent_files: Vec::new(),
        },
    };

    (StatusCode::OK, Json(body)).into_response()
}

async fn api_status(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(resp) = check_auth(&headers, state.token.as_deref()) {
        return resp;
    }

    let now = now_secs();
    let body = match current_valid_summary(&state, now) {
        Some((p, is_stale)) => {
            let state_str = compute_state(&p.status, is_stale);
            StatusResponse {
                has_data: true,
                is_stale,
                updated_at: p.updated_at,
                state: state_str,
                tracking: p.status.tracking,
                paused: p.status.paused,
                screen_locked: p.status.screen_locked,
                current_app: p.status.current_app,
                current_title: p.status.current_title,
                current_category: p.status.current_category,
                current_duration_sec: p.status.current_duration_sec,
            }
        }
        None => StatusResponse {
            has_data: false,
            is_stale: true,
            updated_at: 0.0,
            state: "offline".to_string(),
            tracking: false,
            paused: false,
            screen_locked: false,
            current_app: None,
            current_title: None,
            current_category: None,
            current_duration_sec: 0.0,
        },
    };

    (StatusCode::OK, Json(body)).into_response()
}

fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/api/v1/health", get(api_health))
        .route(
            "/api/v1/summary/today",
            put(api_ingest_today).get(api_summary_today),
        )
        .route("/api/v1/widget/today", get(api_widget_today))
        .route("/api/v1/status", get(api_status))
        .with_state(state)
}

#[tokio::main]
async fn main() -> Result<(), String> {
    let cli = Cli::parse();
    let addr = cli
        .addr
        .or_else(|| std::env::var("ACTIVITY_REMOTE_ADDR").ok().filter(|s| !s.is_empty()))
        .unwrap_or_else(|| "0.0.0.0:7879".to_string());
    let token = cli
        .token
        .or_else(|| std::env::var("ACTIVITY_REMOTE_TOKEN").ok().filter(|s| !s.is_empty()));
    let stale_secs = cli
        .stale_secs
        .or_else(|| {
            std::env::var("ACTIVITY_REMOTE_STALE_SECS")
                .ok()
                .and_then(|s| s.parse::<f64>().ok())
        })
        .unwrap_or(60.0);

    let state = AppState {
        summary: Arc::new(RwLock::new(None)),
        token,
        stale_secs,
        verbose: cli.verbose,
    };

    let app = build_router(state);
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .map_err(|e| format!("Failed to bind {addr}: {e}"))?;

    eprintln!("activity-remote-server listening on http://{addr}");

    let shutdown = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await
        .map_err(|e| format!("Server error: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use activity_protocol::{AppItem, CategoryItem};
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    fn sample_payload(date: &str, updated_at: f64) -> DailySummaryPayload {
        DailySummaryPayload {
            date: date.to_string(),
            source_host: "test-pc".to_string(),
            updated_at,
            total_active_sec: 1200.0,
            status: LiveStatus {
                tracking: true,
                paused: false,
                screen_locked: false,
                current_app: Some("dev.zed.Zed".to_string()),
                current_title: Some("main.rs".to_string()),
                current_category: Some("Development".to_string()),
                current_duration_sec: 120.0,
            },
            categories: vec![
                CategoryItem {
                    category: "Development".to_string(),
                    total_sec: 900.0,
                    share_pct: 75.0,
                    session_count: 3,
                    app_count: 1,
                },
                CategoryItem {
                    category: "Learning".to_string(),
                    total_sec: 300.0,
                    share_pct: 25.0,
                    session_count: 1,
                    app_count: 1,
                },
            ],
            apps: vec![
                AppItem {
                    app_name: "dev.zed.Zed".to_string(),
                    category: "Development".to_string(),
                    total_sec: 900.0,
                    session_count: 3,
                    file_count: 2,
                },
                AppItem {
                    app_name: "org.kde.okular".to_string(),
                    category: "Learning".to_string(),
                    total_sec: 300.0,
                    session_count: 1,
                    file_count: 1,
                },
            ],
            top_sites: Vec::new(),
            recent_files: Vec::new(),
        }
    }

    #[tokio::test]
    async fn empty_state_and_ingest_roundtrip() {
        let state = AppState {
            summary: Arc::new(RwLock::new(None)),
            token: None,
            stale_secs: 60.0,
            verbose: false,
        };
        let app = build_router(state);

        // 1. Empty widget returns 200 with has_data = false
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/widget/today")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let w: WidgetSummaryResponse = serde_json::from_slice(&bytes).unwrap();
        assert!(!w.has_data);
        assert_eq!(w.state, "offline");

        // 2. Ingest today's summary
        let today = today_date_str();
        let payload = sample_payload(&today, now_secs());
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/v1/summary/today")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&payload).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // 3. Widget returns top=1
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/widget/today?top=1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let w: WidgetSummaryResponse = serde_json::from_slice(&bytes).unwrap();
        assert!(w.has_data);
        assert!(!w.is_stale);
        assert_eq!(w.state, "active");
        assert_eq!(w.top_categories.len(), 1);
        assert_eq!(w.top_apps.len(), 1);
        assert_eq!(w.top_categories[0].category, "Development");

        // 4. Full summary endpoint
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/summary/today")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let s: SummaryResponse = serde_json::from_slice(&bytes).unwrap();
        assert!(s.has_data);
        assert_eq!(s.categories.len(), 2);
        assert_eq!(s.apps.len(), 2);
    }

    #[tokio::test]
    async fn bearer_auth_enforced_when_configured() {
        let state = AppState {
            summary: Arc::new(RwLock::new(None)),
            token: Some("secret123".to_string()),
            stale_secs: 60.0,
            verbose: false,
        };
        let app = build_router(state);

        // Health is unauthenticated
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Missing auth -> 401
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/widget/today")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // Valid auth -> 200
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/widget/today")
                    .header(header::AUTHORIZATION, "Bearer secret123")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn stale_data_marks_state_offline() {
        let today = today_date_str();
        let old_ts = now_secs() - 120.0;
        let state = AppState {
            summary: Arc::new(RwLock::new(Some(sample_payload(&today, old_ts)))),
            token: None,
            stale_secs: 60.0,
            verbose: false,
        };
        let app = build_router(state);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let st: StatusResponse = serde_json::from_slice(&bytes).unwrap();
        assert!(st.has_data);
        assert!(st.is_stale);
        assert_eq!(st.state, "offline");
    }
}
