//! Shared HTTP API types between `activity-tracker` daemon and `activity-remote-server`.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LiveStatus {
    pub tracking: bool,
    pub paused: bool,
    pub screen_locked: bool,
    pub current_app: Option<String>,
    pub current_title: Option<String>,
    pub current_category: Option<String>,
    pub current_duration_sec: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CategoryItem {
    pub category: String,
    pub total_sec: f64,
    pub share_pct: f64,
    pub session_count: i64,
    pub app_count: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AppItem {
    pub app_name: String,
    pub category: String,
    pub total_sec: f64,
    pub session_count: i64,
    pub file_count: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SiteItem {
    pub domain: String,
    pub page_title: String,
    pub app_name: String,
    pub last_seen_at: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FileItem {
    pub app_name: String,
    pub file_path: String,
    pub source: String,
    pub last_seen_at: f64,
}

/// Payload sent by the daemon to `PUT /api/v1/summary/today`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DailySummaryPayload {
    pub date: String,
    pub source_host: String,
    pub updated_at: f64,
    pub total_active_sec: f64,
    pub status: LiveStatus,
    pub categories: Vec<CategoryItem>,
    pub apps: Vec<AppItem>,
    #[serde(default)]
    pub top_sites: Vec<SiteItem>,
    #[serde(default)]
    pub recent_files: Vec<FileItem>,
}

/// Response for `GET /api/v1/health`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HealthResponse {
    pub status: String,
    pub has_data: bool,
    pub date: Option<String>,
    pub updated_at: Option<f64>,
}

/// Response for `PUT /api/v1/summary/today`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IngestAck {
    pub ok: bool,
    pub date: String,
    pub updated_at: f64,
}

/// Compact category entry for home screen widgets.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WidgetCategoryItem {
    pub category: String,
    pub total_sec: f64,
    pub share_pct: f64,
}

/// Compact app entry for home screen widgets.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WidgetAppItem {
    pub app_name: String,
    pub total_sec: f64,
}

/// Response for `GET /api/v1/widget/today`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WidgetSummaryResponse {
    pub date: String,
    pub has_data: bool,
    pub is_stale: bool,
    pub updated_at: f64,
    pub total_active_sec: f64,
    pub state: String,
    pub current_app: Option<String>,
    pub current_category: Option<String>,
    pub current_duration_sec: f64,
    pub top_categories: Vec<WidgetCategoryItem>,
    pub top_apps: Vec<WidgetAppItem>,
}

/// Response for `GET /api/v1/summary/today`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SummaryResponse {
    pub has_data: bool,
    pub is_stale: bool,
    pub date: String,
    pub source_host: Option<String>,
    pub updated_at: f64,
    pub total_active_sec: f64,
    pub status: LiveStatus,
    pub categories: Vec<CategoryItem>,
    pub apps: Vec<AppItem>,
    pub top_sites: Vec<SiteItem>,
    pub recent_files: Vec<FileItem>,
}

/// Response for `GET /api/v1/status`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StatusResponse {
    pub has_data: bool,
    pub is_stale: bool,
    pub updated_at: f64,
    pub state: String,
    pub tracking: bool,
    pub paused: bool,
    pub screen_locked: bool,
    pub current_app: Option<String>,
    pub current_title: Option<String>,
    pub current_category: Option<String>,
    pub current_duration_sec: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ErrorResponse {
    pub error: String,
}
