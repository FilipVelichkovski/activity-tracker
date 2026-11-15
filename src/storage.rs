//! SQLite storage layer for active window sessions and opened files.

use rusqlite::{Connection, params};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use crate::categorizer::classify_activity;

#[derive(Debug, Clone, Serialize)]
pub struct CategorySummary {
    pub category: String,
    pub total_sec: f64,
    pub session_count: i64,
    pub app_count: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct AppSummary {
    pub app_name: String,
    pub total_sec: f64,
    pub session_count: i64,
    pub file_count: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct OpenedFileRecord {
    pub app_name: String,
    pub file_path: String,
    pub source: String,
    pub first_seen_at: f64,
    pub last_seen_at: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct VisitedSiteRecord {
    pub app_name: String,
    pub domain: String,
    pub url: String,
    pub page_title: String,
    pub source: String,
    pub first_seen_at: f64,
    pub last_seen_at: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct SessionRecord {
    pub id: i64,
    pub app_name: String,
    pub window_title: String,
    pub pid: i64,
    pub started_at: f64,
    pub ended_at: f64,
    pub duration_sec: f64,
}

pub fn default_db_path() -> PathBuf {
    if let Ok(env_path) = std::env::var("ACTIVITY_TRACKER_DB") {
        if !env_path.is_empty() {
            return PathBuf::from(env_path);
        }
    }
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    home.join(".local/share/activity-tracker/activity.db")
}

pub struct TrackerDb {
    conn: Connection,
    path: PathBuf,
}

impl TrackerDb {
    pub fn open(override_path: Option<&Path>) -> rusqlite::Result<Self> {
        let path = override_path
            .map(Path::to_path_buf)
            .unwrap_or_else(default_db_path);
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let conn = Connection::open(&path)?;
        conn.execute_batch(
            "
            PRAGMA foreign_keys = ON;
            PRAGMA journal_mode = WAL;

            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                app_name TEXT NOT NULL,
                window_title TEXT NOT NULL,
                pid INTEGER NOT NULL,
                started_at REAL NOT NULL,
                ended_at REAL NOT NULL,
                duration_sec REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS opened_files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER REFERENCES sessions(id) ON DELETE SET NULL,
                app_name TEXT NOT NULL,
                file_path TEXT NOT NULL,
                source TEXT NOT NULL,
                first_seen_at REAL NOT NULL,
                last_seen_at REAL NOT NULL,
                UNIQUE(app_name, file_path, source)
            );

            CREATE TABLE IF NOT EXISTS visited_sites (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER REFERENCES sessions(id) ON DELETE SET NULL,
                app_name TEXT NOT NULL,
                domain TEXT NOT NULL,
                url TEXT NOT NULL,
                page_title TEXT NOT NULL,
                source TEXT NOT NULL,
                first_seen_at REAL NOT NULL,
                last_seen_at REAL NOT NULL,
                UNIQUE(app_name, url, page_title)
            );

            CREATE INDEX IF NOT EXISTS idx_sessions_started ON sessions(started_at);
            CREATE INDEX IF NOT EXISTS idx_sessions_app ON sessions(app_name);
            CREATE INDEX IF NOT EXISTS idx_files_app ON opened_files(app_name);
            CREATE INDEX IF NOT EXISTS idx_files_path ON opened_files(file_path);
            CREATE INDEX IF NOT EXISTS idx_files_last_seen ON opened_files(last_seen_at);
            CREATE INDEX IF NOT EXISTS idx_sites_last_seen ON visited_sites(last_seen_at);
            CREATE INDEX IF NOT EXISTS idx_sites_domain ON visited_sites(domain);
            ",
        )?;
        Ok(Self { conn, path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn start_session(
        &self,
        app_name: &str,
        window_title: &str,
        pid: i64,
        now: f64,
    ) -> rusqlite::Result<i64> {
        self.conn.execute(
            "INSERT INTO sessions (app_name, window_title, pid, started_at, ended_at, duration_sec)
             VALUES (?1, ?2, ?3, ?4, ?4, 0.0)",
            params![app_name, window_title, pid, now],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn update_session_end(&self, session_id: i64, now: f64) -> rusqlite::Result<()> {
        self.conn.execute(
            "UPDATE sessions
             SET ended_at = ?1,
                 duration_sec = MAX(0.0, ?1 - started_at)
             WHERE id = ?2",
            params![now, session_id],
        )?;
        Ok(())
    }

    pub fn record_file(
        &self,
        session_id: Option<i64>,
        app_name: &str,
        file_path: &str,
        source: &str,
        now: f64,
    ) -> rusqlite::Result<()> {
        self.conn.execute(
            "INSERT INTO opened_files (session_id, app_name, file_path, source, first_seen_at, last_seen_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?5)
             ON CONFLICT(app_name, file_path, source) DO UPDATE SET
                 session_id = COALESCE(excluded.session_id, opened_files.session_id),
                 last_seen_at = MAX(opened_files.last_seen_at, excluded.last_seen_at)",
            params![session_id, app_name, file_path, source, now],
        )?;
        Ok(())
    }

    pub fn record_site(
        &self,
        session_id: Option<i64>,
        app_name: &str,
        domain: &str,
        url: &str,
        page_title: &str,
        source: &str,
        now: f64,
    ) -> rusqlite::Result<()> {
        self.conn.execute(
            "INSERT INTO visited_sites (session_id, app_name, domain, url, page_title, source, first_seen_at, last_seen_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)
             ON CONFLICT(app_name, url, page_title) DO UPDATE SET
                 session_id = COALESCE(excluded.session_id, visited_sites.session_id),
                 last_seen_at = MAX(visited_sites.last_seen_at, excluded.last_seen_at)",
            params![session_id, app_name, domain, url, page_title, source, now],
        )?;
        Ok(())
    }

    pub fn query_visited_sites(
        &self,
        since_ts: f64,
        until_ts: f64,
        app_filter: Option<&str>,
        limit: i64,
    ) -> rusqlite::Result<Vec<VisitedSiteRecord>> {
        let filter_pattern = app_filter.map(|f| format!("%{}%", f.to_lowercase()));
        let mut stmt = self.conn.prepare(
            "SELECT app_name, domain, url, page_title, source, first_seen_at, last_seen_at
             FROM visited_sites
             WHERE last_seen_at >= ?1 AND last_seen_at <= ?2
               AND (?3 IS NULL OR LOWER(app_name) LIKE ?3 OR LOWER(domain) LIKE ?3 OR LOWER(page_title) LIKE ?3)
             ORDER BY last_seen_at DESC
             LIMIT ?4",
        )?;

        let rows = stmt.query_map(params![since_ts, until_ts, filter_pattern, limit], |row| {
            Ok(VisitedSiteRecord {
                app_name: row.get(0)?,
                domain: row.get(1)?,
                url: row.get(2)?,
                page_title: row.get(3)?,
                source: row.get(4)?,
                first_seen_at: row.get(5)?,
                last_seen_at: row.get(6)?,
            })
        })?;

        rows.collect()
    }

    pub fn purge_noisy_proc_files<F>(&self, is_relevant: F) -> rusqlite::Result<usize>
    where
        F: Fn(&str) -> bool,
    {
        let mut stmt = self
            .conn
            .prepare("SELECT id, file_path FROM opened_files WHERE source = 'proc-fd'")?;
        let rows: Vec<(i64, String)> = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .flatten()
            .collect();

        let mut deleted = 0usize;
        for (id, path) in rows {
            if !is_relevant(&path) {
                deleted += self
                    .conn
                    .execute("DELETE FROM opened_files WHERE id = ?1", params![id])?;
            }
        }
        Ok(deleted)
    }

    pub fn query_category_summary(
        &self,
        since_ts: f64,
        until_ts: f64,
        app_filter: Option<&str>,
    ) -> rusqlite::Result<Vec<CategorySummary>> {
        let filter_pattern = app_filter.map(|f| format!("%{}%", f.to_lowercase()));
        let mut stmt = self.conn.prepare(
            "SELECT app_name, window_title, duration_sec
             FROM sessions
             WHERE started_at >= ?1 AND started_at <= ?2
               AND (?3 IS NULL OR LOWER(app_name) LIKE ?3)",
        )?;

        let mut agg: HashMap<&'static str, (f64, i64, HashSet<String>)> = HashMap::new();
        let rows = stmt.query_map(params![since_ts, until_ts, filter_pattern], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, f64>(2)?,
            ))
        })?;

        for row in rows.flatten() {
            let (app, title, dur) = row;
            let cat = classify_activity(&app, &title);
            let entry = agg.entry(cat).or_insert_with(|| (0.0, 0, HashSet::new()));
            entry.0 += dur;
            entry.1 += 1;
            entry.2.insert(app);
        }

        let mut out: Vec<CategorySummary> = agg
            .into_iter()
            .map(|(cat, (total_sec, session_count, apps))| CategorySummary {
                category: cat.to_string(),
                total_sec,
                session_count,
                app_count: apps.len() as i64,
            })
            .collect();
        out.sort_by(|a, b| b.total_sec.total_cmp(&a.total_sec));
        Ok(out)
    }

    pub fn query_app_summary(
        &self,
        since_ts: f64,
        until_ts: f64,
        app_filter: Option<&str>,
    ) -> rusqlite::Result<Vec<AppSummary>> {
        let filter_pattern = app_filter.map(|f| format!("%{}%", f.to_lowercase()));
        let mut stmt = self.conn.prepare(
            "SELECT
                s.app_name,
                SUM(s.duration_sec) AS total_sec,
                COUNT(s.id) AS session_count,
                COALESCE((
                    SELECT COUNT(DISTINCT f.file_path)
                    FROM opened_files f
                    WHERE f.app_name = s.app_name
                      AND f.last_seen_at >= ?1 AND f.last_seen_at <= ?2
                ), 0) AS file_count
             FROM sessions s
             WHERE s.started_at >= ?1 AND s.started_at <= ?2
               AND (?3 IS NULL OR LOWER(s.app_name) LIKE ?3)
             GROUP BY s.app_name
             ORDER BY total_sec DESC",
        )?;

        let rows = stmt.query_map(params![since_ts, until_ts, filter_pattern], |row| {
            Ok(AppSummary {
                app_name: row.get(0)?,
                total_sec: row.get(1)?,
                session_count: row.get(2)?,
                file_count: row.get(3)?,
            })
        })?;

        rows.collect()
    }

    pub fn query_opened_files(
        &self,
        since_ts: f64,
        until_ts: f64,
        app_filter: Option<&str>,
        limit: i64,
    ) -> rusqlite::Result<Vec<OpenedFileRecord>> {
        let filter_pattern = app_filter.map(|f| format!("%{}%", f.to_lowercase()));
        let mut stmt = self.conn.prepare(
            "SELECT app_name, file_path, source, first_seen_at, last_seen_at
             FROM opened_files
             WHERE last_seen_at >= ?1 AND last_seen_at <= ?2
               AND (?3 IS NULL OR LOWER(app_name) LIKE ?3)
             ORDER BY last_seen_at DESC
             LIMIT ?4",
        )?;

        let rows = stmt.query_map(params![since_ts, until_ts, filter_pattern, limit], |row| {
            Ok(OpenedFileRecord {
                app_name: row.get(0)?,
                file_path: row.get(1)?,
                source: row.get(2)?,
                first_seen_at: row.get(3)?,
                last_seen_at: row.get(4)?,
            })
        })?;

        rows.collect()
    }

    pub fn query_recent_sessions(&self, limit: i64) -> rusqlite::Result<Vec<SessionRecord>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, app_name, window_title, pid, started_at, ended_at, duration_sec
             FROM sessions
             ORDER BY started_at DESC
             LIMIT ?1",
        )?;

        let rows = stmt.query_map(params![limit], |row| {
            Ok(SessionRecord {
                id: row.get(0)?,
                app_name: row.get(1)?,
                window_title: row.get(2)?,
                pid: row.get(3)?,
                started_at: row.get(4)?,
                ended_at: row.get(5)?,
                duration_sec: row.get(6)?,
            })
        })?;

        rows.collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_summary_has_no_join_fanout() {
        let dir = std::env::temp_dir().join(format!("agy_test_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let db_path = dir.join("fanout.db");
        let _ = std::fs::remove_file(&db_path);

        let db = TrackerDb::open(Some(&db_path)).unwrap();
        let sid = db.start_session("org.kde.kate", "a.txt", 1234, 100.0).unwrap();
        db.update_session_end(sid, 110.0).unwrap();
        db.record_file(Some(sid), "org.kde.kate", "/tmp/a.txt", "xbel", 105.0).unwrap();
        db.record_file(Some(sid), "org.kde.kate", "/tmp/b.txt", "dbus:activity-manager", 106.0).unwrap();

        let summary = db.query_app_summary(0.0, 200.0, None).unwrap();
        assert_eq!(summary.len(), 1);
        assert!((summary[0].total_sec - 10.0).abs() < 1e-6);
        assert_eq!(summary[0].session_count, 1);
        assert_eq!(summary[0].file_count, 2);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
