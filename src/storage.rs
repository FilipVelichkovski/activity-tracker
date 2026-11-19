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

use std::io::Read;
use std::os::unix::fs::PermissionsExt;

const KEYRING_SERVICE: &str = "activity-tracker";
const KEYRING_USER: &str = "sqlite-db-key";
const SQLITE_HEADER: &[u8; 16] = b"SQLite format 3\0";

fn generate_hex_key() -> std::io::Result<String> {
    let mut buf = [0u8; 32];
    let mut f = std::fs::File::open("/dev/urandom")?;
    f.read_exact(&mut buf)?;
    Ok(buf.iter().map(|b| format!("{b:02x}")).collect())
}

fn read_or_create_keyfile(db_path: &Path) -> Result<String, String> {
    let key_path = db_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(".db_key");
    if let Ok(existing) = std::fs::read_to_string(&key_path) {
        let trimmed = existing.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_string());
        }
    }
    let key = generate_hex_key().map_err(|e| format!("Failed to generate DB key: {e}"))?;
    if let Some(parent) = key_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    std::fs::write(&key_path, &key).map_err(|e| format!("Failed to write keyfile: {e}"))?;
    let _ = std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600));
    Ok(key)
}

fn resolve_db_key(db_path: &Path) -> Result<String, String> {
    if let Ok(env_key) = std::env::var("ACTIVITY_TRACKER_DB_KEY") {
        let trimmed = env_key.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_string());
        }
    }

    match keyring::Entry::new(KEYRING_SERVICE, KEYRING_USER) {
        Ok(entry) => match entry.get_password() {
            Ok(pw) if !pw.trim().is_empty() => Ok(pw),
            Ok(_) | Err(keyring::Error::NoEntry) => {
                let key =
                    generate_hex_key().map_err(|e| format!("Failed to generate DB key: {e}"))?;
                match entry.set_password(&key) {
                    Ok(()) => Ok(key),
                    Err(e) => {
                        eprintln!(
                            "[storage] Secret Service unavailable ({e}); falling back to 0600 keyfile"
                        );
                        read_or_create_keyfile(db_path)
                    }
                }
            }
            Err(e) => {
                eprintln!(
                    "[storage] Secret Service lookup failed ({e}); falling back to 0600 keyfile"
                );
                read_or_create_keyfile(db_path)
            }
        },
        Err(e) => {
            eprintln!("[storage] Keyring init failed ({e}); falling back to 0600 keyfile");
            read_or_create_keyfile(db_path)
        }
    }
}

fn is_plaintext_sqlite(path: &Path) -> bool {
    let Ok(mut f) = std::fs::File::open(path) else {
        return false;
    };
    let mut header = [0u8; 16];
    matches!(f.read_exact(&mut header), Ok(()) if &header == SQLITE_HEADER)
}

fn migrate_plaintext_to_sqlcipher(path: &Path, key: &str) -> rusqlite::Result<()> {
    let tmp_path = path.with_extension("db.enc.tmp");
    let _ = std::fs::remove_file(&tmp_path);

    {
        let plain = Connection::open(path)?;
        let _ = plain.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);");
        let tmp_str = tmp_path.to_string_lossy().replace('\'', "''");
        let key_esc = key.replace('\'', "''");
        plain.execute_batch(&format!(
            "ATTACH DATABASE '{tmp_str}' AS encrypted KEY '{key_esc}';
             SELECT sqlcipher_export('encrypted');
             DETACH DATABASE encrypted;"
        ))?;
    }

    // Remove stale WAL/SHM from the plaintext DB before replacing it
    let _ = std::fs::remove_file(PathBuf::from(format!("{}-wal", path.display())));
    let _ = std::fs::remove_file(PathBuf::from(format!("{}-shm", path.display())));
    std::fs::rename(&tmp_path, path).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
    })?;
    eprintln!(
        "[storage] Migrated plaintext database {} to SQLCipher encryption",
        path.display()
    );
    Ok(())
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
        let key = resolve_db_key(&path).map_err(|e| {
            rusqlite::Error::InvalidParameterName(format!("DB key resolution failed: {e}"))
        })?;
        Self::open_with_key(Some(&path), &key)
    }

    pub fn open_with_key(override_path: Option<&Path>, key: &str) -> rusqlite::Result<Self> {
        let path = override_path
            .map(Path::to_path_buf)
            .unwrap_or_else(default_db_path);
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if path.exists() && is_plaintext_sqlite(&path) {
            migrate_plaintext_to_sqlcipher(&path, key)?;
        }
        let conn = Connection::open(&path)?;
        conn.pragma_update(None, "key", key)?;
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

        let mut agg: HashMap<String, (f64, i64, HashSet<String>)> = HashMap::new();
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
                category: cat,
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

    pub fn query_sessions_in_range(
        &self,
        since_ts: f64,
        until_ts: f64,
    ) -> rusqlite::Result<Vec<SessionRecord>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, app_name, window_title, pid, started_at, ended_at, duration_sec
             FROM sessions
             WHERE started_at >= ?1 AND started_at <= ?2
             ORDER BY started_at ASC",
        )?;

        let rows = stmt.query_map(params![since_ts, until_ts], |row| {
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

        let db = TrackerDb::open_with_key(Some(&db_path), "0123456789abcdef0123456789abcdef").unwrap();
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

    #[test]
    fn sqlcipher_encrypts_and_migrates_plaintext_db() {
        let dir = std::env::temp_dir().join(format!("agy_cipher_test_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let db_path = dir.join("migrate.db");
        let _ = std::fs::remove_file(&db_path);

        // 1. Create a legacy plaintext SQLite database
        {
            let plain = Connection::open(&db_path).unwrap();
            plain
                .execute_batch(
                    "CREATE TABLE sessions (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        app_name TEXT NOT NULL,
                        window_title TEXT NOT NULL,
                        pid INTEGER NOT NULL,
                        started_at REAL NOT NULL,
                        ended_at REAL NOT NULL,
                        duration_sec REAL NOT NULL
                    );
                    INSERT INTO sessions (app_name, window_title, pid, started_at, ended_at, duration_sec)
                    VALUES ('dev.zed.Zed', 'lib.rs', 42, 100.0, 130.0, 30.0);",
                )
                .unwrap();
        }
        assert!(is_plaintext_sqlite(&db_path));

        // 2. Opening with TrackerDb::open_with_key migrates it to SQLCipher & preserves rows
        let key = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
        {
            let db = TrackerDb::open_with_key(Some(&db_path), key).unwrap();
            let sessions = db.query_sessions_in_range(0.0, 200.0).unwrap();
            assert_eq!(sessions.len(), 1);
            assert_eq!(sessions[0].app_name, "dev.zed.Zed");
            assert_eq!(sessions[0].window_title, "lib.rs");
        }

        // 3. File is no longer plaintext SQLite and rejects wrong/missing keys
        assert!(!is_plaintext_sqlite(&db_path));
        assert!(TrackerDb::open_with_key(Some(&db_path), "wrong-key").is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
