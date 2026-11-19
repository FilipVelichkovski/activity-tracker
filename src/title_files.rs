//! Extract opened user files from editor/IDE/viewer window titles and Zed workspace DB.

use rusqlite::{Connection, OpenFlags};
use std::path::{Path, PathBuf};

fn looks_like_filename(s: &str) -> bool {
    let trimmed = s.trim();
    if trimmed.is_empty() || trimmed.len() > 200 || trimmed.contains("://") {
        return false;
    }
    // Check for file extension (e.g. .cpp, .hpp, .rs, .md, .py, .pdf, .txt, etc.)
    if let Some(dot) = trimmed.rfind('.') {
        let ext = &trimmed[dot + 1..];
        if !ext.is_empty() && ext.len() <= 12 && ext.chars().all(|c| c.is_ascii_alphanumeric()) {
            return true;
        }
    }
    // Common extensionless files
    matches!(
        trimmed,
        "Makefile" | "CMakeLists.txt" | "Dockerfile" | "Cargo.lock" | ".gitignore" | ".env"
    )
}

fn find_file_in_dir(root: &Path, filename: &str, max_depth: usize) -> Option<PathBuf> {
    if max_depth == 0 || !root.is_dir() {
        return None;
    }
    let direct = root.join(filename);
    if direct.is_file() {
        return Some(direct);
    }
    let Ok(entries) = std::fs::read_dir(root) else {
        return None;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
            if name.starts_with('.') || matches!(name, "target" | "build" | "node_modules" | "dist") {
                continue;
            }
            if let Some(found) = find_file_in_dir(&path, filename, max_depth - 1) {
                return Some(found);
            }
        }
    }
    None
}

fn resolve_zed_workspace_root(project_name: &str) -> Option<PathBuf> {
    let home = std::env::var_os("HOME").map(PathBuf::from)?;
    let zed_db = home.join(".local/share/zed/db/0-stable/db.sqlite");
    if zed_db.exists() {
        if let Ok(conn) = Connection::open_with_flags(zed_db, OpenFlags::SQLITE_OPEN_READ_ONLY) {
            if let Ok(mut stmt) = conn.prepare(
                "SELECT paths FROM workspaces WHERE paths IS NOT NULL ORDER BY timestamp DESC LIMIT 100",
            ) {
                if let Ok(rows) = stmt.query_map([], |row| row.get::<_, String>(0)) {
                    for paths_str in rows.flatten() {
                        for line in paths_str.lines() {
                            let p = Path::new(line.trim());
                            if p.file_name().and_then(|s| s.to_str()) == Some(project_name) && p.is_dir() {
                                return Some(p.to_path_buf());
                            }
                        }
                    }
                }
            }
        }
    }

    // Fallback: check common repo directories
    for base in [
        home.join("repos"),
        home.join("Projects"),
        home.join("Documents"),
        home.clone(),
    ] {
        let candidate = base.join(project_name);
        if candidate.is_dir() {
            return Some(candidate);
        }
    }
    None
}

/// Extract an opened file path (or project/filename) from an active editor/viewer window title.
pub fn extract_file_from_title(app_name: &str, window_title: &str) -> Option<(String, &'static str)> {
    let lower = app_name.to_lowercase();
    let title = window_title.trim();
    if title.is_empty() {
        return None;
    }

    // Zed: "<project> — <filename>" (or "<project> — <filename> •" when unsaved)
    if lower.contains("zed") {
        if let Some((proj, file_part)) = title.split_once(" — ") {
            let filename = file_part.trim().trim_end_matches(" •").trim();
            if looks_like_filename(filename) {
                if let Some(root) = resolve_zed_workspace_root(proj.trim()) {
                    if let Some(full) = find_file_in_dir(&root, filename, 4) {
                        return Some((full.to_string_lossy().into_owned(), "zed:workspace"));
                    }
                    return Some((
                        root.join(filename).to_string_lossy().into_owned(),
                        "zed:title",
                    ));
                }
                return Some((format!("{}/{filename}", proj.trim()), "zed:title"));
            }
        }
        return None;
    }

    // Kate / KWrite: "<filename> — Kate" or "<filename> [*] — Kate"
    if lower.contains("kate") || lower.contains("kwrite") {
        let stripped = title
            .strip_suffix(" — Kate")
            .or_else(|| title.strip_suffix(" — KWrite"))
            .unwrap_or(title)
            .trim()
            .trim_end_matches("[*]")
            .trim();
        if looks_like_filename(stripped) {
            return Some((stripped.to_string(), "editor:title"));
        }
        return None;
    }

    // VS Code / Antigravity: "<filename> - <workspace> - Visual Studio Code"
    if lower.contains("code") || lower.contains("antigravity") {
        let parts: Vec<&str> = title.split(" - ").collect();
        if parts.len() >= 2 {
            let candidate = parts[0].trim().trim_start_matches("● ").trim();
            if looks_like_filename(candidate) {
                return Some((candidate.to_string(), "editor:title"));
            }
        }
        return None;
    }

    // Okular / Gwenview / LibreOffice / Evince
    if lower.contains("okular")
        || lower.contains("gwenview")
        || lower.contains("libreoffice")
        || lower.contains("evince")
    {
        let candidate = title
            .split(" — ")
            .next()
            .or_else(|| title.split(" - ").next())
            .unwrap_or(title)
            .trim();
        if looks_like_filename(candidate) {
            return Some((candidate.to_string(), "viewer:title"));
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_zed_and_kate_titles() {
        let zed = extract_file_from_title("dev.zed.Zed", "my-project — main.rs");
        assert!(zed.is_some());
        let (path, _) = zed.unwrap();
        assert!(path.ends_with("main.rs"));

        let kate = extract_file_from_title("org.kde.kate", "main.cpp [*] — Kate");
        assert_eq!(kate.as_ref().map(|(p, _)| p.as_str()), Some("main.cpp"));
    }
}
