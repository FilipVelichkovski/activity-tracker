//! Activity categorization based on application name, window title, and optional user rules.

use serde::Deserialize;
use std::fs;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::SystemTime;

const DEV_APPS: &[&str] = &[
    "zed",
    "antigravity",
    "code",
    "codium",
    "clion",
    "intellij",
    "pycharm",
    "rustrover",
    "kate",
    "kwrite",
    "nvim",
    "neovim",
    "vim",
    "emacs",
    "konsole",
    "alacritty",
    "kitty",
    "wezterm",
    "ghostty",
    "ptyxis",
];

const DEV_TITLE_KEYWORDS: &[&str] = &[
    "github",
    "gitlab",
    "docs.rs",
    "crates.io",
    "cppreference",
    "stackoverflow",
    "127.0.0.1",
    "localhost",
    ".cpp",
    ".hpp",
    ".rs",
    ".py",
];

const LEARNING_KEYWORDS: &[&str] = &[
    "coursera",
    "udemy",
    "edx",
    "khan academy",
    "anki",
    "duolingo",
    "wikipedia",
    "lecture",
    "homework",
];

const COMM_APPS: &[&str] = &[
    "discord",
    "slack",
    "telegram",
    "signal",
    "element",
    "thunderbird",
    "kmail",
    "zoom",
    "teams",
];

const SOCIAL_KEYWORDS: &[&str] = &[
    "bsky",
    "bluesky",
    "twitter",
    "reddit",
    "mastodon",
    "instagram",
    "facebook",
    "threads",
];

const MEDIA_APPS_OR_KEYWORDS: &[&str] = &[
    "youtube",
    "twitch",
    "netflix",
    "spotify",
    "vlc",
    "mpv",
    "elisa",
    "steam",
    "gwenview",
];

const SYSTEM_APPS: &[&str] = &[
    "dolphin",
    "plasmashell",
    "systemsettings",
    "krunner",
    "discover",
    "ark",
    "spectacle",
    "ksysguard",
    "plasma-systemmonitor",
];

const BROWSER_APPS: &[&str] = &[
    "firefox",
    "librewolf",
    "chrome",
    "chromium",
    "brave",
    "vivaldi",
    "zen",
];

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct CategoriesConfig {
    pub rules: Vec<CategoryRule>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CategoryRule {
    pub category: String,
    #[serde(default)]
    pub title_keywords: Vec<String>,
    #[serde(default)]
    pub app_keywords: Vec<String>,
}

struct CategoryCache {
    path: Option<PathBuf>,
    last_mtime: Option<SystemTime>,
    config: CategoriesConfig,
}

static CATEGORY_CACHE: OnceLock<Mutex<CategoryCache>> = OnceLock::new();

fn default_categories_path() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("ACTIVITY_TRACKER_CATEGORIES_CONFIG") {
        let trimmed = p.trim();
        if !trimmed.is_empty() {
            return Some(PathBuf::from(trimmed));
        }
    }
    let home = std::env::var_os("HOME").map(PathBuf::from)?;
    Some(home.join(".config/activity-tracker/categories.json"))
}

fn load_categories_config(path: &PathBuf) -> Option<CategoriesConfig> {
    let raw = fs::read_to_string(path).ok()?;
    let mut cfg: CategoriesConfig = serde_json::from_str(&raw).ok()?;
    for rule in &mut cfg.rules {
        for kw in &mut rule.title_keywords {
            *kw = kw.to_lowercase();
        }
        for kw in &mut rule.app_keywords {
            *kw = kw.to_lowercase();
        }
    }
    Some(cfg)
}

fn with_cached_config<F, R>(f: F) -> R
where
    F: FnOnce(&CategoriesConfig) -> R,
{
    let lock = CATEGORY_CACHE.get_or_init(|| {
        Mutex::new(CategoryCache {
            path: default_categories_path(),
            last_mtime: None,
            config: CategoriesConfig::default(),
        })
    });

    let mut guard = lock.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(ref path) = guard.path.clone() {
        let mtime = fs::metadata(path).and_then(|m| m.modified()).ok();
        if mtime != guard.last_mtime {
            guard.config = load_categories_config(path).unwrap_or_default();
            guard.last_mtime = mtime;
        }
    }
    f(&guard.config)
}

pub fn classify_activity(app_name: &str, window_title: &str) -> String {
    with_cached_config(|cfg| classify_activity_with_config(app_name, window_title, cfg))
}

pub fn classify_activity_with_config(
    app_name: &str,
    window_title: &str,
    config: &CategoriesConfig,
) -> String {
    let app = app_name.to_lowercase();
    let title = window_title.to_lowercase();

    // 0. User-configured rules from ~/.config/activity-tracker/categories.json
    for rule in &config.rules {
        if rule.title_keywords.iter().any(|k| !k.is_empty() && title.contains(k.as_str()))
            || rule.app_keywords.iter().any(|k| !k.is_empty() && app.contains(k.as_str()))
        {
            return rule.category.clone();
        }
    }

    // 1. Session title-based classification first (what the user is actually doing in the session)
    if LEARNING_KEYWORDS.iter().any(|k| title.contains(k)) {
        return "Learning".to_string();
    }

    if title.contains("gmail") || title.contains("proton mail") || title.contains("meet.google") {
        return "Communication".to_string();
    }

    if SOCIAL_KEYWORDS.iter().any(|k| title.contains(k)) {
        return "Social".to_string();
    }

    if MEDIA_APPS_OR_KEYWORDS.iter().any(|k| title.contains(k)) {
        return "Media & Entertainment".to_string();
    }

    if DEV_TITLE_KEYWORDS.iter().any(|k| title.contains(k)) {
        return "Development".to_string();
    }

    // 2. App-level fallback when window title has no specific topic signal
    if COMM_APPS.iter().any(|k| app.contains(k)) {
        return "Communication".to_string();
    }

    if app.contains("okular") || app.contains("zotero") || app.contains("xournal") {
        return "Learning".to_string();
    }

    if SOCIAL_KEYWORDS.iter().any(|k| app.contains(k)) {
        return "Social".to_string();
    }

    if MEDIA_APPS_OR_KEYWORDS.iter().any(|k| app.contains(k)) {
        return "Media & Entertainment".to_string();
    }

    if DEV_APPS.iter().any(|k| app.contains(k)) {
        return "Development".to_string();
    }

    if SYSTEM_APPS.iter().any(|k| app.contains(k)) {
        return "System & Files".to_string();
    }

    if BROWSER_APPS.iter().any(|k| app.contains(k)) {
        return "Web Browsing".to_string();
    }

    "Other".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn categorizes_apps_and_browser_titles() {
        let empty = CategoriesConfig::default();
        assert_eq!(
            classify_activity_with_config("dev.zed.Zed", "my-project — main.rs", &empty),
            "Development"
        );
        assert_eq!(
            classify_activity_with_config("org.kde.okular", "Lecture Notes.pdf — Okular", &empty),
            "Learning"
        );
        assert_eq!(
            classify_activity_with_config(
                "org.mozilla.firefox",
                "Machine Learning - Coursera — Mozilla Firefox",
                &empty
            ),
            "Learning"
        );
        assert_eq!(
            classify_activity_with_config(
                "org.mozilla.firefox",
                "r/rust — Reddit — Mozilla Firefox",
                &empty
            ),
            "Social"
        );
        assert_eq!(
            classify_activity_with_config("com.discordapp.Discord", "#general - Discord", &empty),
            "Communication"
        );
        assert_eq!(
            classify_activity_with_config("org.kde.dolphin", "Home — Dolphin", &empty),
            "System & Files"
        );
    }

    #[test]
    fn custom_rules_override_builtin_categories() {
        let cfg = CategoriesConfig {
            rules: vec![
                CategoryRule {
                    category: "Learning".to_string(),
                    title_keywords: vec!["study-notes".to_string()],
                    app_keywords: vec!["rnote".to_string()],
                },
                CategoryRule {
                    category: "Social".to_string(),
                    title_keywords: vec!["fediverse".to_string()],
                    app_keywords: vec![],
                },
            ],
        };
        assert_eq!(
            classify_activity_with_config("dev.zed.Zed", "study-notes — chapter1.md", &cfg),
            "Learning"
        );
        assert_eq!(
            classify_activity_with_config("com.github.flxzt.rnote", "notes.rnote", &cfg),
            "Learning"
        );
        assert_eq!(
            classify_activity_with_config("org.mozilla.firefox", "Home - Fediverse — Firefox", &cfg),
            "Social"
        );
    }
}
