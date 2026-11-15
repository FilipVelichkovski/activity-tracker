//! Activity categorization based on application name and window title.

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
    "activity tracker",
    "variant",
    ".cpp",
    ".hpp",
    ".rs",
    ".py",
];

const LEARNING_KEYWORDS: &[&str] = &[
    "memrise",
    "blinklearning",
    "coursera",
    "udemy",
    "edx",
    "khan academy",
    "anki",
    "duolingo",
    "wikipedia",
    "explainer",
    "netzwerk",
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
    "witchsky",
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

pub fn classify_activity(app_name: &str, window_title: &str) -> &'static str {
    let app = app_name.to_lowercase();
    let title = window_title.to_lowercase();

    if COMM_APPS.iter().any(|k| app.contains(k))
        || title.contains("gmail")
        || title.contains("proton mail")
        || title.contains("meet.google")
    {
        return "Communication";
    }

    if DEV_APPS.iter().any(|k| app.contains(k))
        || DEV_TITLE_KEYWORDS.iter().any(|k| title.contains(k))
    {
        return "Development";
    }

    if app.contains("okular")
        || app.contains("zotero")
        || LEARNING_KEYWORDS.iter().any(|k| title.contains(k))
    {
        return "Learning";
    }

    if SOCIAL_KEYWORDS.iter().any(|k| title.contains(k) || app.contains(k)) {
        return "Social";
    }

    if MEDIA_APPS_OR_KEYWORDS
        .iter()
        .any(|k| app.contains(k) || title.contains(k))
    {
        return "Media & Entertainment";
    }

    if SYSTEM_APPS.iter().any(|k| app.contains(k)) {
        return "System & Files";
    }

    if BROWSER_APPS.iter().any(|k| app.contains(k)) {
        return "Web Browsing";
    }

    "Other"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn categorizes_apps_and_browser_titles() {
        assert_eq!(
            classify_activity("dev.zed.Zed", "hw03 — variant.hpp"),
            "Development"
        );
        assert_eq!(
            classify_activity("org.mozilla.firefox", "Jacobs Netzwerk A2.2 - Memrise — Mozilla Firefox"),
            "Learning"
        );
        assert_eq!(
            classify_activity("org.mozilla.firefox", "Discover — Witchsky — Mozilla Firefox"),
            "Social"
        );
        assert_eq!(
            classify_activity("com.discordapp.Discord", "#general - Discord"),
            "Communication"
        );
        assert_eq!(
            classify_activity("org.kde.dolphin", "Home — Dolphin"),
            "System & Files"
        );
    }
}
