//! Strict /proc/<pid>/fd fallback scanner that ignores app internals and compiler/runtime noise.

use std::collections::{HashSet, VecDeque};
use std::fs;
use std::path::Path;

const IGNORED_PREFIXES: &[&str] = &[
    "/proc/",
    "/sys/",
    "/dev/",
    "/usr/",
    "/lib/",
    "/lib64/",
    "/etc/",
    "/var/cache/",
    "/var/log/",
    "/var/lib/",
    "/run/",
    "/boot/",
    "/tmp/",
];

const IGNORED_SUBSTRINGS: &[&str] = &[
    "/.cache/",
    "/.config/",
    "/.local/share/",
    "/.var/app/",
    "/.pki/",
    "/.mozilla/",
    "/.gemini/",
    "/Antigravity-x64",
    "/Cache/",
    "/Code Cache/",
    "/GPUCache/",
    "/DawnCache/",
    "/DawnGraphiteCache/",
    "/DawnWebGPUCache/",
    "/Service Worker/",
    "/IndexedDB/",
    "/Local Storage/",
    "/Session Storage/",
    "/Shared Dictionary/",
    "/WebStorage/",
    "/blob_storage/",
    "/ShaderCache/",
    "/Crash Reports/",
    "/shared_proto_db/",
    "/target/debug/",
    "/target/release/",
    "/node_modules/",
    "/.git/",
    "/CMakeFiles/",
];

const IGNORED_BASENAMES: &[&str] = &[
    "Cookies",
    "DIPS",
    "Trust Tokens",
    "QuotaManager",
    "QuotaManager-journal",
    "LOCK",
    "LOG",
    "v8_context_snapshot.bin",
    "icudtl.dat",
];

const IGNORED_EXTENSIONS: &[&str] = &[
    ".so",
    ".pak",
    ".asar",
    ".ttf",
    ".otf",
    ".woff",
    ".woff2",
    ".ttc",
    ".lock",
    ".pid",
    ".shm",
    ".wal",
    "-wal",
    "-shm",
    ".idx",
    ".vscdb",
    ".ldb",
    ".log",
    ".sqlite",
    ".sqlite3",
    ".db",
    ".mdb",
    ".sql",
    ".xpi",
    ".parentlock",
    ".bin",
    ".dat",
    ".bdic",
    ".par",
    ".o",
    ".a",
    ".d",
    ".pch",
    ".pcm",
];

pub fn is_relevant_file(path: &str) -> bool {
    if !path.starts_with('/') || path.ends_with(" (deleted)") {
        return false;
    }
    if IGNORED_PREFIXES.iter().any(|p| path.starts_with(p)) {
        return false;
    }
    if IGNORED_SUBSTRINGS.iter().any(|s| path.contains(s)) {
        return false;
    }
    if let Some(base) = Path::new(path).file_name().and_then(|s| s.to_str()) {
        if IGNORED_BASENAMES.contains(&base) || base.starts_with("MANIFEST-") {
            return false;
        }
        let lower_base = base.to_lowercase();
        if lower_base.contains(".so.") || lower_base.contains(".log.") {
            return false;
        }
    }
    let lower = path.to_lowercase();
    if IGNORED_EXTENSIONS.iter().any(|ext| lower.ends_with(ext)) {
        return false;
    }
    true
}

fn collect_descendant_pids(root_pid: i64, max_pids: usize) -> Vec<i64> {
    if root_pid <= 0 {
        return Vec::new();
    }
    let mut seen = HashSet::new();
    let mut queue = VecDeque::from([root_pid]);
    let mut result = Vec::new();

    while let Some(pid) = queue.pop_front() {
        if result.len() >= max_pids {
            break;
        }
        if !seen.insert(pid) {
            continue;
        }
        let task_dir = format!("/proc/{pid}/task");
        let Ok(tasks) = fs::read_dir(&task_dir) else {
            continue;
        };
        result.push(pid);

        for tid_entry in tasks.flatten() {
            let children_path = tid_entry.path().join("children");
            if let Ok(raw) = fs::read_to_string(children_path) {
                for token in raw.split_whitespace() {
                    if let Ok(child_pid) = token.parse::<i64>() {
                        if !seen.contains(&child_pid) {
                            queue.push_back(child_pid);
                        }
                    }
                }
            }
        }
    }

    result
}

pub fn scan_open_files(root_pid: i64) -> Vec<String> {
    let pids = collect_descendant_pids(root_pid, 64);
    let mut found = HashSet::new();

    for pid in pids {
        let fd_dir = format!("/proc/{pid}/fd");
        let Ok(entries) = fs::read_dir(&fd_dir) else {
            continue;
        };
        for entry in entries.flatten() {
            if let Ok(target) = fs::read_link(entry.path()) {
                if let Some(s) = target.to_str() {
                    if is_relevant_file(s) && Path::new(s).is_file() {
                        found.insert(s.to_string());
                    }
                }
            }
        }
    }

    let mut out: Vec<String> = found.into_iter().collect();
    out.sort();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filters_app_internals_and_keeps_user_files() {
        assert!(is_relevant_file("/var/home/silver/repos/hw03/variant.hpp"));
        assert!(is_relevant_file("/var/home/silver/Documents/report.pdf"));

        assert!(!is_relevant_file("pipe:[1234]"));
        assert!(!is_relevant_file("/usr/lib64/libc.so.6"));
        assert!(!is_relevant_file("/var/home/silver/.config/Antigravity/Cookies"));
        assert!(!is_relevant_file("/var/home/silver/.local/share/zed/threads/threads.db"));
        assert!(!is_relevant_file("/var/home/silver/.var/app/com.discordapp.Discord/config/discord/MANIFEST-000001"));
        assert!(!is_relevant_file("/tmp/agy_acp_server.par.fedora-yoga.silver.log.INFO.123"));
    }
}
