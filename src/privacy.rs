//! Runtime-configurable privacy, filtering, and redaction pipeline.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use crate::categorizer::classify_activity;

/// Default sensitive domains that are ignored/redacted unless overridden via `allow_domains`.
pub const DEFAULT_SENSITIVE_DOMAINS: &[&str] = &[
    // Password managers & secrets
    "bitwarden.com",
    "bitwarden.eu",
    "vault.bitwarden.com",
    "1password.com",
    "1password.eu",
    "1password.ca",
    "lastpass.com",
    "dashlane.com",
    "keepersecurity.com",
    "nordpass.com",
    "roboform.com",
    "enpass.io",
    "pass.proton.me",
    "keepass.info",
    "keepassxc.org",
    // Identity, SSO, 2FA & auth
    "accounts.google.com",
    "myaccount.google.com",
    "login.microsoftonline.com",
    "login.live.com",
    "account.microsoft.com",
    "appleid.apple.com",
    "id.apple.com",
    "auth0.com",
    "okta.com",
    "duosecurity.com",
    "login.yahoo.com",
    "login.salesforce.com",
    "signin.aws.amazon.com",
    "auth.mozilla.com",
    // Banking, payments, tax & investments
    "paypal.com",
    "stripe.com",
    "dashboard.stripe.com",
    "chase.com",
    "bankofamerica.com",
    "wellsfargo.com",
    "citibank.com",
    "citi.com",
    "capitalone.com",
    "americanexpress.com",
    "discover.com",
    "usbank.com",
    "pnc.com",
    "td.com",
    "tdbank.com",
    "hsbc.com",
    "barclays.co.uk",
    "lloydsbank.com",
    "natwest.com",
    "santander.com",
    "santander.co.uk",
    "n26.com",
    "monzo.com",
    "starlingbank.com",
    "wise.com",
    "revolut.com",
    "venmo.com",
    "cash.app",
    "zellepay.com",
    "klarna.com",
    "affirm.com",
    "robinhood.com",
    "schwab.com",
    "fidelity.com",
    "vanguard.com",
    "etrade.com",
    "interactivebrokers.com",
    "mint.intuit.com",
    "turbotax.intuit.com",
    "creditkarma.com",
    "experian.com",
    "equifax.com",
    "transunion.com",
    "irs.gov",
    "ssa.gov",
    // Cryptocurrency & wallets
    "coinbase.com",
    "binance.com",
    "binance.us",
    "kraken.com",
    "gemini.com",
    "crypto.com",
    "kucoin.com",
    "okx.com",
    "bybit.com",
    "blockchain.com",
    "metamask.io",
    "ledger.com",
    "trezor.io",
    "phantom.app",
    // Healthcare, insurance & medical portals
    "mychart.com",
    "myuhc.com",
    "aetna.com",
    "cigna.com",
    "anthem.com",
    "bcbs.com",
    "kaiserpermanente.org",
    "humana.com",
    "goodrx.com",
    "teladoc.com",
    "zocdoc.com",
    "betterhelp.com",
    "talkspace.com",
    "healthcare.gov",
    // Government, HR, payroll & legal signing
    "login.gov",
    "uscis.gov",
    "elster.de",
    "docusign.com",
    "docusign.net",
    "hellosign.com",
    "adp.com",
    "workday.com",
    "gusto.com",
    "rippling.com",
    // Private email & encrypted messaging web
    "mail.proton.me",
    "proton.me",
    "protonmail.com",
    "tutanota.com",
    "tuta.com",
    "app.tuta.com",
    "fastmail.com",
    "mailbox.org",
    "posteo.de",
    "startmail.com",
    "web.whatsapp.com",
    "web.telegram.org",
    "app.element.io",
    "mail.google.com",
    "outlook.live.com",
    "outlook.office.com",
    // Dating & adult
    "onlyfans.com",
    "pornhub.com",
    "xvideos.com",
    "xnxx.com",
    "xhamster.com",
    "chaturbate.com",
    "fetlife.com",
    "tinder.com",
    "bumble.com",
    "hinge.co",
    "grindr.com",
];

/// Default sensitive desktop applications (password/secret managers, keyrings).
pub const DEFAULT_SENSITIVE_APPS: &[&str] = &[
    "bitwarden",
    "1password",
    "keepassxc",
    "keepass",
    "lastpass",
    "dashlane",
    "enpass",
    "nordpass",
    "protonpass",
    "kwalletmanager",
    "org.gnome.seahorse",
    "gnome-keyring",
];

/// Default sensitive substring/prefix keywords for portals without fixed domains.
pub const DEFAULT_SENSITIVE_KEYWORDS: &[&str] = &[
    "mychart.",
    "patientportal",
    "bluecross",
    "vaultwarden",
    "gov.uk/sign-in",
    "santander",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Sink {
    Storage,
    Ui,
    Remote,
    Llm,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SensitiveDomainAction {
    /// Drop the session/site/title completely.
    Ignore,
    /// Keep app & time/category, but strip URL/domain and redact window title.
    Redact,
}

impl Default for SensitiveDomainAction {
    fn default() -> Self {
        Self::Ignore
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleAction {
    Ignore,
    Redact,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SinkPolicy {
    pub enabled: bool,
    pub include_app: bool,
    pub include_title: bool,
    pub include_files: bool,
    pub include_sites: bool,
    pub include_category: bool,
    pub redact_text: String,
}

impl Default for SinkPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            include_app: true,
            include_title: true,
            include_files: true,
            include_sites: true,
            include_category: true,
            redact_text: "[redacted]".to_string(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SinkPolicyOverride {
    pub enabled: Option<bool>,
    pub include_app: Option<bool>,
    pub include_title: Option<bool>,
    pub include_files: Option<bool>,
    pub include_sites: Option<bool>,
    pub include_category: Option<bool>,
}

impl SinkPolicy {
    pub fn apply_override(&self, ov: &SinkPolicyOverride) -> Self {
        Self {
            enabled: ov.enabled.unwrap_or(self.enabled),
            include_app: ov.include_app.unwrap_or(self.include_app),
            include_title: ov.include_title.unwrap_or(self.include_title),
            include_files: ov.include_files.unwrap_or(self.include_files),
            include_sites: ov.include_sites.unwrap_or(self.include_sites),
            include_category: ov.include_category.unwrap_or(self.include_category),
            redact_text: self.redact_text.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PrivacyRule {
    /// Optional human-readable name.
    pub name: Option<String>,
    /// Match substring (case-insensitive) against app_name.
    pub app: Option<String>,
    /// Match substring (case-insensitive) against window_title.
    pub title: Option<String>,
    /// Match substring (case-insensitive) against domain/url.
    pub domain: Option<String>,
    /// Match exact category (case-insensitive), e.g. "Communication".
    pub category: Option<String>,
    /// Action when matched (if `sinks` is empty, applies to all sinks).
    pub action: RuleAction,
    /// Optional per-sink overrides when this rule matches.
    pub sinks: HashMap<Sink, SinkPolicyOverride>,
}

impl Default for PrivacyRule {
    fn default() -> Self {
        Self {
            name: None,
            app: None,
            title: None,
            domain: None,
            category: None,
            action: RuleAction::Redact,
            sinks: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SinksConfig {
    pub storage: SinkPolicy,
    pub ui: SinkPolicy,
    pub remote: SinkPolicy,
    pub llm: SinkPolicy,
}

impl Default for SinksConfig {
    fn default() -> Self {
        Self {
            storage: SinkPolicy::default(),
            ui: SinkPolicy::default(),
            remote: SinkPolicy::default(),
            llm: SinkPolicy::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DiscordRpcConfig {
    /// Disabled by default.
    pub enabled: bool,
    /// Discord Application Client ID (required when enabled).
    pub client_id: String,
    /// When true (default), anything not in `allowed_apps` or `allowed_categories` is hidden.
    pub hide_by_default: bool,
    /// Whitelist of app_name substrings (case-insensitive).
    pub allowed_apps: Vec<String>,
    /// Whitelist of category names (case-insensitive).
    pub allowed_categories: Vec<String>,
    /// Show window title for whitelisted apps (false by default for privacy).
    pub show_title: bool,
    /// Show category for whitelisted apps.
    pub show_category: bool,
    /// Show elapsed timer on Discord Rich Presence.
    pub show_elapsed: bool,
}

impl Default for DiscordRpcConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            client_id: String::new(),
            hide_by_default: true,
            allowed_apps: Vec::new(),
            allowed_categories: Vec::new(),
            show_title: false,
            show_category: true,
            show_elapsed: true,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct PluginsConfig {
    pub discord_rpc: DiscordRpcConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PrivacyConfig {
    pub use_default_sensitive_domains: bool,
    pub use_default_sensitive_apps: bool,
    pub use_default_sensitive_keywords: bool,
    pub auto_load_lists_dir: bool,
    pub sensitive_domains: Vec<String>,
    pub sensitive_domain_files: Vec<String>,
    pub allow_domains: Vec<String>,
    pub sensitive_keywords: Vec<String>,
    pub allow_keywords: Vec<String>,
    pub sensitive_apps: Vec<String>,
    pub allow_apps: Vec<String>,
    pub sensitive_domain_action: SensitiveDomainAction,
    pub sinks: SinksConfig,
    pub rules: Vec<PrivacyRule>,
    pub plugins: PluginsConfig,
}

impl Default for PrivacyConfig {
    fn default() -> Self {
        Self {
            use_default_sensitive_domains: true,
            use_default_sensitive_apps: true,
            use_default_sensitive_keywords: true,
            auto_load_lists_dir: true,
            sensitive_domains: Vec::new(),
            sensitive_domain_files: Vec::new(),
            allow_domains: Vec::new(),
            sensitive_keywords: Vec::new(),
            allow_keywords: Vec::new(),
            sensitive_apps: Vec::new(),
            allow_apps: Vec::new(),
            sensitive_domain_action: SensitiveDomainAction::Ignore,
            sinks: SinksConfig::default(),
            rules: Vec::new(),
            plugins: PluginsConfig::default(),
        }
    }
}

impl PrivacyConfig {
    /// Fail-closed fallback used if an existing privacy.json is unreadable or invalid on first load.
    pub fn restricted_fallback() -> Self {
        let mut cfg = Self::default();
        cfg.sinks.remote.enabled = false;
        cfg.sinks.llm.enabled = false;
        for sink in [&mut cfg.sinks.storage, &mut cfg.sinks.ui] {
            sink.include_title = false;
            sink.include_files = false;
            sink.include_sites = false;
        }
        cfg
    }
}

pub fn default_privacy_config_path() -> PathBuf {
    if let Ok(env_path) = std::env::var("ACTIVITY_TRACKER_PRIVACY_CONFIG") {
        if !env_path.trim().is_empty() {
            return PathBuf::from(env_path);
        }
    }
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        if !xdg.trim().is_empty() {
            return PathBuf::from(xdg).join("activity-tracker/privacy.json");
        }
    }
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    home.join(".config/activity-tracker/privacy.json")
}

#[derive(Debug, Clone)]
pub struct EffectiveDecision {
    pub allow: bool,
    pub app_name: String,
    pub window_title: String,
    pub category: String,
    pub allow_files: bool,
    pub allow_sites: bool,
}

pub fn default_lists_dir(config_path: &Path) -> PathBuf {
    config_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("lists")
}

pub fn normalize_domain_entry(raw: &str) -> Option<String> {
    let mut s = raw.trim().to_lowercase();
    if s.is_empty() {
        return None;
    }
    if let Some(rest) = s.strip_prefix("https://") {
        s = rest.to_string();
    } else if let Some(rest) = s.strip_prefix("http://") {
        s = rest.to_string();
    }
    if let Some(rest) = s.strip_prefix("||") {
        s = rest.split('^').next().unwrap_or("").to_string();
    }
    s = s
        .split('/')
        .next()
        .unwrap_or("")
        .split('?')
        .next()
        .unwrap_or("")
        .split('#')
        .next()
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("")
        .trim_start_matches("*.")
        .trim_matches('.')
        .to_string();

    if s.contains('.')
        && !s.contains(' ')
        && s != "localhost"
        && s != "localhost.localdomain"
    {
        Some(s)
    } else {
        None
    }
}

/// Parses premade domain lists in any of:
/// - MISP warninglist JSON (`{"list": ["example.com", ...]}`)
/// - JSON string array (`["example.com", ...]`)
/// - Hosts format (`0.0.0.0 example.com`, `127.0.0.1 example.com`)
/// - Adblock format (`||example.com^`)
/// - Plain one-domain-per-line text (`example.com`), ignoring `#` and `!` comments
pub fn parse_domain_list_content(content: &str) -> Vec<String> {
    let trimmed = content.trim();
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(trimmed) {
            let arr = val
                .as_array()
                .or_else(|| val.get("list").and_then(|v| v.as_array()));
            if let Some(items) = arr {
                return items
                    .iter()
                    .filter_map(|v| v.as_str())
                    .filter_map(normalize_domain_entry)
                    .collect();
            }
        }
    }

    let mut out = Vec::new();
    for raw_line in content.lines() {
        let line = raw_line.split('#').next().unwrap_or("").trim();
        if line.is_empty() || line.starts_with('!') || line.starts_with("//") {
            continue;
        }
        let candidate = if line.starts_with("||") {
            line
        } else {
            let mut parts = line.split_whitespace();
            let first = parts.next().unwrap_or("");
            if first == "0.0.0.0" || first == "127.0.0.1" || first == "::1" || first == "::" {
                parts.next().unwrap_or("")
            } else {
                first
            }
        };
        if let Some(clean) = normalize_domain_entry(candidate) {
            out.push(clean);
        }
    }
    out
}

fn extract_candidate_hosts(haystack: &str) -> Vec<String> {
    let lower = haystack.to_lowercase();
    let mut hosts = Vec::new();
    for token in lower.split(|c: char| !c.is_alphanumeric() && c != '.' && c != '-') {
        let clean = token.trim_matches(|c: char| c == '.' || c == '-');
        if clean.contains('.') && !clean.starts_with('.') && !clean.ends_with('.') {
            hosts.push(clean.to_string());
        }
    }
    hosts
}

fn longest_matching_domain_len(host: &str, set: &HashSet<String>) -> Option<usize> {
    let mut s = host.trim_matches('.');
    while !s.is_empty() {
        if set.contains(s) {
            return Some(s.len());
        }
        match s.find('.') {
            Some(idx) => s = &s[idx + 1..],
            None => break,
        }
    }
    None
}

fn host_matches_set(host: &str, set: &HashSet<String>) -> bool {
    longest_matching_domain_len(host, set).is_some()
}

fn app_matches_pattern(app_lower: &str, pat_lower: &str) -> bool {
    let pat = pat_lower.trim();
    if pat.is_empty() {
        return false;
    }
    if app_lower == pat {
        return true;
    }
    if pat.contains('.') || pat.contains('-') {
        // Bounded match for multi-segment IDs like "org.gnome.seahorse" or "gnome-keyring"
        let bytes = app_lower.as_bytes();
        let mut start = 0;
        while let Some(idx) = app_lower[start..].find(pat) {
            let pos = start + idx;
            let end = pos + pat.len();
            let left_ok = pos == 0 || !bytes[pos - 1].is_ascii_alphanumeric();
            let right_ok = end == bytes.len() || !bytes[end].is_ascii_alphanumeric();
            if left_ok && right_ok {
                return true;
            }
            start = pos + 1;
        }
        return false;
    }
    app_lower
        .split(|c: char| !c.is_alphanumeric())
        .any(|tok| tok == pat)
}

pub struct PrivacyEngine {
    path: PathBuf,
    config: PrivacyConfig,
    last_mtime: Option<SystemTime>,
    loaded_domains: HashSet<String>,
    sensitive_set: HashSet<String>,
    allow_set: HashSet<String>,
    keyword_set: Vec<String>,
    allow_keywords: Vec<String>,
    list_mtimes: HashMap<PathBuf, Option<SystemTime>>,
    last_list_check: Option<std::time::Instant>,
    list_check_interval: std::time::Duration,
}

impl PrivacyEngine {
    pub fn load(override_path: Option<&Path>) -> Self {
        let path = override_path
            .map(Path::to_path_buf)
            .unwrap_or_else(default_privacy_config_path);
        let mut engine = Self {
            path,
            config: PrivacyConfig::default(),
            last_mtime: None,
            loaded_domains: HashSet::new(),
            sensitive_set: HashSet::new(),
            allow_set: HashSet::new(),
            keyword_set: Vec::new(),
            allow_keywords: Vec::new(),
            list_mtimes: HashMap::new(),
            last_list_check: None,
            list_check_interval: std::time::Duration::from_secs(2),
        };
        if engine.path.exists() {
            match std::fs::read_to_string(&engine.path) {
                Ok(text) => match serde_json::from_str::<PrivacyConfig>(&text) {
                    Ok(cfg) => {
                        engine.config = cfg;
                        engine.last_mtime = std::fs::metadata(&engine.path)
                            .ok()
                            .and_then(|m| m.modified().ok());
                    }
                    Err(e) => {
                        eprintln!(
                            "[privacy] Failed to parse {}: {e} (using restricted fallback)",
                            engine.path.display()
                        );
                        engine.config = PrivacyConfig::restricted_fallback();
                        engine.last_mtime = std::fs::metadata(&engine.path)
                            .ok()
                            .and_then(|m| m.modified().ok());
                    }
                },
                Err(e) => {
                    eprintln!(
                        "[privacy] Failed to read {}: {e} (using restricted fallback)",
                        engine.path.display()
                    );
                    engine.config = PrivacyConfig::restricted_fallback();
                }
            }
        }
        engine.reload_domain_lists();
        engine
    }

    pub fn from_config(config: PrivacyConfig) -> Self {
        let mut engine = Self {
            path: default_privacy_config_path(),
            config,
            last_mtime: None,
            loaded_domains: HashSet::new(),
            sensitive_set: HashSet::new(),
            allow_set: HashSet::new(),
            keyword_set: Vec::new(),
            allow_keywords: Vec::new(),
            list_mtimes: HashMap::new(),
            last_list_check: None,
            list_check_interval: std::time::Duration::from_secs(2),
        };
        engine.reload_domain_lists();
        engine
    }

    #[cfg(test)]
    pub(crate) fn set_list_check_interval(&mut self, interval: std::time::Duration) {
        self.list_check_interval = interval;
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn config(&self) -> &PrivacyConfig {
        &self.config
    }

    pub fn loaded_domain_count(&self) -> usize {
        self.loaded_domains.len()
    }

    fn expand_tilde(raw: &str) -> PathBuf {
        if let Some(rest) = raw.strip_prefix("~/") {
            if let Some(home) = std::env::var_os("HOME") {
                return PathBuf::from(home).join(rest);
            }
        }
        PathBuf::from(raw)
    }

    fn collect_list_paths(&self) -> Vec<PathBuf> {
        let mut paths: Vec<PathBuf> = self
            .config
            .sensitive_domain_files
            .iter()
            .filter(|s| !s.trim().is_empty())
            .map(|s| Self::expand_tilde(s.trim()))
            .collect();

        if self.config.auto_load_lists_dir {
            let lists_dir = default_lists_dir(&self.path);
            if let Ok(entries) = std::fs::read_dir(&lists_dir) {
                for entry in entries.flatten() {
                    let p = entry.path();
                    if p.is_file() {
                        paths.push(p);
                    }
                }
            }
        }
        paths.sort();
        paths.dedup();
        paths
    }

    pub fn reload_domain_lists(&mut self) {
        self.loaded_domains.clear();
        self.sensitive_set.clear();
        self.allow_set.clear();
        self.keyword_set.clear();
        self.allow_keywords.clear();
        self.list_mtimes.clear();

        let paths = self.collect_list_paths();
        for p in paths {
            let mtime = std::fs::metadata(&p).ok().and_then(|m| m.modified().ok());
            self.list_mtimes.insert(p.clone(), mtime);
            if let Ok(content) = std::fs::read_to_string(&p) {
                for dom in parse_domain_list_content(&content) {
                    self.loaded_domains.insert(dom);
                }
            }
        }

        if self.config.use_default_sensitive_domains {
            for d in DEFAULT_SENSITIVE_DOMAINS {
                if let Some(norm) = normalize_domain_entry(d) {
                    self.sensitive_set.insert(norm);
                }
            }
        }
        for d in &self.config.sensitive_domains {
            if let Some(norm) = normalize_domain_entry(d) {
                self.sensitive_set.insert(norm);
            } else {
                let kw = d.trim().to_lowercase();
                if !kw.is_empty() {
                    eprintln!(
                        "[privacy] sensitive_domains entry {:?} is not a domain; treating as sensitive_keywords substring",
                        d
                    );
                    self.keyword_set.push(kw);
                }
            }
        }
        for d in &self.loaded_domains {
            self.sensitive_set.insert(d.clone());
        }
        for d in &self.config.allow_domains {
            if let Some(norm) = normalize_domain_entry(d) {
                self.allow_set.insert(norm);
            } else if !d.trim().is_empty() {
                eprintln!(
                    "[privacy] Ignoring invalid allow_domains entry {:?} (use allow_keywords for non-domain patterns)",
                    d
                );
            }
        }

        if self.config.use_default_sensitive_keywords {
            for kw in DEFAULT_SENSITIVE_KEYWORDS {
                self.keyword_set.push((*kw).to_string());
            }
        }
        for kw in &self.config.sensitive_keywords {
            let clean = kw.trim().to_lowercase();
            if !clean.is_empty() {
                self.keyword_set.push(clean);
            }
        }
        for kw in &self.config.allow_keywords {
            let clean = kw.trim().to_lowercase();
            if !clean.is_empty() {
                self.allow_keywords.push(clean);
            }
        }
        self.last_list_check = Some(std::time::Instant::now());
    }

    fn list_files_changed(&self) -> bool {
        let current_paths = self.collect_list_paths();
        if current_paths.len() != self.list_mtimes.len() {
            return true;
        }
        for p in &current_paths {
            let mtime = std::fs::metadata(p).ok().and_then(|m| m.modified().ok());
            match self.list_mtimes.get(p) {
                Some(prev) if *prev == mtime => {}
                _ => return true,
            }
        }
        false
    }

    /// Hot-reloads the privacy config or external domain lists if modified on disk.
    /// Keeps the last good config on transient file deletion or parse errors.
    pub fn reload_if_changed(&mut self) -> bool {
        let mut reloaded = false;
        if let Ok(meta) = std::fs::metadata(&self.path) {
            if let Ok(mtime) = meta.modified() {
                if self.last_mtime != Some(mtime) {
                    if let Ok(text) = std::fs::read_to_string(&self.path) {
                        match serde_json::from_str::<PrivacyConfig>(&text) {
                            Ok(cfg) => {
                                self.config = cfg;
                                self.last_mtime = Some(mtime);
                                self.reload_domain_lists();
                                reloaded = true;
                            }
                            Err(e) => {
                                eprintln!(
                                    "[privacy] Failed to parse {}: {e} (keeping previous config)",
                                    self.path.display()
                                );
                                self.last_mtime = Some(mtime);
                            }
                        }
                    }
                }
            }
        }
        let should_check_lists = match self.last_list_check {
            Some(prev) => prev.elapsed() >= self.list_check_interval,
            None => true,
        };
        if !reloaded && should_check_lists {
            if self.list_files_changed() {
                self.reload_domain_lists();
                reloaded = true;
            } else {
                self.last_list_check = Some(std::time::Instant::now());
            }
        }
        reloaded
    }

    pub fn sink_policy(&self, sink: Sink) -> &SinkPolicy {
        match sink {
            Sink::Storage => &self.config.sinks.storage,
            Sink::Ui => &self.config.sinks.ui,
            Sink::Remote => &self.config.sinks.remote,
            Sink::Llm => &self.config.sinks.llm,
        }
    }

    pub fn is_sensitive_app(&self, app_name: &str) -> bool {
        let lower = app_name.trim().to_lowercase();
        if lower.is_empty() {
            return false;
        }
        if self
            .config
            .allow_apps
            .iter()
            .any(|a| app_matches_pattern(&lower, &a.to_lowercase()))
        {
            return false;
        }
        if self.config.use_default_sensitive_apps
            && DEFAULT_SENSITIVE_APPS
                .iter()
                .any(|a| app_matches_pattern(&lower, a))
        {
            return true;
        }
        self.config
            .sensitive_apps
            .iter()
            .any(|a| app_matches_pattern(&lower, &a.to_lowercase()))
    }

    pub fn is_sensitive_domain(&self, haystack: &str) -> bool {
        if haystack.trim().is_empty() {
            return false;
        }
        for host in extract_candidate_hosts(haystack) {
            if let Some(sens_len) = longest_matching_domain_len(&host, &self.sensitive_set) {
                let allow_len = longest_matching_domain_len(&host, &self.allow_set);
                // Most specific match wins: allow only overrides if it is at least as specific.
                if !matches!(allow_len, Some(a) if a >= sens_len) {
                    return true;
                }
            }
        }
        false
    }

    pub fn is_sensitive_keyword(&self, haystack: &str) -> bool {
        let lower = haystack.trim().to_lowercase();
        if lower.is_empty() {
            return false;
        }
        if self.allow_keywords.iter().any(|k| lower.contains(k.as_str())) {
            return false;
        }
        self.keyword_set.iter().any(|k| lower.contains(k.as_str()))
    }

    fn rule_matches(
        rule: &PrivacyRule,
        app_name: &str,
        window_title: &str,
        domain: &str,
        category: &str,
    ) -> bool {
        let app_l = app_name.to_lowercase();
        let title_l = window_title.to_lowercase();
        let dom_l = domain.to_lowercase();
        let cat_l = category.to_lowercase();

        let has_any = rule.app.is_some()
            || rule.title.is_some()
            || rule.domain.is_some()
            || rule.category.is_some();
        if !has_any {
            return false;
        }

        if let Some(ref pat) = rule.app {
            if !app_l.contains(&pat.to_lowercase()) {
                return false;
            }
        }
        if let Some(ref pat) = rule.title {
            if !title_l.contains(&pat.to_lowercase()) {
                return false;
            }
        }
        if let Some(ref pat) = rule.domain {
            if let Some(norm) = normalize_domain_entry(pat) {
                let mut set = HashSet::new();
                set.insert(norm);
                let matched_dom = extract_candidate_hosts(domain)
                    .iter()
                    .any(|h| host_matches_set(h, &set));
                let matched_title = extract_candidate_hosts(window_title)
                    .iter()
                    .any(|h| host_matches_set(h, &set));
                if !matched_dom && !matched_title {
                    return false;
                }
            } else {
                let pat_l = pat.trim().to_lowercase();
                if pat_l.is_empty() || (!dom_l.contains(&pat_l) && !title_l.contains(&pat_l)) {
                    return false;
                }
            }
        }
        if let Some(ref pat) = rule.category {
            if cat_l != pat.to_lowercase() {
                return false;
            }
        }
        true
    }

    pub fn evaluate_activity(
        &self,
        sink: Sink,
        app_name: &str,
        window_title: &str,
        domain: &str,
    ) -> EffectiveDecision {
        let raw_category = classify_activity(app_name, window_title).to_string();
        let mut policy = self.sink_policy(sink).clone();

        if !policy.enabled {
            return EffectiveDecision {
                allow: false,
                app_name: String::new(),
                window_title: String::new(),
                category: String::new(),
                allow_files: false,
                allow_sites: false,
            };
        }

        // Apply matching custom rules in order
        for rule in &self.config.rules {
            if Self::rule_matches(rule, app_name, window_title, domain, &raw_category) {
                if let Some(ov) = rule.sinks.get(&sink) {
                    policy = policy.apply_override(ov);
                    if !policy.enabled {
                        return EffectiveDecision {
                            allow: false,
                            app_name: String::new(),
                            window_title: String::new(),
                            category: String::new(),
                            allow_files: false,
                            allow_sites: false,
                        };
                    }
                } else if rule.sinks.is_empty() {
                    match rule.action {
                        RuleAction::Ignore => {
                            return EffectiveDecision {
                                allow: false,
                                app_name: String::new(),
                                window_title: String::new(),
                                category: String::new(),
                                allow_files: false,
                                allow_sites: false,
                            };
                        }
                        RuleAction::Redact => {
                            policy.include_title = false;
                            policy.include_files = false;
                            policy.include_sites = false;
                        }
                    }
                }
            }
        }

        // Sensitive app, domain & keyword handling applied LAST (non-overridable by custom rules)
        if self.is_sensitive_app(app_name)
            || self.is_sensitive_domain(domain)
            || self.is_sensitive_domain(window_title)
            || self.is_sensitive_keyword(domain)
            || self.is_sensitive_keyword(window_title)
        {
            match self.config.sensitive_domain_action {
                SensitiveDomainAction::Ignore => {
                    return EffectiveDecision {
                        allow: false,
                        app_name: String::new(),
                        window_title: String::new(),
                        category: String::new(),
                        allow_files: false,
                        allow_sites: false,
                    };
                }
                SensitiveDomainAction::Redact => {
                    policy.include_title = false;
                    policy.include_files = false;
                    policy.include_sites = false;
                }
            }
        }

        let out_app = if policy.include_app {
            app_name.to_string()
        } else {
            policy.redact_text.clone()
        };
        let out_title = if policy.include_title {
            window_title.to_string()
        } else {
            policy.redact_text.clone()
        };
        let out_cat = if policy.include_category {
            raw_category
        } else {
            policy.redact_text
        };

        EffectiveDecision {
            allow: true,
            app_name: out_app,
            window_title: out_title,
            category: out_cat,
            allow_files: policy.include_files,
            allow_sites: policy.include_sites,
        }
    }

    pub fn allow_file(&self, sink: Sink, app_name: &str, file_path: &str) -> bool {
        let policy = self.sink_policy(sink);
        if !policy.enabled || !policy.include_files {
            return false;
        }
        let decision = self.evaluate_activity(sink, app_name, file_path, "");
        decision.allow && decision.allow_files
    }

    pub fn allow_site(&self, sink: Sink, app_name: &str, domain: &str, page_title: &str) -> bool {
        let policy = self.sink_policy(sink);
        if !policy.enabled || !policy.include_sites {
            return false;
        }
        let decision = self.evaluate_activity(sink, app_name, page_title, domain);
        decision.allow && decision.allow_sites
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_sensitive_domains_and_overrides() {
        let mut cfg = PrivacyConfig::default();
        cfg.auto_load_lists_dir = false;
        cfg.allow_domains = vec!["accounts.google.com".to_string()];
        let engine = PrivacyEngine::from_config(cfg);

        assert!(engine.is_sensitive_domain("vault.bitwarden.com"));
        assert!(engine.is_sensitive_domain("paypal.com - Checkout — Mozilla Firefox"));
        assert!(!engine.is_sensitive_domain("accounts.google.com"));
        assert!(!engine.is_sensitive_domain("docs.rs"));
    }

    #[test]
    fn label_boundary_matching_and_allow_list_fail_closed() {
        let mut cfg = PrivacyConfig::default();
        cfg.auto_load_lists_dir = false;
        cfg.allow_domains = vec!["x.com".to_string(), "github.com".to_string()];
        let engine = PrivacyEngine::from_config(cfg);

        // Allowing x.com must NOT allow okx.com
        assert!(engine.is_sensitive_domain("okx.com"));
        assert!(!engine.is_sensitive_domain("x.com"));

        // Blocking wise.com / td.com must NOT over-match likewise.com / ltd.com
        assert!(!engine.is_sensitive_domain("likewise.com"));
        assert!(!engine.is_sensitive_domain("acme-ltd.com"));
        assert!(engine.is_sensitive_domain("wise.com"));
        assert!(engine.is_sensitive_domain("td.com"));

        // Mixed allowed + sensitive domain in the same title must still be flagged sensitive
        assert!(engine.is_sensitive_domain("github.com - oauth callback to paypal.com"));

        // Punctuation/query boundaries like u=paypal.com must be extracted
        assert!(engine.is_sensitive_domain("https://example.org/redirect?u=paypal.com"));
    }

    #[test]
    fn sensitive_app_name_checked_and_allow_apps_override() {
        let mut cfg = PrivacyConfig::default();
        cfg.auto_load_lists_dir = false;
        let engine = PrivacyEngine::from_config(cfg.clone());

        assert!(engine.is_sensitive_app("com.bitwarden.desktop"));
        let decision = engine.evaluate_activity(
            Sink::Remote,
            "com.bitwarden.desktop",
            "Bitwarden",
            "",
        );
        assert!(!decision.allow);

        cfg.allow_apps = vec!["bitwarden".to_string()];
        let engine2 = PrivacyEngine::from_config(cfg);
        assert!(!engine2.is_sensitive_app("com.bitwarden.desktop"));
    }

    #[test]
    fn sensitive_domain_cannot_be_undone_by_custom_rules() {
        let mut cfg = PrivacyConfig::default();
        cfg.auto_load_lists_dir = false;
        cfg.sensitive_domain_action = SensitiveDomainAction::Redact;
        let mut sinks = HashMap::new();
        sinks.insert(
            Sink::Remote,
            SinkPolicyOverride {
                include_title: Some(true),
                include_files: Some(true),
                include_sites: Some(true),
                ..Default::default()
            },
        );
        cfg.rules.push(PrivacyRule {
            name: Some("Try to re-enable fields for Firefox".to_string()),
            app: Some("firefox".to_string()),
            sinks,
            ..Default::default()
        });

        let engine = PrivacyEngine::from_config(cfg);
        let decision = engine.evaluate_activity(
            Sink::Remote,
            "org.mozilla.firefox",
            "Sign in - paypal.com",
            "paypal.com",
        );
        assert!(decision.allow);
        assert_eq!(decision.window_title, "[redacted]");
        assert!(!decision.allow_files);
        assert!(!decision.allow_sites);
    }

    #[test]
    fn per_sink_combinations_work_independently() {
        let mut cfg = PrivacyConfig::default();
        cfg.auto_load_lists_dir = false;
        // Storage: save app + title, no files
        cfg.sinks.storage.include_files = false;
        // Remote: send category only, redact app & title
        cfg.sinks.remote.include_app = false;
        cfg.sinks.remote.include_title = false;
        // LLM: disabled completely
        cfg.sinks.llm.enabled = false;

        let engine = PrivacyEngine::from_config(cfg);

        let st = engine.evaluate_activity(Sink::Storage, "dev.zed.Zed", "main.rs", "");
        assert!(st.allow);
        assert_eq!(st.app_name, "dev.zed.Zed");
        assert_eq!(st.window_title, "main.rs");
        assert!(!st.allow_files);

        let rem = engine.evaluate_activity(Sink::Remote, "dev.zed.Zed", "main.rs", "");
        assert!(rem.allow);
        assert_eq!(rem.app_name, "[redacted]");
        assert_eq!(rem.window_title, "[redacted]");
        assert_eq!(rem.category, "Development");

        let llm = engine.evaluate_activity(Sink::Llm, "dev.zed.Zed", "main.rs", "");
        assert!(!llm.allow);
    }

    #[test]
    fn custom_rule_per_sink_override() {
        let mut cfg = PrivacyConfig::default();
        cfg.auto_load_lists_dir = false;
        let mut sinks = HashMap::new();
        sinks.insert(
            Sink::Remote,
            SinkPolicyOverride {
                enabled: Some(false),
                ..Default::default()
            },
        );
        cfg.rules.push(PrivacyRule {
            name: Some("Hide Discord from remote".to_string()),
            app: Some("discord".to_string()),
            sinks,
            ..Default::default()
        });

        let engine = PrivacyEngine::from_config(cfg);
        assert!(
            engine
                .evaluate_activity(Sink::Ui, "com.discordapp.Discord", "#general", "")
                .allow
        );
        assert!(
            !engine
                .evaluate_activity(Sink::Remote, "com.discordapp.Discord", "#general", "")
                .allow
        );
    }

    #[test]
    fn parses_misp_hosts_and_plain_domain_lists() {
        let misp_json = r#"{"name":"bank-website","list":["*.ing.nl","https://rabobank.nl/","abnamro.nl"]}"#;
        let parsed_json = parse_domain_list_content(misp_json);
        assert_eq!(parsed_json, vec!["ing.nl", "rabobank.nl", "abnamro.nl"]);

        let hosts_txt = "# comment\n0.0.0.0 localhost\n0.0.0.0 example-adult.com # inline\n127.0.0.1 another.org\n||adblock-bank.de^\nplainbank.fr\n";
        let parsed_txt = parse_domain_list_content(hosts_txt);
        assert_eq!(
            parsed_txt,
            vec!["example-adult.com", "another.org", "adblock-bank.de", "plainbank.fr"]
        );

        let dir = std::env::temp_dir().join(format!("agy_privacy_list_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let list_path = dir.join("banks.json");
        std::fs::write(&list_path, misp_json).unwrap();

        let mut cfg = PrivacyConfig::default();
        cfg.use_default_sensitive_domains = false;
        cfg.auto_load_lists_dir = false;
        cfg.sensitive_domain_files = vec![list_path.to_string_lossy().to_string()];
        cfg.allow_domains = vec!["abnamro.nl".to_string()];

        let engine = PrivacyEngine::from_config(cfg);
        assert_eq!(engine.loaded_domain_count(), 3);
        assert!(engine.is_sensitive_domain("mijn.ing.nl"));
        assert!(engine.is_sensitive_domain("Login at rabobank.nl — Mozilla Firefox"));
        assert!(!engine.is_sensitive_domain("abnamro.nl"));
        assert!(!engine.is_sensitive_domain("github.com"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn config_reload_fail_closed_last_good_and_list_mtime() {
        let dir = std::env::temp_dir().join(format!("agy_privacy_reload_{}", std::process::id()));
        let lists_dir = dir.join("lists");
        let _ = std::fs::create_dir_all(&lists_dir);
        let cfg_path = dir.join("privacy.json");

        let set_mtime_secs = |p: &Path, secs: u64| {
            let f = std::fs::OpenOptions::new().write(true).open(p).unwrap();
            f.set_modified(SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(secs))
                .unwrap();
        };

        // 1. Corrupt initial config -> fail closed for Remote/LLM and redact Storage/UI
        std::fs::write(&cfg_path, "{ not valid json").unwrap();
        set_mtime_secs(&cfg_path, 1_700_000_000);
        let mut engine = PrivacyEngine::load(Some(&cfg_path));
        engine.set_list_check_interval(std::time::Duration::ZERO);
        assert!(!engine.sink_policy(Sink::Remote).enabled);
        assert!(!engine.sink_policy(Sink::Llm).enabled);
        assert!(engine.sink_policy(Sink::Storage).enabled);
        assert!(!engine.sink_policy(Sink::Storage).include_title);
        assert!(!engine.sink_policy(Sink::Ui).include_title);

        // 2. Write valid config with newer mtime -> reload picks it up
        let valid_cfg = r#"{
            "use_default_sensitive_domains": false,
            "auto_load_lists_dir": true,
            "sinks": {
                "remote": { "enabled": true, "include_title": false },
                "llm": { "enabled": true }
            }
        }"#;
        std::fs::write(&cfg_path, valid_cfg).unwrap();
        set_mtime_secs(&cfg_path, 1_700_000_010);
        assert!(engine.reload_if_changed());
        assert!(engine.sink_policy(Sink::Remote).enabled);
        assert!(!engine.sink_policy(Sink::Remote).include_title);

        // 3. Delete config transiently (atomic rename) -> keeps last good config
        std::fs::remove_file(&cfg_path).unwrap();
        assert!(!engine.reload_if_changed());
        assert!(engine.sink_policy(Sink::Remote).enabled);
        assert!(!engine.sink_policy(Sink::Remote).include_title);

        // Restore valid config
        std::fs::write(&cfg_path, valid_cfg).unwrap();
        set_mtime_secs(&cfg_path, 1_700_000_010);
        engine.reload_if_changed();

        // 4. Add/modify list file without touching privacy.json -> reload picks up new domain
        let list_file = lists_dir.join("custom.txt");
        std::fs::write(&list_file, "secretbank.example\n").unwrap();
        set_mtime_secs(&list_file, 1_700_000_020);
        assert!(engine.reload_if_changed());
        assert!(engine.is_sensitive_domain("login.secretbank.example"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn broad_allow_does_not_beat_specific_sensitive() {
        let mut cfg = PrivacyConfig::default();
        cfg.auto_load_lists_dir = false;
        cfg.allow_domains = vec!["google.com".to_string()];
        let engine = PrivacyEngine::from_config(cfg.clone());

        // Broad google.com allow must NOT unmask accounts.google.com or mail.google.com
        assert!(engine.is_sensitive_domain("accounts.google.com"));
        assert!(engine.is_sensitive_domain("mail.google.com"));

        // Exact or more specific allow DOES unmask
        cfg.allow_domains.push("accounts.google.com".to_string());
        let engine2 = PrivacyEngine::from_config(cfg);
        assert!(!engine2.is_sensitive_domain("accounts.google.com"));
        assert!(engine2.is_sensitive_domain("mail.google.com"));
    }

    #[test]
    fn sensitive_keywords_and_dotless_domain_fallback() {
        let mut cfg = PrivacyConfig::default();
        cfg.auto_load_lists_dir = false;
        // Dotless entry in legacy sensitive_domains should still protect via keyword promotion
        cfg.sensitive_domains = vec!["internalbank".to_string()];
        // Dotless domain in custom rule should still match
        cfg.rules.push(PrivacyRule {
            name: Some("Redact intranet".to_string()),
            domain: Some("intranet".to_string()),
            action: RuleAction::Redact,
            ..Default::default()
        });
        let engine = PrivacyEngine::from_config(cfg);

        // Default keywords preserved
        assert!(!engine
            .evaluate_activity(Sink::Remote, "firefox", "MyChart - Login", "mychart.stanford.org")
            .allow);
        assert!(!engine
            .evaluate_activity(Sink::Remote, "firefox", "Sign in", "gov.uk/sign-in")
            .allow);
        // Legacy dotless sensitive_domains entry still protects
        assert!(!engine
            .evaluate_activity(Sink::Remote, "firefox", "internalbank portal", "")
            .allow);
        // Dotless rule.domain still matches
        let d = engine.evaluate_activity(Sink::Remote, "firefox", "intranet wiki", "");
        assert!(d.allow);
        assert_eq!(d.window_title, "[redacted]");
    }

    #[test]
    fn app_token_boundaries_and_idn_domains() {
        let mut cfg = PrivacyConfig::default();
        cfg.auto_load_lists_dir = false;
        cfg.use_default_sensitive_domains = false;
        cfg.sensitive_domains = vec!["bücher.de".to_string()];
        let engine = PrivacyEngine::from_config(cfg);

        // "enpass" must not match "enpassant"; "org.gnome.seahorse" must not match generic "seahorse"
        assert!(!engine.is_sensitive_app("enpassant"));
        assert!(!engine.is_sensitive_app("seahorse"));
        assert!(engine.is_sensitive_app("io.enpass.Enpass"));
        assert!(engine.is_sensitive_app("org.gnome.seahorse"));

        // IDN domain bücher.de is extracted intact (not truncated to cher.de)
        assert!(engine.is_sensitive_domain("https://bücher.de/checkout"));
        assert!(!engine.is_sensitive_domain("https://cher.de/"));
    }
}
