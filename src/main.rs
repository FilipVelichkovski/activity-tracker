mod browser;
mod categorizer;
mod daemon;
mod dbus_monitor;
mod proc_scanner;
mod storage;
mod title_files;
mod tray;
mod uri;
mod web_ui;
mod xbel;

use chrono::{DateTime, Duration, Local, NaiveDate, TimeZone};
use clap::{Parser, Subcommand};
use serde::Serialize;
use std::path::PathBuf;
use std::process::Command;

use storage::{AppSummary, CategorySummary, OpenedFileRecord, TrackerDb, VisitedSiteRecord};
use xbel::{default_xbel_path, parse_xbel_bytes};

const SERVICE_NAME: &str = "activity-tracker.service";

#[derive(Parser)]
#[command(
    name = "activity-tracker",
    about = "KDE Wayland active (non-minimized) app time & opened file tracker"
)]
struct Cli {
    /// Path to SQLite database (default: ~/.local/share/activity-tracker/activity.db)
    #[arg(long, global = true)]
    db: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the tracker daemon in the foreground
    Run {
        /// Log window switches and discovered files to stderr
        #[arg(short, long)]
        verbose: bool,
        /// Disable /proc/<pid>/fd fallback scanning (use DBus + XBEL only)
        #[arg(long)]
        no_proc_fallback: bool,
        /// Web UI bind address
        #[arg(long, default_value = "127.0.0.1:7878")]
        web_addr: String,
        /// Disable embedded Web UI server
        #[arg(long)]
        no_web: bool,
        /// Disable system tray icon
        #[arg(long)]
        no_tray: bool,
    },
    /// Serve the Web UI standalone (read-only historical view)
    Web {
        /// Web UI bind address
        #[arg(long, default_value = "127.0.0.1:7878")]
        addr: String,
    },
    /// Show application time and opened files summary
    Report {
        /// Look back N days (default: since midnight today)
        #[arg(long)]
        days: Option<i64>,
        /// Start date YYYY-MM-DD
        #[arg(long)]
        since: Option<String>,
        /// Filter by application name substring
        #[arg(long)]
        app: Option<String>,
        /// Max opened files to display
        #[arg(long, default_value_t = 30)]
        file_limit: i64,
        /// Output JSON
        #[arg(long)]
        json: bool,
    },
    /// List opened files
    Files {
        #[arg(long)]
        days: Option<i64>,
        #[arg(long)]
        since: Option<String>,
        #[arg(long)]
        app: Option<String>,
        #[arg(long, default_value_t = 100)]
        limit: i64,
        #[arg(long)]
        json: bool,
    },
    /// List recent active window sessions
    Sessions {
        #[arg(long, default_value_t = 20)]
        limit: i64,
    },
    /// List visited websites (from browser sessionstore & window titles)
    Sites {
        #[arg(long)]
        days: Option<i64>,
        #[arg(long)]
        since: Option<String>,
        #[arg(long)]
        app: Option<String>,
        #[arg(long, default_value_t = 100)]
        limit: i64,
        #[arg(long)]
        json: bool,
    },
    /// Purge noisy internal/cache proc-fd entries from the database
    CleanNoise,
    /// Import existing entries from ~/.local/share/recently-used.xbel into the DB
    ImportXbel {
        /// Optional path to .xbel file
        #[arg(long)]
        path: Option<PathBuf>,
    },
    /// Install & start systemd user service
    InstallService,
    /// Stop & remove systemd user service
    UninstallService,
}

fn format_duration(seconds: f64) -> String {
    let total = seconds.round() as i64;
    let hours = total / 3600;
    let mins = (total % 3600) / 60;
    let secs = total % 60;
    if hours > 0 {
        format!("{hours}h {mins:02}m {secs:02}s")
    } else if mins > 0 {
        format!("{mins}m {secs:02}s")
    } else {
        format!("{secs}s")
    }
}

fn format_ts(ts: f64) -> String {
    let secs = ts.floor() as i64;
    DateTime::from_timestamp(secs, 0)
        .map(|dt| dt.with_timezone(&Local).format("%Y-%m-%d %H:%M:%S").to_string())
        .unwrap_or_else(|| "-".to_string())
}

fn resolve_time_range(days: Option<i64>, since: Option<&str>) -> Result<(f64, f64), String> {
    let now = Local::now();
    let until_ts = (now.timestamp_millis() as f64 / 1000.0) + 1.0;
    if let Some(date_str) = since {
        let d = NaiveDate::parse_from_str(date_str, "%Y-%m-%d")
            .map_err(|e| format!("Invalid --since date {date_str:?}: {e}"))?;
        let naive_dt = d.and_hms_opt(0, 0, 0).unwrap();
        let dt = Local
            .from_local_datetime(&naive_dt)
            .single()
            .ok_or_else(|| "Ambiguous local time".to_string())?;
        return Ok((dt.timestamp() as f64, until_ts));
    }
    if let Some(n) = days {
        let start = now - Duration::days(n);
        return Ok((start.timestamp() as f64, until_ts));
    }
    let today = now.date_naive().and_hms_opt(0, 0, 0).unwrap();
    let midnight = Local.from_local_datetime(&today).unwrap();
    Ok((midnight.timestamp() as f64, until_ts))
}

#[derive(Serialize)]
struct ReportJson {
    categories: Vec<CategorySummary>,
    apps: Vec<AppSummary>,
    files: Vec<OpenedFileRecord>,
    sites: Vec<VisitedSiteRecord>,
}

fn cmd_report(
    db_path: Option<&PathBuf>,
    days: Option<i64>,
    since: Option<&str>,
    app: Option<&str>,
    file_limit: i64,
    json: bool,
) -> Result<(), String> {
    let (since_ts, until_ts) = resolve_time_range(days, since)?;
    let db = TrackerDb::open(db_path.map(|p| p.as_path())).map_err(|e| e.to_string())?;
    let categories = db
        .query_category_summary(since_ts, until_ts, app)
        .map_err(|e| e.to_string())?;
    let apps = db
        .query_app_summary(since_ts, until_ts, app)
        .map_err(|e| e.to_string())?;
    let files = db
        .query_opened_files(since_ts, until_ts, app, file_limit)
        .map_err(|e| e.to_string())?;
    let sites = db
        .query_visited_sites(since_ts, until_ts, app, file_limit)
        .map_err(|e| e.to_string())?;

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&ReportJson {
                categories,
                apps,
                files,
                sites,
            })
            .unwrap()
        );
        return Ok(());
    }

    let total_sec: f64 = apps.iter().map(|a| a.total_sec).sum();
    println!(
        "Activity Report ({} -> {})",
        format_ts(since_ts),
        format_ts(until_ts)
    );
    println!("Total active time: {}\n", format_duration(total_sec));

    if apps.is_empty() {
        println!("No active window sessions recorded in this period.");
    } else {
        if !categories.is_empty() {
            println!(
                "{:<34} {:>12} {:>7} {:>9} {:>7}",
                "Category", "Time", "Share", "Sessions", "Apps"
            );
            println!("{}", "-".repeat(74));
            for cat in &categories {
                let pct = if total_sec > 0.0 {
                    cat.total_sec / total_sec * 100.0
                } else {
                    0.0
                };
                println!(
                    "{:<34} {:>12} {:>6.1}% {:>9} {:>7}",
                    cat.category,
                    format_duration(cat.total_sec),
                    pct,
                    cat.session_count,
                    cat.app_count
                );
            }
            println!();
        }

        println!(
            "{:<34} {:>12} {:>7} {:>9} {:>7}",
            "Application", "Time", "Share", "Sessions", "Files"
        );
        println!("{}", "-".repeat(74));
        for row in &apps {
            let pct = if total_sec > 0.0 {
                row.total_sec / total_sec * 100.0
            } else {
                0.0
            };
            let app_disp: String = row.app_name.chars().take(33).collect();
            println!(
                "{:<34} {:>12} {:>6.1}% {:>9} {:>7}",
                app_disp,
                format_duration(row.total_sec),
                pct,
                row.session_count,
                row.file_count
            );
        }
    }

    if !files.is_empty() {
        println!("\nOpened Files (top {}):", files.len());
        println!("{}", "-".repeat(74));
        for f in &files {
            println!(
                "[{} | {}] {}  (last: {})",
                f.app_name,
                f.source,
                f.file_path,
                format_ts(f.last_seen_at)
            );
        }
    }

    if !sites.is_empty() {
        println!("\nWebsites Visited (top {}):", sites.len());
        println!("{}", "-".repeat(74));
        for s in &sites {
            let loc = if s.url.is_empty() {
                s.page_title.as_str()
            } else {
                s.url.as_str()
            };
            println!(
                "[{} | {}] {}  — {}  (last: {})",
                s.domain,
                s.source,
                loc,
                s.page_title,
                format_ts(s.last_seen_at)
            );
        }
    }

    Ok(())
}

fn cmd_files(
    db_path: Option<&PathBuf>,
    days: Option<i64>,
    since: Option<&str>,
    app: Option<&str>,
    limit: i64,
    json: bool,
) -> Result<(), String> {
    let (since_ts, until_ts) = resolve_time_range(days, since)?;
    let db = TrackerDb::open(db_path.map(|p| p.as_path())).map_err(|e| e.to_string())?;
    let files = db
        .query_opened_files(since_ts, until_ts, app, limit)
        .map_err(|e| e.to_string())?;

    if json {
        println!("{}", serde_json::to_string_pretty(&files).unwrap());
        return Ok(());
    }
    if files.is_empty() {
        println!("No opened files recorded in this period.");
        return Ok(());
    }
    for f in files {
        println!(
            "{} .. {}  [{} | {}]  {}",
            format_ts(f.first_seen_at),
            format_ts(f.last_seen_at),
            f.app_name,
            f.source,
            f.file_path
        );
    }
    Ok(())
}

fn cmd_sites(
    db_path: Option<&PathBuf>,
    days: Option<i64>,
    since: Option<&str>,
    app: Option<&str>,
    limit: i64,
    json: bool,
) -> Result<(), String> {
    let (since_ts, until_ts) = resolve_time_range(days, since)?;
    let db = TrackerDb::open(db_path.map(|p| p.as_path())).map_err(|e| e.to_string())?;
    let sites = db
        .query_visited_sites(since_ts, until_ts, app, limit)
        .map_err(|e| e.to_string())?;

    if json {
        println!("{}", serde_json::to_string_pretty(&sites).unwrap());
        return Ok(());
    }
    if sites.is_empty() {
        println!("No visited websites recorded in this period.");
        return Ok(());
    }
    for s in sites {
        let loc = if s.url.is_empty() { &s.page_title } else { &s.url };
        println!(
            "{} .. {}  [{} | {}]  {}  ({})",
            format_ts(s.first_seen_at),
            format_ts(s.last_seen_at),
            s.domain,
            s.source,
            loc,
            s.page_title
        );
    }
    Ok(())
}

fn cmd_clean_noise(db_path: Option<&PathBuf>) -> Result<(), String> {
    let db = TrackerDb::open(db_path.map(|p| p.as_path())).map_err(|e| e.to_string())?;
    let removed = db
        .purge_noisy_proc_files(proc_scanner::is_relevant_file)
        .map_err(|e| e.to_string())?;
    println!("Removed {removed} noisy internal/cache proc-fd entries.");
    Ok(())
}

fn cmd_sessions(db_path: Option<&PathBuf>, limit: i64) -> Result<(), String> {
    let db = TrackerDb::open(db_path.map(|p| p.as_path())).map_err(|e| e.to_string())?;
    let rows = db.query_recent_sessions(limit).map_err(|e| e.to_string())?;
    if rows.is_empty() {
        println!("No sessions recorded yet.");
        return Ok(());
    }
    for r in rows {
        println!(
            "#{:<5} {}  {:>10}  [{}]  {}",
            r.id,
            format_ts(r.started_at),
            format_duration(r.duration_sec),
            r.app_name,
            r.window_title
        );
    }
    Ok(())
}

fn cmd_import_xbel(db_path: Option<&PathBuf>, xbel_path: Option<&PathBuf>) -> Result<(), String> {
    let path = xbel_path.cloned().unwrap_or_else(default_xbel_path);
    let bytes = std::fs::read(&path)
        .map_err(|e| format!("Failed to read {}: {e}", path.display()))?;
    let entries = parse_xbel_bytes(&bytes);
    let db = TrackerDb::open(db_path.map(|p| p.as_path())).map_err(|e| e.to_string())?;
    for entry in &entries {
        db.record_file(
            None,
            &entry.app_name,
            &entry.file_path,
            "xbel",
            entry.modified_ts,
        )
        .map_err(|e| e.to_string())?;
    }
    println!("Imported {} file entries from {}", entries.len(), path.display());
    Ok(())
}

fn cmd_install_service(db_path: Option<&PathBuf>) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| "HOME not set".to_string())?;
    let unit_dir = home.join(".config/systemd/user");
    std::fs::create_dir_all(&unit_dir).map_err(|e| e.to_string())?;
    let unit_path = unit_dir.join(SERVICE_NAME);

    let db_arg = db_path
        .map(|p| format!(" --db {}", p.display()))
        .unwrap_or_default();
    let unit = format!(
        "[Unit]\n\
         Description=KDE Wayland Active Window & Opened File Tracker\n\
         After=graphical-session.target plasma-kwin_wayland.service\n\
         PartOf=graphical-session.target\n\n\
         [Service]\n\
         Type=simple\n\
         ExecStart={}{} run\n\
         Restart=on-failure\n\
         RestartSec=3\n\n\
         [Install]\n\
         WantedBy=graphical-session.target\n",
        exe.display(),
        db_arg
    );

    std::fs::write(&unit_path, unit).map_err(|e| e.to_string())?;
    Command::new("systemctl")
        .args(["--user", "daemon-reload"])
        .status()
        .map_err(|e| e.to_string())?;
    Command::new("systemctl")
        .args(["--user", "enable", "--now", SERVICE_NAME])
        .status()
        .map_err(|e| e.to_string())?;
    println!("Installed and started {}", unit_path.display());
    Ok(())
}

fn cmd_uninstall_service() -> Result<(), String> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| "HOME not set".to_string())?;
    let unit_path = home.join(".config/systemd/user").join(SERVICE_NAME);
    let _ = Command::new("systemctl")
        .args(["--user", "disable", "--now", SERVICE_NAME])
        .status();
    if unit_path.exists() {
        let _ = std::fs::remove_file(&unit_path);
    }
    let _ = Command::new("systemctl")
        .args(["--user", "daemon-reload"])
        .status();
    println!("Uninstalled {SERVICE_NAME}");
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), String> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Run {
            verbose,
            no_proc_fallback,
            web_addr,
            no_web,
            no_tray,
        } => {
            let web = if no_web { None } else { Some(web_addr) };
            daemon::run_daemon(
                cli.db.as_deref(),
                verbose,
                !no_proc_fallback,
                web,
                !no_tray,
            )
            .await?;
        }
        Commands::Web { addr } => {
            let db_path = cli
                .db
                .clone()
                .unwrap_or_else(storage::default_db_path);
            println!("Serving Activity Tracker Web UI at http://{addr}");
            web_ui::serve_web_ui(
                &addr,
                web_ui::WebContext {
                    db_path,
                    state: None,
                },
            )
            .await?;
        }
        Commands::Report {
            days,
            since,
            app,
            file_limit,
            json,
        } => {
            cmd_report(
                cli.db.as_ref(),
                days,
                since.as_deref(),
                app.as_deref(),
                file_limit,
                json,
            )?;
        }
        Commands::Files {
            days,
            since,
            app,
            limit,
            json,
        } => {
            cmd_files(
                cli.db.as_ref(),
                days,
                since.as_deref(),
                app.as_deref(),
                limit,
                json,
            )?;
        }
        Commands::Sites {
            days,
            since,
            app,
            limit,
            json,
        } => {
            cmd_sites(
                cli.db.as_ref(),
                days,
                since.as_deref(),
                app.as_deref(),
                limit,
                json,
            )?;
        }
        Commands::CleanNoise => {
            cmd_clean_noise(cli.db.as_ref())?;
        }
        Commands::Sessions { limit } => {
            cmd_sessions(cli.db.as_ref(), limit)?;
        }
        Commands::ImportXbel { path } => {
            cmd_import_xbel(cli.db.as_ref(), path.as_ref())?;
        }
        Commands::InstallService => {
            cmd_install_service(cli.db.as_ref())?;
        }
        Commands::UninstallService => {
            cmd_uninstall_service()?;
        }
    }
    Ok(())
}
